use std::io::Cursor;
use std::sync::Arc;

use libvz::ext_meta::Xattr;
use libvz::{
    CODEC_NONE, CODEC_ZSTD, CountingRangeReader, EncryptionKey, EntryOptions, ExtTime,
    FUSE_ROOT_ID, FuseFileKind, FuseVolume, KIND_LNK, LsmAppendWriter, OwnerEntry, VzError,
    VzReader, VzReaderOptions, VzWriter, VzWriterConfig,
};

#[test]
fn test_fuse3_volume_metadata_readdirplus_hardlinks_chunk_cache_and_zero_amp() {
    let raw_key = EncryptionKey::Raw256([0x33; 32]);
    let cfg = VzWriterConfig {
        default_codec: CODEC_ZSTD,
        target_cluster_size: 64 * 1024,
        multi_cluster_threshold: 64 * 1024,
        encryption: Some(raw_key.clone()),
        ..Default::default()
    };
    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
    w.add_dir("/dir", 0o755, 1_700_000_000_000_000_000).unwrap();
    w.add_dir("/dir/sub", 0o750, 1_700_000_001_000_000_000).unwrap();

    // 1. Small inline-sized file (encrypted) with xattrs, owner, ExtTime
    let ext_t = ExtTime {
        mtime_sec: 1_700_000_002,
        btime_sec: 1_699_000_000,
        mtime_nsec: 123_456_789,
        btime_nsec: 555,
    };
    w.add_file_with_options(
        "/dir/meta.txt",
        b"fuse metadata payload",
        EntryOptions {
            mode: 0o640,
            ext_time: Some(ext_t),
            owner: Some(OwnerEntry {
                uid: 1000,
                gid: 1000,
                uname: "alice".into(),
                gname: "users".into(),
            }),
            xattrs: vec![Xattr {
                key: "user.tag".into(),
                value: b"v1".to_vec(),
            }],
            ..Default::default()
        },
    )
    .unwrap();

    // 2. Hardlink sharing inode + nlink == 2
    w.add_hardlink("/dir/sub/meta_link.txt", "/dir/meta.txt")
        .unwrap();

    // 3. Symlink
    w.add_file_with_options(
        "/dir/latest",
        b"meta.txt",
        EntryOptions {
            kind: KIND_LNK,
            mode: 0o777,
            ..Default::default()
        },
    )
    .unwrap();

    // 4. Multi-cluster Zstd encrypted blob (256 KiB = 4 x 64 KiB chunks)
    let mc_data: Vec<u8> = (0u32..262_144)
        .map(|i| ((i ^ (i >> 7)).wrapping_mul(19) >> 3) as u8)
        .collect();
    w.add_file("/dir/big.bin", &mc_data).unwrap();

    // 5. Sparse file with a 1 MiB zero hole in the middle
    w.add_sparse_file(
        "/dir/sparse.dat",
        2 * 1024 * 1024,
        &[(0, b"HEAD"), (1536 * 1024, b"TAIL")],
        EntryOptions::default(),
    )
    .unwrap();

    // 6. Entry to be deleted via LSM overlay + 20 paginated dir items
    w.add_file("/dir/to_delete.txt", b"bye").unwrap();
    for i in 0..15 {
        w.add_file(&format!("/dir/f_{i:02}.txt"), format!("item-{i}").as_bytes())
            .unwrap();
    }
    let bytes1 = w.finish().unwrap().into_inner();

    // Apply LSM overlay deleting `/dir/to_delete.txt` and adding `/dir/overlay.txt`
    let mut app = LsmAppendWriter::open(Cursor::new(bytes1), Some(raw_key.clone()), 512, 128).unwrap();
    app.delete("/dir/to_delete.txt").unwrap();
    app.add_file("/dir/overlay.txt", b"new overlay data").unwrap();
    let bytes2 = app.finish().unwrap().into_inner();

    let counter = CountingRangeReader::new(bytes2);
    let vr = Arc::new(
        VzReader::open_with_options(
            counter,
            VzReaderOptions {
                encryption: Some(raw_key),
                repair_boot_ecc: true,
            },
        )
        .unwrap(),
    );

    let fs = FuseVolume::mount(Arc::clone(&vr)).unwrap();
    // Reset read counters after mount! All metadata ops below must issue ZERO disk reads!
    fs.reader().reader().reset();

    // Verify root & dir hierarchy, nlink, getattr, lookup, xattrs, readlink, LSM visibility
    let root_attr = fs.getattr(FUSE_ROOT_ID).unwrap();
    assert_eq!(root_attr.kind, FuseFileKind::Directory);
    assert_eq!(root_attr.nlink, 3); // "." + ".." + "dir"

    let dir_attr = fs.lookup(FUSE_ROOT_ID, "dir").unwrap();
    assert_eq!(dir_attr.kind, FuseFileKind::Directory);
    assert_eq!(dir_attr.nlink, 3); // "." + ".." + "sub"

    let sub_attr = fs.lookup(dir_attr.ino, "sub").unwrap();
    assert_eq!(sub_attr.nlink, 2); // "." + ".."

    assert_eq!(fs.lookup(dir_attr.ino, "to_delete.txt"), Err(VzError::NotFound));
    assert_eq!(VzError::NotFound.to_errno(), 2);

    let meta_attr = fs.lookup(dir_attr.ino, "meta.txt").unwrap();
    let link_attr = fs.lookup(sub_attr.ino, "meta_link.txt").unwrap();
    assert_eq!(meta_attr.ino, link_attr.ino);
    assert_eq!(meta_attr.nlink, 2);
    assert_eq!(meta_attr.uid, 1000);
    assert_eq!(meta_attr.gid, 1000);
    assert_eq!(meta_attr.crtime_sec, 1_699_000_000);
    assert_eq!(meta_attr.mtime_nsec, 123_456_789);
    assert_eq!(fs.getxattr(meta_attr.ino, "user.tag").unwrap(), b"v1");
    assert_eq!(fs.listxattr(meta_attr.ino).unwrap(), vec!["user.tag"]);

    // Paginated `readdirplus` across `/dir` in batches of 4
    let mut cursor = 0u64;
    let mut names = Vec::new();
    loop {
        let batch = fs.readdirplus(dir_attr.ino, cursor, 4).unwrap();
        if batch.is_empty() {
            break;
        }
        cursor = batch.last().unwrap().offset;
        for item in batch {
            names.push(item.name);
        }
    }
    assert_eq!(names[0], ".");
    assert_eq!(names[1], "..");
    assert!(!names.iter().any(|n| n == "to_delete.txt"));
    assert!(names.iter().any(|n| n == "overlay.txt"));
    assert_eq!(names.len(), 2 + 15 + 6); // ., .., f_00..14, big.bin, latest, meta.txt, overlay.txt, sparse.dat, sub

    // Statfs check
    let stfs = fs.statfs();
    assert!(stfs.blocks >= 1);
    assert!(stfs.files >= 22);

    // Zero disk reads issued during all metadata, lookup, readdirplus, xattr, statfs calls!
    assert_eq!(fs.reader().reader().reads(), 0);

    // Read symlink & overlay file
    let sym_attr = fs.lookup(dir_attr.ino, "latest").unwrap();
    assert_eq!(fs.readlink(sym_attr.ino).unwrap(), b"meta.txt");

    // Sparse zero-hole read issues ZERO I/O inside the hole!
    let sp_attr = fs.lookup(dir_attr.ino, "sparse.dat").unwrap();
    let fh_sp = fs.open(sp_attr.ino).unwrap();
    fs.reader().reader().reset();
    let hole = fs.read(&fh_sp, 512 * 1024, 4096).unwrap();
    assert!(hole.iter().all(|&b| b == 0));
    assert_eq!(fs.reader().reader().reads(), 0);
    assert_eq!(fs.read(&fh_sp, 1536 * 1024, 4).unwrap(), b"TAIL");

    // Multi-cluster sequential VFS 4 KiB reads inside Chunk 0 (64 KiB = 16 x 4 KiB reads):
    // open() fetches chunk table ONCE; first 4 KiB read decodes chunk 0 ONCE; next 15 reads do 0 I/O!
    let big_attr = fs.lookup(dir_attr.ino, "big.bin").unwrap();
    let fh_big = fs.open(big_attr.ino).unwrap();
    fs.reader().reader().reset();
    for page in 0..16 {
        let off = page * 4096;
        let got = fs.read(&fh_big, off as u64, 4096).unwrap();
        assert_eq!(got, mc_data[off..off + 4096]);
    }
    // Exactly 1 single cluster read across all 16 x 4 KiB sequential VFS reads!
    assert_eq!(fs.reader().reader().reads(), 1);
}

#[test]
fn test_fuse3_uncompressed_zero_read_amplification() {
    // 512 KiB uncompressed single-cluster file -> 4 KiB FUSE read must read ONLY 4,096 bytes!
    let mut raw = vec![0u8; 512 * 1024];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = (i.wrapping_mul(29) >> 4) as u8;
    }
    let cfg = VzWriterConfig {
        default_codec: CODEC_NONE,
        ..Default::default()
    };
    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
    w.add_file("/uncomp.bin", &raw).unwrap();
    let archive = w.finish().unwrap().into_inner();

    let counter = CountingRangeReader::new(archive);
    let vr = Arc::new(VzReader::open(counter).unwrap());
    let fs = FuseVolume::mount(vr).unwrap();
    let attr = fs.lookup(FUSE_ROOT_ID, "uncomp.bin").unwrap();
    let fh = fs.open(attr.ino).unwrap();

    fs.reader().reader().reset();
    let slice = fs.read(&fh, 200_000, 4096).unwrap();
    assert_eq!(slice, raw[200_000..204_096]);
    assert_eq!(fs.reader().reader().reads(), 1);
    assert_eq!(fs.reader().reader().bytes_read(), 4096);
}
