use std::io::{Cursor, Read, Write};

use libvz::ext_meta::{
    ColumnEncoding, ColumnLogicalType, ColumnMeta, DictEntry, OwnerEntry, SchemaEntry,
    TensorDtype, TensorMeta, Xattr,
};
use libvz::{
    CODEC_LZ4, CODEC_ZSTD, EncryptionKey, EntryOptions, ExtTime, INCOMPAT_ENCRYPTED, KIND_COLUMN,
    KIND_TENSOR, LsmAppendWriter, RO_COMPAT_LSM_RUNS, TREE_HEIGHT_PIPE, VzError, VzPipeWriter,
    VzReader, VzReaderOptions, VzWriter, VzWriterConfig, compact_archive, finalize_pipe_archive,
    scan_clusters_forward, verify_archive, walk_clusters_reverse,
};

#[test]
fn test_10000_nested_files_tree_height_ge_2() {
    let cfg = VzWriterConfig {
        max_leaf_entries: 128,
        max_route_entries: 64,
        target_cluster_size: 256 * 1024,
        ..Default::default()
    };
    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();

    // 100 directories x 100 files = 10,000 files + 100 dir entries = 10,100 entries.
    for d in 0..100 {
        w.add_dir(&format!("/d_{d:03}"), 0o755, d as i64).unwrap();
        for f in 0..100 {
            let mut data = Vec::with_capacity(32);
            data.extend_from_slice(&(d as u32).to_le_bytes());
            data.extend_from_slice(&(f as u32).to_le_bytes());
            if (d + f) % 2 == 0 {
                // Inline <= 27 B
                w.add_file(&format!("/d_{d:03}/f_{f:03}.bin"), &data)
                    .unwrap();
            } else {
                // External >= 28 B
                data.resize(40, ((d ^ f) & 0xFF) as u8);
                w.add_file(&format!("/d_{d:03}/f_{f:03}.bin"), &data)
                    .unwrap();
            }
        }
    }

    let archive = w.finish().unwrap().into_inner();
    let reader = VzReader::open(archive).unwrap();
    assert!(
        reader.active_slot().tree_height >= 2,
        "expected tree_height >= 2, got {}",
        reader.active_slot().tree_height
    );
    assert_eq!(reader.active_slot().total_entries, 10_100);

    let root_dirs = reader.readdir("/").unwrap();
    assert_eq!(root_dirs.len(), 100);

    // Verify every directory via readdir and byte-for-byte extraction across all 10,000 files.
    for d in 0..100 {
        let dir_path = format!("/d_{d:03}");
        let entries = reader.readdir(&dir_path).unwrap();
        assert_eq!(entries.len(), 100);
        for f in 0..100 {
            let file_path = format!("{dir_path}/f_{f:03}.bin");
            let mut expected = Vec::new();
            expected.extend_from_slice(&(d as u32).to_le_bytes());
            expected.extend_from_slice(&(f as u32).to_le_bytes());
            if (d + f) % 2 != 0 {
                expected.resize(40, ((d ^ f) & 0xFF) as u8);
            }
            let got = reader.read_file(&file_path).unwrap();
            assert_eq!(got, expected, "mismatch at {file_path}");
        }
    }
}

#[inline]
fn pattern_byte(idx: usize) -> u8 {
    let mut x = (idx as u64).wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (x ^ (x >> 31)) as u8
}

struct PatternReader {
    remaining: usize,
    offset: usize,
}

impl Read for PatternReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.remaining);
        for (i, slot) in buf[..n].iter_mut().enumerate() {
            *slot = pattern_byte(self.offset + i);
        }
        self.offset += n;
        self.remaining -= n;
        Ok(n)
    }
}

struct VerifyingSink {
    offset: usize,
}

impl Write for VerifyingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for (i, &b) in buf.iter().enumerate() {
            let expected = pattern_byte(self.offset + i);
            if b != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "byte mismatch",
                ));
            }
        }
        self.offset += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_multi_cluster_streaming_bounded_memory() {
    // 16 MiB streamed through 512 KiB chunks using PatternReader -> TempFile -> VerifyingSink.
    let total_bytes = 16 * 1024 * 1024;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let cfg = VzWriterConfig {
        target_cluster_size: 512 * 1024,
        multi_cluster_threshold: 512 * 1024,
        default_codec: CODEC_LZ4,
        ..Default::default()
    };
    let mut w = VzWriter::new(tmp.reopen().unwrap(), cfg).unwrap();
    let mut pre_flushed_pos = 0u64;
    w.add_file_reader(
        "/big_stream.bin",
        PatternReader {
            remaining: total_bytes,
            offset: 0,
        },
        EntryOptions::default(),
    )
    .unwrap();
    // Before finish() is called, chunk clusters have ALREADY streamed directly to disk!
    pre_flushed_pos = pre_flushed_pos.max(tmp.as_file().metadata().unwrap().len());
    assert!(
        pre_flushed_pos > 1024 * 1024,
        "chunks must stream directly to disk before finish(), got {pre_flushed_pos}"
    );
    w.finish().unwrap();

    let reader = VzReader::open(tmp.reopen().unwrap()).unwrap();
    let st = reader.stat("/big_stream.bin").unwrap();
    assert!(st.is_multi_cluster);
    assert_eq!(st.size, total_bytes as u64);

    let mut sink = VerifyingSink { offset: 0 };
    let written = reader.read_file_to_writer("/big_stream.bin", &mut sink).unwrap();
    assert_eq!(written, total_bytes as u64);
    assert_eq!(sink.offset, total_bytes);
}

#[test]
fn test_boundary_matrix_inline_sparse_hardlink_xattrs_exttime_tensors_dicts() {
    let dict_samples = b"common_json_prefix={\"id\":123,\"status\":\"ok\",\"payload\":\"value\"};";
    let dict_bytes = vec![dict_samples.as_slice(); 32].concat();
    let dict_id = 42u32;

    let schemas = vec![
        SchemaEntry::Tensor(TensorMeta {
            schema_id: 10,
            name: "embed".into(),
            dtype: TensorDtype::F32,
            byte_order: 0,
            dims: vec![4, 8],
            strides: vec![32, 4],
        }),
        SchemaEntry::Column(ColumnMeta {
            schema_id: 20,
            name: "ts".into(),
            logical_type: ColumnLogicalType::TimestampNs,
            encoding: ColumnEncoding::Plain,
            row_count: 100,
            null_count: 0,
            min_stat: Some(10i64.to_le_bytes().to_vec()),
            max_stat: Some(999i64.to_le_bytes().to_vec()),
        }),
    ];

    let cfg = VzWriterConfig {
        dicts: vec![DictEntry {
            dict_id,
            codec: CODEC_ZSTD,
            flags: 0,
            bytes: dict_bytes,
        }],
        schemas,
        enable_col_stats: true,
        ..Default::default()
    };

    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();

    // 0 B, 27 B inline vs 28 B external cutoff
    w.add_file("/empty.bin", b"").unwrap();
    w.add_file("/inline27.bin", &[b'A'; 27]).unwrap();
    w.add_file("/ext28.bin", &[b'B'; 28]).unwrap();

    // Sparse file with 4 MiB logical size & two small extents + all-zero 2 MiB sparse file
    w.add_sparse_file(
        "/sparse.bin",
        4 * 1024 * 1024,
        &[(0, b"HEAD"), (3 * 1024 * 1024, b"TAIL")],
        EntryOptions {
            codec: Some(CODEC_ZSTD),
            ..Default::default()
        },
    )
    .unwrap();
    w.add_sparse_file("/sparse_zero.bin", 2 * 1024 * 1024, &[], EntryOptions::default())
        .unwrap();

    // Hardlink + xattrs + pre-1970/post-2262 ExtTime + 64-bit inode + owner
    let pre1970_post2262 = ExtTime {
        mtime_sec: -50_000_000_000,
        btime_sec: 50_000_000_000,
        mtime_nsec: 777,
        btime_nsec: 888,
    };
    let xattrs = vec![
        Xattr {
            key: "user.author".into(),
            value: b"vz".to_vec(),
        },
        Xattr {
            key: "security.cap".into(),
            value: vec![1, 2, 3, 4],
        },
    ];
    let big_payload = vec![0x5Au8; 1024];
    w.add_file_with_options(
        "/orig.bin",
        &big_payload,
        EntryOptions {
            entry_id: Some(0x1_0000_0005),
            ext_time: Some(pre1970_post2262),
            xattrs: xattrs.clone(),
            owner: Some(OwnerEntry {
                uid: 1001,
                gid: 2002,
                uname: "dev".into(),
                gname: "eng".into(),
            }),
            ..Default::default()
        },
    )
    .unwrap();
    w.add_hardlink("/hardlink.bin", "/orig.bin").unwrap();

    // Zstd + Dictionary
    let dict_payload = b"common_json_prefix={\"id\":999,\"status\":\"ok\",\"payload\":\"value\"};extra"
        .repeat(8);
    w.add_file_with_options(
        "/dict.json",
        &dict_payload,
        EntryOptions {
            codec: Some(CODEC_ZSTD),
            dict_id: Some(dict_id),
            ..Default::default()
        },
    )
    .unwrap();

    // Tensor & Column entries
    w.add_file_with_options(
        "/model.tensor",
        &[0u8; 128],
        EntryOptions {
            kind: KIND_TENSOR,
            schema_id: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    w.add_file_with_options(
        "/events.col",
        &[1u8; 128],
        EntryOptions {
            kind: KIND_COLUMN,
            schema_id: Some(20),
            ..Default::default()
        },
    )
    .unwrap();

    let archive = w.finish().unwrap().into_inner();
    let r = VzReader::open(archive).unwrap();

    let st0 = r.stat("/empty.bin").unwrap();
    assert!(st0.is_inline);
    assert_eq!(r.read_file("/empty.bin").unwrap(), b"");

    let st27 = r.stat("/inline27.bin").unwrap();
    assert!(st27.is_inline);
    assert_eq!(r.read_file("/inline27.bin").unwrap(), vec![b'A'; 27]);

    let st28 = r.stat("/ext28.bin").unwrap();
    assert!(!st28.is_inline);
    assert_eq!(r.read_file("/ext28.bin").unwrap(), vec![b'B'; 28]);

    let sparse_got = r.read_file("/sparse.bin").unwrap();
    assert_eq!(sparse_got.len(), 4 * 1024 * 1024);
    assert_eq!(&sparse_got[..4], b"HEAD");
    assert!(sparse_got[4..3 * 1024 * 1024].iter().all(|&b| b == 0));
    assert_eq!(&sparse_got[3 * 1024 * 1024..3 * 1024 * 1024 + 4], b"TAIL");

    let sz_got = r.read_file("/sparse_zero.bin").unwrap();
    assert_eq!(sz_got.len(), 2 * 1024 * 1024);
    assert!(sz_got.iter().all(|&b| b == 0));

    let st_orig = r.stat("/orig.bin").unwrap();
    let st_hl = r.stat("/hardlink.bin").unwrap();
    assert_eq!(st_orig.entry_id, 0x1_0000_0005);
    assert_eq!(st_orig.entry_id, st_hl.entry_id);
    assert_eq!(st_orig.ext_time, Some(pre1970_post2262));
    assert_eq!(r.read_xattrs("/orig.bin").unwrap(), xattrs);
    assert_eq!(r.read_file("/hardlink.bin").unwrap(), big_payload);

    assert_eq!(r.read_file("/dict.json").unwrap(), dict_payload);

    let tmeta = r.read_tensor_meta("/model.tensor").unwrap();
    assert_eq!(tmeta.dtype, TensorDtype::F32);
    assert_eq!(tmeta.dims, vec![4, 8]);
    let cmeta = r.read_column_meta("/events.col").unwrap();
    assert_eq!(cmeta.logical_type, ColumnLogicalType::TimestampNs);
    assert_eq!(cmeta.row_count, 100);
}

#[test]
fn test_encryption_argon2id_raw256_and_tamper_rejection() {
    // 1. Argon2id password mode + Zstd compression
    let pw_key = EncryptionKey::from_password_with_params("hunter2-vz", 4096, 1, 1);
    let cfg = VzWriterConfig {
        default_codec: CODEC_ZSTD,
        encryption: Some(pw_key.clone()),
        ..Default::default()
    };
    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
    w.add_file("/secret.txt", b"top secret encrypted payload 1234567890")
        .unwrap();
    w.add_file("/other.txt", b"second file payload for splicing test")
        .unwrap();
    let archive = w.finish().unwrap().into_inner();

    // Missing key or wrong password must fail with CryptoError
    assert_eq!(
        VzReader::open(archive.clone()).err(),
        Some(VzError::CryptoError)
    );
    let wrong_pw = EncryptionKey::from_password_with_params("wrong-pw", 4096, 1, 1);
    assert_eq!(
        VzReader::open_with_options(
            archive.clone(),
            VzReaderOptions {
                encryption: Some(wrong_pw),
                repair_boot_ecc: true,
            }
        )
        .err(),
        Some(VzError::CryptoError)
    );

    let ok_r = VzReader::open_with_options(
        archive.clone(),
        VzReaderOptions {
            encryption: Some(pw_key.clone()),
            repair_boot_ecc: true,
        },
    )
    .unwrap();
    assert_ne!(ok_r.active_slot().incompat_flags & INCOMPAT_ENCRYPTED, 0);
    assert_eq!(
        ok_r.read_file("/secret.txt").unwrap(),
        b"top secret encrypted payload 1234567890"
    );

    // Tamper with ciphertext / tag in the first cluster -> must fail CryptoError
    let mut tampered = archive.clone();
    let boot_sz = 65_536usize;
    tampered[boot_sz + 140] ^= 0x01;
    let tr = VzReader::open_with_options(
        tampered,
        VzReaderOptions {
            encryption: Some(pw_key.clone()),
            repair_boot_ecc: true,
        },
    )
    .unwrap();
    assert_eq!(tr.read_file("/secret.txt"), Err(VzError::CryptoError));

    // Tamper with ClusterHeader::cluster_seq (AAD binding!) -> must fail CryptoError
    let mut aad_tampered = archive.clone();
    let seq_off = boot_sz + 24; // ClusterHeader.cluster_seq
    aad_tampered[seq_off] ^= 0x01;
    let ar = VzReader::open_with_options(
        aad_tampered,
        VzReaderOptions {
            encryption: Some(pw_key),
            repair_boot_ecc: true,
        },
    )
    .unwrap();
    assert_eq!(ar.read_file("/secret.txt"), Err(VzError::CryptoError));

    // 2. Raw 256-bit key mode
    let raw_key = EncryptionKey::Raw256([0x42u8; 32]);
    let mut rw = VzWriter::new(
        Cursor::new(Vec::new()),
        VzWriterConfig {
            encryption: Some(raw_key.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    rw.add_file("/k.bin", b"raw256 payload data").unwrap();
    let raw_arc = rw.finish().unwrap().into_inner();
    let rr = VzReader::open_with_options(
        raw_arc,
        VzReaderOptions {
            encryption: Some(raw_key),
            repair_boot_ecc: true,
        },
    )
    .unwrap();
    assert_eq!(rr.read_file("/k.bin").unwrap(), b"raw256 payload data");
}

#[test]
fn test_lsm_overlay_tombstone_and_compact() {
    let raw_key = EncryptionKey::Raw256([0x99u8; 32]);
    let cfg = VzWriterConfig {
        encryption: Some(raw_key.clone()),
        ..Default::default()
    };
    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
    w.add_file("/a.txt", b"version1-a-payload-data-00000000").unwrap();
    w.add_file("/b.txt", b"version1-b-payload-data-00000000").unwrap();
    w.add_file("/c.txt", b"version1-c-payload-data-00000000").unwrap();
    let cur = w.finish().unwrap();

    // Run 2: overwrite /b.txt, delete /c.txt, add /d.txt
    let mut app = LsmAppendWriter::open(cur, Some(raw_key.clone()), 512, 128).unwrap();
    app.add_file("/b.txt", b"version2-b-updated-payload-111111")
        .unwrap();
    app.delete("/c.txt").unwrap();
    app.add_file("/d.txt", b"version2-d-new-payload-2222222222")
        .unwrap();
    let cur2 = app.finish().unwrap();

    let r2 = VzReader::open_with_options(
        cur2.clone(),
        VzReaderOptions {
            encryption: Some(raw_key.clone()),
            repair_boot_ecc: true,
        },
    )
    .unwrap();
    assert_eq!(r2.active_slot().lsm_run_count, 2);
    assert_ne!(r2.active_slot().ro_compat_flags & RO_COMPAT_LSM_RUNS, 0);
    assert_eq!(r2.active_slot().total_entries, 3);
    assert_eq!(
        r2.read_file("/a.txt").unwrap(),
        b"version1-a-payload-data-00000000"
    );
    assert_eq!(
        r2.read_file("/b.txt").unwrap(),
        b"version2-b-updated-payload-111111"
    );
    assert_eq!(r2.read_file("/c.txt"), Err(VzError::NotFound));
    assert_eq!(
        r2.read_file("/d.txt").unwrap(),
        b"version2-d-new-payload-2222222222"
    );
    let ls_root: Vec<_> = r2.readdir("/").unwrap().into_iter().map(|s| s.name).collect();
    assert_eq!(ls_root, vec!["a.txt", "b.txt", "d.txt"]);

    // Compact to single-run
    let compacted_cur = compact_archive(
        &r2,
        Cursor::new(Vec::new()),
        VzWriterConfig {
            encryption: Some(raw_key.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let rc = VzReader::open_with_options(
        compacted_cur,
        VzReaderOptions {
            encryption: Some(raw_key),
            repair_boot_ecc: true,
        },
    )
    .unwrap();
    assert_eq!(rc.active_slot().lsm_run_count, 1);
    assert_eq!(rc.active_slot().total_entries, 3);
    assert_eq!(rc.read_file("/c.txt"), Err(VzError::NotFound));
    assert_eq!(
        rc.read_file("/b.txt").unwrap(),
        b"version2-b-updated-payload-111111"
    );
}

#[test]
fn test_streaming_pipe_unfinalized_and_finalized_and_cluster_walkers() {
    // 1. Unfinalized pipe written to a pure `Write` sink (Vec<u8> wrapped in write-only struct)
    struct WriteOnly(Vec<u8>);
    impl Write for WriteOnly {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut pw = VzPipeWriter::new(WriteOnly(Vec::new()), VzWriterConfig::default()).unwrap();
    pw.add_file("/pipe1.txt", b"inline pipe").unwrap();
    pw.add_file("/pipe2.bin", &[0xABu8; 2048]).unwrap();
    let (wo, info) = pw.finish().unwrap();
    let unfinalized = wo.0;

    // Unfinalized header has TREE_HEIGHT_PIPE; VzReader automatically recovers via TAG_ROOT_FALLBACK!
    let r_unfin = VzReader::open(unfinalized.clone()).unwrap();
    assert_eq!(r_unfin.active_slot().tree_height, TREE_HEIGHT_PIPE);
    assert_eq!(r_unfin.read_file("/pipe1.txt").unwrap(), b"inline pipe");
    assert_eq!(r_unfin.read_file("/pipe2.bin").unwrap(), vec![0xABu8; 2048]);

    // Walk clusters reverse & forward!
    let rev = walk_clusters_reverse(&unfinalized).unwrap();
    let fwd = scan_clusters_forward(&unfinalized, 65_536).unwrap();
    assert_eq!(rev, fwd);
    assert!(!rev.is_empty());

    // Finalize Boot Block on seekable cursor
    let mut seekable = Cursor::new(unfinalized);
    finalize_pipe_archive(&mut seekable, &info).unwrap();
    let finalized = seekable.into_inner();
    let r_fin = VzReader::open(finalized.clone()).unwrap();
    assert_ne!(r_fin.active_slot().tree_height, TREE_HEIGHT_PIPE);
    assert_ne!(r_fin.active_slot().root_fallback_off, 0);
    assert_eq!(r_fin.read_file("/pipe2.bin").unwrap(), vec![0xABu8; 2048]);
    let rep = verify_archive(&finalized, None).unwrap();
    assert!(rep.is_clean(), "pipe verify errors: {:?}", rep.errors);
}

#[test]
fn test_read_file_range_inline_single_multicluster_sparse_and_encrypted() {
    let raw_key = EncryptionKey::Raw256([0x42; 32]);
    let cfg = VzWriterConfig {
        target_cluster_size: 256 * 1024,
        multi_cluster_threshold: 256 * 1024,
        default_codec: CODEC_ZSTD,
        encryption: Some(raw_key.clone()),
        ..Default::default()
    };
    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();

    // 1. Inline (<= 27 B)
    let inline_data = b"0123456789abcdef0123456789A";
    assert_eq!(inline_data.len(), 27);
    w.add_file("/inline.bin", inline_data).unwrap();

    // 2. Single-cluster compressed + encrypted
    let single_data: Vec<u8> = (0u32..16_384).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect();
    w.add_file("/single.bin", &single_data).unwrap();

    // 3. Multi-cluster (6 chunks x 256 KiB = 1.5 MiB) compressed + encrypted
    let mc_len = 6 * 256 * 1024;
    let mc_data: Vec<u8> = (0u32..mc_len as u32)
        .map(|i| ((i ^ (i >> 9)).wrapping_mul(17) >> 4) as u8)
        .collect();
    w.add_file_reader(
        "/multi.bin",
        Cursor::new(mc_data.clone()),
        EntryOptions::default(),
    )
    .unwrap();

    // 4. Sparse (4 MiB logical, extents at 0 and 3 MiB)
    w.add_sparse_file(
        "/sparse.bin",
        4 * 1024 * 1024,
        &[(0, b"HEAD_DATA"), (3 * 1024 * 1024, b"TAIL_BYTES")],
        EntryOptions::default(),
    )
    .unwrap();

    let bytes = w.finish().unwrap().into_inner();

    let counter = libvz::CountingRangeReader::new(bytes.as_slice());
    let reader = VzReader::open_with_options(
        counter,
        VzReaderOptions {
            encryption: Some(raw_key),
            repair_boot_ecc: false,
        },
    )
    .unwrap();

    // Inline edge cases
    assert_eq!(reader.read_file_range("/inline.bin", 5, 6).unwrap(), b"56789a");
    assert_eq!(reader.read_file_range("/inline.bin", 25, 100).unwrap(), b"9A");
    assert_eq!(reader.read_file_range("/inline.bin", 27, 10).unwrap(), b"");
    assert_eq!(reader.read_file_range("/inline.bin", 0, 0).unwrap(), b"");

    // Single-cluster slice
    assert_eq!(
        reader.read_file_range("/single.bin", 1000, 777).unwrap(),
        single_data[1000..1777]
    );

    // Multi-cluster partial range spanning chunk boundary (chunk 3 & chunk 4 only, NOT all 6!)
    reader.reader().reset();
    let off = (3 * 256 * 1024 - 50) as u64;
    let span = 200usize;
    let got_mc = reader.read_file_range("/multi.bin", off, span).unwrap();
    assert_eq!(got_mc, mc_data[off as usize..off as usize + span]);
    // Must only fetch metadata + 2 chunks, strictly less than half of full 1.5 MiB raw data
    // (1 read for dir/chunk table + 2 cluster reads <= 10 reads).
    assert!(
        reader.reader().bytes_read() < mc_len as u64 / 2,
        "read_file_range read too many bytes: {}",
        reader.reader().bytes_read()
    );

    // Multi-cluster range completely past EOF returns empty
    assert_eq!(
        reader.read_file_range("/multi.bin", mc_len as u64 + 10, 64).unwrap(),
        b""
    );

    // Sparse range straddling hole + TAIL_BYTES
    let sp_off = (3 * 1024 * 1024 - 4) as u64;
    let sp_got = reader.read_file_range("/sparse.bin", sp_off, 14).unwrap();
    assert_eq!(sp_got, b"\0\0\0\0TAIL_BYTES");
}

#[test]
fn test_high_level_api_and_zero_reencode_compaction_mixed_codecs() {
    use libvz::low_level::{MAGIC_HEADER, CODEC_NONE};
    use libvz::{Archive, ArchiveBuilder, CompactOptions, Compression, compact_archive_with_options};

    assert_eq!(MAGIC_HEADER, u64::from_le_bytes(*b"VZ\x01\x00\x00\x00\x00\x00"));

    // Build initial archive via high-level ArchiveBuilder with mixed per-entry codecs,
    // hardlinks, sparse files, multi-cluster file, and a dictionary.
    let dict_bytes = vec![b'A'; 4096];
    let mut builder = ArchiveBuilder::new()
        .compression(Compression::zstd())
        .zstd_dictionary(7, dict_bytes, 3)
        .cluster_size(64 * 1024)
        .in_memory()
        .unwrap();

    let raw_zstd_payload = vec![0x5Au8; 10_000];
    let raw_lz4_payload = vec![0x3Cu8; 12_000];
    let raw_plain_payload = vec![0x77u8; 8_000];
    let mc_payload: Vec<u8> = (0u32..300_000).map(|i| (i.wrapping_mul(37) >> 4) as u8).collect();

    builder
        .add_with(
            "/dict_file.bin",
            &raw_zstd_payload,
            EntryOptions {
                codec: Some(CODEC_ZSTD),
                dict_id: Some(7),
                ..Default::default()
            },
        )
        .unwrap()
        .add_with(
            "/lz4_file.bin",
            &raw_lz4_payload,
            EntryOptions {
                codec: Some(CODEC_LZ4),
                dict_id: None,
                ..Default::default()
            },
        )
        .unwrap()
        .add_with(
            "/plain_file.bin",
            &raw_plain_payload,
            EntryOptions {
                codec: Some(CODEC_NONE),
                dict_id: None,
                ..Default::default()
            },
        )
        .unwrap()
        .add_with(
            "/lz4_explicit_none_dict.bin",
            &raw_zstd_payload,
            EntryOptions {
                codec: Some(CODEC_ZSTD),
                ..Default::default()
            },
        )
        .unwrap()
        .add_hardlink("/plain_hardlink.bin", "/plain_file.bin")
        .unwrap()
        .add_sparse("/sparse.bin", 2 * 1024 * 1024, &[(0, b"START"), (1024 * 1024, b"END")])
        .unwrap();
    // Explicitly force no dict + multi-cluster threshold via lower-level mut access
    builder
        .inner_mut()
        .add_file_with_options(
            "/multi.bin",
            &mc_payload,
            EntryOptions {
                codec: Some(CODEC_ZSTD),
                ..Default::default()
            },
        )
        .unwrap();
    let run1 = builder.finish().unwrap().into_inner();

    // Add 2 LSM overlay runs: overwrite /lz4_file.bin, delete /lz4_explicit_none_dict.bin, add /new.txt
    let mut app1 = LsmAppendWriter::open(Cursor::new(run1), None, 512, 128).unwrap();
    let updated_lz4 = vec![0x99u8; 9_000];
    app1.add_file_with_options(
        "/lz4_file.bin",
        &updated_lz4,
        EntryOptions {
            codec: Some(CODEC_LZ4),
            ..Default::default()
        },
    )
    .unwrap();
    app1.delete("/lz4_explicit_none_dict.bin").unwrap();
    let run2 = app1.finish().unwrap().into_inner();

    let mut app2 = LsmAppendWriter::open(Cursor::new(run2), None, 512, 128).unwrap();
    app2.add_file("/new.txt", b"overlay run 3 inline").unwrap();
    let run3 = app2.finish().unwrap().into_inner();

    let ar3 = Archive::from_vec(run3).unwrap();
    assert_eq!(ar3.reader().active_slot().lsm_run_count, 3);
    assert!(!ar3.exists("/lz4_explicit_none_dict.bin").unwrap());

    // Capture original stored_size and codec metadata before zero-reencode compaction
    let st_dict_before = ar3.stat("/dict_file.bin").unwrap();
    let st_lz4_before = ar3.stat("/lz4_file.bin").unwrap();
    let st_plain_before = ar3.stat("/plain_file.bin").unwrap();

    let compacted_bytes = compact_archive_with_options(
        ar3.reader(),
        Cursor::new(Vec::new()),
        CompactOptions::default(),
    )
    .unwrap()
    .into_inner();

    let arc = Archive::from_bytes(&compacted_bytes).unwrap();
    assert_eq!(arc.reader().active_slot().lsm_run_count, 1);
    assert_eq!(
        arc.reader().active_slot().ro_compat_flags & RO_COMPAT_LSM_RUNS,
        0
    );
    assert!(!arc.exists("/lz4_explicit_none_dict.bin").unwrap());

    // Exact codec and stored_size preserved WITHOUT re-encoding!
    let st_dict_after = arc.stat("/dict_file.bin").unwrap();
    let st_lz4_after = arc.stat("/lz4_file.bin").unwrap();
    let st_plain_after = arc.stat("/plain_file.bin").unwrap();
    let st_hl_after = arc.stat("/plain_hardlink.bin").unwrap();
    assert_eq!(st_dict_after.codec, st_dict_before.codec);
    assert_eq!(st_dict_after.stored_size, st_dict_before.stored_size);
    assert_eq!(st_lz4_after.codec, CODEC_LZ4);
    assert_eq!(st_lz4_after.stored_size, st_lz4_before.stored_size);
    assert_eq!(st_plain_after.codec, CODEC_NONE);
    assert_eq!(st_plain_after.stored_size, st_plain_before.stored_size);
    // Hardlinks preserve shared entry_id!
    assert_eq!(st_plain_after.entry_id, st_hl_after.entry_id);

    // Every surviving entry extracts identically and verify_archive passes clean
    assert_eq!(arc.get("/dict_file.bin").unwrap(), raw_zstd_payload);
    assert_eq!(arc.get("/lz4_file.bin").unwrap(), updated_lz4);
    assert_eq!(arc.get("/plain_file.bin").unwrap(), raw_plain_payload);
    assert_eq!(arc.get("/plain_hardlink.bin").unwrap(), raw_plain_payload);
    assert_eq!(arc.get("/multi.bin").unwrap(), mc_payload);
    assert_eq!(arc.get("/new.txt").unwrap(), b"overlay run 3 inline");
    assert_eq!(arc.get_range("/sparse.bin", 1024 * 1024, 3).unwrap(), b"END");

    let mut extracted_count = 0usize;
    arc.extract_all_with(|_entry, _data| {
        extracted_count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(extracted_count, 7);

    let rep = verify_archive(&compacted_bytes.as_slice(), None).unwrap();
    assert!(rep.is_clean(), "compacted verify errors: {:?}", rep.errors);
}
