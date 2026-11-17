use std::io::Cursor;

use libvz::ext_meta::{
    decode_chunk_table, decode_dict_table, decode_lsm_runs, decode_owner_table,
    decode_schema_table, decode_sparse_extents, decode_xattr_list,
};
use libvz::{
    BootHeader, CODEC_ZSTD, ClusterHeader, DirEntry, LeafNodeHeader, LeafNodeView, ParityManifest,
    RouteTableView, TlvIter, VzError, VzReader, VzWriter, VzWriterConfig, read_levint_safe,
    scan_clusters_forward, tlv_next, validate_cluster, verify_archive, walk_clusters_reverse,
};

fn build_sample_archive(height_ge_1: bool) -> Vec<u8> {
    let cfg = VzWriterConfig {
        default_codec: CODEC_ZSTD,
        max_leaf_entries: if height_ge_1 { 4 } else { 512 },
        max_route_entries: 4,
        target_cluster_size: 4096,
        enable_boot_ecc: false,
        ..Default::default()
    };
    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
    let n = if height_ge_1 { 20 } else { 3 };
    for i in 0..n {
        w.add_file(&format!("/f_{i:02}.bin"), &[i as u8; 128])
            .unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn test_exhaustive_byte_truncation_zero_panics() {
    for height_ge_1 in [false, true] {
        let archive = build_sample_archive(height_ge_1);
        for cut in 0..archive.len() {
            let truncated = &archive[..cut];
            let _ = BootHeader::from_bytes(truncated);
            let _ = walk_clusters_reverse(&truncated.to_vec());
            let _ = scan_clusters_forward(&truncated.to_vec(), 65_536);
            if let Ok(r) = VzReader::open(truncated.to_vec()) {
                let _ = r.stat("/f_00.bin");
                let _ = r.read_file("/f_00.bin");
                let _ = r.readdir("/");
            }
            let _ = verify_archive(&truncated.to_vec(), None);
        }
    }
}

#[test]
fn test_deterministic_bit_flips_zero_panics() {
    let archive = build_sample_archive(true);
    let mut state = 0x1234_5678_9ABC_DEF0_u64;
    for step in 0..500 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let pos = (state as usize) % archive.len();
        let bit = 1u8 << ((step % 8) as u8);
        let mut mutated = archive.clone();
        mutated[pos] ^= bit;

        if let Ok(r) = VzReader::open(mutated.clone()) {
            let _ = r.stat("/f_00.bin");
            let _ = r.read_file("/f_00.bin");
            let _ = r.readdir("/");
        }
        let _ = verify_archive(&mutated, None);
    }
}

#[test]
fn test_max_length_overflow_injection_zero_panics() {
    // 1. LE-VINT >= 2^62 or truncated
    let max_vint = u64::MAX.to_le_bytes();
    let (v, w) = read_levint_safe(&max_vint).unwrap();
    assert_eq!((v, w), ((1u64 << 62) - 1, 8));
    assert_eq!(read_levint_safe(&[0x03, 0xFF]), Err(VzError::BufferTooSmall));

    // 2. TLV with u64::MAX-scale length (2^62 - 1)
    let mut bad_tlv = vec![0x20]; // TAG_DATA_MANIFEST
    bad_tlv.extend_from_slice(&max_vint);
    assert!(tlv_next(&bad_tlv).is_err());
    for res in TlvIter::new(&bad_tlv) {
        assert!(res.is_err());
    }

    // 3. LeafNodeHeader with u32::MAX entry_count / pools
    let bad_leaf = LeafNodeHeader {
        entry_count: u32::MAX,
        name_pool_len: u32::MAX,
        ext_meta_len: u32::MAX,
        node_crc32c: 0,
    };
    let leaf_bytes = bad_leaf.to_bytes();
    assert!(LeafNodeView::parse(&leaf_bytes).is_err());

    // 4. ClusterHeader with u64::MAX cluster_len
    let bad_ch = ClusterHeader {
        sync_magic: libvz::MAGIC_CLUSTER,
        cluster_len: u64::MAX,
        prev_cluster_len: u64::MAX,
        cluster_seq: u64::MAX,
    };
    let mut cbuf = [0u8; 64];
    bad_ch.write_bytes(&mut cbuf).unwrap();
    assert!(validate_cluster(&cbuf).is_err());

    // 5. ParityManifest with u16::MAX K
    let bad_pm = ParityManifest {
        ecc_codec: libvz::ECC_RS_GF256,
        interleave_stride: 1,
        data_clusters_k: u16::MAX,
        parity_clusters_m: u16::MAX,
        parity_index: 0,
        first_cluster_seq: 0,
        max_cluster_len: u64::MAX,
    };
    assert!(ParityManifest::parse_with_offsets(&bad_pm.to_bytes()).is_err());

    // 6. RouteTableView with usize::MAX / large count
    assert!(RouteTableView::new(&[0u8; 64], usize::MAX / 2).is_err());

    // 7. Extended metadata tables with u32::MAX / u64::MAX counts
    let max_u32 = u32::MAX.to_le_bytes();
    assert!(decode_chunk_table(&[max_u32, max_u32].concat()).is_err());
    assert!(decode_schema_table(&[max_u32, [0; 4]].concat()).is_err());
    assert!(decode_owner_table(&[0xFF, 0xFF, 0, 0]).is_err());
    assert!(decode_dict_table(&[0xFF, 0xFF, 0, 0]).is_err());
    assert!(decode_lsm_runs(&[0xFF, 0xFF, 0, 0]).is_err());
    assert!(decode_sparse_extents(&max_vint).is_err());
    assert!(decode_xattr_list(&max_vint).is_err());

    // 8. DirEntry inline_len > 27
    let mut bad_de = [0u8; 64];
    bad_de[63] = libvz::FLAG_INLINE_DATA;
    bad_de[43] = 28;
    assert_eq!(DirEntry::from_bytes(&bad_de), Err(VzError::BadFormat));
}
