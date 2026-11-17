use libvz::ext_meta::{
    ChunkExtent, CipherHeader, ColumnEncoding, ColumnLogicalType, ColumnMeta, DataManifestHeader,
    DictEntry, ExtCodecMeta, LsmRunDesc, OwnerEntry, RootFallback, SchemaEntry, SchemaLinkMeta,
    SparseExtent, TensorDtype, TensorMeta, Xattr, decode_chunk_table, decode_dict_table,
    decode_ext_codec, decode_ext_owner, decode_lsm_runs, decode_manifest_col_stats,
    decode_owner_table, decode_root_fallback, decode_schema_link, decode_schema_table,
    decode_sparse_extents, decode_xattr_list, encode_chunk_table, encode_dict_table,
    encode_ext_codec, encode_ext_owner, encode_lsm_runs, encode_owner_table, encode_root_fallback,
    encode_schema_link, encode_schema_table, encode_sparse_extents, encode_xattr_list, push_tlv,
    ColChunkStats,
};
use libvz::rs::parse_parity_cluster_body;
use libvz::*;

fn sample_header_slot(incompat: u16) -> HeaderSlot {
    HeaderSlot {
        magic: MAGIC_HEADER,
        generation: 0,
        boot_block_size: DEFAULT_BOOT_SIZE as u32,
        compat_flags: COMPAT_BOOT_ECC,
        ro_compat_flags: 0,
        incompat_flags: incompat,
        tree_height: 0,
        hash_algo: HASH_ALGO_BUILTIN,
        lsm_run_count: 1,
        registry_offset: 0x0080,
        registry_size: 0,
        root_node_offset: 0x0100,
        total_entries: 42,
        root_fallback_off: 0,
        root_entry_count: 42,
        header_crc32c: 0,
    }
}

#[test]
fn test_magics_exact() {
    assert_eq!(MAGIC_HEADER, u64::from_le_bytes(*b"VZ\x01\x00\x00\x00\x00\x00"));
    assert_eq!(MAGIC_CLUSTER, u64::from_le_bytes(*b"VZ_CLUST"));
    assert_eq!(MAGIC_FOOTER, u32::from_le_bytes(*b"ENDC"));
    assert_eq!(MAGIC_BOOT_ECC, u32::from_le_bytes(*b"BECC"));
}

#[test]
fn test_crc32c_standard_vector() {
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
}

#[test]
fn test_levint_edge_cases() {
    let cases = [
        (0u64, 1usize),
        (1, 1),
        (63, 1),
        (64, 2),
        (16_383, 2),
        (16_384, 4),
        ((1 << 30) - 1, 4),
        (1 << 30, 8),
        ((1 << 62) - 1, 8),
    ];
    for (val, expected_w) in cases {
        let mut buf = [0u8; 8];
        let w = write_levint(&mut buf, val).unwrap();
        assert_eq!(w, expected_w);
        assert_eq!(levint_len(val).unwrap(), expected_w);
        let (dec_safe, w_safe) = read_levint_safe(&buf[..w]).unwrap();
        assert_eq!((dec_safe, w_safe), (val, expected_w));
        let (dec_fast, w_fast) = read_levint_fast(&buf);
        assert_eq!((dec_fast, w_fast), (val, expected_w));
    }
    let mut buf = [0u8; 8];
    assert_eq!(write_levint(&mut buf, 1 << 62), Err(VzError::ValueOverflow));
    assert_eq!(levint_len(1 << 62), Err(VzError::ValueOverflow));
    assert_eq!(read_levint_safe(&[]), Err(VzError::BufferTooSmall));
}

#[test]
fn test_pool_shift_boundaries() {
    assert_eq!(pool_shift(0), 0);
    assert_eq!(pool_shift(1), 0);
    assert_eq!(pool_shift(65_536), 0);
    assert_eq!(pool_shift(65_537), 1);
    assert_eq!(pool_shift(131_072), 1);
    assert_eq!(pool_shift(131_073), 2);
    assert_eq!(pool_shift(u32::MAX), 16);
    // Verify max u16 << pool_shift(u32::MAX) covers 4 GiB - 1!
    assert!((0xFFFFu64 << pool_shift(u32::MAX)) + (1 << 16) > u32::MAX as u64);
}

#[test]
fn test_context_free_padding_and_tlv() {
    let mut buf = [0u8; 64];
    assert_eq!(write_void_align64(&mut buf, 63).unwrap(), 1);
    assert_eq!(buf[0], 0x00);
    assert_eq!(skip_padding(&buf[..1]), 1);
    let (elem, rest) = tlv_next(&buf[..1]).unwrap();
    assert_eq!(elem.tag, TAG_NOP);
    assert!(elem.value.is_empty());
    assert!(rest.is_empty());

    assert_eq!(write_void_align64(&mut buf, 62).unwrap(), 2);
    assert_eq!(&buf[..2], &[0xEC, 0x00]);
    assert_eq!(skip_padding(&buf[..2]), 2);
    let (elem2, rest2) = tlv_next(&buf[..2]).unwrap();
    assert_eq!(elem2.tag, TAG_VOID);
    assert!(elem2.value.is_empty());
    assert!(rest2.is_empty());

    assert_eq!(write_void_align64(&mut buf, 60).unwrap(), 4);
    assert_eq!(&buf[..4], &[0xEC, 0x08, 0x00, 0x00]);
    assert_eq!(skip_padding(&buf[..4]), 4);
}

#[test]
fn test_dual_slot_no_incompat_downgrade() {
    let mut boot = BootHeader {
        slot_a: sample_header_slot(0),
        slot_b: sample_header_slot(0),
    };
    let slot_v1 = sample_header_slot(0);
    assert_eq!(boot.commit(&slot_v1), 0);

    let slot_v2 = sample_header_slot(INCOMPAT_ENCRYPTED);
    assert_eq!(boot.commit(&slot_v2), 1);

    // Must reject instead of silently downgrading to slot_a (generation 1).
    assert_eq!(boot.select_active(0), Err(VzError::IncompatibleFeature));

    let (active, idx) = boot.select_active(INCOMPAT_ENCRYPTED).unwrap();
    assert_eq!(idx, 1);
    assert_eq!(active.generation, 2);
}

#[test]
fn test_boot_ecc_repair_and_dual_corruption() {
    let mut block = [0u8; DEFAULT_BOOT_SIZE];
    for (i, b) in block[..BOOT_ECC_DESC_OFF].iter_mut().enumerate() {
        *b = ((i * 131 + 17) & 0xFF) as u8;
    }
    let original = block;

    boot_ecc_encode(&mut block).unwrap();
    let encoded = block;
    assert_eq!(boot_ecc_verify_and_repair(&mut block), Ok(None));

    // Corrupt Page 3 data.
    block[3 * PAGE_SIZE + 123] ^= 0xA5;
    assert_eq!(boot_ecc_verify_and_repair(&mut block), Ok(Some(3)));
    assert_eq!(block[..BOOT_ECC_DESC_OFF], original[..BOOT_ECC_DESC_OFF]);

    // Corrupt Page 14 descriptor (Case A).
    block[BOOT_ECC_DESC_OFF] ^= 0xFF;
    assert_eq!(boot_ecc_verify_and_repair(&mut block), Ok(Some(14)));
    assert_eq!(block, encoded);

    // Corrupt Page 15 parity.
    block[BOOT_PARITY_OFFSET + 77] ^= 0x5A;
    assert_eq!(boot_ecc_verify_and_repair(&mut block), Ok(Some(15)));
    assert_eq!(block, encoded);

    // Corrupt BOTH Page 14 descriptor AND Page 15 tail -> must fail.
    block[BOOT_ECC_DESC_OFF + 1] ^= 0xFF;
    block[DEFAULT_BOOT_SIZE - 1] ^= 0x01;
    assert_eq!(
        boot_ecc_verify_and_repair(&mut block),
        Err(VzError::CorruptUnrecoverable)
    );
}

#[test]
fn test_fixed_structs_roundtrip() {
    let slot = sample_header_slot(INCOMPAT_BIG_BOOT);
    let slot_dec = HeaderSlot::from_bytes(&slot.to_bytes()).unwrap();
    assert_eq!(slot, slot_dec);

    let boot = BootHeader {
        slot_a: slot,
        slot_b: sample_header_slot(0),
    };
    assert_eq!(BootHeader::from_bytes(&boot.to_bytes()).unwrap(), boot);

    let route = RouteEntry {
        min_parent_hash: 1,
        min_name_hash: 2,
        max_parent_hash: 3,
        max_name_hash: 4,
        child_cluster_off: 65536,
        child_cluster_len: 4096,
        subtree_count_lo: 99,
    };
    assert_eq!(RouteEntry::from_bytes(&route.to_bytes()).unwrap(), route);

    let ext_t = ExtTime {
        mtime_sec: -500_000_000_000,
        btime_sec: 90_000_000_000,
        mtime_nsec: 123_456_789,
        btime_nsec: 987_654_321,
    };
    assert_eq!(ExtTime::from_bytes(&ext_t.to_bytes()).unwrap(), ext_t);

    let pm = ParityManifest {
        ecc_codec: ECC_RS_GF256,
        interleave_stride: 1,
        data_clusters_k: 4,
        parity_clusters_m: 2,
        parity_index: 1,
        first_cluster_seq: 10,
        max_cluster_len: 8192,
    };
    assert_eq!(ParityManifest::from_bytes(&pm.to_bytes()).unwrap(), pm);

    let de_inline = DirEntry {
        parent_hash: 11,
        name_hash: 22,
        payload: DirPayload::Inline {
            bytes: [b'x'; 27],
            len: 27,
        },
        entry_id_lo: 5,
        mtime_ns: -1,
        name_pool_off: 0,
        ext_meta_off: 0,
        posix_mode: KIND_REG | 0o640,
        owner_idx: 2,
        flags_and_codec: CODEC_NONE | FLAG_INLINE_DATA,
    };
    assert_eq!(
        DirEntry::from_bytes(&de_inline.to_bytes().unwrap()).unwrap(),
        de_inline
    );

    let de_ref = DirEntry {
        parent_hash: 11,
        name_hash: 22,
        payload: DirPayload::Ref {
            data_offset: 0x2_0000,
            stored_size: 512,
            raw_size: 1024,
            in_cluster_offset: 128,
        },
        entry_id_lo: 6,
        mtime_ns: 42,
        name_pool_off: 10,
        ext_meta_off: 4,
        posix_mode: KIND_TENSOR | 0o444,
        owner_idx: 255,
        flags_and_codec: CODEC_ZSTD | FLAG_SPARSE,
    };
    assert_eq!(
        DirEntry::from_bytes(&de_ref.to_bytes().unwrap()).unwrap(),
        de_ref
    );
}

#[test]
fn test_all_tlv_payloads_roundtrip() {
    let owners = vec![
        OwnerEntry {
            uid: 1000,
            gid: 1000,
            uname: "alice".into(),
            gname: "staff".into(),
        },
        OwnerEntry {
            uid: 0,
            gid: 0,
            uname: "root".into(),
            gname: "wheel".into(),
        },
    ];
    let enc_o = encode_owner_table(&owners).unwrap();
    assert_eq!(decode_owner_table(&enc_o).unwrap(), owners);
    assert_eq!(
        decode_ext_owner(&encode_ext_owner(&owners[0]).unwrap()).unwrap(),
        owners[0]
    );

    let dicts = vec![DictEntry {
        dict_id: 7,
        codec: CODEC_ZSTD,
        flags: 0,
        bytes: b"dictionary-sample-bytes".to_vec(),
    }];
    assert_eq!(
        decode_dict_table(&encode_dict_table(&dicts).unwrap()).unwrap(),
        dicts
    );

    let schemas = vec![
        SchemaEntry::Tensor(TensorMeta {
            schema_id: 1,
            name: "weights".into(),
            dtype: TensorDtype::Bf16,
            byte_order: 0,
            dims: vec![16, 64],
            strides: vec![128, 2],
        }),
        SchemaEntry::Column(ColumnMeta {
            schema_id: 2,
            name: "user_id".into(),
            logical_type: ColumnLogicalType::Int64,
            encoding: ColumnEncoding::DeltaBinaryPacked,
            row_count: 10_000,
            null_count: 3,
            min_stat: Some(1i64.to_le_bytes().to_vec()),
            max_stat: Some(99_999i64.to_le_bytes().to_vec()),
        }),
    ];
    assert_eq!(
        decode_schema_table(&encode_schema_table(&schemas).unwrap()).unwrap(),
        schemas
    );

    let runs = vec![LsmRunDesc {
        run_generation: 3,
        root_offset: 0x40000,
        root_entry_count: 12,
        tree_height: 1,
        root_is_cluster: true,
    }];
    assert_eq!(
        decode_lsm_runs(&encode_lsm_runs(&runs).unwrap()).unwrap(),
        runs
    );

    let ch = CipherHeader {
        version: 1,
        kdf_mode: KDF_MODE_ARGON2ID,
        cipher_suite: CIPHER_XCHACHA20_POLY1305,
        reserved: 0,
        argon2_m_cost_kib: 65536,
        argon2_t_cost: 3,
        argon2_p_cost: 1,
        salt: [1u8; 16],
        wrap_nonce: [2u8; 24],
        wrapped_cek: [3u8; 48],
    };
    assert_eq!(CipherHeader::from_bytes(&ch.to_bytes()).unwrap(), ch);

    let xattrs = vec![Xattr {
        key: "user.mime".into(),
        value: b"application/octet-stream".to_vec(),
    }];
    assert_eq!(
        decode_xattr_list(&encode_xattr_list(&xattrs).unwrap()).unwrap(),
        xattrs
    );

    let sparse = vec![
        SparseExtent {
            logical_offset: 0,
            length: 4096,
        },
        SparseExtent {
            logical_offset: 1_048_576,
            length: 512,
        },
    ];
    assert_eq!(
        decode_sparse_extents(&encode_sparse_extents(&sparse).unwrap()).unwrap(),
        sparse
    );

    let ec = ExtCodecMeta {
        ext_codec_id: EXT_CODEC_ZSTD_DICT,
        dict_id: 7,
        params: vec![1, 2, 3],
    };
    assert_eq!(
        decode_ext_codec(&encode_ext_codec(&ec).unwrap()).unwrap(),
        ec
    );

    let sl = SchemaLinkMeta {
        schema_id: 42,
        extra: vec![9, 8],
    };
    assert_eq!(
        decode_schema_link(&encode_schema_link(&sl).unwrap()).unwrap(),
        sl
    );

    let chunks = vec![ChunkExtent {
        cluster_offset: 0x10000,
        in_cluster_offset: 64,
        stored_size: 1000,
        raw_size: 2000,
    }];
    assert_eq!(
        decode_chunk_table(&encode_chunk_table(&chunks).unwrap()).unwrap(),
        chunks
    );

    let fb = RootFallback {
        stream_generation: 1,
        total_entries: 99,
        root_cluster_off: 0,
        root_entry_count: 10,
        tree_height: 0,
        hash_algo: HASH_ALGO_BLAKE3,
        embedded_root: Some(vec![7; 32]),
    };
    assert_eq!(decode_root_fallback(&encode_root_fallback(&fb)).unwrap(), fb);

    let dm = DataManifestHeader {
        entry_id: 123,
        raw_size: 500,
        stored_size: 250,
        payload_crc32c: 0xDEAD_BEEF,
        manifest_flags: 0x0003,
        payload_rel_off: 64,
    };
    let mut dm_buf = vec![0u8; 64];
    dm.write_bytes(&mut dm_buf).unwrap();
    // Write ColChunkStats at 32..
    dm_buf[32..36].copy_from_slice(&2u32.to_le_bytes());
    dm_buf[36..44].copy_from_slice(&100u64.to_le_bytes());
    dm_buf[44..52].copy_from_slice(&1u64.to_le_bytes());
    let mut pos = 52;
    pos += write_levint(&mut dm_buf[pos..], 1).unwrap();
    dm_buf[pos] = 10;
    pos += 1;
    pos += write_levint(&mut dm_buf[pos..], 1).unwrap();
    dm_buf[pos] = 99;
    let st = decode_manifest_col_stats(&dm_buf).unwrap().unwrap();
    assert_eq!(
        st,
        ColChunkStats {
            col_schema_id: 2,
            row_count: 100,
            null_count: 1,
            min_bytes: vec![10],
            max_bytes: vec![99],
        }
    );
}

#[test]
fn test_unsupported_ecc_codecs() {
    for codec in [ECC_RS_GF65536, ECC_RAPTORQ] {
        let pm = ParityManifest {
            ecc_codec: codec,
            interleave_stride: 1,
            data_clusters_k: 2,
            parity_clusters_m: 1,
            parity_index: 0,
            first_cluster_seq: 0,
            max_cluster_len: 64,
        };
        let mut val = pm.to_bytes().to_vec();
        val.extend_from_slice(&[0u8; 16 + 64]);
        let mut body = Vec::new();
        push_tlv(&mut body, TAG_PARITY_CLUSTER, &val).unwrap();
        assert_eq!(parse_parity_cluster_body(&body), Err(VzError::Unsupported));
    }
}

#[test]
fn test_leaf_lookup_collision_guard_and_readdir() {
    let parent = hash64(b"/dir");
    let name_a = b"alpha.bin";
    let name_b = b"beta.bin";
    let ha = hash64(name_a);
    let hb = hash64(name_b);

    let mut e1 = DirEntry {
        parent_hash: parent,
        name_hash: ha,
        payload: DirPayload::Inline {
            bytes: [0u8; 27],
            len: 3,
        },
        entry_id_lo: 1,
        mtime_ns: 1_700_000_000,
        name_pool_off: 0,
        ext_meta_off: EXT_META_NONE,
        posix_mode: KIND_REG | 0o644,
        owner_idx: 0,
        flags_and_codec: CODEC_NONE | FLAG_INLINE_DATA,
    };
    if let DirPayload::Inline { ref mut bytes, .. } = e1.payload {
        bytes[..3].copy_from_slice(b"abc");
    }

    let mut e2 = e1;
    e2.name_hash = hb;
    e2.entry_id_lo = 2;

    let mut name_pool = [0u8; 32];
    let w1 = write_levint(&mut name_pool, name_a.len() as u64).unwrap();
    name_pool[w1..w1 + name_a.len()].copy_from_slice(name_a);
    let off2 = w1 + name_a.len();
    let w2 = write_levint(&mut name_pool[off2..], name_b.len() as u64).unwrap();
    name_pool[off2 + w2..off2 + w2 + name_b.len()].copy_from_slice(name_b);
    let pool_len = off2 + w2 + name_b.len();

    if ha <= hb {
        e1.name_pool_off = 0;
        e2.name_pool_off = off2 as u16;
    } else {
        e2.name_pool_off = 0;
        let w_b = write_levint(&mut name_pool, name_b.len() as u64).unwrap();
        name_pool[w_b..w_b + name_b.len()].copy_from_slice(name_b);
        let o2 = w_b + name_b.len();
        let w_a = write_levint(&mut name_pool[o2..], name_a.len() as u64).unwrap();
        name_pool[o2 + w_a..o2 + w_a + name_a.len()].copy_from_slice(name_a);
        e1.name_pool_off = o2 as u16;
    }
    let (first, second) = if ha <= hb { (e1, e2) } else { (e2, e1) };

    let mut leaf_buf = [0u8; 256];
    let hdr = LeafNodeHeader {
        entry_count: 2,
        name_pool_len: pool_len as u32,
        ext_meta_len: 0,
        node_crc32c: 0,
    };
    hdr.write_bytes(&mut leaf_buf).unwrap();
    first.write_bytes(&mut leaf_buf[16..80]).unwrap();
    second.write_bytes(&mut leaf_buf[80..144]).unwrap();
    leaf_buf[144..144 + pool_len].copy_from_slice(&name_pool[..pool_len]);
    LeafNodeHeader::stamp_crc(&mut leaf_buf).unwrap();

    let view = LeafNodeView::parse(&leaf_buf).unwrap();
    assert!(view.lookup(parent, ha, Some(name_a)).unwrap().is_some());
    assert!(
        view.lookup(parent, ha, Some(b"evil_coll"))
            .unwrap()
            .is_none()
    );
    assert_eq!(view.iter_dir(parent).unwrap().count(), 2);
}

#[test]
fn test_route_lower_bound_and_gf256() {
    let r0 = RouteEntry {
        min_parent_hash: 10,
        min_name_hash: 100,
        max_parent_hash: 10,
        max_name_hash: 500,
        child_cluster_off: 0x1_0000,
        child_cluster_len: 4096,
        subtree_count_lo: 5,
    };
    let r1 = RouteEntry {
        min_parent_hash: 20,
        min_name_hash: 200,
        max_parent_hash: 20,
        max_name_hash: 800,
        child_cluster_off: 0x2_0000,
        child_cluster_len: 4096,
        subtree_count_lo: 8,
    };
    let mut buf = [0u8; 96];
    r0.write_bytes(&mut buf[0..48]).unwrap();
    r1.write_bytes(&mut buf[48..96]).unwrap();

    let table = RouteTableView::new(&buf, 2).unwrap();
    assert_eq!(table.lookup(20, 0).unwrap(), None);
    assert_eq!(table.lower_bound(20, 0).unwrap(), Some((1, r1)));
    assert_eq!(table.lookup(20, 300).unwrap(), Some((1, r1)));

    let src: [u8; 256] = core::array::from_fn(|i| i as u8);
    for coeff in [0u8, 1, 2, 0x53, 0xFF] {
        let mut dst = [0xA7u8; 256];
        let mut expected = dst;
        for (d, &s) in expected.iter_mut().zip(src.iter()) {
            *d ^= gf256_mul(s, coeff);
        }
        rs_gf256_madd_slice(&mut dst, &src, coeff).unwrap();
        assert_eq!(dst, expected);
    }

    for a in 1u8..=255 {
        let inv = gf256_inv(a).unwrap();
        assert_eq!(gf256_mul(a, inv), 1);
    }
}

#[test]
fn test_hash_algos_xxh3_and_blake3() {
    for algo in [HASH_ALGO_BUILTIN, HASH_ALGO_XXH3_64, HASH_ALGO_BLAKE3] {
        let h = AlgoHasher::new(algo).unwrap();
        let v1 = h.hash(b"/dir/file.txt").unwrap();
        let v2 = h.hash(b"/dir/file.txt").unwrap();
        let v3 = h.hash(b"/dir/other.txt").unwrap();
        assert_eq!(v1, v2);
        assert_ne!(v1, v3);
    }
}
