use std::io::Cursor;

use libvz::ext_meta::{SchemaEntry, TensorDtype, TensorMeta};
use libvz::{
    ByteOrder, EntryOptions, HeaderSlot, KIND_TENSOR, MAGIC_HEADER, VzError, VzReader, VzWriter,
    VzWriterConfig, crc32c, crc32c_sw, crc32c_update, crc32c_update_sw, read_be_i64, read_be_u16,
    read_be_u32, read_be_u64, read_le_i64, read_le_u16, read_le_u32, read_le_u64, write_be_i64,
    write_be_u16, write_be_u32, write_be_u64, write_le_i64, write_le_u16, write_le_u32,
    write_le_u64,
};

#[test]
fn test_crc32c_sw_slice8_exact_parity_with_hw_and_golden() {
    assert_eq!(crc32c_sw(b"123456789"), 0xE306_9283);
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    assert_eq!(crc32c_sw(&[]), crc32c(&[]));

    // Exhaustively test every length 0..=260 across every byte alignment 0..=15.
    let mut backing = vec![0u8; 300];
    for (i, b) in backing.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(131)) ^ (i >> 3)) as u8;
    }
    for align in 0..16 {
        for len in 0..=260 {
            let slice = &backing[align..align + len];
            let sw = crc32c_sw(slice);
            let hw = crc32c(slice);
            assert_eq!(sw, hw, "CRC32C mismatch at align={align}, len={len}");
        }
    }

    // Large buffer + incremental update parity
    let large: Vec<u8> = (0..65_539)
        .map(|i| ((i * 73) ^ (i >> 5)) as u8)
        .collect();
    assert_eq!(crc32c_sw(&large), crc32c(&large));

    let split = 13_579;
    let inc_sw = !crc32c_update_sw(
        crc32c_update_sw(0xFFFF_FFFF, &large[..split]),
        &large[split..],
    );
    let inc_hw = !crc32c_update(crc32c_update(0xFFFF_FFFF, &large[..split]), &large[split..]);
    assert_eq!(inc_sw, inc_hw);
    assert_eq!(inc_sw, crc32c(&large));
}

#[test]
fn test_wire_le_be_misaligned_and_canonical_bytes() {
    // Test unaligned byte offsets 0..=7 for both LE and BE integer helpers.
    let mut buf = [0u8; 24];
    for off in 0..8 {
        write_le_u16(&mut buf, off, 0x1234);
        assert_eq!(&buf[off..off + 2], &[0x34, 0x12]);
        assert_eq!(read_le_u16(&buf, off), 0x1234);

        write_be_u16(&mut buf, off, 0x1234);
        assert_eq!(&buf[off..off + 2], &[0x12, 0x34]);
        assert_eq!(read_be_u16(&buf, off), 0x1234);

        write_le_u32(&mut buf, off, 0x1234_5678);
        assert_eq!(&buf[off..off + 4], &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(read_le_u32(&buf, off), 0x1234_5678);

        write_be_u32(&mut buf, off, 0x1234_5678);
        assert_eq!(&buf[off..off + 4], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(read_be_u32(&buf, off), 0x1234_5678);

        let v64 = 0x0102_0304_0506_0708u64;
        write_le_u64(&mut buf, off, v64);
        assert_eq!(
            &buf[off..off + 8],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(read_le_u64(&buf, off), v64);

        write_be_u64(&mut buf, off, v64);
        assert_eq!(
            &buf[off..off + 8],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(read_be_u64(&buf, off), v64);

        let neg = -0x0123_4567_89AB_CDEF_i64;
        write_le_i64(&mut buf, off, neg);
        assert_eq!(read_le_i64(&buf, off), neg);
        write_be_i64(&mut buf, off, neg);
        assert_eq!(read_be_i64(&buf, off), neg);
    }

    // Verify canonical little-endian byte positions inside serialized HeaderSlot.
    let slot = HeaderSlot {
        magic: MAGIC_HEADER,
        generation: 0x1122_3344_5566_7788,
        boot_block_size: 65_536,
        compat_flags: 0,
        ro_compat_flags: 0,
        incompat_flags: 0,
        tree_height: 0,
        hash_algo: 0,
        lsm_run_count: 1,
        registry_offset: 0x0080,
        registry_size: 0,
        root_node_offset: 0x0100,
        total_entries: 0x0A0B_0C0D_0E0F_1011,
        root_fallback_off: 0,
        root_entry_count: 0,
        header_crc32c: 0,
    };
    let raw = slot.to_bytes();
    assert_eq!(&raw[0..8], b"VZ\x01\x00\x00\x00\x00\x00");
    assert_eq!(
        &raw[8..16],
        &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
    );
    assert_eq!(read_le_u64(&raw, 0), MAGIC_HEADER);
    assert_eq!(read_le_u64(&raw, 40), 0x0A0B_0C0D_0E0F_1011);
}

#[test]
fn test_tensor_meta_le_and_be_typed_decode_encode_and_archive_roundtrip() {
    // 1. Verify Big-Endian (byte_order = 1) vs Little-Endian (byte_order = 0) across widths
    let f32_vals = [-3.5f32, -0.0f32, 0.0f32, 1.25f32, 1e12f32, f32::INFINITY];
    let t_le = TensorMeta {
        schema_id: 10,
        name: "weights_le".to_string(),
        dtype: TensorDtype::F32,
        byte_order: ByteOrder::LittleEndian as u8,
        dims: vec![2, 3],
        strides: vec![0, 0],
    };
    let t_be = TensorMeta {
        schema_id: 11,
        name: "weights_be".to_string(),
        dtype: TensorDtype::F32,
        byte_order: ByteOrder::BigEndian as u8,
        dims: vec![2, 3],
        strides: vec![0, 0],
    };

    assert_eq!(t_le.payload_byte_len().unwrap(), 24);
    let raw_le = t_le.encode_f32(&f32_vals).unwrap();
    let raw_be = t_be.encode_f32(&f32_vals).unwrap();
    // Exact byte-swapped encoding on disk for -3.5f32 (0xC060_0000)
    assert_eq!(&raw_le[..4], &(-3.5f32).to_le_bytes());
    assert_eq!(&raw_be[..4], &(-3.5f32).to_be_bytes());
    assert_ne!(raw_le, raw_be);

    // Misaligned slice decoding (+1 offset padding) must succeed with zero UB.
    let mut padded_be = vec![0xAAu8];
    padded_be.extend_from_slice(&raw_be);
    let dec_be = t_be.decode_f32(&padded_be[1..]).unwrap();
    let dec_le = t_le.decode_f32(&raw_le).unwrap();
    for i in 0..f32_vals.len() {
        assert_eq!(dec_be[i].to_bits(), f32_vals[i].to_bits());
        assert_eq!(dec_le[i].to_bits(), f32_vals[i].to_bits());
    }

    // Wrong dtype / wrong byte_order / wrong byte len return explicit VzError
    assert_eq!(t_be.decode_u32(&raw_be), Err(VzError::InvalidInput));
    assert_eq!(t_be.decode_f32(&raw_be[..20]), Err(VzError::BadFormat));
    let bad_order = TensorMeta {
        byte_order: 2,
        ..t_be.clone()
    };
    assert_eq!(bad_order.order(), Err(VzError::BadFormat));

    // Check remaining widths: U16, I16, U32, I32, U64, I64, F64 in Big-Endian mode
    let mk = |dtype: TensorDtype, len: u64| TensorMeta {
        schema_id: 1,
        name: "t".to_string(),
        dtype,
        byte_order: ByteOrder::BigEndian as u8,
        dims: vec![len],
        strides: vec![0],
    };
    let v_u16 = [0u16, 0x01FF, u16::MAX];
    assert_eq!(mk(TensorDtype::U16, 3).decode_u16(&mk(TensorDtype::U16, 3).encode_u16(&v_u16).unwrap()).unwrap(), v_u16);
    let v_i16 = [i16::MIN, -42, i16::MAX];
    assert_eq!(mk(TensorDtype::I16, 3).decode_i16(&mk(TensorDtype::I16, 3).encode_i16(&v_i16).unwrap()).unwrap(), v_i16);
    let v_u32 = [0u32, 0xDEAD_BEEF, u32::MAX];
    assert_eq!(mk(TensorDtype::U32, 3).decode_u32(&mk(TensorDtype::U32, 3).encode_u32(&v_u32).unwrap()).unwrap(), v_u32);
    let v_i32 = [i32::MIN, -123456, i32::MAX];
    assert_eq!(mk(TensorDtype::I32, 3).decode_i32(&mk(TensorDtype::I32, 3).encode_i32(&v_i32).unwrap()).unwrap(), v_i32);
    let v_u64 = [0u64, 0x0102_0304_0506_0708, u64::MAX];
    assert_eq!(mk(TensorDtype::U64, 3).decode_u64(&mk(TensorDtype::U64, 3).encode_u64(&v_u64).unwrap()).unwrap(), v_u64);
    let v_i64 = [i64::MIN, -987_654_321_012_345, i64::MAX];
    assert_eq!(mk(TensorDtype::I64, 3).decode_i64(&mk(TensorDtype::I64, 3).encode_i64(&v_i64).unwrap()).unwrap(), v_i64);
    let v_f64 = [-1e200f64, std::f64::consts::PI, 1e-200f64];
    assert_eq!(mk(TensorDtype::F64, 3).decode_f64(&mk(TensorDtype::F64, 3).encode_f64(&v_f64).unwrap()).unwrap(), v_f64);

    // 2. End-to-end archive roundtrip storing a Big-Endian F32 tensor + LE F32 tensor
    let cfg = VzWriterConfig {
        schemas: vec![SchemaEntry::Tensor(t_be.clone())],
        ..Default::default()
    };
    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
    w.add_file_with_options(
        "/tensors/be_weights.bin",
        &raw_be,
        EntryOptions {
            kind: KIND_TENSOR,
            schema_id: Some(11),
            ..Default::default()
        },
    )
    .unwrap();
    let archive = w.finish().unwrap().into_inner();
    let reader = VzReader::open(archive.as_slice()).unwrap();
    let payload = reader.read_file("/tensors/be_weights.bin").unwrap();
    let SchemaEntry::Tensor(meta_out) = &reader.schemas()[0] else {
        panic!("expected Tensor schema");
    };
    assert_eq!(meta_out.order().unwrap(), ByteOrder::BigEndian);
    assert_eq!(meta_out.decode_f32(&payload).unwrap(), f32_vals);
}
