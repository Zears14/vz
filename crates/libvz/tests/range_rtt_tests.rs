use std::io::Cursor;

use libvz::{CountingRangeReader, DEFAULT_BOOT_SIZE, SliceRangeReader, VzReader, VzWriter, VzWriterConfig};

#[test]
fn test_1_rtt_inline_when_tree_height_0() {
    let mut w = VzWriter::new(Cursor::new(Vec::new()), VzWriterConfig::default()).unwrap();
    w.add_file("/hello.txt", b"1-RTT inline payload!").unwrap();
    w.add_file("/small.bin", &[7u8; 27]).unwrap();
    let archive = w.finish().unwrap().into_inner();

    let counter = CountingRangeReader::new(SliceRangeReader(&archive));
    let reader = VzReader::open(&counter).unwrap();
    assert_eq!(reader.active_slot().tree_height, 0);
    assert_eq!(reader.read_file("/hello.txt").unwrap(), b"1-RTT inline payload!");
    assert_eq!(reader.read_file("/small.bin").unwrap(), vec![7u8; 27]);
    assert_eq!(counter.reads(), 1);
    assert_eq!(counter.bytes_read(), DEFAULT_BOOT_SIZE as u64);
}

#[test]
fn test_exact_1_plus_tree_height_plus_1_rtts_deep_external() {
    // Height 1: 60 files with max_leaf_entries = 16 -> ~4 leaves -> tree_height == 1.
    let cfg_h1 = VzWriterConfig {
        max_leaf_entries: 16,
        max_route_entries: 16,
        target_cluster_size: 4096,
        ..Default::default()
    };
    let mut w1 = VzWriter::new(Cursor::new(Vec::new()), cfg_h1).unwrap();
    for i in 0..60 {
        let data = vec![(i & 0xFF) as u8; 128];
        w1.add_file(&format!("/f_{i:04}.bin"), &data).unwrap();
    }
    let arc1 = w1.finish().unwrap().into_inner();
    let c1 = CountingRangeReader::new(SliceRangeReader(&arc1));
    let r1 = VzReader::open(&c1).unwrap();
    assert_eq!(r1.active_slot().tree_height, 1);
    assert_eq!(r1.read_file("/f_0033.bin").unwrap(), vec![33u8; 128]);
    assert_eq!(c1.reads(), 1 + 1 + 1);

    // Height 2: 400 files with max_leaf_entries = 16, max_route_entries = 4 -> tree_height == 2.
    let cfg_h2 = VzWriterConfig {
        max_leaf_entries: 16,
        max_route_entries: 4,
        target_cluster_size: 4096,
        ..Default::default()
    };
    let mut w2 = VzWriter::new(Cursor::new(Vec::new()), cfg_h2).unwrap();
    for i in 0..400 {
        let data = vec![(i & 0xFF) as u8; 256];
        w2.add_file(&format!("/deep/f_{i:04}.bin"), &data).unwrap();
    }
    let arc2 = w2.finish().unwrap().into_inner();
    let c2 = CountingRangeReader::new(SliceRangeReader(&arc2));
    let r2 = VzReader::open(&c2).unwrap();
    assert!(r2.active_slot().tree_height >= 2);
    assert_eq!(r2.read_file("/deep/f_0250.bin").unwrap(), vec![250u8; 256]);
    // Exact 1 (Boot Block) + tree_height + 1 (Payload) RTTs!
    assert_eq!(c2.reads(), 1 + r2.active_slot().tree_height as usize + 1);
}
