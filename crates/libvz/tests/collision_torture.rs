use std::io::Cursor;

use libvz::{
    FnHasher, HASH_ALGO_BUILTIN, VzError, VzReader, VzReaderOptions, VzWriter, VzWriterConfig,
};

#[test]
fn test_synthetic_name_and_parent_hash_collisions() {
    // Pluggable hasher that intentionally collides:
    // - All directory paths ("/dir_a", "/dir_b", "/dir_c") -> 0x1111_2222_3333_4444
    // - All filenames starting with "item_" -> 0xAAAA_BBBB_CCCC_DDDD
    // - All filenames starting with "twin_" -> 0xDEAD_BEEF_CAFE_BABE
    let make_hasher = || {
        Box::new(FnHasher::new(HASH_ALGO_BUILTIN, |data: &[u8]| {
            if data == b"/dir_a" || data == b"/dir_b" || data == b"/dir_c" {
                0x1111_2222_3333_4444
            } else if data.starts_with(b"item_") {
                0xAAAA_BBBB_CCCC_DDDD
            } else if data.starts_with(b"twin_") {
                0xDEAD_BEEF_CAFE_BABE
            } else {
                libvz::hash64(data)
            }
        }))
    };

    let cfg = VzWriterConfig {
        max_leaf_entries: 4,
        max_route_entries: 4,
        target_cluster_size: 4096,
        ..Default::default()
    };
    let mut w = VzWriter::with_hasher(Cursor::new(Vec::new()), cfg, make_hasher()).unwrap();

    w.add_dir("/dir_a", 0o755, 1).unwrap();
    w.add_dir("/dir_b", 0o755, 2).unwrap();
    w.add_dir("/dir_c", 0o755, 3).unwrap();

    // Same basename "shared.txt" in three colliding parent directories!
    w.add_file("/dir_a/shared.txt", b"content-in-dir-a-shared").unwrap();
    w.add_file("/dir_b/shared.txt", b"content-in-dir-b-shared-longer-payload").unwrap();
    w.add_file("/dir_c/shared.txt", b"content-in-dir-c-shared").unwrap();

    // Multiple colliding basenames across colliding parent directories (6 entries sharing exact 128-bit key > max_leaf_entries=4!)
    for d in ["dir_a", "dir_b", "dir_c"] {
        for i in 0..4 {
            let path = format!("/{d}/item_{i}.bin");
            let data = format!("payload-{d}-item-{i}-extra-bytes-to-externalize");
            w.add_file(&path, data.as_bytes()).unwrap();
        }
        w.add_file(&format!("/{d}/twin_x"), format!("twin-x-{d}").as_bytes())
            .unwrap();
        w.add_file(&format!("/{d}/twin_y"), format!("twin-y-{d}").as_bytes())
            .unwrap();
    }

    let archive = w.finish().unwrap().into_inner();
    let reader = VzReader::open_with_hasher(
        archive,
        VzReaderOptions::default(),
        make_hasher(),
    )
    .unwrap();

    // Verify stat + read_file across every colliding path & non-existent colliding path
    assert_eq!(
        reader.read_file("/dir_a/shared.txt").unwrap(),
        b"content-in-dir-a-shared"
    );
    assert_eq!(
        reader.read_file("/dir_b/shared.txt").unwrap(),
        b"content-in-dir-b-shared-longer-payload"
    );
    assert_eq!(
        reader.read_file("/dir_c/shared.txt").unwrap(),
        b"content-in-dir-c-shared"
    );
    assert_eq!(
        reader.stat("/dir_a/item_99.bin").err(),
        Some(VzError::NotFound)
    );
    assert_eq!(
        reader.stat("/dir_a/twin_z").err(),
        Some(VzError::NotFound)
    );

    for d in ["dir_a", "dir_b", "dir_c"] {
        for i in 0..4 {
            let path = format!("/{d}/item_{i}.bin");
            let expected = format!("payload-{d}-item-{i}-extra-bytes-to-externalize");
            assert_eq!(reader.read_file(&path).unwrap(), expected.as_bytes());
            let st = reader.stat(&path).unwrap();
            assert!(st.has_hash_collision);
        }
        assert_eq!(
            reader.read_file(&format!("/{d}/twin_x")).unwrap(),
            format!("twin-x-{d}").as_bytes()
        );
        assert_eq!(
            reader.read_file(&format!("/{d}/twin_y")).unwrap(),
            format!("twin-y-{d}").as_bytes()
        );

        // Verify readdir isolates ONLY this directory's 7 children despite identical parent_hash!
        let entries = reader.readdir(&format!("/{d}")).unwrap();
        let names: Vec<_> = entries.into_iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            vec![
                "item_0.bin",
                "item_1.bin",
                "item_2.bin",
                "item_3.bin",
                "shared.txt",
                "twin_x",
                "twin_y"
            ]
        );
        let mut visited_names = Vec::new();
        reader
            .readdir_visit(&format!("/{d}"), |item| {
                visited_names.push(item.name.to_string());
                Ok(())
            })
            .unwrap();
        visited_names.sort();
        assert_eq!(visited_names, names);
    }
}
