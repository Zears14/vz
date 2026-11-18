use std::io::Cursor;

use libvz::{
    BOOT_ECC_DESC_OFF, BOOT_PAGES, BootHeader, COMPAT_BOOT_ECC, DEFAULT_BOOT_SIZE, HeaderSlot,
    PAGE_SIZE, RO_COMPAT_STREAM_ECC, VzError, VzReader, VzWriter, VzWriterConfig,
    boot_ecc_verify_and_repair, repair_slice, scan_clusters_forward, verify_archive,
};

fn build_rs_test_archive() -> Vec<u8> {
    // 6+ files forced into separate 4 KiB-ish clusters so we get at least 6 data clusters -> K=6, M=3.
    let cfg = VzWriterConfig {
        target_cluster_size: 4096,
        multi_cluster_threshold: 1024 * 1024,
        rs_parity: Some((6, 3)),
        ..Default::default()
    };
    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
    for i in 0..10 {
        let data = vec![((i * 37 + 13) & 0xFF) as u8; 4096];
        w.add_file(&format!("/blob_{i:02}.bin"), &data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn test_exhaustive_boot_ecc_pages_0_through_15_and_dual_fail() {
    let original = build_rs_test_archive();

    // Corrupt every single page 0..=15 individually.
    for page in 0..BOOT_PAGES {
        let mut damaged = original.clone();
        if page == 14 {
            // Test BOTH Page 14 data region (0xE000..0xEFAF) AND Page 14 BootEccDescriptor (0xEFB0..0xF000)!
            damaged[14 * PAGE_SIZE + 50] ^= 0xFF;
            assert_eq!(boot_ecc_verify_and_repair(&mut damaged), Ok(Some(14)));
            assert_eq!(damaged, original);

            let mut damaged_desc = original.clone();
            damaged_desc[BOOT_ECC_DESC_OFF + 8] ^= 0xAA;
            damaged_desc[BOOT_ECC_DESC_OFF + 77] ^= 0x55;
            assert_eq!(boot_ecc_verify_and_repair(&mut damaged_desc), Ok(Some(14)));
            assert_eq!(damaged_desc, original);
        } else {
            // Invert entire 4 KiB page (guarantees corruption even for all-zero unused pages)!
            let start = page * PAGE_SIZE;
            for b in &mut damaged[start..start + PAGE_SIZE] {
                *b ^= 0xFF;
            }
            let mut for_reader = damaged.clone();
            assert_eq!(boot_ecc_verify_and_repair(&mut damaged), Ok(Some(page)));
            assert_eq!(damaged, original);

            // VzReader::open must also transparently recover in 1 RTT even if Page 0 (BootHeader) was wiped!
            let r = VzReader::open(for_reader.clone()).unwrap();
            assert_eq!(r.read_file("/blob_00.bin").unwrap(), vec![13u8; 4096]);
            let rep = repair_slice(&mut for_reader).unwrap();
            assert_eq!(rep.boot_page_repaired, Some(page));
            assert_eq!(for_reader, original);
        }
    }

    // Dual-page corruptions must fail cleanly with CorruptUnrecoverable.
    let mut dual_a = original.clone();
    dual_a[BOOT_ECC_DESC_OFF + 2] ^= 0xFF; // Page 14 desc
    dual_a[DEFAULT_BOOT_SIZE - 1] ^= 0x01; // Page 15 tail
    assert_eq!(
        boot_ecc_verify_and_repair(&mut dual_a),
        Err(VzError::CorruptUnrecoverable)
    );

    let mut dual_b = original.clone();
    dual_b[0] ^= 0xFF; // Page 0
    dual_b[5 * PAGE_SIZE + 100] ^= 0xFF; // Page 5
    assert_eq!(
        boot_ecc_verify_and_repair(&mut dual_b),
        Err(VzError::CorruptUnrecoverable)
    );
}

#[test]
fn test_torn_commit_fallback_without_boot_ecc_update() {
    let mut archive = build_rs_test_archive();
    // Simulate a torn commit: commit slot_b with generation 2 (valid CRC), modifying page 0 + page 1
    // WITHOUT re-running boot_ecc_encode!
    let mut hdr = BootHeader::from_bytes(&archive).unwrap();
    let (active, _) = hdr.select_active(0xFFFF).unwrap();
    let mut new_slot: HeaderSlot = *active;
    new_slot.total_entries = 999;
    hdr.commit(&new_slot);
    hdr.write_bytes(&mut archive[..BootHeader::SIZE]).unwrap();
    // Also flip a byte in Page 1 so 2 pages disagree with BootECC.
    archive[PAGE_SIZE + 123] ^= 0x11;

    // BootECC fails, so VzReader falls back to dual-slot header check and opens generation 2!
    let r = VzReader::open(archive).unwrap();
    assert_eq!(r.active_slot().generation, 2);
    assert_eq!(r.active_slot().total_entries, 999);
}

#[test]
fn test_rs_gf256_stripe_k6_m3_wipe_and_repair() {
    let original = build_rs_test_archive();
    let r = VzReader::open(original.clone()).unwrap();
    assert_ne!(r.active_slot().ro_compat_flags & RO_COMPAT_STREAM_ECC, 0);
    assert_ne!(r.active_slot().compat_flags & COMPAT_BOOT_ECC, 0);

    let clusters = scan_clusters_forward(&original, DEFAULT_BOOT_SIZE as u64).unwrap();
    // First 6 clusters (0..6) are data clusters of Stripe 0, followed by 3 parity clusters (6..9).
    assert!(clusters.len() >= 9);

    // Scenario 1: Completely zero out 3 data clusters (0, 2, 5) including their ClusterHeaders!
    let mut buf1 = original.clone();
    for idx in [0usize, 2, 5] {
        let (off, hdr) = clusters[idx];
        let s = off as usize;
        let e = s + hdr.cluster_len as usize;
        buf1[s..e].fill(0);
    }
    let rep1 = repair_slice(&mut buf1).unwrap();
    assert_eq!(rep1.data_clusters_repaired, 3);
    assert_eq!(buf1, original);
    assert!(verify_archive(&buf1, None).unwrap().is_clean());

    // Scenario 2: Mixed wipe of last data cluster (5) + parity_0 (6) + parity_1 (7), leaving parity_2 (8)!
    let mut buf2 = original.clone();
    for idx in [5usize, 6, 7] {
        let (off, hdr) = clusters[idx];
        let s = off as usize;
        let e = s + hdr.cluster_len as usize;
        buf2[s..e].fill(0xAA);
    }
    let rep2 = repair_slice(&mut buf2).unwrap();
    assert_eq!(rep2.data_clusters_repaired, 1);
    assert_eq!(rep2.parity_clusters_repaired, 2);
    assert_eq!(buf2, original);

    // Scenario 3: Wipe M + 1 = 4 clusters in Stripe 0 -> must fail cleanly with CorruptUnrecoverable!
    let mut buf_fail = original.clone();
    for idx in [0usize, 1, 2, 6] {
        let (off, hdr) = clusters[idx];
        let s = off as usize;
        let e = s + hdr.cluster_len as usize;
        buf_fail[s..e].fill(0);
    }
    assert_eq!(repair_slice(&mut buf_fail), Err(VzError::CorruptUnrecoverable));
}

#[test]
fn test_verify_resyncs_past_bad_cluster_and_repair_saves_healthy_stripe() {
    // Force >= 2 full RS(2,1) stripes so Stripe 0 has M+1 hits and Stripe 1 has 1 hit.
    let cfg = VzWriterConfig {
        target_cluster_size: 4096,
        multi_cluster_threshold: 1024 * 1024,
        rs_parity: Some((2, 1)),
        ..Default::default()
    };
    let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
    for i in 0..8 {
        w.add_file(&format!("/s_{i:02}.bin"), &vec![(i + 1) as u8; 4096])
            .unwrap();
    }
    let original = w.finish().unwrap().into_inner();
    let clusters = scan_clusters_forward(&original, DEFAULT_BOOT_SIZE as u64).unwrap();
    // Stripe 0: data 0,1 parity 2. Stripe 1: data 3,4 parity 5. Stripe 2+: 6..
    assert!(clusters.len() >= 8);

    // 1. Corrupt cluster 0 completely -> verify_archive MUST resync and still inspect clusters & parity stripes!
    let mut one_bad = original.clone();
    let (off0, hdr0) = clusters[0];
    one_bad[off0 as usize..off0 as usize + hdr0.cluster_len as usize].fill(0);
    let rep = verify_archive(&one_bad, None).unwrap();
    assert!(!rep.is_clean());
    assert!(rep.clusters_checked >= clusters.len() - 1);
    assert!(rep.parity_stripes_checked >= 2);

    // 2. Make Stripe 0 unrecoverable (wipe data 0 and data 1), AND wipe data 3 in Stripe 1 (recoverable).
    // repair_slice must still repair Stripe 1 even though Stripe 0 returns CorruptUnrecoverable.
    let mut mixed = original.clone();
    for idx in [0usize, 1, 3] {
        let (off, hdr) = clusters[idx];
        mixed[off as usize..off as usize + hdr.cluster_len as usize].fill(0x55);
    }
    assert_eq!(repair_slice(&mut mixed), Err(VzError::CorruptUnrecoverable));
    let (off3, hdr3) = clusters[3];
    assert_eq!(
        &mixed[off3 as usize..off3 as usize + hdr3.cluster_len as usize],
        &original[off3 as usize..off3 as usize + hdr3.cluster_len as usize]
    );
}
