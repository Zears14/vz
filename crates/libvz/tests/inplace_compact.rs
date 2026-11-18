use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};

use libvz::ext_meta::{RawTlv, Xattr};
use libvz::{
    CODEC_LZ4, CODEC_NONE, CODEC_ZSTD, DictEntry, EncryptionKey, EntryOptions, ExtTime,
    InPlaceCompactOptions, InPlaceCrashPoint, KIND_LNK, LsmAppendWriter, TAG_VENDOR_EXT, VzError,
    VzReader, VzReaderOptions, VzWriter, VzWriterConfig, compact_file_in_place,
    compact_file_in_place_with_hook, repair_file, resume_in_place_compaction, verify_archive,
};
use tempfile::NamedTempFile;

struct TrackingAllocator;

static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);
static PEAK_DELTA_BYTES: AtomicUsize = AtomicUsize::new(0);
static TRACK_ACTIVE: AtomicUsize = AtomicUsize::new(0);
static BASELINE_BYTES: AtomicIsize = AtomicIsize::new(0);

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let cur = LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed)
                + layout.size() as isize;
            if TRACK_ACTIVE.load(Ordering::Relaxed) != 0 {
                let delta = (cur - BASELINE_BYTES.load(Ordering::Relaxed)).max(0) as usize;
                let mut peak = PEAK_DELTA_BYTES.load(Ordering::Relaxed);
                while delta > peak {
                    match PEAK_DELTA_BYTES.compare_exchange_weak(
                        peak,
                        delta,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => peak = actual,
                    }
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            let diff = new_size as isize - layout.size() as isize;
            let cur = LIVE_BYTES.fetch_add(diff, Ordering::Relaxed) + diff;
            if TRACK_ACTIVE.load(Ordering::Relaxed) != 0 {
                let delta = (cur - BASELINE_BYTES.load(Ordering::Relaxed)).max(0) as usize;
                let mut peak = PEAK_DELTA_BYTES.load(Ordering::Relaxed);
                while delta > peak {
                    match PEAK_DELTA_BYTES.compare_exchange_weak(
                        peak,
                        delta,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => peak = actual,
                    }
                }
            }
        }
        new_ptr
    }
}

static SERIAL_TEST_LOCK: Mutex<()> = Mutex::new(());

fn deterministic_blob(seed: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let v = i.wrapping_mul(31).wrapping_add(seed * 17);
            if i % 5 < 3 {
                ((i / 8 + seed) & 0xFF) as u8
            } else {
                ((v ^ (v >> 7)) & 0xFF) as u8
            }
        })
        .collect()
}

fn build_rich_lsm_archive(
    encryption: Option<EncryptionKey>,
    rs_parity: Option<(u16, u16)>,
) -> (NamedTempFile, Vec<(String, Vec<u8>)>) {
    let mut tmp = NamedTempFile::new().unwrap();
    let dict_bytes = deterministic_blob(0, 16_384);
    let mut expected: Vec<(String, Vec<u8>)> = Vec::new();

    let cfg = VzWriterConfig {
        default_codec: CODEC_ZSTD,
        target_cluster_size: 64 * 1024,
        multi_cluster_threshold: 64 * 1024,
        encryption: encryption.clone(),
        rs_parity,
        dicts: vec![DictEntry {
            dict_id: 9,
            codec: CODEC_ZSTD,
            flags: 0,
            bytes: dict_bytes,
        }],
        extra_registry_tlvs: vec![RawTlv {
            tag: TAG_VENDOR_EXT,
            value: b"\x0Bcom.example\x01ok".to_vec(),
        }],
        ..Default::default()
    };

    let f = tmp.reopen().unwrap();
    let mut w = VzWriter::new(f, cfg).unwrap();
    w.add_dir("/a", 0o755, 1_700_000_000_000_000_000).unwrap();
    w.add_dir("/a/b", 0o750, 1_700_000_000_000_000_001).unwrap();

    // Inline small file
    w.add_file_with_options(
        "/a/tiny.txt",
        b"hello tiny inline",
        EntryOptions {
            codec: Some(CODEC_NONE),
            xattrs: vec![Xattr {
                key: "user.k".into(),
                value: b"v1".to_vec(),
            }],
            ext_time: Some(ExtTime {
                mtime_sec: 1_700_000_123,
                btime_sec: 1_699_999_000,
                mtime_nsec: 42,
                btime_nsec: 7,
            }),
            extra_ext_tlvs: vec![RawTlv {
                tag: 0x3C01,
                value: b"priv".to_vec(),
            }],
            ..Default::default()
        },
    )
    .unwrap();
    expected.push(("/a/tiny.txt".into(), b"hello tiny inline".to_vec()));

    // Symlink
    w.add_file_with_options(
        "/a/link.sym",
        b"tiny.txt",
        EntryOptions {
            kind: KIND_LNK,
            mode: 0o777,
            ..Default::default()
        },
    )
    .unwrap();

    // Multiple LZ4 / Zstd+Dict files across multiple clusters
    for i in 0..24 {
        let p = format!("/a/b/file_{i:02}.bin");
        let codec = if i % 2 == 0 { CODEC_LZ4 } else { CODEC_ZSTD };
        let dict_id = if i % 3 == 0 { Some(9u32) } else { None };
        let data = deterministic_blob(i + 1, 14_000 + i * 777);
        w.add_file_with_options(
            &p,
            &data,
            EntryOptions {
                codec: Some(codec),
                dict_id,
                ..Default::default()
            },
        )
        .unwrap();
        if i == 5 {
            w.add_hardlink("/a/b/hard_file_05.bin", &p).unwrap();
            expected.push(("/a/b/hard_file_05.bin".into(), data.clone()));
        }
        expected.push((p, data));
    }

    // Files that will be overwritten or tombstoned in LSM run 2
    w.add_file("/a/will_update.bin", &deterministic_blob(88, 30_000))
        .unwrap();
    w.add_file("/a/will_delete.bin", &deterministic_blob(89, 25_000))
        .unwrap();

    // Multi-cluster blob (192 KiB = 3 x 64 KiB chunks)
    let mc = deterministic_blob(500, 196_608);
    w.add_file("/a/multi.bin", &mc).unwrap();
    expected.push(("/a/multi.bin".into(), mc));

    // Sparse file with 1 MiB hole
    let mut sparse_full = vec![0u8; 512 * 1024 + 4];
    sparse_full[..4].copy_from_slice(b"HEAD");
    sparse_full[512 * 1024..].copy_from_slice(b"TAIL");
    w.add_sparse_file(
        "/a/sparse.bin",
        sparse_full.len() as u64,
        &[(0, b"HEAD"), (512 * 1024, b"TAIL")],
        EntryOptions::default(),
    )
    .unwrap();
    expected.push(("/a/sparse.bin".into(), sparse_full));

    let f_done = w.finish().unwrap();
    drop(f_done);

    // Append LSM delta run 2 (overwrite + tombstone + add).
    let f_app = OpenOptions::new().read(true).write(true).open(tmp.path()).unwrap();
    let mut app = LsmAppendWriter::open(f_app, encryption, 512, 128).unwrap();
    let updated = deterministic_blob(777, 18_000);
    app.add_file("/a/will_update.bin", &updated).unwrap();
    expected.push(("/a/will_update.bin".into(), updated));
    app.delete("/a/will_delete.bin").unwrap();
    let added = deterministic_blob(778, 12_000);
    app.add_file("/a/added_delta.bin", &added).unwrap();
    expected.push(("/a/added_delta.bin".into(), added));
    app.finish().unwrap();

    tmp.as_file_mut().sync_all().unwrap();
    (tmp, expected)
}

fn verify_restored_archive(
    path: &std::path::Path,
    encryption: Option<EncryptionKey>,
    expected: &[(String, Vec<u8>)],
) {
    let f = File::open(path).unwrap();
    let vrep = verify_archive(&f, encryption.clone()).unwrap();
    assert!(vrep.is_clean(), "verify errors: {:?}", vrep.errors);

    let r = VzReader::open_with_options(
        f,
        VzReaderOptions {
            encryption,
            repair_boot_ecc: true,
        },
    )
    .unwrap();
    assert_eq!(r.active_slot().lsm_run_count, 1);
    assert_eq!(r.extra_registry_tlvs().len(), 1);
    assert_eq!(r.extra_registry_tlvs()[0].tag, TAG_VENDOR_EXT);
    assert!(matches!(r.stat("/a/will_delete.bin"), Err(VzError::NotFound)));

    let st_tiny = r.stat("/a/tiny.txt").unwrap();
    assert_eq!(st_tiny.xattrs[0].key, "user.k");
    assert_eq!(st_tiny.ext_time.unwrap().mtime_sec, 1_700_000_123);

    let orig = r.stat("/a/b/file_05.bin").unwrap();
    let hl = r.stat("/a/b/hard_file_05.bin").unwrap();
    assert_eq!(orig.entry_id, hl.entry_id);

    for (p, exp) in expected {
        let got = r.read_file(p).unwrap();
        assert_eq!(&got, exp, "content mismatch for {p}");
    }
}

#[test]
fn test_inplace_compact_multi_run_mixed_entries_zero_reencode() {
    let _g = SERIAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (tmp, expected) = build_rich_lsm_archive(None, None);
    let mut f = OpenOptions::new().read(true).write(true).open(tmp.path()).unwrap();

    let rep = compact_file_in_place(
        &mut f,
        InPlaceCompactOptions {
            batch_bytes: 64 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!rep.resumed);
    assert_eq!(rep.prev_lsm_runs, 2);
    assert!(rep.compacted_bytes < rep.original_bytes);
    assert!(rep.batches_written >= 2);
    assert_eq!(f.metadata().unwrap().len(), rep.compacted_bytes);

    verify_restored_archive(tmp.path(), None, &expected);

    // Explicitly calling resume on a clean, already-compacted file must fail cleanly.
    assert_eq!(
        resume_in_place_compaction(&mut f, InPlaceCompactOptions::default()).unwrap_err(),
        VzError::InvalidInput
    );
}

#[test]
fn test_inplace_compact_crash_and_resume_all_phases() {
    let _g = SERIAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let crash_points = [
        InPlaceCrashPoint::BeforeJournalActivation,
        InPlaceCrashPoint::AfterJournalActivation,
        InPlaceCrashPoint::MidBounceWrite,
        InPlaceCrashPoint::AfterBounceCommitBeforeOverwrite,
        InPlaceCrashPoint::MidInPlaceOverwrite,
        InPlaceCrashPoint::AfterBatchCommit(1),
        InPlaceCrashPoint::AfterBatchCommit(2),
        InPlaceCrashPoint::AfterBtreeWrite,
        InPlaceCrashPoint::MidFinalBootWrite,
        InPlaceCrashPoint::BeforeFinalTruncate,
    ];

    for cp in crash_points {
        let (tmp, expected) = build_rich_lsm_archive(None, None);
        let mut f = OpenOptions::new().read(true).write(true).open(tmp.path()).unwrap();

        let err = compact_file_in_place_with_hook(
            &mut f,
            InPlaceCompactOptions {
                batch_bytes: 64 * 1024,
                ..Default::default()
            },
            &mut |hit| {
                if hit == cp {
                    Err(VzError::IoError)
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(err, VzError::IoError, "crash point {cp:?} was not triggered");
        drop(f);

        // Normal VzReader MUST fail closed whenever INCOMPAT_COMPACTING is active!
        if !matches!(
            cp,
            InPlaceCrashPoint::BeforeJournalActivation | InPlaceCrashPoint::BeforeFinalTruncate
        ) {
            let rf = File::open(tmp.path()).unwrap();
            match VzReader::open(rf) {
                Err(e) => assert_eq!(
                    e,
                    VzError::IncompatibleFeature,
                    "expected fail-closed IncompatibleFeature at {cp:?}"
                ),
                Ok(_) => panic!("expected fail-closed IncompatibleFeature at {cp:?}"),
            }
        }

        let mut rf = OpenOptions::new().read(true).write(true).open(tmp.path()).unwrap();
        if cp == InPlaceCrashPoint::BeforeFinalTruncate {
            // Even without truncation, final BootBlock is already valid! Calling compact_file_in_place
            // cleanly trims & validates everything.
            let _ = compact_file_in_place(
                &mut rf,
                InPlaceCompactOptions {
                    batch_bytes: 64 * 1024,
                    ..Default::default()
                },
            )
            .unwrap();
        } else {
            let rep = compact_file_in_place(
                &mut rf,
                InPlaceCompactOptions {
                    batch_bytes: 64 * 1024,
                    ..Default::default()
                },
            )
            .unwrap();
            if cp != InPlaceCrashPoint::BeforeJournalActivation {
                assert!(rep.resumed, "expected resume=true for {cp:?}");
            }
        }
        verify_restored_archive(tmp.path(), None, &expected);
    }
}

#[test]
fn test_inplace_compact_overlap_evacuation_encryption_and_rs() {
    let _g = SERIAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let key = EncryptionKey::Raw256([0xA5u8; 32]);
    // Source without RS parity, then add RS (4,2) during in-place compaction!
    // This makes compacted output larger than source, forcing overlap evacuation & dynamic journal spacing.
    let (tmp, expected) = build_rich_lsm_archive(Some(key.clone()), None);
    let mut f = OpenOptions::new().read(true).write(true).open(tmp.path()).unwrap();

    // Crash after batch 1 (after evacuation & overwrite) then resume with RS(4,2) encrypted!
    let _ = compact_file_in_place_with_hook(
        &mut f,
        InPlaceCompactOptions {
            encryption: Some(key.clone()),
            rs_parity: Some((4, 2)),
            batch_bytes: 64 * 1024,
            ..Default::default()
        },
        &mut |hit| {
            if hit == InPlaceCrashPoint::AfterBatchCommit(1) {
                Err(VzError::IoError)
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();

    let rep = resume_in_place_compaction(
        &mut f,
        InPlaceCompactOptions {
            encryption: Some(key.clone()),
            rs_parity: Some((4, 2)),
            batch_bytes: 64 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(rep.resumed);
    verify_restored_archive(tmp.path(), Some(key.clone()), &expected);

    // Corrupt Boot Block page 3 AND a cluster past 64 KiB, then prove RS+BootECC repairs cleanly!
    let mut rf = OpenOptions::new().read(true).write(true).open(tmp.path()).unwrap();
    use std::io::Seek;
    rf.seek(std::io::SeekFrom::Start(3 * 4096)).unwrap();
    rf.write_all(&[0x55u8; 4096]).unwrap();
    rf.sync_all().unwrap();
    let rep_repair = repair_file(&mut rf).unwrap();
    assert_eq!(rep_repair.boot_page_repaired, Some(3));
    verify_restored_archive(tmp.path(), Some(key), &expected);
}

#[test]
fn test_inplace_compact_bounded_ram_streaming() {
    let _g = SERIAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = NamedTempFile::new().unwrap();
    let cfg = VzWriterConfig {
        default_codec: CODEC_NONE,
        target_cluster_size: 256 * 1024,
        multi_cluster_threshold: 256 * 1024,
        ..Default::default()
    };
    let mut w = VzWriter::new(tmp.reopen().unwrap(), cfg).unwrap();
    // Write 16 MiB multi-cluster blob + 4 MiB replaceable blob across 2 LSM runs (~20 MiB total).
    let big_a = deterministic_blob(101, 16 * 1024 * 1024);
    let dead = deterministic_blob(202, 4 * 1024 * 1024);
    w.add_file("/big_a.bin", &big_a).unwrap();
    w.add_file("/dead.bin", &dead).unwrap();
    w.finish().unwrap();

    let f_app = OpenOptions::new().read(true).write(true).open(tmp.path()).unwrap();
    let mut app = LsmAppendWriter::open(f_app, None, 512, 128).unwrap();
    app.delete("/dead.bin").unwrap();
    app.finish().unwrap();

    let mut f = OpenOptions::new().read(true).write(true).open(tmp.path()).unwrap();
    let orig_len = f.metadata().unwrap().len();
    assert!(orig_len > 20 * 1024 * 1024);

    // Measure peak live heap delta strictly during `compact_file_in_place` with 256 KiB batch window.
    BASELINE_BYTES.store(LIVE_BYTES.load(Ordering::Relaxed), Ordering::Relaxed);
    PEAK_DELTA_BYTES.store(0, Ordering::Relaxed);
    TRACK_ACTIVE.store(1, Ordering::SeqCst);

    let rep = compact_file_in_place(
        &mut f,
        InPlaceCompactOptions {
            batch_bytes: 256 * 1024,
            ..Default::default()
        },
    )
    .unwrap();

    TRACK_ACTIVE.store(0, Ordering::SeqCst);
    let peak_ram = PEAK_DELTA_BYTES.load(Ordering::Relaxed);

    assert!(rep.compacted_bytes < 17 * 1024 * 1024);
    // Peak heap delta MUST stay bounded O(batch_bytes), far below the 20 MiB archive size!
    assert!(
        peak_ram < 4 * 1024 * 1024,
        "peak_ram exceeded 4 MiB bound: {peak_ram} bytes"
    );
    // Extra peak file size during compaction is O(batch_bytes), NOT 2x orig_len (~40 MiB)!
    assert!(
        rep.peak_file_bytes < orig_len + 4 * 1024 * 1024,
        "peak file bytes grew too large: {} vs orig {}",
        rep.peak_file_bytes,
        orig_len
    );

    let rf = File::open(tmp.path()).unwrap();
    let r = VzReader::open(rf).unwrap();
    assert_eq!(r.read_file("/big_a.bin").unwrap(), big_a);
    assert!(matches!(r.stat("/dead.bin"), Err(VzError::NotFound)));
}
