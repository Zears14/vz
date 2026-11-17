use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use libvz::ext_meta::DictEntry;
use libvz::{
    CODEC_LZ4, CODEC_NONE, CODEC_ZSTD, DEFAULT_BOOT_SIZE, EncryptionKey, EntryOptions,
    FUSE_ROOT_ID, FuseVolume, LsmAppendWriter, MmapRangeReader, VzReader, VzWriter,
    VzWriterConfig, boot_ecc_encode, boot_ecc_verify_and_repair, compact_archive, crc32c,
    encode_rs_gf256_stripe, parse_parity_cluster_body, read_levint_fast, read_levint_safe,
    recover_rs_gf256_stripe, rs_gf256_madd_slice, validate_cluster, write_levint,
};

fn bench_crc32c(c: &mut Criterion) {
    let mut group = c.benchmark_group("crc32c");
    for &sz in &[64usize, 4096, 65_536, 1024 * 1024, 16 * 1024 * 1024] {
        let data = vec![0xA5u8; sz];
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &data, |b, d| {
            b.iter(|| black_box(crc32c(black_box(d))))
        });
    }
    group.finish();
}

fn bench_levint(c: &mut Criterion) {
    let mut group = c.benchmark_group("levint");
    let mut enc = [0u8; 8];
    let _ = write_levint(&mut enc, 123_456_789).unwrap();

    group.bench_function("read_levint_fast", |b| {
        b.iter(|| black_box(read_levint_fast(black_box(&enc))))
    });
    group.bench_function("read_levint_safe", |b| {
        b.iter(|| black_box(read_levint_safe(black_box(&enc)).unwrap()))
    });
    group.bench_function("write_levint", |b| {
        let mut out = [0u8; 8];
        b.iter(|| black_box(write_levint(black_box(&mut out), black_box(123_456_789)).unwrap()))
    });
    group.finish();
}

fn bench_boot_ecc(c: &mut Criterion) {
    let mut group = c.benchmark_group("boot_ecc");
    let mut block = vec![0x5Au8; DEFAULT_BOOT_SIZE];
    group.throughput(Throughput::Bytes(DEFAULT_BOOT_SIZE as u64));
    group.bench_function("encode", |b| {
        b.iter(|| boot_ecc_encode(black_box(&mut block)).unwrap())
    });
    boot_ecc_encode(&mut block).unwrap();
    group.bench_function("verify_clean", |b| {
        b.iter(|| black_box(boot_ecc_verify_and_repair(black_box(&mut block)).unwrap()))
    });
    group.bench_function("repair_page_3", |b| {
        b.iter(|| {
            block[3 * 4096 + 42] ^= 0xFF;
            black_box(boot_ecc_verify_and_repair(black_box(&mut block)).unwrap())
        })
    });
    group.finish();
}

fn bench_rs_gf256(c: &mut Criterion) {
    let mut group = c.benchmark_group("rs_gf256");
    group.sample_size(20);
    let src = vec![0x3Cu8; 1024 * 1024];
    let mut dst = vec![0u8; 1024 * 1024];
    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("madd_slice_1mib", |b| {
        b.iter(|| rs_gf256_madd_slice(black_box(&mut dst), black_box(&src), 0x53).unwrap())
    });

    for &(k, m) in &[(8u16, 2u16), (16u16, 4u16)] {
        let mut clusters = Vec::with_capacity(k as usize);
        let mut offsets = Vec::with_capacity(k as usize);
        let mut prev_len = 0u64;
        for j in 0..k {
            let body = vec![0xECu8, 0x00]; // small void
            let mut full = libvz::build_cluster_from_body(&body, prev_len, j as u64).unwrap();
            full.resize(1024 * 1024, (j & 0xFF) as u8);
            prev_len = full.len() as u64;
            offsets.push(DEFAULT_BOOT_SIZE as u64 + j as u64 * 1024 * 1024);
            clusters.push(full);
        }
        // Build real 1 MiB valid clusters for encode + decode bench
        let mut real_clusters = Vec::with_capacity(k as usize);
        let mut prev = 0u64;
        for j in 0..k {
            let payload_len = 1024 * 1024 - 64;
            let mut body = Vec::with_capacity(payload_len + 8);
            body.push(0xEC);
            let mut lb = [0u8; 8];
            let lw = write_levint(&mut lb, payload_len as u64).unwrap();
            body.extend_from_slice(&lb[..lw]);
            body.resize(body.len() + payload_len, ((j * 17 + 5) & 0xFF) as u8);
            let cl = libvz::build_cluster_from_body(&body, prev, j as u64).unwrap();
            prev = cl.len() as u64;
            real_clusters.push(cl);
        }
        let refs: Vec<&[u8]> = real_clusters.iter().map(Vec::as_slice).collect();
        let max_len = real_clusters.iter().map(Vec::len).max().unwrap();

        group.throughput(Throughput::Bytes((k as u64) * 1024 * 1024));
        group.bench_function(format!("encode_k{k}_m{m}_1mib"), |b| {
            b.iter(|| {
                black_box(
                    encode_rs_gf256_stripe(&refs, &offsets, 0, m, k as u64, prev).unwrap(),
                )
            })
        });

        let (parities, _) =
            encode_rs_gf256_stripe(&refs, &offsets, 0, m, k as u64, prev).unwrap();
        let parity_slots: Vec<Option<(u16, Vec<u8>)>> = parities
            .iter()
            .map(|p| {
                let (_, body, _) = validate_cluster(p).unwrap();
                let (man, _, pay) = parse_parity_cluster_body(body).unwrap().unwrap();
                Some((man.parity_index, pay.to_vec()))
            })
            .collect();

        group.bench_function(format!("recover_k{k}_m{m}_1mib_m_erasures"), |b| {
            b.iter(|| {
                let mut dslots: Vec<Option<Vec<u8>>> =
                    real_clusters.iter().map(|c| Some(c.clone())).collect();
                for slot in dslots.iter_mut().take(m as usize) {
                    *slot = None;
                }
                black_box(
                    recover_rs_gf256_stripe(
                        &mut dslots,
                        &parity_slots,
                        k as usize,
                        m as usize,
                        max_len,
                    )
                    .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn bench_archive_codecs_and_lookups(c: &mut Criterion) {
    let mut group = c.benchmark_group("archive_ops");
    group.sample_size(15);
    group.measurement_time(Duration::from_secs(3));

    // Small-file corpus: 1,000 files of 512 B (fast enough for criterion iterations)
    let small_files: Vec<(String, Vec<u8>)> = (0..1000)
        .map(|i| {
            let path = format!("/d{}/{i:04}.txt", i % 20);
            let body = format!("record={i:06};status=ok;payload=compressible_repeated_text_")
                .repeat(8)
                .into_bytes();
            (path, body)
        })
        .collect();
    let total_small_bytes: u64 = small_files.iter().map(|(_, b)| b.len() as u64).sum();

    let dict_bytes = b"record=000001;status=ok;payload=compressible_repeated_text_"
        .repeat(128);
    let raw_key = EncryptionKey::Raw256([0x11u8; 32]);

    for (label, codec, dict, enc) in [
        ("none", CODEC_NONE, None, None),
        ("lz4", CODEC_LZ4, None, None),
        ("zstd", CODEC_ZSTD, None, None),
        ("zstd_dict", CODEC_ZSTD, Some(1u32), None),
        ("encrypted_raw256", CODEC_NONE, None, Some(raw_key.clone())),
    ] {
        group.throughput(Throughput::Bytes(total_small_bytes));
        group.bench_function(format!("pack_1000small_{label}"), |b| {
            b.iter(|| {
                let cfg = VzWriterConfig {
                    default_codec: codec,
                    dicts: dict
                        .map(|id| {
                            vec![DictEntry {
                                dict_id: id,
                                codec: CODEC_ZSTD,
                                flags: 0,
                                bytes: dict_bytes.clone(),
                            }]
                        })
                        .unwrap_or_default(),
                    encryption: enc.clone(),
                    ..Default::default()
                };
                let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
                for (p, d) in &small_files {
                    w.add_file_with_options(
                        p,
                        d,
                        EntryOptions {
                            dict_id: dict,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                }
                black_box(w.finish().unwrap().into_inner())
            })
        });
    }

    // Random-access mmap vs File lookup benchmark on 10,000 files (tree_height >= 2)
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let cfg = VzWriterConfig {
        max_leaf_entries: 128,
        max_route_entries: 64,
        ..Default::default()
    };
    let mut w = VzWriter::new(tmp.reopen().unwrap(), cfg).unwrap();
    for i in 0..10_000 {
        let p = format!("/d_{:02}/f_{i:05}.bin", i % 50);
        w.add_file(&p, &vec![(i & 0xFF) as u8; 256]).unwrap();
    }
    w.finish().unwrap();

    let f_ro = tmp.reopen().unwrap();
    // SAFETY: tmp file is immutable for duration of bench.
    let mmap = unsafe { MmapRangeReader::from_file(&f_ro) }.unwrap();
    let r_mmap = VzReader::open(mmap).unwrap();
    let r_file = VzReader::open(tmp.reopen().unwrap()).unwrap();

    group.throughput(Throughput::Elements(1));
    group.bench_function("cold_open_file", |b| {
        b.iter(|| black_box(VzReader::open(tmp.reopen().unwrap()).unwrap().active_slot().generation))
    });
    group.bench_function("stat_10k_h2_mmap", |b| {
        b.iter(|| black_box(r_mmap.stat("/d_25/f_05025.bin").unwrap()))
    });
    group.bench_function("stat_10k_h2_file", |b| {
        b.iter(|| black_box(r_file.stat("/d_25/f_05025.bin").unwrap()))
    });
    group.bench_function("read_10k_h2_mmap", |b| {
        b.iter(|| black_box(r_mmap.read_file("/d_25/f_05025.bin").unwrap()))
    });
    group.bench_function("read_10k_h2_file", |b| {
        b.iter(|| black_box(r_file.read_file("/d_25/f_05025.bin").unwrap()))
    });

    // LSM 16 runs vs compacted
    let mut lsm_buf = Cursor::new(Vec::new());
    let mut lw = VzWriter::new(lsm_buf, VzWriterConfig::default()).unwrap();
    for i in 0..100 {
        lw.add_file(&format!("/base_{i}.bin"), &[1u8; 64]).unwrap();
    }
    lsm_buf = lw.finish().unwrap();
    for run in 1..16 {
        let mut app = LsmAppendWriter::open(lsm_buf, None, 512, 128).unwrap();
        app.add_file(&format!("/delta_{run}.bin"), &[run as u8; 64])
            .unwrap();
        lsm_buf = app.finish().unwrap();
    }
    let r_lsm16 = VzReader::open(lsm_buf).unwrap();
    let comp_buf =
        compact_archive(&r_lsm16, Cursor::new(Vec::new()), VzWriterConfig::default())
            .unwrap()
            .into_inner();
    let r_comp = VzReader::open(comp_buf).unwrap();

    group.bench_function("lsm_16_runs_stat_base", |b| {
        b.iter(|| black_box(r_lsm16.stat("/base_50.bin").unwrap()))
    });
    group.bench_function("lsm_compacted_stat_base", |b| {
        b.iter(|| black_box(r_comp.stat("/base_50.bin").unwrap()))
    });

    // readdir(10) vs readdir(5000) and zero-copy readdir_visit
    for &dir_n in &[10usize, 5_000usize] {
        let mut dw = VzWriter::new(Cursor::new(Vec::new()), VzWriterConfig::default()).unwrap();
        for i in 0..dir_n {
            dw.add_file(&format!("/bigdir/entry_{i:05}.txt"), b"x")
                .unwrap();
        }
        let darc = dw.finish().unwrap().into_inner();
        let dr = VzReader::open(darc).unwrap();
        group.bench_function(format!("readdir_owned_{dir_n}"), |b| {
            b.iter(|| black_box(dr.readdir("/bigdir").unwrap()))
        });
        group.bench_function(format!("readdir_visit_{dir_n}"), |b| {
            b.iter(|| {
                let mut count = 0usize;
                dr.readdir_visit("/bigdir", |e| {
                    black_box(e.name);
                    count += 1;
                    Ok(())
                })
                .unwrap();
                black_box(count)
            })
        });
    }

    group.finish();
}

fn bench_fuse3(c: &mut Criterion) {
    let mut group = c.benchmark_group("fuse3");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(3));

    // Build 5,000-file archive (2,000 in /hot + 3,000 in /sub_XX) for mount + metadata ops.
    let mut w = VzWriter::new(Cursor::new(Vec::new()), VzWriterConfig::default()).unwrap();
    w.add_dir("/hot", 0o755, 0).unwrap();
    for d in 0..30 {
        w.add_dir(&format!("/sub_{d:02}"), 0o755, 0).unwrap();
    }
    for i in 0..5_000 {
        let path = if i < 2_000 {
            format!("/hot/f_{i:04}.txt")
        } else {
            format!("/sub_{:02}/f_{i:04}.txt", i % 30)
        };
        w.add_file(&path, b"fuse-meta-bench").unwrap();
    }
    let meta_arc = w.finish().unwrap().into_inner();
    let meta_reader = Arc::new(VzReader::open(meta_arc).unwrap());

    group.bench_function("mount_5000", |b| {
        b.iter(|| black_box(FuseVolume::mount(Arc::clone(&meta_reader)).unwrap()))
    });

    let fs = FuseVolume::mount(Arc::clone(&meta_reader)).unwrap();
    let hot_attr = fs.lookup(FUSE_ROOT_ID, "hot").unwrap();
    let target_attr = fs.lookup(hot_attr.ino, "f_1000.txt").unwrap();

    group.bench_function("getattr_o1", |b| {
        b.iter(|| black_box(fs.getattr(black_box(target_attr.ino)).unwrap()))
    });
    group.bench_function("lookup_2k_dir", |b| {
        b.iter(|| black_box(fs.lookup(hot_attr.ino, black_box("f_1000.txt")).unwrap()))
    });
    group.bench_function("readdirplus_2000_batch64", |b| {
        b.iter(|| {
            let mut off = 0u64;
            let mut count = 0usize;
            loop {
                let batch = fs.readdirplus(hot_attr.ino, off, 64).unwrap();
                if batch.is_empty() {
                    break;
                }
                off = batch.last().unwrap().offset;
                count += batch.len();
            }
            black_box(count)
        })
    });

    // Multi-cluster Zstd (256 KiB in 64 KiB chunks) sequential 4 KiB FUSE page reads.
    let mut w_z = VzWriter::new(
        Cursor::new(Vec::new()),
        VzWriterConfig {
            default_codec: CODEC_ZSTD,
            target_cluster_size: 64 * 1024,
            multi_cluster_threshold: 64 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    let z_blob: Vec<u8> = (0usize..256 * 1024)
        .map(|i| ((i.wrapping_mul(13) ^ (i >> 5)) & 0xFF) as u8)
        .collect();
    w_z.add_file("/blob.zst", &z_blob).unwrap();
    let z_arc = w_z.finish().unwrap().into_inner();
    let z_fs = FuseVolume::mount(Arc::new(VzReader::open(z_arc).unwrap())).unwrap();
    let z_attr = z_fs.lookup(FUSE_ROOT_ID, "blob.zst").unwrap();
    let z_fh = z_fs.open(z_attr.ino).unwrap();
    group.throughput(Throughput::Bytes(256 * 1024));
    group.bench_function("read_4k_seq_256k_zstd_mc", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for page in 0..64u64 {
                let slice = z_fs.read(&z_fh, page * 4096, 4096).unwrap();
                sum += slice.len();
            }
            black_box(sum)
        })
    });

    // Uncompressed CODEC_NONE 4 KiB random VFS read (zero read-amplification).
    let mut w_none = VzWriter::new(
        Cursor::new(Vec::new()),
        VzWriterConfig {
            default_codec: CODEC_NONE,
            ..Default::default()
        },
    )
    .unwrap();
    w_none.add_file("/raw.bin", &vec![0x7Au8; 4 * 1024 * 1024]).unwrap();
    let none_arc = w_none.finish().unwrap().into_inner();
    let none_fs = FuseVolume::mount(Arc::new(VzReader::open(none_arc).unwrap())).unwrap();
    let none_attr = none_fs.lookup(FUSE_ROOT_ID, "raw.bin").unwrap();
    let none_fh = none_fs.open(none_attr.ino).unwrap();
    group.throughput(Throughput::Bytes(4096));
    group.bench_function("read_4k_rand_4m_none", |b| {
        b.iter(|| black_box(none_fs.read(&none_fh, black_box(2 * 1024 * 1024 + 4096), 4096).unwrap()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_crc32c,
    bench_levint,
    bench_boot_ecc,
    bench_rs_gf256,
    bench_archive_codecs_and_lookups,
    bench_fuse3
);
criterion_main!(benches);
