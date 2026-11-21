use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::File;
use std::hint::black_box;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use libvz::ext_meta::DictEntry;
use libvz::{
    CODEC_LZ4, CODEC_NONE, CODEC_ZSTD, CountingRangeReader, DEFAULT_BOOT_SIZE, EncryptionKey,
    EntryOptions, FUSE_ROOT_ID, FuseVolume, LsmAppendWriter, MmapRangeReader, VzPipeWriter,
    VzReader, VzReaderOptions, VzWriter, VzWriterConfig, boot_ecc_encode,
    boot_ecc_verify_and_repair, compact_archive, crc32c, crc32c_hw_active,
    encode_rs_gf256_stripe, parse_parity_cluster_body, read_levint_fast, read_levint_safe,
    recover_rs_gf256_stripe, rs_gf256_madd_slice, validate_cluster, write_levint,
};

struct TrackingAllocator;

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static CURRENT_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            let cur = CURRENT_BYTES.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK_BYTES.fetch_max(cur, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
}

fn reset_alloc_tracker() -> (u64, usize) {
    let cur = CURRENT_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(cur, Ordering::Relaxed);
    let cnt = ALLOC_COUNT.load(Ordering::Relaxed);
    (cnt, cur)
}

fn read_vm_hwm_kib() -> Option<u64> {
    let txt = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in txt.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let num = rest.split_whitespace().next()?;
            return num.parse::<u64>().ok();
        }
    }
    None
}

struct StreamGen {
    remaining: usize,
    state: u64,
}

impl Read for StreamGen {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.remaining);
        for slot in &mut buf[..n] {
            self.state = self
                .state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *slot = (self.state >> 56) as u8;
        }
        self.remaining -= n;
        Ok(n)
    }
}

struct NullSink(u64);
impl Write for NullSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn compressible_payload(seed: usize, len: usize) -> Vec<u8> {
    let pat = format!("id={seed:06};key=vz_benchmark_entry;status=ok;region=us_east_1;");
    let pb = pat.as_bytes();
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let take = (len - out.len()).min(pb.len());
        out.extend_from_slice(&pb[..take]);
    }
    out
}

fn main() {
    println!("=== VZ Multi-Metric Release Benchmark Runner ===");
    println!("crc32c_hw_active: {}", crc32c_hw_active());
    let max_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!("available_parallelism: {max_threads}");

    // 1. Primitives
    println!("\n[1] Primitive Throughput");
    for &sz in &[64usize, 4096, 65_536, 1024 * 1024, 16 * 1024 * 1024] {
        let data = vec![0xA5u8; sz];
        let iters = if sz <= 4096 {
            200_000
        } else if sz <= 65_536 {
            20_000
        } else if sz <= 1024 * 1024 {
            1_000
        } else {
            64
        };
        let t0 = Instant::now();
        for _ in 0..iters {
            black_box(crc32c(black_box(&data)));
        }
        let dt = t0.elapsed().as_secs_f64();
        let mb_s = (sz as f64 * iters as f64) / (1024.0 * 1024.0 * dt);
        let ns_op = (dt * 1e9) / iters as f64;
        println!("crc32c sz={sz}: {mb_s:.2} MB/s ({ns_op:.2} ns/op)");
    }

    let mut enc = [0u8; 8];
    let _ = write_levint(&mut enc, 123_456_789).unwrap();
    let n_vint = 10_000_000usize;
    let t0 = Instant::now();
    for _ in 0..n_vint {
        black_box(read_levint_fast(black_box(&enc)));
    }
    let dt_fast = t0.elapsed().as_secs_f64();
    let t0 = Instant::now();
    for _ in 0..n_vint {
        black_box(read_levint_safe(black_box(&enc)).unwrap());
    }
    let dt_safe = t0.elapsed().as_secs_f64();
    let t0 = Instant::now();
    for _ in 0..n_vint {
        black_box(write_levint(black_box(&mut enc), black_box(123_456_789)).unwrap());
    }
    let dt_write = t0.elapsed().as_secs_f64();
    println!(
        "read_levint_fast: {:.2} ns/op ({:.2} Mops/s)",
        dt_fast * 1e9 / n_vint as f64,
        n_vint as f64 / (dt_fast * 1e6)
    );
    println!(
        "read_levint_safe: {:.2} ns/op ({:.2} Mops/s)",
        dt_safe * 1e9 / n_vint as f64,
        n_vint as f64 / (dt_safe * 1e6)
    );
    println!(
        "write_levint: {:.2} ns/op ({:.2} Mops/s)",
        dt_write * 1e9 / n_vint as f64,
        n_vint as f64 / (dt_write * 1e6)
    );

    let mut boot = vec![0x5Au8; DEFAULT_BOOT_SIZE];
    let n_ecc = 20_000usize;
    let t0 = Instant::now();
    for _ in 0..n_ecc {
        boot_ecc_encode(black_box(&mut boot)).unwrap();
    }
    let dt_enc = t0.elapsed().as_secs_f64();
    let t0 = Instant::now();
    for _ in 0..n_ecc {
        black_box(boot_ecc_verify_and_repair(black_box(&mut boot)).unwrap());
    }
    let dt_ver = t0.elapsed().as_secs_f64();
    let t0 = Instant::now();
    for _ in 0..n_ecc {
        boot[3 * 4096 + 7] ^= 0xFF;
        black_box(boot_ecc_verify_and_repair(black_box(&mut boot)).unwrap());
    }
    let dt_rep = t0.elapsed().as_secs_f64();
    println!("boot_ecc_encode: {:.2} us/op", dt_enc * 1e6 / n_ecc as f64);
    println!(
        "boot_ecc_verify_clean: {:.2} us/op",
        dt_ver * 1e6 / n_ecc as f64
    );
    println!(
        "boot_ecc_repair_1page: {:.2} us/op",
        dt_rep * 1e6 / n_ecc as f64
    );

    let src_1m = vec![0x3Cu8; 1024 * 1024];
    let mut dst_1m = vec![0u8; 1024 * 1024];
    let n_madd = 500usize;
    let t0 = Instant::now();
    for _ in 0..n_madd {
        rs_gf256_madd_slice(black_box(&mut dst_1m), black_box(&src_1m), 0x53).unwrap();
    }
    let dt_madd = t0.elapsed().as_secs_f64();
    println!(
        "rs_gf256_madd_slice_1mib: {:.2} MB/s",
        (n_madd as f64) / dt_madd
    );

    for &(k, m) in &[(8u16, 2u16), (16u16, 4u16)] {
        let mut clusters = Vec::with_capacity(k as usize);
        let mut offsets = Vec::with_capacity(k as usize);
        let mut prev = 0u64;
        for j in 0..k {
            let plen = 1024 * 1024 - 64;
            let mut body = Vec::with_capacity(plen + 8);
            body.push(0xEC);
            let mut lb = [0u8; 8];
            let lw = write_levint(&mut lb, plen as u64).unwrap();
            body.extend_from_slice(&lb[..lw]);
            body.resize(body.len() + plen, ((j * 17 + 5) & 0xFF) as u8);
            let cl = libvz::build_cluster_from_body(&body, prev, j as u64).unwrap();
            prev = cl.len() as u64;
            offsets.push(DEFAULT_BOOT_SIZE as u64 + j as u64 * 1024 * 1024);
            clusters.push(cl);
        }
        let refs: Vec<&[u8]> = clusters.iter().map(Vec::as_slice).collect();
        let max_len = clusters.iter().map(Vec::len).max().unwrap();
        let reps = 10usize;
        let t0 = Instant::now();
        let mut last_parities = Vec::new();
        for _ in 0..reps {
            let (p, _) = encode_rs_gf256_stripe(&refs, &offsets, 0, m, k as u64, prev).unwrap();
            last_parities = p;
        }
        let dt_rs_enc = t0.elapsed().as_secs_f64();
        let parity_slots: Vec<Option<(u16, Vec<u8>)>> = last_parities
            .iter()
            .map(|p| {
                let (_, body, _) = validate_cluster(p).unwrap();
                let (man, _, pay) = parse_parity_cluster_body(body).unwrap().unwrap();
                Some((man.parity_index, pay.to_vec()))
            })
            .collect();
        let t0 = Instant::now();
        for _ in 0..reps {
            let mut dslots: Vec<Option<Vec<u8>>> = clusters.iter().map(|c| Some(c.clone())).collect();
            for s in dslots.iter_mut().take(m as usize) {
                *s = None;
            }
            black_box(
                recover_rs_gf256_stripe(&mut dslots, &parity_slots, k as usize, m as usize, max_len)
                    .unwrap(),
            );
        }
        let dt_rs_dec = t0.elapsed().as_secs_f64();
        println!(
            "RS_GF256 K={k},M={m} encode: {:.2} MB/s (data), recover ({m} erasures): {:.2} MB/s (data)",
            (k as f64 * reps as f64) / dt_rs_enc,
            (k as f64 * reps as f64) / dt_rs_dec
        );
    }

    // 2. End-to-end Archive Throughput: 10,000 small files (0..4 KiB) + 64 MiB large blob
    println!("\n[2] End-to-End Pack / Unpack Throughput");
    let small_corpus: Vec<(String, Vec<u8>)> = (0..10_000)
        .map(|i| {
            let sz = (i * 409) % 4097;
            (format!("/d_{:02}/f_{i:05}.dat", i % 50), compressible_payload(i, sz))
        })
        .collect();
    let small_raw_bytes: u64 = small_corpus.iter().map(|(_, d)| d.len() as u64).sum();
    let dict_bytes = compressible_payload(0, 16_384);
    let raw_key = EncryptionKey::Raw256([0x77u8; 32]);

    for (label, codec, dict, enc) in [
        ("CODEC_NONE", CODEC_NONE, None, None),
        ("CODEC_LZ4", CODEC_LZ4, None, None),
        ("CODEC_ZSTD", CODEC_ZSTD, None, None),
        ("ZSTD+Dict", CODEC_ZSTD, Some(1u32), None),
        ("Encrypted(Raw256)", CODEC_NONE, None, Some(raw_key.clone())),
    ] {
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
        let t0 = Instant::now();
        let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
        for (p, d) in &small_corpus {
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
        let arc = w.finish().unwrap().into_inner();
        let dt_pack = t0.elapsed().as_secs_f64();

        let t0 = Instant::now();
        let r = VzReader::open_with_options(
            arc.clone(),
            VzReaderOptions {
                encryption: enc,
                repair_boot_ecc: true,
            },
        )
        .unwrap();
        let mut total_unpacked = 0u64;
        for (p, _) in &small_corpus {
            total_unpacked += black_box(r.read_file(p).unwrap().len() as u64);
        }
        let dt_unpack = t0.elapsed().as_secs_f64();
        assert_eq!(total_unpacked, small_raw_bytes);
        println!(
            "10k small ({:.2} MiB) [{label}]: pack {:.2} MB/s ({:.0} files/s), unpack {:.2} MB/s ({:.0} files/s), arc={:.2} MiB",
            small_raw_bytes as f64 / (1024.0 * 1024.0),
            small_raw_bytes as f64 / (1024.0 * 1024.0 * dt_pack),
            10_000.0 / dt_pack,
            small_raw_bytes as f64 / (1024.0 * 1024.0 * dt_unpack),
            10_000.0 / dt_unpack,
            arc.len() as f64 / (1024.0 * 1024.0)
        );
    }

    // Large 64 MiB blob
    let blob_64m = compressible_payload(999, 64 * 1024 * 1024);
    for (label, codec, enc) in [
        ("CODEC_NONE", CODEC_NONE, None),
        ("CODEC_LZ4", CODEC_LZ4, None),
        ("CODEC_ZSTD", CODEC_ZSTD, None),
        ("Encrypted(Raw256)", CODEC_NONE, Some(raw_key.clone())),
    ] {
        let cfg = VzWriterConfig {
            default_codec: codec,
            encryption: enc.clone(),
            ..Default::default()
        };
        let t0 = Instant::now();
        let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
        w.add_file("/blob64m.bin", &blob_64m).unwrap();
        let arc = w.finish().unwrap().into_inner();
        let dt_pack = t0.elapsed().as_secs_f64();

        let t0 = Instant::now();
        let r = VzReader::open_with_options(
            arc.clone(),
            VzReaderOptions {
                encryption: enc,
                repair_boot_ecc: true,
            },
        )
        .unwrap();
        let got = r.read_file("/blob64m.bin").unwrap();
        let dt_unpack = t0.elapsed().as_secs_f64();
        assert_eq!(got.len(), blob_64m.len());
        println!(
            "64 MiB blob [{label}]: pack {:.2} MB/s, unpack {:.2} MB/s, arc={:.2} MiB",
            64.0 / dt_pack,
            64.0 / dt_unpack,
            arc.len() as f64 / (1024.0 * 1024.0)
        );
    }

    // 3 & 4. Random-Access Latency (100, 10k, 100k) + mmap vs File + readdir + LSM + HTTP Range RTTs
    println!("\n[3 & 4] Random-Access Lookup, Mmap vs File, readdir, LSM & HTTP Range RTTs");
    for &(n_files, leaf_cap, route_cap) in &[
        (100usize, 512usize, 128usize),
        (10_000, 512, 128),
        (100_000, 512, 128),
    ] {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let cfg = VzWriterConfig {
            max_leaf_entries: leaf_cap,
            max_route_entries: route_cap,
            ..Default::default()
        };
        let mut w = VzWriter::new(tmp.reopen().unwrap(), cfg).unwrap();
        for i in 0..n_files {
            w.add_file(&format!("/d_{:03}/f_{i:06}.bin", i % 100), &[0x44u8; 1024])
                .unwrap();
        }
        w.finish().unwrap();

        let f_ro = tmp.reopen().unwrap();
        let mmap = unsafe { MmapRangeReader::from_file(&f_ro) }.unwrap();
        let r_mmap = VzReader::open(mmap).unwrap();
        let r_file = VzReader::open(tmp.reopen().unwrap()).unwrap();
        let height = r_mmap.active_slot().tree_height;
        let target = format!("/d_{:03}/f_{:06}.bin", (n_files / 2) % 100, n_files / 2);

        // Cold open latency
        let n_open = 200usize;
        let t0 = Instant::now();
        for _ in 0..n_open {
            black_box(VzReader::open(tmp.reopen().unwrap()).unwrap().active_slot().generation);
        }
        let cold_us = t0.elapsed().as_secs_f64() * 1e6 / n_open as f64;

        let n_q = 2_000usize;
        let t0 = Instant::now();
        for _ in 0..n_q {
            black_box(r_mmap.stat(&target).unwrap());
        }
        let stat_mmap_us = t0.elapsed().as_secs_f64() * 1e6 / n_q as f64;

        let t0 = Instant::now();
        for _ in 0..n_q {
            black_box(r_file.stat(&target).unwrap());
        }
        let stat_file_us = t0.elapsed().as_secs_f64() * 1e6 / n_q as f64;

        let t0 = Instant::now();
        for _ in 0..n_q {
            black_box(r_mmap.read_file(&target).unwrap());
        }
        let read_mmap_us = t0.elapsed().as_secs_f64() * 1e6 / n_q as f64;

        let t0 = Instant::now();
        for _ in 0..n_q {
            black_box(r_file.read_file(&target).unwrap());
        }
        let read_file_us = t0.elapsed().as_secs_f64() * 1e6 / n_q as f64;

        // CountingRangeReader HTTP Range RTTs & Read Amplification for 1 KiB file
        let f_cnt = File::open(tmp.path()).unwrap();
        let counter = CountingRangeReader::new(f_cnt);
        let r_cnt = VzReader::open(&counter).unwrap();
        let _ = r_cnt.read_file(&target).unwrap();
        let rtts_cold = counter.reads();
        let bytes_cold = counter.bytes_read();
        let amp_cold = bytes_cold as f64 / 1024.0;
        counter.reset();
        let _ = r_cnt.read_file(&target).unwrap();
        let rtts_warm = counter.reads();
        let bytes_warm = counter.bytes_read();
        let amp_warm = bytes_warm as f64 / 1024.0;

        println!(
            "n={n_files} (h={height}): cold_open={cold_us:.2}us | stat mmap={stat_mmap_us:.2}us file={stat_file_us:.2}us | read(1KiB) mmap={read_mmap_us:.2}us file={read_file_us:.2}us | RTTs(cold/warm)={rtts_cold}/{rtts_warm} bytes={bytes_cold}/{bytes_warm} amp={amp_cold:.1}x/{amp_warm:.1}x"
        );
    }

    // readdir 10 vs 5,000 entries (owned VzStat vs zero-copy readdir_visit)
    for &dir_n in &[10usize, 5_000usize] {
        let mut w = VzWriter::new(Cursor::new(Vec::new()), VzWriterConfig::default()).unwrap();
        for i in 0..dir_n {
            w.add_file(&format!("/bigdir/entry_{i:05}.txt"), b"x").unwrap();
        }
        let arc = w.finish().unwrap().into_inner();
        let r = VzReader::open(arc).unwrap();
        let reps = if dir_n == 10 { 10_000 } else { 200 };
        let t0 = Instant::now();
        for _ in 0..reps {
            black_box(r.readdir("/bigdir").unwrap());
        }
        let us = t0.elapsed().as_secs_f64() * 1e6 / reps as f64;
        let t1 = Instant::now();
        for _ in 0..reps {
            let mut cnt = 0usize;
            r.readdir_visit("/bigdir", |item| {
                black_box(item.name);
                cnt += 1;
                Ok(())
            })
            .unwrap();
            black_box(cnt);
        }
        let us_visit = t1.elapsed().as_secs_f64() * 1e6 / reps as f64;
        println!("readdir({dir_n} entries): owned={us:.2} us/op | readdir_visit(zero-copy)={us_visit:.2} us/op");
    }

    // LSM 1, 4, 16 runs vs compacted
    let mut lsm_buf = Cursor::new(Vec::new());
    let mut w = VzWriter::new(lsm_buf, VzWriterConfig::default()).unwrap();
    for i in 0..200 {
        w.add_file(&format!("/base_{i:03}.bin"), &[1u8; 64]).unwrap();
    }
    lsm_buf = w.finish().unwrap();
    for runs_target in [1usize, 4, 16] {
        while (VzReader::open(lsm_buf.clone())
            .unwrap()
            .active_slot()
            .lsm_run_count as usize)
            < runs_target
        {
            let cur_runs = VzReader::open(lsm_buf.clone()).unwrap().active_slot().lsm_run_count;
            let mut app = LsmAppendWriter::open(lsm_buf, None, 512, 128).unwrap();
            app.add_file(&format!("/delta_{cur_runs}.bin"), &[2u8; 64])
                .unwrap();
            lsm_buf = app.finish().unwrap();
        }
        let r = VzReader::open(lsm_buf.clone()).unwrap();
        let t0 = Instant::now();
        for _ in 0..5000 {
            black_box(r.read_file("/base_100.bin").unwrap());
        }
        let us = t0.elapsed().as_secs_f64() * 1e6 / 5000.0;
        println!("LSM {runs_target} run(s) read_file(base): {us:.2} us/op");
    }
    let r16 = VzReader::open(lsm_buf).unwrap();
    let comp = compact_archive(&r16, Cursor::new(Vec::new()), VzWriterConfig::default())
        .unwrap()
        .into_inner();
    let rc = VzReader::open(comp).unwrap();
    let t0 = Instant::now();
    for _ in 0..5000 {
        black_box(rc.read_file("/base_100.bin").unwrap());
    }
    println!(
        "LSM compacted(1 run) read_file(base): {:.2} us/op",
        t0.elapsed().as_secs_f64() * 1e6 / 5000.0
    );

    // 5. Space Overhead & Alignment Efficiency
    println!("\n[5] Space Overhead & Alignment Efficiency");
    // Tiny inline (5000 x 1..27 B) vs forced external (5000 x 28 B)
    let mut w_tiny = VzWriter::new(Cursor::new(Vec::new()), VzWriterConfig::default()).unwrap();
    let mut tiny_raw = 0usize;
    for i in 0..5_000 {
        let len = 1 + (i % 27);
        tiny_raw += len;
        w_tiny
            .add_file(&format!("/t/{i:04}"), &vec![b'a'; len])
            .unwrap();
    }
    let arc_tiny = w_tiny.finish().unwrap().into_inner();
    let mut w_ext = VzWriter::new(Cursor::new(Vec::new()), VzWriterConfig::default()).unwrap();
    let mut ext_raw = 0usize;
    for i in 0..5_000 {
        ext_raw += 28;
        w_ext
            .add_file(&format!("/e/{i:04}"), &[b'a'; 28])
            .unwrap();
    }
    let arc_ext = w_ext.finish().unwrap().into_inner();
    println!(
        "5000 inline (1..27 B, raw={tiny_raw} B): arc={} B (ratio={:.3}x, data_clusters=0)",
        arc_tiny.len(),
        arc_tiny.len() as f64 / tiny_raw as f64
    );
    println!(
        "5000 external (28 B, raw={ext_raw} B): arc={} B (ratio={:.3}x)",
        arc_ext.len(),
        arc_ext.len() as f64 / ext_raw as f64
    );

    // Mixed codebase 1 KiB..64 KiB (500 files)
    let mut w_mix = VzWriter::new(Cursor::new(Vec::new()), VzWriterConfig::default()).unwrap();
    let mut mix_raw = 0usize;
    for i in 0..500 {
        let sz = 1024 + ((i * 127) % (63 * 1024));
        mix_raw += sz;
        w_mix
            .add_file(&format!("/src/m_{i:04}.rs"), &vec![(i & 0xFF) as u8; sz])
            .unwrap();
    }
    let arc_mix = w_mix.finish().unwrap().into_inner();
    println!(
        "Mixed 500x(1..64 KiB, raw={mix_raw} B): arc={} B (ratio={:.4}x, overhead={:.2}%)",
        arc_mix.len(),
        arc_mix.len() as f64 / mix_raw as f64,
        (arc_mix.len() as f64 - mix_raw as f64) * 100.0 / mix_raw as f64
    );

    // Large 16 MiB blob: no ECC vs Boot ECC vs Boot ECC + RS(8,2)
    let blob_16m = vec![0x55u8; 16 * 1024 * 1024];
    let mut w_no_ecc = VzWriter::new(
        Cursor::new(Vec::new()),
        VzWriterConfig {
            enable_boot_ecc: false,
            ..Default::default()
        },
    )
    .unwrap();
    w_no_ecc.add_file("/b.bin", &blob_16m).unwrap();
    let arc_no_ecc = w_no_ecc.finish().unwrap().into_inner();

    let mut w_ecc = VzWriter::new(Cursor::new(Vec::new()), VzWriterConfig::default()).unwrap();
    w_ecc.add_file("/b.bin", &blob_16m).unwrap();
    let arc_ecc = w_ecc.finish().unwrap().into_inner();

    let mut w_rs = VzWriter::new(
        Cursor::new(Vec::new()),
        VzWriterConfig {
            rs_parity: Some((8, 2)),
            ..Default::default()
        },
    )
    .unwrap();
    w_rs.add_file("/b.bin", &blob_16m).unwrap();
    let arc_rs = w_rs.finish().unwrap().into_inner();
    println!(
        "16 MiB blob: raw={} B | VZ(no_ecc)={} (+{:.3}%) | VZ(+BootECC)={} (+{:.3}%) | VZ(+RS 8,2)={} (+{:.2}%)",
        blob_16m.len(),
        arc_no_ecc.len(),
        (arc_no_ecc.len() - blob_16m.len()) as f64 * 100.0 / blob_16m.len() as f64,
        arc_ecc.len(),
        (arc_ecc.len() - blob_16m.len()) as f64 * 100.0 / blob_16m.len() as f64,
        arc_rs.len(),
        (arc_rs.len() - blob_16m.len()) as f64 * 100.0 / blob_16m.len() as f64,
    );

    // 6. Memory Footprint (64 MiB streaming pipe write & multi-cluster read)
    println!("\n[6] Streaming Memory Footprint (64 MiB payload, 1 MiB cluster)");
    let tmp_stream = tempfile::NamedTempFile::new().unwrap();
    let (cnt0, base0) = reset_alloc_tracker();
    {
        let mut pw = VzPipeWriter::new(
            tmp_stream.reopen().unwrap(),
            VzWriterConfig {
                target_cluster_size: 1024 * 1024,
                multi_cluster_threshold: 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        pw.add_file_reader(
            "/stream64m.bin",
            StreamGen {
                remaining: 64 * 1024 * 1024,
                state: 12345,
            },
            EntryOptions::default(),
        )
        .unwrap();
        let _ = pw.finish().unwrap();
    }
    let cnt1 = ALLOC_COUNT.load(Ordering::Relaxed);
    let peak1 = PEAK_BYTES.load(Ordering::Relaxed);
    println!(
        "64 MiB streaming pipe write: allocs={}, peak_heap_delta={:.2} MiB (baseline={:.2} MiB)",
        cnt1 - cnt0,
        peak1.saturating_sub(base0) as f64 / (1024.0 * 1024.0),
        base0 as f64 / (1024.0 * 1024.0)
    );

    let (cnt2, base2) = reset_alloc_tracker();
    {
        let r = VzReader::open(tmp_stream.reopen().unwrap()).unwrap();
        let mut sink = NullSink(0);
        r.read_file_to_writer("/stream64m.bin", &mut sink).unwrap();
        assert_eq!(sink.0, 64 * 1024 * 1024);
    }
    let cnt3 = ALLOC_COUNT.load(Ordering::Relaxed);
    let peak3 = PEAK_BYTES.load(Ordering::Relaxed);
    println!(
        "64 MiB multi-cluster stream read: allocs={}, peak_heap_delta={:.2} MiB, VmHWM={:?} KiB",
        cnt3 - cnt2,
        peak3.saturating_sub(base2) as f64 / (1024.0 * 1024.0),
        read_vm_hwm_kib()
    );

    // 7. FUSE3 VFS Surface (Mount, Zero-I/O Metadata, Chunk-Cached & Zero-Amp Reads)
    println!("\n[7] FUSE3 VFS Performance & Read Amplification");
    {
        let mut wf = VzWriter::new(
            Cursor::new(Vec::new()),
            VzWriterConfig {
                default_codec: CODEC_ZSTD,
                target_cluster_size: 64 * 1024,
                multi_cluster_threshold: 64 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        wf.add_dir("/hot", 0o755, 0).unwrap();
        for d in 0..30 {
            wf.add_dir(&format!("/d_{d:02}"), 0o755, 0).unwrap();
        }
        for i in 0..5_000 {
            let p = if i < 2_000 {
                format!("/hot/f_{i:04}.txt")
            } else {
                format!("/d_{:02}/f_{i:04}.txt", i % 30)
            };
            wf.add_file(&p, b"fuse3-meta-entry").unwrap();
        }
        let z_blob = compressible_payload(7, 256 * 1024);
        wf.add_file("/big_zst.bin", &z_blob).unwrap();
        wf.add_file_with_options(
            "/raw_1m.bin",
            &vec![0x42u8; 1024 * 1024],
            EntryOptions {
                codec: Some(CODEC_NONE),
                ..Default::default()
            },
        )
        .unwrap();
        wf.add_sparse_file(
            "/sparse.dat",
            2 * 1024 * 1024,
            &[(0, b"HEAD"), (1536 * 1024, b"TAIL")],
            EntryOptions::default(),
        )
        .unwrap();
        let fuse_arc = wf.finish().unwrap().into_inner();
        let fuse_reader = Arc::new(VzReader::open(CountingRangeReader::new(fuse_arc)).unwrap());

        let t0 = Instant::now();
        for _ in 0..10 {
            black_box(FuseVolume::mount(Arc::clone(&fuse_reader)).unwrap());
        }
        let mount_ms = t0.elapsed().as_secs_f64() * 1000.0 / 10.0;
        let fs = FuseVolume::mount(Arc::clone(&fuse_reader)).unwrap();
        fs.reader().reader().reset();

        let hot = fs.lookup(FUSE_ROOT_ID, "hot").unwrap();
        let f_target = fs.lookup(hot.ino, "f_1000.txt").unwrap();

        let t_ga = Instant::now();
        for _ in 0..1_000_000 {
            black_box(fs.getattr(f_target.ino).unwrap());
        }
        let ga_ns = t_ga.elapsed().as_secs_f64() * 1e9 / 1_000_000.0;

        let t_lu = Instant::now();
        for _ in 0..200_000 {
            black_box(fs.lookup(hot.ino, "f_1000.txt").unwrap());
        }
        let lu_ns = t_lu.elapsed().as_secs_f64() * 1e9 / 200_000.0;

        let t_rdp = Instant::now();
        for _ in 0..500 {
            let mut off = 0u64;
            let mut cnt = 0usize;
            loop {
                let batch = fs.readdirplus(hot.ino, off, 64).unwrap();
                if batch.is_empty() {
                    break;
                }
                off = batch.last().unwrap().offset;
                cnt += batch.len();
            }
            black_box(cnt);
        }
        let rdp_us = t_rdp.elapsed().as_secs_f64() * 1e6 / 500.0;
        let meta_reads = fs.reader().reader().reads();

        // Sequential 64 x 4 KiB VFS reads across 256 KiB compressed multi-cluster (4 x 64 KiB chunks)
        let bz_attr = fs.lookup(FUSE_ROOT_ID, "big_zst.bin").unwrap();
        let bz_fh = fs.open(bz_attr.ino).unwrap();
        fs.reader().reader().reset();
        let t_mc = Instant::now();
        for page in 0..64u64 {
            black_box(fs.read(&bz_fh, page * 4096, 4096).unwrap());
        }
        let mc_us = t_mc.elapsed().as_secs_f64() * 1e6;
        let mc_reads = fs.reader().reader().reads();
        let mc_bytes = fs.reader().reader().bytes_read();

        // Zero read-amplification 4 KiB CODEC_NONE read
        let raw_attr = fs.lookup(FUSE_ROOT_ID, "raw_1m.bin").unwrap();
        let raw_fh = fs.open(raw_attr.ino).unwrap();
        fs.reader().reader().reset();
        let t_none = Instant::now();
        for _ in 0..10_000 {
            black_box(fs.read(&raw_fh, 524_288, 4096).unwrap());
        }
        let none_us = t_none.elapsed().as_secs_f64() * 1e6 / 10_000.0;
        let none_reads_per_op = fs.reader().reader().reads() / 10_000;
        let none_bytes_per_op = fs.reader().reader().bytes_read() / 10_000;

        // Zero-I/O sparse hole read
        let sp_attr = fs.lookup(FUSE_ROOT_ID, "sparse.dat").unwrap();
        let sp_fh = fs.open(sp_attr.ino).unwrap();
        fs.reader().reader().reset();
        let hole = fs.read(&sp_fh, 512 * 1024, 4096).unwrap();
        assert_eq!(hole.len(), 4096);
        let hole_reads = fs.reader().reader().reads();
        let hole_bytes = fs.reader().reader().bytes_read();

        println!(
            "FuseVolume::mount (5,003 entries): {mount_ms:.2} ms | meta reads after mount = {meta_reads}"
        );
        println!(
            "getattr (O(1)): {ga_ns:.1} ns/op ({:.1} Mops/s) | lookup (2k dir): {lu_ns:.1} ns/op ({:.2} Mops/s)",
            1000.0 / ga_ns,
            1000.0 / lu_ns
        );
        println!(
            "readdirplus (2,000 entries, batch=64): {rdp_us:.2} us/scan (0 disk I/O)"
        );
        println!(
            "64x4 KiB seq VFS reads (256 KiB Zstd MC, 64 KiB chunks): {mc_us:.2} us total ({:.2} us/page) | reads={mc_reads}, bytes={mc_bytes}",
            mc_us / 64.0
        );
        println!(
            "4 KiB random VFS read (1 MiB CODEC_NONE): {none_us:.2} us/op | reads/op={none_reads_per_op}, bytes/op={none_bytes_per_op} ({:.2}x amp)",
            none_bytes_per_op as f64 / 4096.0
        );
        println!(
            "4 KiB sparse hole read: reads={hole_reads}, bytes={hole_bytes} (zero-I/O fast path)"
        );
    }

    // 8. Multi-Threaded Random I/O Scaling (1T vs max_threads)
    println!(
        "\n[8] Multi-Threaded Random I/O Scaling (10,000 files, 1T vs {max_threads}T)"
    );
    {
        fn bench_reader_iops<R: libvz::RangeReader + Send + Sync>(
            reader: &Arc<VzReader<R>>,
            paths: &[String],
            threads: usize,
            total_ops: usize,
        ) -> f64 {
            let ops_per_thread = (total_ops / threads).max(1);
            let t0 = Instant::now();
            std::thread::scope(|s| {
                for tid in 0..threads {
                    let vr = Arc::clone(reader);
                    s.spawn(move || {
                        let mut state =
                            0x9E37_79B9_7F4A_7C15u64 ^ ((tid as u64 + 1) * 0xBF58_476D_1CE4_E5B9);
                        let mut scratch = Vec::with_capacity(8192);
                        for _ in 0..ops_per_thread {
                            state ^= state << 13;
                            state ^= state >> 7;
                            state ^= state << 17;
                            let idx = (state as usize) % paths.len();
                            vr.read_file_into(&paths[idx], &mut scratch).unwrap();
                            black_box(scratch.len());
                        }
                    });
                }
            });
            (ops_per_thread * threads) as f64 / t0.elapsed().as_secs_f64()
        }

        let mut paths_10k = Vec::with_capacity(10_000);
        let mut blobs_10k = Vec::with_capacity(10_000);
        for i in 0..10_000 {
            paths_10k.push(format!("/scale/{:02}/f_{i:05}.bin", i % 64));
            blobs_10k.push(compressible_payload(i, 256 + ((i * 97) % 3840)));
        }

        let max_ops = (max_threads * 5_000).max(30_000);
        for (label, codec) in [
            ("None", CODEC_NONE),
            ("LZ4 ", CODEC_LZ4),
            ("Zstd", CODEC_ZSTD),
        ] {
            let tf = tempfile::NamedTempFile::new().unwrap();
            {
                let mut w = VzWriter::new(
                    tf.reopen().unwrap(),
                    VzWriterConfig {
                        default_codec: codec,
                        ..Default::default()
                    },
                )
                .unwrap();
                let batch_opts = EntryOptions::default();
                let batch: Vec<(&str, &[u8], &EntryOptions)> = paths_10k
                    .iter()
                    .zip(blobs_10k.iter())
                    .map(|(p, b)| (p.as_str(), b.as_slice(), &batch_opts))
                    .collect();
                w.add_files_batch(&batch).unwrap();
                w.finish().unwrap();
            }

            let file_reader = Arc::new(VzReader::open(tf.reopen().unwrap()).unwrap());
            let mmap = unsafe { MmapRangeReader::from_file(&tf.reopen().unwrap()).unwrap() };
            let mmap_reader = Arc::new(VzReader::open(mmap).unwrap());

            let f1 = bench_reader_iops(&file_reader, &paths_10k, 1, 10_000);
            let m1 = bench_reader_iops(&mmap_reader, &paths_10k, 1, 10_000);
            if max_threads > 1 {
                let fm = bench_reader_iops(&file_reader, &paths_10k, max_threads, max_ops);
                let mm = bench_reader_iops(&mmap_reader, &paths_10k, max_threads, max_ops);
                println!(
                    "VZ {label}: File 1T={f1:.0} -> {max_threads}T={fm:.0} IOPS ({:.2}x) | Mmap 1T={m1:.0} -> {max_threads}T={mm:.0} IOPS ({:.2}x)",
                    fm / f1.max(1.0),
                    mm / m1.max(1.0)
                );
            } else {
                println!("VZ {label}: File 1T={f1:.0} IOPS | Mmap 1T={m1:.0} IOPS");
            }
        }
    }
}
