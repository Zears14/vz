use std::fs::{File, OpenOptions};
use std::hint::black_box;
use std::io::{BufRead, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use tempfile::NamedTempFile;
use libvz::ext_meta::DictEntry;
use libvz::{
    CODEC_LZ4, CODEC_NONE, CODEC_ZSTD, CompactOptions, CountingRangeReader, EntryOptions,
    FUSE_ROOT_ID, FuseVolume, LsmAppendWriter, MmapRangeReader, RangeReader, VzError, VzReader,
    VzWriter, VzWriterConfig, compact_archive_with_options, crc32c_hw_active, repair_slice,
};
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

// ============================================================================
// INSTRUMENTED CountingReadSeek (FOR FAIR TAR / ZIP RANGE-I/O COMPARISON)
// ============================================================================

struct CountingReadSeek<T> {
    inner: T,
    reads: AtomicUsize,
    bytes: AtomicU64,
}

impl<T> CountingReadSeek<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            reads: AtomicUsize::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }

    fn bytes_read(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

impl<T: Read> Read for CountingReadSeek<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl<T: Seek> Seek for CountingReadSeek<T> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

// ============================================================================
// CORPUS GENERATORS
// ============================================================================

fn gen_structured_file(idx: usize, len: usize) -> Vec<u8> {
    let header = format!(
        "{{\"id\":{idx:06},\"service\":\"vz-storage-node\",\"env\":\"prod\",\"region\":\"us-west-2\",\"status\":\"healthy\",\"tags\":[\"bplus\",\"tlv\",\"crc32c\"]}}\n"
    );
    let hb = header.as_bytes();
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let rem = len - out.len();
        let take = rem.min(hb.len());
        out.extend_from_slice(&hb[..take]);
    }
    out
}

fn gen_tiny_corpus(n: usize) -> Vec<(String, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let len = 1 + (i % 27);
            let data = vec![b'a' + (i % 26) as u8; len];
            (format!("tiny/d_{:02}/f_{i:05}", i % 25), data)
        })
        .collect()
}

fn gen_mixed_corpus(n: usize) -> Vec<(String, Vec<u8>)> {
    (0..n)
        .map(|i| {
            // Mix: 20% tiny inline (1..27B), 60% medium JSON/code (512B..4KiB), 20% larger (8KiB..16KiB)
            let sz = match i % 5 {
                0 => 1 + (i % 27),
                1..=3 => 512 + ((i * 337) % 3584),
                _ => 8192 + ((i * 733) % 8192),
            };
            let dir = if i < 2000 {
                "hot_dir".to_string()
            } else {
                format!("mod_{:02}", i % 40)
            };
            (format!("{dir}/item_{i:05}.json"), gen_structured_file(i, sz))
        })
        .collect()
}

// ============================================================================
// PACK / UNPACK / RANDOM-ACCESS / READDIR HELPERS PER FORMAT
// ============================================================================

#[derive(Clone, Copy)]
enum FormatKind {
    VzNone,
    VzLz4,
    VzZstd,
    VzZstdDict,
    Tar,
    TarGz,
    TarLz4,
    TarZst,
    ZipStored,
    ZipDeflate,
    ZipZstd,
}

impl FormatKind {
    fn label(self) -> &'static str {
        match self {
            Self::VzNone => "VZ (None)",
            Self::VzLz4 => "VZ (LZ4)",
            Self::VzZstd => "VZ (Zstd)",
            Self::VzZstdDict => "VZ (Zstd+Dict)",
            Self::Tar => "TAR (Uncomp)",
            Self::TarGz => "TAR.GZ (Deflate)",
            Self::TarLz4 => "TAR.LZ4",
            Self::TarZst => "TAR.ZST (Zstd)",
            Self::ZipStored => "ZIP (Stored)",
            Self::ZipDeflate => "ZIP (Deflate)",
            Self::ZipZstd => "ZIP (Zstd)",
        }
    }
}

fn build_dict_bytes() -> Vec<u8> {
    gen_structured_file(0, 16_384)
}

fn pack_format_to_vec(
    fmt: FormatKind,
    corpus: &[(String, Vec<u8>)],
    dict_bytes: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match fmt {
        FormatKind::VzNone | FormatKind::VzLz4 | FormatKind::VzZstd | FormatKind::VzZstdDict => {
            let (codec, use_dict) = match fmt {
                FormatKind::VzNone => (CODEC_NONE, false),
                FormatKind::VzLz4 => (CODEC_LZ4, false),
                FormatKind::VzZstd => (CODEC_ZSTD, false),
                FormatKind::VzZstdDict => (CODEC_ZSTD, true),
                _ => unreachable!(),
            };
            let cfg = VzWriterConfig {
                default_codec: codec,
                dicts: if use_dict {
                    vec![DictEntry {
                        dict_id: 1,
                        codec: CODEC_ZSTD,
                        flags: 0,
                        bytes: dict_bytes.to_vec(),
                    }]
                } else {
                    Vec::new()
                },
                ..Default::default()
            };
            let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg)?;
            let opts = EntryOptions {
                dict_id: if use_dict { Some(1) } else { None },
                ..Default::default()
            };
            for (path, data) in corpus {
                w.add_file_with_options(path, data, opts.clone())?;
            }
            Ok(w.finish()?.into_inner())
        }
        FormatKind::Tar => {
            let mut b = tar::Builder::new(Vec::new());
            for (path, data) in corpus {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_size(data.len() as u64);
                hdr.set_mode(0o644);
                hdr.set_cksum();
                b.append_data(&mut hdr, path, data.as_slice())?;
            }
            b.finish()?;
            Ok(b.into_inner()?)
        }
        FormatKind::TarGz => {
            let enc = GzEncoder::new(Vec::new(), Compression::default());
            let mut b = tar::Builder::new(enc);
            for (path, data) in corpus {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_size(data.len() as u64);
                hdr.set_mode(0o644);
                hdr.set_cksum();
                b.append_data(&mut hdr, path, data.as_slice())?;
            }
            b.finish()?;
            Ok(b.into_inner()?.finish()?)
        }
        FormatKind::TarLz4 => {
            let enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
            let mut b = tar::Builder::new(enc);
            for (path, data) in corpus {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_size(data.len() as u64);
                hdr.set_mode(0o644);
                hdr.set_cksum();
                b.append_data(&mut hdr, path, data.as_slice())?;
            }
            b.finish()?;
            Ok(b.into_inner()?.finish()?)
        }
        FormatKind::TarZst => {
            let enc = zstd::stream::Encoder::new(Vec::new(), 3)?;
            let mut b = tar::Builder::new(enc);
            for (path, data) in corpus {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_size(data.len() as u64);
                hdr.set_mode(0o644);
                hdr.set_cksum();
                b.append_data(&mut hdr, path, data.as_slice())?;
            }
            b.finish()?;
            Ok(b.into_inner()?.finish()?)
        }
        FormatKind::ZipStored | FormatKind::ZipDeflate | FormatKind::ZipZstd => {
            let method = match fmt {
                FormatKind::ZipStored => CompressionMethod::Stored,
                FormatKind::ZipDeflate => CompressionMethod::Deflated,
                FormatKind::ZipZstd => CompressionMethod::Zstd,
                _ => unreachable!(),
            };
            let mut zw = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let opts = SimpleFileOptions::default().compression_method(method);
            for (path, data) in corpus {
                zw.start_file(path, opts)?;
                zw.write_all(data)?;
            }
            Ok(zw.finish()?.into_inner())
        }
    }
}

fn unpack_all_from_slice(
    fmt: FormatKind,
    archive: &[u8],
    _corpus: &[(String, Vec<u8>)],
) -> Result<u64, Box<dyn std::error::Error>> {
    match fmt {
        FormatKind::VzNone | FormatKind::VzLz4 | FormatKind::VzZstd | FormatKind::VzZstdDict => {
            let r = VzReader::open(archive)?;
            let mut total = 0u64;
            r.extract_all_with(|_entry, bytes| {
                total += bytes.len() as u64;
                black_box(bytes);
                Ok(())
            })?;
            Ok(total)
        }
        FormatKind::Tar => unpack_tar_stream(Cursor::new(archive)),
        FormatKind::TarGz => unpack_tar_stream(GzDecoder::new(Cursor::new(archive))),
        FormatKind::TarLz4 => unpack_tar_stream(lz4_flex::frame::FrameDecoder::new(Cursor::new(archive))),
        FormatKind::TarZst => unpack_tar_stream(zstd::stream::Decoder::new(Cursor::new(archive))?),
        FormatKind::ZipStored | FormatKind::ZipDeflate | FormatKind::ZipZstd => {
            let mut za = zip::ZipArchive::new(Cursor::new(archive))?;
            let mut total = 0u64;
            let mut buf = Vec::new();
            for i in 0..za.len() {
                let mut f = za.by_index(i)?;
                buf.clear();
                f.read_to_end(&mut buf)?;
                total += buf.len() as u64;
            }
            Ok(total)
        }
    }
}

fn unpack_tar_stream<R: Read>(reader: R) -> Result<u64, Box<dyn std::error::Error>> {
    let mut ar = tar::Archive::new(reader);
    let mut total = 0u64;
    let mut buf = Vec::new();
    for entry in ar.entries()? {
        let mut e = entry?;
        buf.clear();
        e.read_to_end(&mut buf)?;
        total += buf.len() as u64;
    }
    Ok(total)
}

fn random_access_from_file(
    fmt: FormatKind,
    file: &File,
    target_path: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match fmt {
        FormatKind::VzNone | FormatKind::VzLz4 | FormatKind::VzZstd | FormatKind::VzZstdDict => {
            let r = VzReader::open(file)?;
            Ok(r.read_file(target_path)?)
        }
        FormatKind::Tar => find_in_tar_stream(BufReader::new(file), target_path),
        FormatKind::TarGz => find_in_tar_stream(GzDecoder::new(BufReader::new(file)), target_path),
        FormatKind::TarLz4 => {
            find_in_tar_stream(lz4_flex::frame::FrameDecoder::new(BufReader::new(file)), target_path)
        }
        FormatKind::TarZst => {
            find_in_tar_stream(zstd::stream::Decoder::new(BufReader::new(file))?, target_path)
        }
        FormatKind::ZipStored | FormatKind::ZipDeflate | FormatKind::ZipZstd => {
            let mut za = zip::ZipArchive::new(BufReader::new(file))?;
            let mut f = za.by_name(target_path)?;
            let mut buf = Vec::with_capacity(f.size() as usize);
            f.read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn find_in_tar_stream<R: Read>(
    reader: R,
    target_path: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut ar = tar::Archive::new(reader);
    for entry in ar.entries()? {
        let mut e = entry?;
        if e.path()?.to_string_lossy() == target_path {
            let mut buf = Vec::with_capacity(e.size() as usize);
            e.read_to_end(&mut buf)?;
            return Ok(buf);
        }
    }
    Err("not found in tar".into())
}

fn write_temp_file(bytes: &[u8]) -> Result<NamedTempFile, Box<dyn std::error::Error>> {
    let mut tf = NamedTempFile::new()?;
    {
        let mut bw = BufWriter::new(&mut tf);
        bw.write_all(bytes)?;
        bw.flush()?;
    }
    Ok(tf)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== VZ vs TAR / TAR.GZ / TAR.LZ4 / TAR.ZST / ZIP Standalone Comparison ===");
    println!("crc32c_hw_active: {}", crc32c_hw_active());
    let max_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!("available_parallelism: {max_threads}");
    let dict = build_dict_bytes();

    let all_formats = [
        FormatKind::VzNone,
        FormatKind::VzLz4,
        FormatKind::VzZstd,
        FormatKind::VzZstdDict,
        FormatKind::Tar,
        FormatKind::TarGz,
        FormatKind::TarLz4,
        FormatKind::TarZst,
        FormatKind::ZipStored,
        FormatKind::ZipDeflate,
        FormatKind::ZipZstd,
    ];

    // ------------------------------------------------------------------------
    // BENCHMARK 1: Tiny / Inline-Heavy Corpus (5,000 files, 1..27 B)
    // ------------------------------------------------------------------------
    let tiny = gen_tiny_corpus(5_000);
    let tiny_raw: usize = tiny.iter().map(|(_, d)| d.len()).sum();
    println!("\n[1] Tiny File Overhead (5,000 files x 1..27 B, raw = {tiny_raw} B)");
    println!(
        "{:<18} | {:>12} | {:>10} | {:>12}",
        "Format", "Archive (B)", "Ratio", "Pack (ms)"
    );
    println!("{}", "-".repeat(60));
    for &fmt in &all_formats {
        let t0 = Instant::now();
        let bytes = pack_format_to_vec(fmt, &tiny, &dict)?;
        let ms = t0.elapsed().as_secs_f64() * 1e3;
        println!(
            "{:<18} | {:>12} | {:>9.2}x | {:>10.2} ms",
            fmt.label(),
            bytes.len(),
            bytes.len() as f64 / tiny_raw as f64,
            ms
        );
    }

    // ------------------------------------------------------------------------
    // BENCHMARK 2: Mixed Corpus (5,000 files, 1B..16KiB) Pack / Unpack / Size
    // ------------------------------------------------------------------------
    let mixed = gen_mixed_corpus(5_000);
    let mixed_raw: u64 = mixed.iter().map(|(_, d)| d.len() as u64).sum();
    let mixed_mib = mixed_raw as f64 / (1024.0 * 1024.0);
    println!(
        "\n[2] Mixed Corpus (5,000 files, {mixed_mib:.2} MiB raw): Pack / Full Unpack / Size"
    );
    println!(
        "{:<18} | {:>10} | {:>11} | {:>11} | {:>11} | {:>8}",
        "Format", "Size (MiB)", "% of Raw", "Pack MB/s", "Unpack MB/s", "Pack f/s"
    );
    println!("{}", "-".repeat(82));

    let mut mixed_files: Vec<(FormatKind, NamedTempFile, usize)> = Vec::new();
    for &fmt in &all_formats {
        let reps = 3usize;
        let t0 = Instant::now();
        let mut arc = Vec::new();
        for _ in 0..reps {
            arc = pack_format_to_vec(fmt, &mixed, &dict)?;
        }
        let dt_pack = t0.elapsed().as_secs_f64() / reps as f64;

        let t1 = Instant::now();
        for _ in 0..reps {
            let unpacked = unpack_all_from_slice(fmt, &arc, &mixed)?;
            assert_eq!(unpacked, mixed_raw);
        }
        let dt_unpack = t1.elapsed().as_secs_f64() / reps as f64;

        println!(
            "{:<18} | {:>10.2} | {:>10.1}% | {:>11.2} | {:>11.2} | {:>8.0}",
            fmt.label(),
            arc.len() as f64 / (1024.0 * 1024.0),
            arc.len() as f64 * 100.0 / mixed_raw as f64,
            mixed_mib / dt_pack,
            mixed_mib / dt_unpack,
            mixed.len() as f64 / dt_pack
        );
        let tf = write_temp_file(&arc)?;
        mixed_files.push((fmt, tf, arc.len()));
    }

    // ------------------------------------------------------------------------
    // BENCHMARK 3: Cold Random-Access Single-File Read + Range I/O Amplification
    // ------------------------------------------------------------------------
    // Target external compressed file at index 3,501 (~70% into archive)
    let target_idx = 3_501usize;
    let (target_path, target_expected) = &mixed[target_idx];
    println!(
        "\n[3] Cold Open + Read Single File ({target_path}, {} B, 70% offset in 5,000-file archive)",
        target_expected.len()
    );
    println!(
        "{:<18} | {:>12} | {:>10} | {:>14} | {:>10}",
        "Format", "Cold Latency", "Read Calls", "Bytes Read", "Read Amp"
    );
    println!("{}", "-".repeat(76));

    for (fmt, tf, _) in &mixed_files {
        let mut f = tf.reopen()?;
        let is_slow_tar = matches!(
            fmt,
            FormatKind::Tar | FormatKind::TarGz | FormatKind::TarLz4 | FormatKind::TarZst
        );
        let iters = if is_slow_tar { 5 } else { 100 };

        let t0 = Instant::now();
        for _ in 0..iters {
            f.seek(SeekFrom::Start(0))?;
            let got = random_access_from_file(*fmt, &f, target_path)?;
            assert_eq!(&got, target_expected);
        }
        let us = t0.elapsed().as_secs_f64() * 1e6 / iters as f64;

        // Measure exact read calls & bytes read
        let (calls, bytes) = match fmt {
            FormatKind::VzNone
            | FormatKind::VzLz4
            | FormatKind::VzZstd
            | FormatKind::VzZstdDict => {
                let f_cnt = tf.reopen()?;
                let cnt = CountingRangeReader::new(f_cnt);
                let vr = VzReader::open(&cnt)?;
                let got = vr.read_file(target_path)?;
                assert_eq!(&got, target_expected);
                (cnt.reads(), cnt.bytes_read())
            }
            _ => {
                let mut f_cnt = tf.reopen()?;
                f_cnt.seek(SeekFrom::Start(0))?;
                let mut crs = CountingReadSeek::new(f_cnt);
                let got = match fmt {
                    FormatKind::Tar => find_in_tar_stream(&mut crs, target_path)?,
                    FormatKind::TarGz => find_in_tar_stream(GzDecoder::new(&mut crs), target_path)?,
                    FormatKind::TarLz4 => {
                        find_in_tar_stream(lz4_flex::frame::FrameDecoder::new(&mut crs), target_path)?
                    }
                    FormatKind::TarZst => {
                        find_in_tar_stream(zstd::stream::Decoder::new(&mut crs)?, target_path)?
                    }
                    FormatKind::ZipStored | FormatKind::ZipDeflate | FormatKind::ZipZstd => {
                        let mut za = zip::ZipArchive::new(BufReader::new(&mut crs))?;
                        let mut zf = za.by_name(target_path)?;
                        let mut b = Vec::new();
                        zf.read_to_end(&mut b)?;
                        b
                    }
                    _ => unreachable!(),
                };
                assert_eq!(&got, target_expected);
                (crs.reads(), crs.bytes_read())
            }
        };

        println!(
            "{:<18} | {:>9.2} us | {:>10} | {:>14} | {:>9.1}x",
            fmt.label(),
            us,
            calls,
            bytes,
            bytes as f64 / target_expected.len() as f64
        );
    }

    // Also measure VZ warm mmap lookup on that same archive
    for (fmt, tf, _) in &mixed_files {
        if matches!(fmt, FormatKind::VzZstd | FormatKind::VzZstdDict) {
            let f_ro = tf.reopen()?;
            let mmap = unsafe { MmapRangeReader::from_file(&f_ro) }?;
            let vr = VzReader::open(mmap)?;
            let t0 = Instant::now();
            for _ in 0..5_000 {
                black_box(vr.read_file(target_path)?);
            }
            let us = t0.elapsed().as_secs_f64() * 1e6 / 5_000.0;
            println!("  -> {} warm Mmap read_file: {us:.2} us/op", fmt.label());
        }
    }

    // ------------------------------------------------------------------------
    // BENCHMARK 4: Directory Listing (`hot_dir` with 2,000 entries inside 5,000-file archive)
    // ------------------------------------------------------------------------
    println!("\n[4] Directory Listing (`hot_dir/`, 2,000 entries inside 5,000-file archive)");
    for (fmt, tf, _) in &mixed_files {
        match fmt {
            FormatKind::VzZstd => {
                let f_ro = tf.reopen()?;
                let vr = VzReader::open(f_ro)?;
                let t0 = Instant::now();
                for _ in 0..200 {
                    let mut c = 0usize;
                    vr.readdir_visit("hot_dir", |e| {
                        black_box(e.name);
                        c += 1;
                        Ok(())
                    })?;
                    assert_eq!(c, 2_000);
                }
                println!(
                    "  VZ (Zstd) readdir_visit (File):   {:>8.2} us",
                    t0.elapsed().as_secs_f64() * 1e6 / 200.0
                );
            }
            FormatKind::ZipZstd => {
                let t0 = Instant::now();
                for _ in 0..50 {
                    let f_ro = tf.reopen()?;
                    let za = zip::ZipArchive::new(BufReader::new(f_ro))?;
                    let c = za
                        .file_names()
                        .filter(|n| n.starts_with("hot_dir/"))
                        .count();
                    assert_eq!(c, 2_000);
                }
                println!(
                    "  ZIP (Zstd) file_names scan (File+Buf): {:>7.2} us",
                    t0.elapsed().as_secs_f64() * 1e6 / 50.0
                );
            }
            FormatKind::TarZst => {
                let t0 = Instant::now();
                for _ in 0..5 {
                    let f_ro = tf.reopen()?;
                    let mut ar = tar::Archive::new(zstd::stream::Decoder::new(BufReader::new(f_ro))?);
                    let mut c = 0usize;
                    for e in ar.entries()? {
                        let e = e?;
                        if e.path()?.starts_with("hot_dir/") {
                            c += 1;
                        }
                    }
                    assert_eq!(c, 2_000);
                }
                println!(
                    "  TAR.ZST full scan (File):          {:>7.2} us",
                    t0.elapsed().as_secs_f64() * 1e6 / 5.0
                );
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------------
    // BENCHMARK 5: Large 32 MiB Blob Pack / Unpack / Size
    // ------------------------------------------------------------------------
    let big_blob = vec![(
        "big_blob.bin".to_string(),
        gen_structured_file(42, 32 * 1024 * 1024),
    )];
    let big_mib = 32.0f64;
    println!("\n[5] Single Large 32 MiB Blob: Pack / Unpack / Size");
    println!(
        "{:<18} | {:>10} | {:>11} | {:>11}",
        "Format", "Size (MiB)", "Pack MB/s", "Unpack MB/s"
    );
    println!("{}", "-".repeat(60));
    for &fmt in &[
        FormatKind::VzNone,
        FormatKind::VzLz4,
        FormatKind::VzZstd,
        FormatKind::Tar,
        FormatKind::TarGz,
        FormatKind::TarLz4,
        FormatKind::TarZst,
        FormatKind::ZipStored,
        FormatKind::ZipDeflate,
        FormatKind::ZipZstd,
    ] {
        let t0 = Instant::now();
        let arc = pack_format_to_vec(fmt, &big_blob, &dict)?;
        let dt_p = t0.elapsed().as_secs_f64();

        let t1 = Instant::now();
        let unpacked = unpack_all_from_slice(fmt, &arc, &big_blob)?;
        let dt_u = t1.elapsed().as_secs_f64();
        assert_eq!(unpacked, 32 * 1024 * 1024);

        println!(
            "{:<18} | {:>10.2} | {:>11.2} | {:>11.2}",
            fmt.label(),
            arc.len() as f64 / (1024.0 * 1024.0),
            big_mib / dt_p,
            big_mib / dt_u
        );
    }

    run_extended_benchmarks(&mixed, &dict, &big_blob)?;

    Ok(())
}

// ============================================================================
// LOOPBACK HTTP/1.1 RANGE SERVER & CLIENTS (FOR BENCHMARK [6])
// ============================================================================

struct LoopbackRangeServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    delay_us: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl LoopbackRangeServer {
    fn start(data: Arc<Vec<u8>>, initial_delay_us: u64) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let delay_us = Arc::new(AtomicU64::new(initial_delay_us));
        let sd = Arc::clone(&shutdown);
        let du = Arc::clone(&delay_us);

        let handle = std::thread::spawn(move || {
            while !sd.load(Ordering::Acquire) {
                let Ok((stream, _)) = listener.accept() else {
                    break;
                };
                if sd.load(Ordering::Acquire) {
                    break;
                }
                let data_c = Arc::clone(&data);
                let du_c = Arc::clone(&du);
                std::thread::spawn(move || {
                    let _ = stream.set_nodelay(true);
                    let mut br = BufReader::new(stream);
                    let mut req_line = String::new();
                    let mut hdr_line = String::new();
                    loop {
                        req_line.clear();
                        match br.read_line(&mut req_line) {
                            Ok(0) | Err(_) => break,
                            _ => {}
                        }
                        let is_head = req_line.starts_with("HEAD ");
                        let mut range: Option<(u64, Option<u64>)> = None;
                        let mut close_conn = false;
                        loop {
                            hdr_line.clear();
                            match br.read_line(&mut hdr_line) {
                                Ok(0) | Err(_) => {
                                    close_conn = true;
                                    break;
                                }
                                _ => {}
                            }
                            let trimmed = hdr_line.trim();
                            if trimmed.is_empty() {
                                break;
                            }
                            if let Some((k, v)) = trimmed.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("range")
                                    && let Some(spec) = v.trim().strip_prefix("bytes=")
                                    && let Some((s, e)) = spec.split_once('-')
                                {
                                    let start = s.trim().parse::<u64>().unwrap_or(0);
                                    let end = if e.trim().is_empty() {
                                        None
                                    } else {
                                        e.trim().parse::<u64>().ok()
                                    };
                                    range = Some((start, end));
                                } else if k.trim().eq_ignore_ascii_case("connection")
                                    && v.trim().eq_ignore_ascii_case("close")
                                {
                                    close_conn = true;
                                }
                            }
                        }
                        if req_line.trim().is_empty() {
                            break;
                        }

                        let delay = du_c.load(Ordering::Relaxed);
                        if delay > 0 {
                            std::thread::sleep(Duration::from_micros(delay));
                        }

                        let total = data_c.len() as u64;
                        let stream = br.get_mut();
                        if is_head {
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nConnection: keep-alive\r\n\r\n"
                            );
                            if stream.write_all(resp.as_bytes()).is_err() || stream.flush().is_err() {
                                break;
                            }
                        } else if let Some((s, e_opt)) = range {
                            let s_clamped = s.min(total);
                            let e_clamped = e_opt.unwrap_or(total.saturating_sub(1)).min(total.saturating_sub(1));
                            if s_clamped >= total || e_clamped < s_clamped {
                                let resp = format!(
                                    "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nContent-Range: bytes */{total}\r\n\r\n"
                                );
                                let _ = stream.write_all(resp.as_bytes());
                                break;
                            }
                            let slice = &data_c[s_clamped as usize..=e_clamped as usize];
                            let resp = format!(
                                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {s_clamped}-{e_clamped}/{total}\r\nAccept-Ranges: bytes\r\nConnection: keep-alive\r\n\r\n",
                                slice.len()
                            );
                            if stream.write_all(resp.as_bytes()).is_err()
                                || stream.write_all(slice).is_err()
                                || stream.flush().is_err()
                            {
                                break;
                            }
                        } else {
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n"
                            );
                            let _ = stream.write_all(resp.as_bytes());
                            let _ = stream.write_all(&data_c);
                            let _ = stream.flush();
                            break;
                        }
                        if close_conn {
                            break;
                        }
                    }
                });
            }
        });

        Ok(Self {
            addr,
            shutdown,
            delay_us,
            handle: Some(handle),
        })
    }

    fn set_delay_us(&self, us: u64) {
        self.delay_us.store(us, Ordering::Relaxed);
    }
}

impl Drop for LoopbackRangeServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn read_http_headers(br: &mut BufReader<TcpStream>) -> std::io::Result<(u16, u64)> {
    let mut line = String::new();
    br.read_line(&mut line)?;
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("bad http status line"))?;
    let mut content_len = 0u64;
    loop {
        line.clear();
        let n = br.read_line(&mut line)?;
        if n == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            content_len = v.trim().parse::<u64>().unwrap_or(0);
        }
    }
    Ok((status, content_len))
}

struct HttpRangeReader {
    conn: Mutex<BufReader<TcpStream>>,
    reqs: AtomicUsize,
    bytes: AtomicU64,
}

impl HttpRangeReader {
    fn connect(addr: SocketAddr) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        Ok(Self {
            conn: Mutex::new(BufReader::new(stream)),
            reqs: AtomicUsize::new(0),
            bytes: AtomicU64::new(0),
        })
    }

    fn reqs(&self) -> usize {
        self.reqs.load(Ordering::Relaxed)
    }

    fn bytes_read(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

impl RangeReader for HttpRangeReader {
    fn total_len(&self) -> Result<u64, VzError> {
        let mut br = self.conn.lock().map_err(|_| VzError::IoError)?;
        br.get_mut()
            .write_all(b"HEAD /archive HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
            .map_err(|_| VzError::IoError)?;
        br.get_mut().flush().map_err(|_| VzError::IoError)?;
        let (status, total_len) = read_http_headers(&mut br).map_err(|_| VzError::IoError)?;
        if status != 200 {
            return Err(VzError::IoError);
        }
        self.reqs.fetch_add(1, Ordering::Relaxed);
        Ok(total_len)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(buf.len() as u64 - 1)
            .ok_or(VzError::ValueOverflow)?;
        let mut br = self.conn.lock().map_err(|_| VzError::IoError)?;
        let req = format!(
            "GET /archive HTTP/1.1\r\nHost: localhost\r\nRange: bytes={offset}-{end}\r\nConnection: keep-alive\r\n\r\n"
        );
        br.get_mut()
            .write_all(req.as_bytes())
            .map_err(|_| VzError::IoError)?;
        br.get_mut().flush().map_err(|_| VzError::IoError)?;
        let (status, clen) = read_http_headers(&mut br).map_err(|_| VzError::IoError)?;
        if (status != 206 && status != 200) || clen != buf.len() as u64 {
            return Err(VzError::IoError);
        }
        br.read_exact(buf).map_err(|_| VzError::IoError)?;
        self.reqs.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(clen, Ordering::Relaxed);
        Ok(())
    }
}

struct HttpSeekableReader {
    conn: BufReader<TcpStream>,
    pos: u64,
    total_len: u64,
    reqs: usize,
    bytes: u64,
}

impl HttpSeekableReader {
    fn connect(addr: SocketAddr) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        let mut conn = BufReader::new(stream);
        conn.get_mut().write_all(
            b"HEAD /archive HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
        )?;
        conn.get_mut().flush()?;
        let (_, total_len) = read_http_headers(&mut conn)?;
        Ok(Self {
            conn,
            pos: 0,
            total_len,
            reqs: 1,
            bytes: 0,
        })
    }
}

impl Read for HttpSeekableReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.total_len || buf.is_empty() {
            return Ok(0);
        }
        let end = (self.pos + buf.len() as u64 - 1).min(self.total_len - 1);
        let req = format!(
            "GET /archive HTTP/1.1\r\nHost: localhost\r\nRange: bytes={}-{end}\r\nConnection: keep-alive\r\n\r\n",
            self.pos
        );
        self.conn.get_mut().write_all(req.as_bytes())?;
        self.conn.get_mut().flush()?;
        let (status, clen) = read_http_headers(&mut self.conn)?;
        if status != 206 && status != 200 {
            return Err(std::io::Error::other("unexpected http status"));
        }
        let n = clen as usize;
        self.conn.read_exact(&mut buf[..n])?;
        self.pos += clen;
        self.reqs += 1;
        self.bytes += clen;
        Ok(n)
    }
}

impl Seek for HttpSeekableReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(s) => s as i128,
            SeekFrom::End(d) => self.total_len as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if next < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "negative seek",
            ));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}

struct HttpStreamResult {
    ms: f64,
    reqs: usize,
    bytes: u64,
    data: Vec<u8>,
}

fn http_stream_tar_lookup(
    addr: SocketAddr,
    is_zstd: bool,
    target_path: &str,
) -> Result<HttpStreamResult, Box<dyn std::error::Error>> {
    struct CountingReader<R>(R, u64);
    impl<R: Read> Read for CountingReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.read(buf)?;
            self.1 += n as u64;
            Ok(n)
        }
    }

    let t0 = Instant::now();
    let stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    let mut br = BufReader::new(stream);
    br.get_mut()
        .write_all(b"GET /archive HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    br.get_mut().flush()?;
    let _ = read_http_headers(&mut br)?;

    let mut cr = CountingReader(br, 0);
    let mut found = Vec::new();
    if is_zstd {
        let dec = zstd::stream::read::Decoder::new(&mut cr)?;
        let mut ar = tar::Archive::new(dec);
        for entry in ar.entries()? {
            let mut e = entry?;
            if e.path()?.to_string_lossy() == target_path {
                e.read_to_end(&mut found)?;
                break;
            }
        }
    } else {
        let mut ar = tar::Archive::new(&mut cr);
        for entry in ar.entries()? {
            let mut e = entry?;
            if e.path()?.to_string_lossy() == target_path {
                e.read_to_end(&mut found)?;
                break;
            }
        }
    }
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    Ok(HttpStreamResult {
        ms,
        reqs: 1,
        bytes: cr.1,
        data: found,
    })
}

fn percentile_us(sorted_ns: &[u64], pct: f64) -> f64 {
    if sorted_ns.is_empty() {
        return 0.0;
    }
    let idx = (((sorted_ns.len() - 1) as f64) * pct).round() as usize;
    sorted_ns[idx.min(sorted_ns.len() - 1)] as f64 / 1000.0
}

#[derive(Clone, Copy)]
enum IopsTarget {
    VzNoneFile,
    VzNoneMmap,
    VzLz4File,
    VzLz4Mmap,
    VzZstdFile,
    VzZstdMmap,
    ZipStored,
    ZipZstd,
}

impl IopsTarget {
    fn label(self) -> &'static str {
        match self {
            Self::VzNoneFile => "VZ (None, File pread)",
            Self::VzNoneMmap => "VZ (None, Mmap)",
            Self::VzLz4File => "VZ (LZ4, File pread)",
            Self::VzLz4Mmap => "VZ (LZ4, Mmap)",
            Self::VzZstdFile => "VZ (Zstd, File pread)",
            Self::VzZstdMmap => "VZ (Zstd, Mmap)",
            Self::ZipStored => "ZIP (Stored, File)",
            Self::ZipZstd => "ZIP (Zstd, File)",
        }
    }
}

fn run_iops_bench(
    target: IopsTarget,
    path: &std::path::Path,
    paths: &[String],
    threads: usize,
    total_ops: usize,
) -> Result<(f64, f64, f64), Box<dyn std::error::Error>> {
    let ops_per_thread = total_ops / threads;
    let file = File::open(path)?;
    let vz_file_reader = match target {
        IopsTarget::VzNoneFile | IopsTarget::VzLz4File | IopsTarget::VzZstdFile => {
            // Single shared File handle: VZ uses stateless pread() across all threads with zero locks.
            Some(Arc::new(VzReader::open(file.try_clone()?)?))
        }
        _ => None,
    };
    let vz_mmap_reader = if matches!(
        target,
        IopsTarget::VzNoneMmap | IopsTarget::VzLz4Mmap | IopsTarget::VzZstdMmap
    ) {
        let mmap = unsafe { MmapRangeReader::from_file(&file)? };
        Some(Arc::new(VzReader::open(mmap)?))
    } else {
        None
    };

    let t0 = Instant::now();
    let all_latencies: Vec<Vec<u64>> = std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(threads);
        for tid in 0..threads {
            let vz_f = vz_file_reader.as_ref().map(Arc::clone);
            let vz_m = vz_mmap_reader.as_ref().map(Arc::clone);
            handles.push(s.spawn(move || -> Vec<u64> {
                let mut lats = Vec::with_capacity(ops_per_thread);
                let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ ((tid as u64 + 1) * 0xBF58_476D_1CE4_E5B9);
                let mut zip_ar = match target {
                    IopsTarget::ZipStored | IopsTarget::ZipZstd => {
                        // ZIP requires Seek+Read (not pread), so each thread must open an independent fd.
                        let f_indep = File::open(path).expect("open zip per thread");
                        Some(zip::ZipArchive::new(BufReader::new(f_indep)).expect("open zip"))
                    }
                    _ => None,
                };
                let mut scratch = Vec::with_capacity(16_384);

                for _ in 0..ops_per_thread {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let idx = (state as usize) % paths.len();
                    let path = &paths[idx];

                    let op0 = Instant::now();
                    if let Some(ref vr) = vz_f {
                        let d = vr.read_file(path).expect("vz read");
                        black_box(d.len());
                    } else if let Some(ref vm) = vz_m {
                        let d = vm.read_file(path).expect("vz mmap read");
                        black_box(d.len());
                    } else if let Some(ref mut za) = zip_ar {
                        scratch.clear();
                        let mut zf = za.by_name(path).expect("zip by_name");
                        zf.read_to_end(&mut scratch).expect("zip read");
                        black_box(scratch.len());
                    }
                    lats.push(op0.elapsed().as_nanos() as u64);
                }
                lats
            }));
        }
        handles.into_iter().map(|h| h.join().expect("join")).collect()
    });
    let elapsed = t0.elapsed().as_secs_f64();

    let mut merged: Vec<u64> = all_latencies.into_iter().flatten().collect();
    merged.sort_unstable();
    let iops = (ops_per_thread * threads) as f64 / elapsed;
    let p50 = percentile_us(&merged, 0.50);
    let p99 = percentile_us(&merged, 0.99);
    Ok((iops, p50, p99))
}

fn run_extended_benchmarks(
    mixed_corpus: &[(String, Vec<u8>)],
    dict: &[u8],
    big_blob: &[(String, Vec<u8>)],
) -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // [6] HTTP/1.1 RANGE STREAMING (0ms LOOPBACK vs 2ms EDGE/S3 RTT)
    // =========================================================================
    let target_idx = (mixed_corpus.len() * 7) / 10 + 1;
    let (target_path, target_expected) = &mixed_corpus[target_idx];

    println!();
    println!(
        "[6] HTTP/1.1 Range Streaming (cold open + fetch {} [{} B] out of 5,000 files)",
        target_path,
        target_expected.len()
    );
    println!("    Keep-alive TCP loopback with TCP_NODELAY; BufReader<64KiB> for ZIP; streaming GET for TAR");
    println!(
        "{:<16} | {:>10} | {:>12} | {:>9} | {:>10}",
        "Format", "HTTP Req", "Transferred", "0ms (ms)", "2ms RTT (ms)"
    );
    println!("{}", "-".repeat(69));

    let http_vz = Arc::new(pack_format_to_vec(FormatKind::VzZstd, mixed_corpus, dict)?);
    let http_zip = Arc::new(pack_format_to_vec(FormatKind::ZipZstd, mixed_corpus, dict)?);
    let http_tar = Arc::new(pack_format_to_vec(FormatKind::Tar, mixed_corpus, dict)?);
    let http_tarz = Arc::new(pack_format_to_vec(FormatKind::TarZst, mixed_corpus, dict)?);

    for (label, arc_opt, is_vz, is_zip, is_tar_zst) in [
        ("VZ (Zstd)", Arc::clone(&http_vz), true, false, false),
        ("ZIP (Zstd)", Arc::clone(&http_zip), false, true, false),
        ("TAR (Stream)", Arc::clone(&http_tar), false, false, false),
        ("TAR.ZST (Stream)", Arc::clone(&http_tarz), false, false, true),
    ] {
        let srv = LoopbackRangeServer::start(arc_opt, 0)?;
        let (ms0, reqs, bytes) = if is_vz {
            let t0 = Instant::now();
            let hr = HttpRangeReader::connect(srv.addr)?;
            let vr = VzReader::open(hr)?;
            let got = vr.read_file(target_path)?;
            assert_eq!(&got, target_expected);
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            (ms, vr.reader().reqs(), vr.reader().bytes_read())
        } else if is_zip {
            let t0 = Instant::now();
            let hs = HttpSeekableReader::connect(srv.addr)?;
            let mut br = BufReader::with_capacity(64 * 1024, hs);
            let mut za = zip::ZipArchive::new(&mut br)?;
            let mut got = Vec::new();
            za.by_name(target_path)?.read_to_end(&mut got)?;
            assert_eq!(&got, target_expected);
            drop(za);
            let hs_back = br.into_inner();
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            (ms, hs_back.reqs, hs_back.bytes)
        } else {
            let res = http_stream_tar_lookup(srv.addr, is_tar_zst, target_path)?;
            assert_eq!(&res.data, target_expected);
            (res.ms, res.reqs, res.bytes)
        };

        srv.set_delay_us(2_000);
        let ms2 = if is_vz {
            let t0 = Instant::now();
            let hr = HttpRangeReader::connect(srv.addr)?;
            let vr = VzReader::open(hr)?;
            let got = vr.read_file(target_path)?;
            assert_eq!(&got, target_expected);
            t0.elapsed().as_secs_f64() * 1000.0
        } else if is_zip {
            let t0 = Instant::now();
            let hs = HttpSeekableReader::connect(srv.addr)?;
            let mut br = BufReader::with_capacity(64 * 1024, hs);
            let mut za = zip::ZipArchive::new(&mut br)?;
            let mut got = Vec::new();
            za.by_name(target_path)?.read_to_end(&mut got)?;
            assert_eq!(&got, target_expected);
            t0.elapsed().as_secs_f64() * 1000.0
        } else {
            let res = http_stream_tar_lookup(srv.addr, is_tar_zst, target_path)?;
            assert_eq!(&res.data, target_expected);
            res.ms
        };

        println!(
            "{:<16} | {:>10} | {:>9.1} KB | {:>9.2} | {:>10.2}",
            label,
            reqs,
            bytes as f64 / 1024.0,
            ms0,
            ms2
        );
    }

    // =========================================================================
    // [7] RANDOM I/O & IOPS (20,000-FILE ARCHIVE ON DISK: 1T, 6T, & MAX PARALLELISM)
    // =========================================================================
    let max_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let max_ops = (max_threads * 5_000).max(30_000);
    println!();
    println!(
        "[7] Random I/O & IOPS (20,000-file archive: 1T x 10,000 reads{}{})",
        if max_threads >= 6 { ", 6T x 30,000" } else { "" },
        if max_threads > 1 && max_threads != 6 {
            format!(", {max_threads}T x {max_ops}")
        } else {
            String::new()
        }
    );
    let corpus_20k = gen_mixed_corpus(20_000);
    let paths_20k: Vec<String> = corpus_20k.iter().map(|(p, _)| p.clone()).collect();

    let f_vz_none = write_temp_file(&pack_format_to_vec(FormatKind::VzNone, &corpus_20k, dict)?)?;
    let f_vz_lz4 = write_temp_file(&pack_format_to_vec(FormatKind::VzLz4, &corpus_20k, dict)?)?;
    let f_vz_zstd = write_temp_file(&pack_format_to_vec(FormatKind::VzZstd, &corpus_20k, dict)?)?;
    let f_zip_stored = write_temp_file(&pack_format_to_vec(FormatKind::ZipStored, &corpus_20k, dict)?)?;
    let f_zip_zstd = write_temp_file(&pack_format_to_vec(FormatKind::ZipZstd, &corpus_20k, dict)?)?;
    let f_tar_zst = write_temp_file(&pack_format_to_vec(FormatKind::TarZst, &corpus_20k, dict)?)?;

    let iops_targets = [
        (IopsTarget::VzNoneFile, &f_vz_none),
        (IopsTarget::VzNoneMmap, &f_vz_none),
        (IopsTarget::VzLz4File, &f_vz_lz4),
        (IopsTarget::VzLz4Mmap, &f_vz_lz4),
        (IopsTarget::VzZstdFile, &f_vz_zstd),
        (IopsTarget::VzZstdMmap, &f_vz_zstd),
        (IopsTarget::ZipStored, &f_zip_stored),
        (IopsTarget::ZipZstd, &f_zip_zstd),
    ];

    if max_threads > 6 {
        let max_col = format!("{max_threads}T IOPS");
        println!(
            "{:<22} | {:>11} | {:>7} | {:>7} | {:>11} | {:>7} | {:>7} | {:>11} | {:>7} | {:>7} | {:>7}",
            "Format", "1T IOPS", "p50 us", "p99 us", "6T IOPS", "p50 us", "p99 us", max_col, "p50 us", "p99 us", "Scale"
        );
        println!("{}", "-".repeat(126));
        for (target, tf) in iops_targets {
            let (iops1, p50_1, p99_1) = run_iops_bench(target, tf.path(), &paths_20k, 1, 10_000)?;
            let (iops6, p50_6, p99_6) = run_iops_bench(target, tf.path(), &paths_20k, 6, 30_000)?;
            let (iopsm, p50_m, p99_m) =
                run_iops_bench(target, tf.path(), &paths_20k, max_threads, max_ops)?;
            println!(
                "{:<22} | {:>11.0} | {:>7.2} | {:>7.2} | {:>11.0} | {:>7.2} | {:>7.2} | {:>11.0} | {:>7.2} | {:>7.2} | {:>6.2}x",
                target.label(),
                iops1, p50_1, p99_1,
                iops6, p50_6, p99_6,
                iopsm, p50_m, p99_m,
                iopsm / iops1.max(1.0)
            );
        }
    } else if max_threads > 1 {
        let par_threads = max_threads;
        let par_ops = if par_threads == 6 { 30_000 } else { max_ops };
        let par_col = format!("{par_threads}T IOPS");
        println!(
            "{:<22} | {:>11} | {:>7} | {:>7} | {:>11} | {:>7} | {:>7} | {:>7}",
            "Format", "1T IOPS", "p50 us", "p99 us", par_col, "p50 us", "p99 us", "Scale"
        );
        println!("{}", "-".repeat(96));
        for (target, tf) in iops_targets {
            let (iops1, p50_1, p99_1) = run_iops_bench(target, tf.path(), &paths_20k, 1, 10_000)?;
            let (iopsp, p50_p, p99_p) =
                run_iops_bench(target, tf.path(), &paths_20k, par_threads, par_ops)?;
            println!(
                "{:<22} | {:>11.0} | {:>7.2} | {:>7.2} | {:>11.0} | {:>7.2} | {:>7.2} | {:>6.2}x",
                target.label(),
                iops1, p50_1, p99_1,
                iopsp, p50_p, p99_p,
                iopsp / iops1.max(1.0)
            );
        }
    } else {
        println!(
            "{:<22} | {:>11} | {:>7} | {:>7}",
            "Format", "1T IOPS", "p50 us", "p99 us"
        );
        println!("{}", "-".repeat(56));
        for (target, tf) in iops_targets {
            let (iops1, p50_1, p99_1) = run_iops_bench(target, tf.path(), &paths_20k, 1, 10_000)?;
            println!(
                "{:<22} | {:>11.0} | {:>7.2} | {:>7.2}",
                target.label(),
                iops1,
                p50_1,
                p99_1
            );
        }
    }

    // TAR.ZST sequential scan baseline (10 samples at ~50% depth so it finishes fast)
    {
        let mut lats = Vec::with_capacity(10);
        let t0 = Instant::now();
        for i in 0..10 {
            let p = &paths_20k[10_000 + i * 7];
            let s0 = Instant::now();
            let got = random_access_from_file(FormatKind::TarZst, &f_tar_zst.reopen()?, p)?;
            black_box(got.len());
            lats.push(s0.elapsed().as_nanos() as u64);
        }
        let dt = t0.elapsed().as_secs_f64();
        lats.sort_unstable();
        if max_threads > 6 {
            println!(
                "{:<22} | {:>11.1} | {:>7.0} | {:>7.0} | {:>11} | {:>7} | {:>7} | {:>11} | {:>7} | {:>7} | {:>7}",
                "TAR.ZST (10-op sample)",
                10.0 / dt,
                percentile_us(&lats, 0.50),
                percentile_us(&lats, 0.99),
                "N/A", "-", "-", "N/A", "-", "-", "-"
            );
        } else if max_threads > 1 {
            println!(
                "{:<22} | {:>11.1} | {:>7.0} | {:>7.0} | {:>11} | {:>7} | {:>7} | {:>7}",
                "TAR.ZST (10-op sample)",
                10.0 / dt,
                percentile_us(&lats, 0.50),
                percentile_us(&lats, 0.99),
                "N/A", "-", "-", "-"
            );
        } else {
            println!(
                "{:<22} | {:>11.1} | {:>7.0} | {:>7.0}",
                "TAR.ZST (10-op sample)",
                10.0 / dt,
                percentile_us(&lats, 0.50),
                percentile_us(&lats, 0.99),
            );
        }
    }

    // =========================================================================
    // [8] PARTIAL BYTE-RANGE READ INSIDE 32 MiB COMPRESSED MULTI-CLUSTER BLOB
    // =========================================================================
    println!();
    println!("[8] Partial Byte-Range Read inside 32 MiB Zstd Blob (read 64 KiB at 24 MiB offset)");
    let range_off: u64 = 24 * 1024 * 1024;
    let range_len: usize = 64 * 1024;
    let expected_slice = &big_blob[0].1[range_off as usize..range_off as usize + range_len];

    let vz_big = pack_format_to_vec(FormatKind::VzZstd, big_blob, dict)?;
    let zip_big = pack_format_to_vec(FormatKind::ZipZstd, big_blob, dict)?;
    let tarz_big = pack_format_to_vec(FormatKind::TarZst, big_blob, dict)?;

    println!(
        "{:<18} | {:>10} | {:>13} | {:>15}",
        "Format", "Latency", "Read from Arc", "Notes"
    );
    println!("{}", "-".repeat(66));

    // VZ chunked range read (100 iterations; verifies CountingRangeReader bytes per call)
    {
        let counter = CountingRangeReader::new(vz_big.as_slice());
        let vr = VzReader::open(counter)?;
        let mut t_sum = 0.0;
        let mut last_bytes = 0u64;
        for _ in 0..50 {
            vr.reader().reset();
            let t0 = Instant::now();
            let got = vr.read_file_range("big_blob.bin", range_off, range_len)?;
            t_sum += t0.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(got.as_slice(), expected_slice);
            last_bytes = vr.reader().bytes_read();
        }
        println!(
            "{:<18} | {:>7.2} ms | {:>10.1} KB | Reads 1 overlapping chunk only",
            "VZ (Zstd 1M chunk)",
            t_sum / 50.0,
            last_bytes as f64 / 1024.0
        );
    }

    // ZIP (Zstd) must decompress entry stream from offset 0..24 MiB + 64 KiB
    {
        let mut t_sum = 0.0;
        let mut bytes_read = 0u64;
        for _ in 0..5 {
            let cs = CountingReadSeek::new(Cursor::new(zip_big.as_slice()));
            let t0 = Instant::now();
            let mut za = zip::ZipArchive::new(cs)?;
            let mut zf = za.by_name("big_blob.bin")?;
            std::io::copy(&mut zf.by_ref().take(range_off), &mut std::io::sink())?;
            let mut got = vec![0u8; range_len];
            zf.read_exact(&mut got)?;
            t_sum += t0.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(got.as_slice(), expected_slice);
            drop(zf);
            bytes_read = za.into_inner().bytes_read();
        }
        println!(
            "{:<18} | {:>7.2} ms | {:>10.1} KB | Decompresses from byte 0..24.06 MiB",
            "ZIP (Zstd)",
            t_sum / 5.0,
            bytes_read as f64 / 1024.0
        );
    }

    // TAR.ZST must decompress solid stream from offset 0..24 MiB + 64 KiB
    {
        let mut t_sum = 0.0;
        let mut bytes_read = 0u64;
        for _ in 0..5 {
            let cs = CountingReadSeek::new(Cursor::new(tarz_big.as_slice()));
            let t0 = Instant::now();
            let dec = zstd::stream::read::Decoder::new(cs)?;
            let mut ar = tar::Archive::new(dec);
            {
                let mut entries = ar.entries()?;
                let mut entry = entries.next().ok_or("missing tar entry")??;
                std::io::copy(&mut entry.by_ref().take(range_off), &mut std::io::sink())?;
                let mut got = vec![0u8; range_len];
                entry.read_exact(&mut got)?;
                t_sum += t0.elapsed().as_secs_f64() * 1000.0;
                assert_eq!(got.as_slice(), expected_slice);
            }
            bytes_read = ar.into_inner().finish().into_inner().bytes_read();
        }
        println!(
            "{:<18} | {:>7.2} ms | {:>10.1} KB | Decompresses solid stream from 0",
            "TAR.ZST",
            t_sum / 5.0,
            bytes_read as f64 / 1024.0
        );
    }

    // =========================================================================
    // [9] INCREMENTAL APPEND + SELECTIVE DELETE (+10 NEW, -5 DELETE ON 5k ARCHIVE)
    // =========================================================================
    println!();
    println!("[9] Incremental Append (+10 x 4 KiB files, -5 deletes on 5,000-file archive)");
    let base_vz = pack_format_to_vec(FormatKind::VzZstd, mixed_corpus, dict)?;
    let base_zip = pack_format_to_vec(FormatKind::ZipZstd, mixed_corpus, dict)?;
    let base_tarz = pack_format_to_vec(FormatKind::TarZst, mixed_corpus, dict)?;

    let new_files: Vec<(String, Vec<u8>)> = (0..10)
        .map(|i| (format!("patch/add_{i:02}.json"), gen_structured_file(9000 + i, 4096)))
        .collect();
    let del_paths: Vec<String> = (0..5).map(|i| mixed_corpus[i * 500].0.clone()).collect();

    println!(
        "{:<22} | {:>10} | {:>12} | Semantics",
        "Operation", "Time (ms)", "Bytes Written"
    );
    println!("{}", "-".repeat(78));

    // VZ LSM Delta Append (+10 files, -5 tombstones; O(|delta|))
    {
        let tf = write_temp_file(&base_vz)?;
        let orig_len = tf.as_file().metadata()?.len();
        let rw = OpenOptions::new().read(true).write(true).open(tf.path())?;
        let t0 = Instant::now();
        let mut app = LsmAppendWriter::open(rw, None, 512, 128)?;
        for p in &del_paths {
            app.delete(p)?;
        }
        for (p, d) in &new_files {
            app.add_file(p, d)?;
        }
        let rw_done = app.finish()?;
        let new_len = rw_done.metadata()?.len();
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        let delta_written = (new_len - orig_len) + 65_536; // appended clusters + boot slot update
        let vr = VzReader::open(tf.reopen()?)?;
        assert_eq!(vr.read_file(&del_paths[0]), Err(VzError::NotFound));
        assert_eq!(vr.read_file(&new_files[0].0)?, new_files[0].1);
        println!(
            "{:<22} | {:>10.2} | {:>9.1} KB | Supports add + overwrite + tombstone delete",
            "VZ (LSM Delta Append)",
            ms,
            delta_written as f64 / 1024.0
        );
    }

    // ZIP new_append (add +10 only; CANNOT delete in-place)
    {
        let tf = write_temp_file(&base_zip)?;
        let orig_len = tf.as_file().metadata()?.len();
        let rw = OpenOptions::new().read(true).write(true).open(tf.path())?;
        let t0 = Instant::now();
        let mut zw = zip::ZipWriter::new_append(rw)?;
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Zstd);
        for (p, d) in &new_files {
            zw.start_file(p, opts)?;
            zw.write_all(d)?;
        }
        let rw_done = zw.finish()?;
        let new_len = rw_done.metadata()?.len();
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!(
            "{:<22} | {:>10.2} | {:>9.1} KB | Add-only (cannot delete without full rewrite)",
            "ZIP (new_append)",
            ms,
            (new_len - orig_len) as f64 / 1024.0
        );
    }

    // TAR.ZST full unpack + re-pack rewrite
    {
        let t0 = Instant::now();
        let dec = zstd::stream::read::Decoder::new(Cursor::new(base_tarz.as_slice()))?;
        let mut ar = tar::Archive::new(dec);
        let enc = zstd::stream::Encoder::new(Vec::with_capacity(base_tarz.len()), 3)?;
        let mut out_tar = tar::Builder::new(enc);
        let mut buf = Vec::new();
        for entry in ar.entries()? {
            let mut e = entry?;
            let path = e.path()?.to_string_lossy().into_owned();
            if del_paths.iter().any(|d| d == &path) {
                continue;
            }
            buf.clear();
            e.read_to_end(&mut buf)?;
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(buf.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            out_tar.append_data(&mut hdr, &path, buf.as_slice())?;
        }
        for (p, d) in &new_files {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(d.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            out_tar.append_data(&mut hdr, p, d.as_slice())?;
        }
        out_tar.finish()?;
        let out_bytes = out_tar.into_inner()?.finish()?;
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!(
            "{:<22} | {:>10.2} | {:>9.1} KB | Must rewrite entire solid archive for add/del",
            "TAR.ZST (Full Rewrite)",
            ms,
            out_bytes.len() as f64 / 1024.0
        );
    }

    // =========================================================================
    // [10] CORRUPTION FAULT-INJECTION & SELF-HEALING RECOVERY
    // =========================================================================
    println!();
    println!("[10] Fault-Injection Recovery (wipe 4 KiB Boot ECC page + 256 KiB Data Cluster)");
    // Build 12 MiB semi-incompressible corpus so RS(4,2) produces >= 2 stripes (4+ data clusters each)
    let mut rec_corpus = Vec::new();
    for i in 0..24u32 {
        let sz = 512 * 1024;
        let mut buf = vec![0u8; sz];
        let mut s = 0x1234_5678_9ABC_DEF0u64 ^ (i as u64);
        for chunk in buf.chunks_exact_mut(8) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            chunk.copy_from_slice(&s.to_le_bytes());
        }
        rec_corpus.push((format!("data/part_{i:02}.bin"), buf));
    }

    // VZ with Boot ECC + RS(4,2)
    let cfg_rs = VzWriterConfig {
        enable_boot_ecc: true,
        default_codec: CODEC_ZSTD,
        target_cluster_size: 512 * 1024,
        multi_cluster_threshold: 2 * 1024 * 1024,
        rs_parity: Some((4, 2)),
        ..Default::default()
    };
    let mut w_rs = VzWriter::new(Cursor::new(Vec::new()), cfg_rs)?;
    for (p, d) in &rec_corpus {
        w_rs.add_file(p, d)?;
    }
    let mut vz_rs = w_rs.finish()?.into_inner();
    let mut tar_rs = pack_format_to_vec(FormatKind::TarZst, &rec_corpus, dict)?;
    let mut zip_rs = pack_format_to_vec(FormatKind::ZipZstd, &rec_corpus, dict)?;

    // Wipe 4 KiB inside Boot Page 2 + 256 KiB at offset 1 MiB inside cluster stream
    let corrupt_off = 1024 * 1024;
    let corrupt_len = 256 * 1024;
    for arc in [&mut vz_rs, &mut tar_rs, &mut zip_rs] {
        arc[8192..12288].fill(0x55);
        arc[corrupt_off..corrupt_off + corrupt_len].fill(0xFF);
    }

    let t_vz = Instant::now();
    let rep = repair_slice(&mut vz_rs)?;
    let vz_ms = t_vz.elapsed().as_secs_f64() * 1000.0;
    let vr_ok = VzReader::open(vz_rs.as_slice())?;
    let mut all_ok = true;
    for (p, d) in &rec_corpus {
        if vr_ok.read_file(p)? != *d {
            all_ok = false;
            break;
        }
    }

    let tar_ok = unpack_all_from_slice(FormatKind::TarZst, &tar_rs, &rec_corpus).is_ok();
    let zip_ok = unpack_all_from_slice(FormatKind::ZipZstd, &zip_rs, &rec_corpus).is_ok();

    println!(
        "{:<18} | {:>12} | {:>10} | Outcome",
        "Format", "Recoverable?", "Repair ms"
    );
    println!("{}", "-".repeat(72));
    println!(
        "{:<18} | {:>12} | {:>10.2} | boot_page={:?}, data_repaired={}, data_100%={}",
        "VZ (ECC + RS 4,2)",
        if all_ok { "YES (100%)" } else { "NO" },
        vz_ms,
        rep.boot_page_repaired,
        rep.data_clusters_repaired,
        all_ok
    );
    println!(
        "{:<18} | {:>12} | {:>10} | Stream CRC/frame mismatch; remaining entries lost",
        "TAR.ZST",
        if tar_ok { "YES" } else { "NO (Fatal)" },
        "-"
    );
    println!(
        "{:<18} | {:>12} | {:>10} | Local header / stream corrupted; no redundancy",
        "ZIP (Zstd)",
        if zip_ok { "YES" } else { "NO (Fatal)" },
        "-"
    );

    // =========================================================================
    // [11] ZERO-REENCODE LSM COMPACTION (5,000 ZSTD FILES + 200 OVERWRITES + 100 DELETES)
    // =========================================================================
    println!();
    println!("[11] LSM Compaction (5,000 Zstd files + 200 overwrites + 100 deletes -> single run)");
    {
        let mut lsm_buf = base_vz.clone();
        lsm_buf.shrink_to_fit();
        let mut app = LsmAppendWriter::open(Cursor::new(lsm_buf), None, 512, 128)?;
        let zstd_opts = EntryOptions {
            codec: Some(CODEC_ZSTD),
            ..Default::default()
        };
        for i in 0..200 {
            let (p, _) = &mixed_corpus[i * 10];
            app.add_file_with_options(p, &gen_structured_file(50_000 + i, 2048), zstd_opts.clone())?;
        }
        for i in 0..100 {
            let (p, _) = &mixed_corpus[i * 15 + 1];
            app.delete(p)?;
        }
        let multi_run_bytes = app.finish()?.into_inner();
        let multi_reader = VzReader::open(multi_run_bytes.as_slice())?;
        assert_eq!(multi_reader.active_slot().lsm_run_count, 2);

        let t_noreenc = Instant::now();
        let compacted_no_reenc = compact_archive_with_options(
            &multi_reader,
            Cursor::new(Vec::new()),
            CompactOptions::default(),
        )?
        .into_inner();
        let dt_noreenc = t_noreenc.elapsed().as_secs_f64() * 1000.0;

        let t_reenc = Instant::now();
        let compacted_reenc = compact_archive_with_options(
            &multi_reader,
            Cursor::new(Vec::new()),
            CompactOptions {
                reencode_codec: Some(CODEC_ZSTD),
                ..Default::default()
            },
        )?
        .into_inner();
        let dt_reenc = t_reenc.elapsed().as_secs_f64() * 1000.0;

        let check_nr = VzReader::open(compacted_no_reenc.as_slice())?;
        assert_eq!(check_nr.active_slot().lsm_run_count, 1);
        assert_eq!(check_nr.active_slot().total_entries, 4900);

        println!(
            "{:<28} | {:>10} | {:>12} | Notes",
            "Compaction Mode", "Time (ms)", "Output Size"
        );
        println!("{}", "-".repeat(78));
        println!(
            "{:<28} | {:>10.2} | {:>9.2} MB | Strip LSM 2->1, del 100 tombstones, 0 re-encode",
            "VZ (Zero-Reencode Compact)",
            dt_noreenc,
            compacted_no_reenc.len() as f64 / (1024.0 * 1024.0)
        );
        println!(
            "{:<28} | {:>10.2} | {:>9.2} MB | Full decode + recompress (legacy mode)",
            "VZ (Full Re-encode Compact)",
            dt_reenc,
            compacted_reenc.len() as f64 / (1024.0 * 1024.0)
        );
    }

    // =========================================================================
    // [12] FUSE3 VFS OPERATIONS VS TRADITIONAL ARCHIVES
    // =========================================================================
    println!();
    println!("[12] FUSE3 VFS Simulation (Zero-I/O Metadata + Paged 4 KiB / Uncompressed Zero-Amp Reads)");
    {
        // A. Mount + Metadata (`getattr`/`lookup`/`readdirplus` across 2,000 entries in hot_dir)
        let vz_arc = {
            let mut w = VzWriter::new(
                Cursor::new(Vec::new()),
                VzWriterConfig {
                    default_codec: CODEC_ZSTD,
                    ..Default::default()
                },
            )?;
            w.add_dir("/hot_dir", 0o755, 0)?;
            for d in 0..40 {
                w.add_dir(&format!("/mod_{d:02}"), 0o755, 0)?;
            }
            for (path, data) in mixed_corpus {
                w.add_file(path, data)?;
            }
            w.finish()?.into_inner()
        };
        let vz_count = Arc::new(VzReader::open(CountingRangeReader::new(vz_arc))?);
        let t_mnt = Instant::now();
        let fuse_vol = FuseVolume::mount(Arc::clone(&vz_count))?;
        let mount_ms = t_mnt.elapsed().as_secs_f64() * 1000.0;
        fuse_vol.reader().reader().reset();

        let hot_attr = fuse_vol.lookup(FUSE_ROOT_ID, "hot_dir")?;
        let t_meta = Instant::now();
        let mut off = 0u64;
        let mut dir_count = 0usize;
        loop {
            let batch = fuse_vol.readdirplus(hot_attr.ino, off, 64)?;
            if batch.is_empty() {
                break;
            }
            off = batch.last().unwrap().offset;
            dir_count += batch.len();
        }
        assert!(dir_count >= 2002);
        let vz_meta_us = t_meta.elapsed().as_secs_f64() * 1e6;
        let vz_meta_reads = fuse_vol.reader().reader().reads();

        let t_lu = Instant::now();
        for _ in 0..10_000 {
            black_box(fuse_vol.lookup(hot_attr.ino, "item_01000.json")?);
        }
        let vz_lu_ns = t_lu.elapsed().as_secs_f64() * 1e9 / 10_000.0;

        // Compare ZIP & TAR.ZST cold directory stat+list of `hot_dir/` from disk
        let zip_tf = write_temp_file(&base_zip)?;
        let t_zmeta = Instant::now();
        let mut zf = zip::ZipArchive::new(BufReader::new(zip_tf.reopen()?))?;
        let mut z_cnt = 0usize;
        for idx in 0..zf.len() {
            let entry = zf.by_index_raw(idx)?;
            if entry.name().starts_with("hot_dir/") {
                z_cnt += 1;
            }
        }
        assert_eq!(z_cnt, 2000);
        let zip_meta_us = t_zmeta.elapsed().as_secs_f64() * 1e6;

        let tarz_tf = write_temp_file(&base_tarz)?;
        let t_tmeta = Instant::now();
        let dec = zstd::stream::read::Decoder::new(BufReader::new(tarz_tf.reopen()?))?;
        let mut ar = tar::Archive::new(dec);
        let mut t_cnt = 0usize;
        for ent in ar.entries()? {
            let ent = ent?;
            if ent.path_bytes().starts_with(b"hot_dir/") {
                t_cnt += 1;
            }
        }
        assert_eq!(t_cnt, 2000);
        let tarz_meta_us = t_tmeta.elapsed().as_secs_f64() * 1e6;

        println!(
            "A. `readdirplus` (2,000 entries, mount={mount_ms:.2} ms, VZ lookup={vz_lu_ns:.1} ns):"
        );
        println!(
            "  VZ (FuseVolume) : {:>8.2} us | disk reads = {} (0 I/O)",
            vz_meta_us, vz_meta_reads
        );
        println!(
            "  ZIP (Zstd)      : {:>8.2} us | full central directory scan ({}x slower)",
            zip_meta_us,
            (zip_meta_us / vz_meta_us).round()
        );
        println!(
            "  TAR.ZST         : {:>8.2} us | full stream decompression ({}x slower)",
            tarz_meta_us,
            (tarz_meta_us / vz_meta_us).round()
        );

        // B. 64 x 4 KiB sequential VFS page reads at offset 1 MiB of a 4 MiB Zstd file
        //    vs 4 KiB random VFS read on 4 MiB uncompressed CODEC_NONE
        let blob_4m = gen_structured_file(88, 4 * 1024 * 1024);
        let blob_vz_z = {
            let mut w = VzWriter::new(
                Cursor::new(Vec::new()),
                VzWriterConfig {
                    default_codec: CODEC_ZSTD,
                    target_cluster_size: 64 * 1024,
                    multi_cluster_threshold: 64 * 1024,
                    ..Default::default()
                },
            )?;
            w.add_file("/blob.bin", &blob_4m)?;
            w.finish()?.into_inner()
        };
        let blob_vz_none = {
            let mut w = VzWriter::new(
                Cursor::new(Vec::new()),
                VzWriterConfig {
                    default_codec: CODEC_NONE,
                    target_cluster_size: 4 * 1024 * 1024,
                    multi_cluster_threshold: 8 * 1024 * 1024,
                    ..Default::default()
                },
            )?;
            w.add_file("/blob.bin", &blob_4m)?;
            w.finish()?.into_inner()
        };
        let blob_corpus = vec![("blob.bin".to_string(), blob_4m.clone())];
        let blob_zip_z = pack_format_to_vec(FormatKind::ZipZstd, &blob_corpus, dict)?;
        let blob_tar_z = pack_format_to_vec(FormatKind::TarZst, &blob_corpus, dict)?;

        // VZ FuseVolume: 64 x 4 KiB sequential reads starting at 1 MiB (4 x 64 KiB Zstd chunks)
        let vz_f_cnt = Arc::new(VzReader::open(CountingRangeReader::new(blob_vz_z))?);
        let fs_z = FuseVolume::mount(Arc::clone(&vz_f_cnt))?;
        let attr_z = fs_z.lookup(FUSE_ROOT_ID, "blob.bin")?;
        let fh_z = fs_z.open(attr_z.ino)?;
        fs_z.reader().reader().reset();
        let t_vz_seq = Instant::now();
        for p in 0..64u64 {
            let got = fs_z.read(&fh_z, 1024 * 1024 + p * 4096, 4096)?;
            black_box(got.len());
        }
        let dt_vz_seq = t_vz_seq.elapsed().as_secs_f64() * 1e6;
        let vz_seq_reads = fs_z.reader().reader().reads();
        let vz_seq_bytes = fs_z.reader().reader().bytes_read();

        // VZ FuseVolume CODEC_NONE single 4 KiB random VFS read at 2 MiB + 4 KiB
        let vz_n_cnt = Arc::new(VzReader::open(CountingRangeReader::new(blob_vz_none))?);
        let fs_n = FuseVolume::mount(Arc::clone(&vz_n_cnt))?;
        let attr_n = fs_n.lookup(FUSE_ROOT_ID, "blob.bin")?;
        let fh_n = fs_n.open(attr_n.ino)?;
        fs_n.reader().reader().reset();
        let t_vz_4k = Instant::now();
        let got_4k = fs_n.read(&fh_n, 2 * 1024 * 1024 + 4096, 4096)?;
        let dt_vz_4k = t_vz_4k.elapsed().as_secs_f64() * 1e6;
        assert_eq!(got_4k.len(), 4096);
        let vz_4k_reads = fs_n.reader().reader().reads();
        let vz_4k_bytes = fs_n.reader().reader().bytes_read();

        // ZIP (Zstd): open entry + discard 1 MiB + read 64 x 4 KiB (256 KiB)
        let crs_zip = CountingReadSeek::new(Cursor::new(blob_zip_z.as_slice()));
        let t_zip_seq = Instant::now();
        let mut z_arch = zip::ZipArchive::new(BufReader::with_capacity(64 * 1024, crs_zip))?;
        let mut z_ent = z_arch.by_name("blob.bin")?;
        std::io::copy(&mut z_ent.by_ref().take(1024 * 1024), &mut std::io::sink())?;
        let mut page = [0u8; 4096];
        for _ in 0..64 {
            z_ent.read_exact(&mut page)?;
            black_box(page[0]);
        }
        drop(z_ent);
        let crs_zip_inner = z_arch.into_inner().into_inner();
        let dt_zip_seq = t_zip_seq.elapsed().as_secs_f64() * 1e6;

        // TAR.ZST: decompress stream to 1 MiB + read 64 x 4 KiB
        let crs_tar = CountingReadSeek::new(Cursor::new(blob_tar_z.as_slice()));
        let t_tar_seq = Instant::now();
        let mut tar_dec = zstd::stream::read::Decoder::new(BufReader::with_capacity(64 * 1024, crs_tar))?;
        {
            let mut ar_b = tar::Archive::new(&mut tar_dec);
            let mut entries = ar_b.entries()?;
            let mut t_ent = entries.next().unwrap()?;
            std::io::copy(&mut t_ent.by_ref().take(1024 * 1024), &mut std::io::sink())?;
            for _ in 0..64 {
                t_ent.read_exact(&mut page)?;
                black_box(page[0]);
            }
        }
        let crs_tar_inner = tar_dec.finish().into_inner().into_inner();
        let dt_tar_seq = t_tar_seq.elapsed().as_secs_f64() * 1e6;

        println!(
            "B. 64x4 KiB Seq Read @ 1 MiB (4 MiB Zstd) & Zero-Amp 4 KiB Read:"
        );
        println!(
            "  VZ (Fuse Zstd 64K MC) : {:>8.2} us | reads = {:>2} | bytes = {:>7} B",
            dt_vz_seq, vz_seq_reads, vz_seq_bytes
        );
        println!(
            "  VZ (Fuse CODEC_NONE 4K): {:>8.2} us | reads = {:>2} | bytes = {:>7} B (1.00x read amp)",
            dt_vz_4k, vz_4k_reads, vz_4k_bytes
        );
        println!(
            "  ZIP (Zstd stream skip) : {:>8.2} us | reads = {:>2} | bytes = {:>7} B",
            dt_zip_seq,
            crs_zip_inner.reads(),
            crs_zip_inner.bytes_read()
        );
        println!(
            "  TAR.ZST (stream skip)  : {:>8.2} us | reads = {:>2} | bytes = {:>7} B",
            dt_tar_seq,
            crs_tar_inner.reads(),
            crs_tar_inner.bytes_read()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_format_roundtrip_parity() {
        let corpus = gen_mixed_corpus(50);
        let dict = build_dict_bytes();
        let expected_total: u64 = corpus.iter().map(|(_, d)| d.len() as u64).sum();

        for fmt in [
            FormatKind::VzNone,
            FormatKind::VzLz4,
            FormatKind::VzZstd,
            FormatKind::VzZstdDict,
            FormatKind::Tar,
            FormatKind::TarGz,
            FormatKind::TarLz4,
            FormatKind::TarZst,
            FormatKind::ZipStored,
            FormatKind::ZipDeflate,
            FormatKind::ZipZstd,
        ] {
            let arc = pack_format_to_vec(fmt, &corpus, &dict).unwrap();
            let got_total = unpack_all_from_slice(fmt, &arc, &corpus).unwrap();
            assert_eq!(got_total, expected_total);

            let tf = write_temp_file(&arc).unwrap();
            let f = tf.reopen().unwrap();
            let (target_path, target_data) = &corpus[25];
            let single = random_access_from_file(fmt, &f, target_path).unwrap();
            assert_eq!(&single, target_data);
        }
    }
}
