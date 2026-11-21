# VZ v1.0 Benchmark Report

All results below were directly measured on this machine using `cargo bench -p libvz --all-features` (`criterion` in `crates/libvz/benches/vz_benchmarks.rs`), `cargo run --release -p libvz --all-features --example metrics_runner`, and `cargo run --release -p vz-bench --bin vz-compare`. No numbers are estimated or extrapolated.

## Environment

- **CPU:** AMD Ryzen 5 5600H with Radeon Graphics (6 cores / 12 threads, `available_parallelism = 12`, x86_64)
- **OS:** Linux `7.3.4-1-cachyos` `x86_64`
- **Toolchain:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`
- **Target Flags:** Default release profile (no custom `RUSTFLAGS`)
- **SIMD / Hardware Acceleration:**
  - `crc32c_hw_active() == true`: tiered dispatch across `AVX-512F + VPCLMULQDQ`, `AVX2 + VPCLMULQDQ`, `SSE4.2 + PCLMULQDQ`, `SSE4.2`, `aarch64 crc`, and portable slice-by-8; on this Zen 3 host (`avx2` + `vpclmulqdq`), runtime detection uses `AVX2 + VPCLMULQDQ` folding for `>= 256 B` and `SSE4.2` for shorter inputs, plus compile-time precomputed `CRC32C_SHIFT_POW2` GF(2) combine tables.
  - `rs_gf256_madd_slice` / `rs_gf256_madd_multi`: tiered dispatch across `AVX-512F + GFNI`, `AVX2 + GFNI`, `AVX-512BW`, 2×-unrolled `AVX2`, `SSSE3`, `aarch64 NEON`, `wasm32 simd128`, and `#![no_std]` scalar; on this Zen 3 host, runtime detection uses 2×-unrolled 32-byte `AVX2 vpshufb` fused multi-output kernels with 32 KiB L1/L2 tile blocking and `adaptive_workers` parallel bands.
  - `boot_ecc`: single-pass 15-way `AVX2` XOR + hardware CRC32C (`boot_ecc_verify_clean` validates page CRCs without cloning the 64 KiB block).

---

## 1. Primitive Throughput & Latency

### 1.1 Castagnoli `crc32c` (`AVX2 + VPCLMULQDQ` >= `256 B`, `SSE4.2` < `256 B`)

| Buffer Size | `metrics_runner` (MB/s) | `metrics_runner` (ns/op) | Criterion Median Time | Criterion Throughput |
| ---: | ---: | ---: | ---: | ---: |
| `64 B` | 14,177.54 MB/s | 4.31 ns | 3.8566 ns | 15.455 GiB/s |
| `4 KiB` | 28,198.67 MB/s | 138.53 ns | 134.15 ns | 28.437 GiB/s |
| `64 KiB` | **29,065.91 MB/s** | 2,150.29 ns | **2.0407 µs** | **29.909 GiB/s** |
| `1 MiB` | 28,216.04 MB/s | 35,440.83 ns | 34.183 µs | 28.569 GiB/s |
| `16 MiB` | 15,222.87 MB/s | 1,051,050.36 ns | 910.45 µs | 17.162 GiB/s |

### 1.2 LE-VINT Encode / Decode

| Operation | `metrics_runner` (ns/op) | `metrics_runner` (Mops/s) | Criterion Median Time |
| :--- | ---: | ---: | ---: |
| `read_levint_fast` (`&[u8; 8]`) | 0.72 ns/op | 1,397.05 Mops/s | 1.4633 ns |
| `read_levint_safe` (`&[u8]`) | 1.14 ns/op | 880.47 Mops/s | 1.7335 ns |
| `write_levint` | 1.42 ns/op | 704.54 Mops/s | 1.6168 ns |

### 1.3 Boot Block 4 KiB ECC (`64 KiB`, 15-Way `AVX2` XOR)

| Operation | `metrics_runner` (µs/op) | Criterion Median Time | Criterion Throughput |
| :--- | ---: | ---: | ---: |
| `boot_ecc_encode` | 3.07 µs | 5.0564 µs | 12.071 GiB/s |
| `boot_ecc_verify_clean` (clean) | **2.15 µs** | **2.1368 µs** | **28.563 GiB/s** |
| `boot_ecc_verify_and_repair` (1 page repair) | 3.35 µs | 5.0055 µs | 12.194 GiB/s |

### 1.4 Reed-Solomon `GF(2^8)` Cauchy Erasure Coding (`1 MiB` Clusters, 2× `AVX2 vpshufb` + Tiled Parallel Stripes)

| Operation | `metrics_runner` | Criterion Median Time | Criterion Throughput |
| :--- | ---: | ---: | ---: |
| `rs_gf256_madd_slice` (`1 MiB`) | 36,665.46 MB/s | 28.988 µs | 33.689 GiB/s |
| `RS_GF256` `K=8, M=2` encode | **8,647.64 MB/s (data)** | **472.68 µs** | **16.528 GiB/s** |
| `RS_GF256` `K=8, M=2` recover (`2` erasures) | 4,112.65 MB/s (data) | 1.2534 ms | 6.2330 GiB/s |
| `RS_GF256` `K=16, M=4` encode | **5,625.47 MB/s (data)** | **1.3475 ms** | **11.596 GiB/s** |
| `RS_GF256` `K=16, M=4` recover (`4` erasures) | 2,701.07 MB/s (data) | 4.6557 ms | 3.3561 GiB/s |

---

## 2. End-to-End Pack & Unpack Throughput

### 2.1 Many-Small-Files Corpus (`10,000` files, `0 B .. 4 KiB`, `19.54 MiB` total raw)

| Codec / Mode | Pack Throughput | Pack File Rate | Unpack Throughput | Unpack File Rate | Archive Size |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `CODEC_NONE` | 607.83 MB/s | 311,132 files/s | 1,642.96 MB/s | 840,986 files/s | 20.96 MiB |
| `CODEC_LZ4` | **1,227.91 MB/s** | **628,532 files/s** | **2,195.05 MB/s** | **1,123,589 files/s** | 2.33 MiB |
| `CODEC_ZSTD` | 666.74 MB/s | 341,286 files/s | 1,970.15 MB/s | 1,008,466 files/s | 2.00 MiB |
| `ZSTD + Dict` (`CDict`/`DDict`) | 746.13 MB/s | 381,925 files/s | 1,732.05 MB/s | 886,588 files/s | 1.50 MiB |
| `Encrypted (Raw256)` | 369.55 MB/s | 189,165 files/s | 448.77 MB/s | 229,712 files/s | 21.34 MiB |

*(Criterion `1,000` small files pack: `CODEC_NONE` `612.36 MiB/s` / `735.08 µs`, `CODEC_LZ4` `451.00 MiB/s` / `998.09 µs`, `CODEC_ZSTD` `229.79 MiB/s` / `1.9589 ms`, `ZSTD+Dict` `231.04 MiB/s` / `1.9483 ms`, `Encrypted(Raw256)` `158.09 MiB/s` / `2.8474 ms`.)*

### 2.2 Large-Blob Corpus (`64 MiB` payload)

| Codec / Mode | Pack Throughput | Unpack Throughput | Archive Size |
| :--- | ---: | ---: | ---: |
| `CODEC_NONE` | 1,915.93 MB/s | 2,072.11 MB/s | 64.08 MiB |
| `CODEC_LZ4` | **9,232.26 MB/s** | 3,112.29 MB/s | 0.33 MiB |
| `CODEC_ZSTD` | 8,353.36 MB/s | **3,330.40 MB/s** | 0.08 MiB |
| `Encrypted (Raw256)` | 919.61 MB/s | 1,616.69 MB/s | 64.08 MiB |

---

## 3. Random-Access Lookup, Indexing Latency & Multi-Core Scaling

### 3.1 Cold Open, `stat`, and `read_file` (`1 KiB` payload): `MmapRangeReader` vs `File`

| Archive Scale | B+Tree Height | Cold Open (`File`) | `stat` (`Mmap`) | `stat` (`File`) | `read_file` (`Mmap`) | `read_file` (`File`) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `100` files | `0` | 9.71 µs | 0.35 µs | 0.35 µs | 0.27 µs | 0.86 µs |
| `10,000` files | `1` | 10.27 µs | 0.62 µs | 0.70 µs | 0.46 µs | 1.03 µs |
| `100,000` files | `2` | 9.43 µs | 0.47 µs | 0.50 µs | 0.38 µs | 1.11 µs |

*(Criterion on `10,000` files forced to `tree_height >= 2`: `cold_open_file` **`9.5363 µs`**, `stat_10k_h2_mmap` **`497.81 ns`**, `stat_10k_h2_file` **`521.29 ns`**, `read_10k_h2_mmap` **`348.99 ns`**, `read_10k_h2_file` **`1.0166 µs`**.)*

### 3.2 `readdir` vs Zero-Copy `readdir_visit` Scaling

| Directory Size | Owned `readdir` (`metrics_runner`) | Zero-Copy `readdir_visit` (`metrics_runner`) | Criterion Owned | Criterion `readdir_visit` |
| ---: | ---: | ---: | ---: | ---: |
| `10` entries | 1.54 µs/op | 0.53 µs/op | 1.5294 µs | 508.48 ns |
| `5,000` entries | 1,582.80 µs/op | **138.71 µs/op** | 1.4928 ms | **156.33 µs** |

### 3.3 LSM Overlay Read Latency (`1`, `4`, `16` Runs vs Compacted)

| State | `read_file` (`metrics_runner`) | Criterion `stat` (`16` runs vs compacted) |
| :--- | ---: | ---: |
| `1` run (baseline) | 0.24 µs/op | — |
| `4` runs | 0.35 µs/op | — |
| `16` runs | 0.75 µs/op | 928.25 ns/op |
| Compacted (`1` run) | **0.27 µs/op** | **311.49 ns/op** |

### 3.4 Multi-Threaded Random I/O Scaling (`10,000` files, `read_file_into`, `1T` vs `12T`)

| Codec | `File` (`1T` IOPS) | `File` (`12T` IOPS) | `File` Scale | `Mmap` (`1T` IOPS) | `Mmap` (`12T` IOPS) | `Mmap` Scale |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `CODEC_NONE` | 509,232 | 4,106,495 | 8.06× | 1,017,993 | 4,609,298 | 4.53× |
| `CODEC_LZ4` | 522,073 | **4,992,444** | **9.56×** | **1,093,014** | 6,601,930 | 6.04× |
| `CODEC_ZSTD` | **528,911** | 4,580,569 | 8.66× | 1,043,463 | **6,620,381** | **6.34×** |

---

## 4. Remote / HTTP Range I/O Efficiency (`CountingRangeReader`)

Reading a single `1 KiB` external file out of `100`, `10,000`, and `100,000`-file archives:

| Archive Scale | Tree Height | Cold RTTs (Open + Lookup + Read) | Cold Bytes Fetched | Cold Read Amp | Warm RTTs (After Open) | Warm Bytes Fetched | Warm Read Amp |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `100` files | `0` | 2 RTTs | 66,560 B | 65.0x | 1 RTT | 1,024 B | 1.0x |
| `10,000` files | `1` | 3 RTTs | 106,112 B | 103.6x | 1 RTT | 1,024 B | 1.0x |
| `100,000` files | `2` | 4 RTTs | 109,440 B | 106.9x | 1 RTT | 1,024 B | 1.0x |

*(For `<= 27 B` inline files when `tree_height == 0`, total cold RTTs is **1 RTT** = `65,536 B`, verified in `tests/range_rtt_tests.rs`.)*

---

## 5. Space Overhead & Alignment Efficiency

| Workload | Raw Payload Size | Archive Size | Ratio (`archive / raw`) | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `5,000` inline files (`1..27 B`) | 69,945 B | 411,776 B | 5.887x | Zero data clusters (`data_clusters = 0`); includes `64 KiB` Boot Block |
| `5,000` external files (`28 B`) | 140,000 B | 731,904 B | 5.228x | Each `28 B` external entry incurs `TAG_DATA_MANIFEST` + 64B alignment |
| Mixed codebase (`500` files, `1..64 KiB`) | 16,355,250 B | 16,456,576 B | 1.0062x | **+0.62%** total metadata + 64B Void alignment overhead |
| `16 MiB` blob (no Boot ECC) | 16,777,216 B | 16,846,400 B | 1.0041x | **+0.412%** (`64 KiB` Boot Block + cluster headers/footers/Void) |
| `16 MiB` blob (+ Boot ECC `4 KiB + 80 B`) | 16,777,216 B | 16,846,400 B | 1.0041x | **+0.412%** (`Boot ECC` fits inside existing fixed `64 KiB` Boot Block) |
| `16 MiB` blob (+ `RS_GF256` `K=8, M=2`) | 16,777,216 B | 21,043,648 B | 1.2543x | **+25.43%** (`M/K = 25%` erasure parity + cluster framing) |

---

## 6. Streaming Memory Footprint (`64 MiB` Payload, `1 MiB` Cluster Size)

Instrumented via `TrackingAllocator` (`#[global_allocator]`) and `/proc/self/status` `VmHWM`:

| Operation | Heap Allocations | Peak Heap Delta | Process `VmHWM` |
| :--- | ---: | ---: | ---: |
| `64 MiB` streaming pipe write (`VzPipeWriter::add_file_reader`) | 157 allocs | 2.00 MiB | — |
| `64 MiB` multi-cluster streaming read (`VzReader::read_file_to_writer`) | 71 allocs | 1.07 MiB | 394,336 KiB |

---

## 7. FUSE3 VFS Surface (`FuseVolume`)

| Operation | `metrics_runner` | Criterion Median | Disk Reads / Amp | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `FuseVolume::mount` (`5,003` entries) | **1.99 ms** | **2.0816 ms** | `0` reads post-mount | Resolves LSM overlays, hardlink `nlink`, and implicit parents |
| `getattr(ino)` (`O(1)`) | **6.1 ns/op** (`162.9 Mops/s`) | 14.432 ns | `0` reads | Direct inode-vec slot access |
| `lookup(parent_ino, name)` (`2k` dir) | **38.1 ns/op** (`26.25 Mops/s`) | **55.305 ns** | `0` reads | Binary search over flat directory child arena + 8-byte inline prefix |
| `readdirplus(2,000 entries, batch=64)` | **72.59 µs/scan** | **65.052 µs** | `0` reads | Paginated `offset` cursor returning full `FuseAttr` |
| `64 × 4 KiB` seq VFS reads (`256 KiB` Zstd MC, `64 KiB` chunks) | 107.30 µs (`1.68 µs/page`) | 22.454 µs (10.873 GiB/s) | `4` reads (`309 B`) | `FuseFileHandle` single-chunk cache avoids 60/64 chunk decodes |
| `4 KiB` random VFS read (`CODEC_NONE`) | **0.13 µs/op** | **119.11 ns** (**32.027 GiB/s**) | **`1` read (`4,096 B`, `1.00x`)** | Zero read-amplification direct `read_at` |
| `4 KiB` sparse hole read | — | — | **`0` reads (`0 B`)** | Zero-I/O sparse hole fast path |

---

## 8. Cross-Format Comparison (`vz-compare`: `libvz` vs TAR / TAR.GZ / TAR.LZ4 / TAR.ZST / ZIP)

Measured with the standalone `vz-bench` binary (`cargo run --release -p vz-bench --bin vz-compare`):

### 8.1 Tiny File Overhead (`5,000` files × `1..27 B`, `69,945 B` raw)

| Format | Archive Size | Ratio | Pack Time |
| :--- | ---: | ---: | ---: |
| `VZ (None / LZ4 / Zstd / Zstd+Dict)` | 426,816 B | 6.10x | 3.81–5.96 ms |
| `ZIP (Stored)` | 619,967 B | 8.86x | 2.21 ms |
| `ZIP (Deflate)` | 574,650 B | 8.22x | 38.45 ms |
| `ZIP (Zstd)` | 630,372 B | 9.01x | 64.25 ms |
| `TAR (Uncomp)` | 5,121,024 B | 73.22x | 3.05 ms |
| `TAR.GZ` / `TAR.LZ4` / `TAR.ZST` (solid) | 74,897 B / 187,264 B / 57,460 B | 1.07x / 2.68x / 0.82x | 26.97 / 3.25 / 4.98 ms |

### 8.2 Mixed Corpus (`5,000` files, `18.32 MiB` raw): Pack / Full Unpack / Size

| Format | Size (MiB) | % of Raw | Pack MB/s | Unpack MB/s | Pack files/s |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `VZ (None)` | 19.01 | 103.8% | 1,405.06 | 6,633.31 | 383,487 |
| `VZ (LZ4)` | 1.39 | 7.6% | **2,464.78** | **8,928.17** | **672,717** |
| `VZ (Zstd)` | 1.18 | 6.4% | 794.08 | 2,372.99 | 216,729 |
| `VZ (Zstd+Dict)` | 0.73 | 4.0% | 1,386.31 | 6,494.68 | 378,369 |
| `TAR (Uncomp)` | 22.21 | 121.2% | 1,812.03 | 3,186.10 | 494,562 |
| `TAR.GZ (Deflate)` | 0.19 | 1.0% | 212.06 | 1,610.86 | 57,877 |
| `TAR.LZ4` | 0.33 | 1.8% | 2,984.23 | 2,597.21 | 814,494 |
| `TAR.ZST (Zstd)` | 0.22 | 1.2% | 1,481.40 | 2,438.73 | 404,321 |
| `ZIP (Stored)` | 18.90 | 103.1% | 1,890.01 | 3,810.15 | 515,846 |
| `ZIP (Deflate)` | 1.11 | 6.1% | 166.25 | 557.71 | 45,374 |
| `ZIP (Zstd)` | 1.06 | 5.8% | 227.48 | 1,378.29 | 62,088 |

### 8.3 Cold Open + Read Single External File (`1,213 B`, 70% offset in `5,000`-file archive) & `readdir`

| Format | Cold Open + Read | Read Calls | Bytes Read | Read Amp | `readdir` (`2,000` entries) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `VZ (None)` | 16.68 µs | 3 | 107,837 B | 88.9x | — |
| `VZ (LZ4)` | **15.59 µs** | 3 | 106,782 B | 88.0x | — |
| `VZ (Zstd)` | 16.96 µs | 3 | 106,746 B | 88.0x | **61.38 µs** (`readdir_visit`) |
| `VZ (Zstd+Dict)` | 39.78 µs | 3 | 111,771 B | 92.1x | — |
| `TAR (Uncomp)` | 5,752.38 µs | 7,004 | 16,323,773 B | 13,457.4x | — |
| `TAR.GZ` | 7,137.45 µs | 5 | 163,840 B | 135.1x | — |
| `TAR.LZ4` | 5,227.44 µs | 502 | 240,161 B | 198.0x | — |
| `TAR.ZST` | 4,799.03 µs | 2 | 226,472 B | 186.7x | 6,783.77 µs (full scan) |
| `ZIP (Stored)` | 12,073.26 µs | 5,005 | 40,499,926 B | 33,388.2x | — |
| `ZIP (Deflate)` | 11,768.31 µs | 5,005 | 40,499,926 B | 33,388.2x | — |
| `ZIP (Zstd)` | 12,024.66 µs | 5,005 | 40,499,926 B | 33,388.2x | 12,091.24 µs (`File+Buf`) |

*(Warm `MmapRangeReader` single-file read latency on the same `5,000`-file archive: `VZ (Zstd)` **`1.80 µs/op`**, `VZ (Zstd+Dict)` **`0.73 µs/op`**.)*

### 8.4 Single Large `32 MiB` Blob: Pack / Unpack / Size

| Format | Size (MiB) | Pack MB/s | Unpack MB/s |
| :--- | ---: | ---: | ---: |
| `VZ (None)` | 32.07 | 2,082.02 | 3,220.27 |
| `VZ (LZ4)` | 0.20 | **5,153.49** | **4,197.59** |
| `VZ (Zstd)` | 0.08 | 4,397.45 | 3,859.85 |
| `TAR (Uncomp)` | 32.00 | 1,663.45 | 1,609.05 |
| `TAR.GZ (Deflate)` | 0.11 | 337.48 | 942.68 |
| `TAR.LZ4` | 0.20 | 5,738.10 | 2,275.78 |
| `TAR.ZST (Zstd)` | 0.00 | 3,629.60 | 1,281.22 |
| `ZIP (Stored)` | 32.00 | 3,314.67 | 1,282.65 |
| `ZIP (Deflate)` | 0.11 | 371.96 | 1,356.97 |
| `ZIP (Zstd)` | 0.00 | 3,184.43 | 1,186.92 |

### 8.5 HTTP/1.1 Range Streaming (`mod_21/item_03501.json`, `1,213 B` inside `5,000`-file archive)

Keep-alive loopback HTTP/1.1 server (`TCP_NODELAY`, `HEAD` + `206 Partial Content` for Range clients, streaming `GET` for TAR; `BufReader<64KiB>` on `ZIP`), measured at both `0 ms` loopback and `2 ms` simulated edge/object-store RTT per request:

| Format | HTTP Requests | Transferred | Loopback (`0 ms`) | Simulated WAN (`2 ms` RTT) |
| :--- | ---: | ---: | ---: | ---: |
| `VZ (Zstd)` | **3** | **104.2 KB** | **0.26 ms** | **6.47 ms** |
| `ZIP (Zstd)` | 5,006 | 289,406.2 KB | 166.03 ms | 10,599.22 ms |
| `TAR (Stream)` | 1 | 15,941.2 KB | 10.49 ms | 14.09 ms |
| `TAR.ZST (Stream)` | 1 | 221.2 KB | 5.47 ms | 7.63 ms |

### 8.6 Random I/O & IOPS (`20,000`-file archive: `1T × 10,000`, `6T × 30,000`, `12T × 60,000` reads)

`VZ` shares a single opened `File` handle across all worker threads via stateless lock-free `pread` (or `Mmap`) with per-thread L1 + sharded L2 verified B+Tree node caching; `ZIP` opens one independent `File` handle per thread (`Seek+Read` cannot share a `File::try_clone` fd across threads):

| Format | `1T` IOPS | `1T` p50 | `1T` p99 | `6T` IOPS | `6T` p50 | `6T` p99 | `12T` IOPS | `12T` p50 | `12T` p99 | Scale (`12T/1T`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None, File pread)` | 410,810 | 2.14 µs | 7.76 µs | 2,556,968 | 1.89 µs | 6.45 µs | 2,965,954 | 2.48 µs | 8.75 µs | 7.22× |
| `VZ (None, Mmap)` | 633,318 | **1.03 µs** | 7.15 µs | 4,199,613 | 0.99 µs | 7.40 µs | 3,961,576 | 1.66 µs | 8.82 µs | 6.26× |
| `VZ (LZ4, File pread)` | 457,776 | 2.03 µs | 5.13 µs | 3,251,553 | 1.63 µs | 3.45 µs | 3,580,250 | 2.33 µs | 5.13 µs | **7.82×** |
| `VZ (LZ4, Mmap)` | **720,549** | 1.12 µs | **3.77 µs** | **4,819,399** | **0.88 µs** | **2.88 µs** | **5,295,995** | **1.25 µs** | **3.76 µs** | 7.35× |
| `VZ (Zstd, File pread)` | 288,969 | 3.51 µs | 7.58 µs | 1,902,117 | 3.13 µs | 5.86 µs | 1,840,686 | 4.61 µs | 7.71 µs | 6.37× |
| `VZ (Zstd, Mmap)` | 412,134 | 2.37 µs | 5.29 µs | 2,427,299 | 2.12 µs | 5.20 µs | 2,374,807 | 3.17 µs | 5.84 µs | 5.76× |
| `ZIP (Stored, File)` | 88,425 | 4.77 µs | 11.46 µs | 260,204 | 5.43 µs | 14.12 µs | 360,919 | 6.58 µs | 17.33 µs | 4.08× |
| `ZIP (Zstd, File)` | 88,651 | 5.80 µs | 10.57 µs | 277,107 | 6.41 µs | 14.76 µs | 372,690 | 8.82 µs | 16.48 µs | 4.20× |
| `TAR.ZST` (10-op sample) | 73.0 | 13,804 µs | 14,218 µs | N/A | — | — | N/A | — | — | — |

### 8.7 Partial Byte-Range Read inside `32 MiB` Zstd Blob (`64 KiB` window at `24 MiB` offset)

| Format | Latency | Read from Archive | Notes |
| :--- | ---: | ---: | :--- |
| `VZ (Zstd, 1 MiB chunks)` | **0.08 ms** | **1.2 KB** | `read_file_range` decodes 1 overlapping chunk only |
| `ZIP (Zstd)` | 3.22 ms | 5.2 KB | Must decompress entry stream from `0..24.06 MiB` |
| `TAR.ZST` | 2.16 ms | 3.2 KB | Must decompress solid stream from `0..24.06 MiB` |

### 8.8 Incremental Append & Selective Delete (`+10 × 4 KiB` new files, `-5` deletes on `5,000`-file archive)

| Operation | Time | Bytes Written | Semantics |
| :--- | ---: | ---: | :--- |
| `VZ (LSM Delta Append)` | **0.44 ms** | **105.3 KB** | Appends delta + updates Boot Slot; add, overwrite & tombstone delete |
| `ZIP (new_append)` | 22.02 ms | 336.2 KB | Append-only (cannot delete entries without full archive rewrite) |
| `TAR.ZST (Full Rewrite)` | 21.72 ms | 221.2 KB | Must decompress and re-pack entire archive |

### 8.9 Fault-Injection Self-Healing Recovery (`4 KiB` Boot ECC page + `256 KiB` data cluster wiped)

| Format | Recoverable? | Repair Time | Measured Result |
| :--- | :--- | ---: | :--- |
| `VZ (Boot ECC + RS(4,2))` | **YES (100%)** | **4.46 ms** | `boot_page=Some(2)`, `data_repaired=2`, `data_100%=true` |
| `TAR.ZST` | NO (Fatal) | — | Stream CRC/frame mismatch; remaining entries lost |
| `ZIP (Zstd)` | NO (Fatal) | — | Local header / stream corrupted; no redundancy |

### 8.10 Zero-Reencode LSM Compaction (`5,000` Zstd files + `200` overwrites + `100` tombstones -> single run)

| Compaction Mode | Time | Output Size | Notes |
| :--- | ---: | ---: | :--- |
| `VZ (Zero-Reencode Compact)` | **5.25 ms** | 1.19 MB | Strips LSM runs `2 -> 1`, drops `100` tombstones, copies compressed chunks verbatim |
| `VZ (Full Re-encode Compact)` | 36.76 ms | 1.19 MB | Decompresses and recompresses every live file (`7.00×` slower) |

### 8.11 FUSE3 / VFS Simulation (`FuseVolume` vs `ZIP` vs `TAR.ZST`)

| Workload | `VZ (FuseVolume)` | `ZIP (Zstd)` | `TAR.ZST` | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `readdirplus` (`2,000` entries; mount=2.44 ms, lookup=93.2 ns) | **97.36 µs** (`0` disk I/O) | 21,118.35 µs (217× slower) | 6,134.40 µs (63× slower) | Zero-I/O in-memory POSIX directory/inode graph |
| `64 × 4 KiB` seq VFS reads @ `1 MiB` (`4 MiB` Zstd) | **47.99 µs** (`4` reads, `484 B`) | 218.29 µs (`6` reads, `1,963 B`) | 159.71 µs (`1` read, `555 B`) | `FuseVolume` caches each `64 KiB` chunk across `16` pages |
| `4 KiB` random VFS read (`CODEC_NONE`, `4 MiB` file) | **0.74 µs** (`1` read, `4,096 B`) | — | — | Exact **`1.00×` read amplification** (`read_at`) |

---

## 9. Real-World Game `.pak` Replacement Case Study (Linux Kernel Corpus vs Unreal Engine `.pak`)

*(Captured in the standalone `pak_patch_bench` case-study run outside the main benchmark suite.)*

This standalone case study (`crates/vz-bench/examples/pak_patch_bench.rs`) evaluates VZ as a drop-in replacement for game asset `.pak` containers across **8 years of Linux kernel source evolution** (`61,734` -> `93,709` files, up to `1,511.99 MiB` raw payload) streamed directly from pre-existing git tags (no double-tree extraction), and directly benchmarks VZ against real **Unreal Engine `.pak` (`repak` V11 Zstd)**, `ZIP`, and `TAR.ZST`.

### 9.1 Full Container Pack & Cold-Open Overhead (`v7.1`, `93,709` files, `1,511.99 MiB` raw, Zstd)

| Format | Archive Size | Pack Time | Cold Open + 1 Read | Cold Bytes Read | 6-Thread Random IOPS |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `VZ (Zstd 256K cluster)` | **309.24 MiB** (`20.5%`) | **10,596.50 ms** | **148.90 µs** | **141,257 B** | **277,483** |
| `UE .pak (repak V11 Zstd)` | 313.46 MiB | 11,503.74 ms | 66,710.47 µs (`448×` slower) | 5,047,104 B (`35.7×` more) | 161,423 (`1.72×` slower) |

* **Why cold open differs by 448×:** Opening an Unreal Engine `.pak` must parse and allocate the entire `O(N)` `5.05 MB` central directory index (`66.71 ms`) before serving the first asset read; VZ traverses its B+tree path index in `O(log_B N)` (`141 KB`, `148.90 µs`).

### 9.2 Three-Tier Patch Matrix (`LsmAppendWriter` Across Real Kernel Releases)

| Tier | Git Transition | File Churn (`+Add / ~Mod / -Del`) | Raw Changed | Delta Written | Delta Write Time |
| :--- | :--- | :--- | ---: | ---: | ---: |
| **1. Day-1 Hotfix** | `v7.1 -> v7.1.4` | `+1 / ~658 / -4` | 29.86 MB | **7.89 MB** | **235.43 ms** |
| **2. Seasonal Update** | `v6.11 -> v6.12` | `+1,234 / ~11,506 / -359` | 314.49 MB | **82.49 MB** | **3,132.77 ms** |
| **3. Major Expansion** | `v4.19 -> v7.1` | `+50,073 / ~38,358 / -18,098` | 1,463.07 MB | **293.00 MB** | **10,132.49 ms** |

*(Base archives before delta: `v7.1` = `93,709` files / `309.24 MiB`; `v6.11` = `85,805` files / `1,400.40 MiB` raw / `286.49 MiB` VZ / `10,872.67 ms`; `v4.19` = `61,734` files / `753.20 MiB` raw / `199.12 MiB` VZ / `7,120.54 ms`.)*

### 9.3 Tier-1 Hotfix Cross-Format Comparison (`v7.1 -> v7.1.4`: `+1 / ~658 / -4`)

| Format | Patch Time | Bytes Written | Deletion Semantics |
| :--- | ---: | ---: | :--- |
| `VZ (LsmAppendWriter)` | **235.43 ms** | **7.89 MB** | Appends delta + tombstones (`4` deleted paths hidden atomically) |
| `UE .pak (repak into_writer)` | 435.17 ms | 12.72 MB | Rewrites full `O(N)` trailer; cannot delete the `4` stale files in-place |
| `TAR.ZST (Full Rewrite)` | 6,409.90 ms | 226.35 MB | Full archive recompression |
| `ZIP (raw_copy rewrite)` | 8,184.93 ms | 301.81 MB | Full archive stream copy + central directory rebuild |

### 9.4 Multi-Patch Stacking, Zero-Reencode Compaction, and Post-Patch Mmap IOPS

* **5-Run Point-Release Stack (`v7.1 -> .1 -> .2 -> .3 -> .4`, `lsm_run_count = 5`):** Total patch time across all 4 incremental appends = **246.75 ms**; `FuseVolume::mount` builds the merged `93,709`-file in-memory POSIX graph in **116.40 ms** (down from `141.07 ms`).
* **Zero-Reencode Compaction (`v4.19 -> v7.1` overlay: `492.06 MiB`, `lsm_run_count = 2`):**
  * **Zero-reencode (`compact_archive_with_options`):** **724.32 ms** -> `300.41 MiB` (**191.65 MiB / 38.9%** dead base space reclaimed).
  * **Full re-encode baseline:** **6,339.76 ms** (`8.75×` slower) -> `303.79 MiB`.
* **Mmap Random Read IOPS (`10,000` reads/thread):**
  * **Stacked Hotfix (`lsm_run_count = 5`, `v7.1.4`):** 1-Thread **58,588 IOPS** (`p50 10.04 µs`, `p99 97.11 µs`) | 6-Thread **253,369 IOPS** (`p50 10.38 µs`, `p99 120.18 µs`)
  * **Massive Expansion Delta (`lsm_run_count = 2`, `v4.19 -> v7.1`):** 1-Thread **58,461 IOPS** (`p50 10.00 µs`, `p99 104.55 µs`) | 6-Thread **331,800 IOPS** (`p50 9.00 µs`, `p99 109.10 µs`)
  * **Compacted Single-Run (`lsm_run_count = 1`, `v7.1`):** 1-Thread **57,840 IOPS** (`p50 10.03 µs`, `p99 110.34 µs`) | 6-Thread **333,652 IOPS** (`p50 9.03 µs`, `p99 109.62 µs`)

---

## 10. Reproduction

```bash
cargo bench -p libvz --all-features
cargo run --release -p libvz --all-features --example metrics_runner
cargo run --release -p vz-bench --bin vz-compare
cargo build --workspace --release --all-features
```

### Optional Real-World Case Study (`.pak` Patch Benchmark, Outside Main Suite)

The 3-tier Linux kernel `.pak` replacement example (`crates/vz-bench/examples/pak_patch_bench.rs`) streams preexisting tags (`v4.19`, `v6.11`, `v6.12`, and `v7.3..v7.3.4` or `v7.1..v7.1.4`) directly from git into `VzWriter`, `LsmAppendWriter`, `compact_archive_with_options`, `FuseVolume`, and Unreal Engine `.pak` (`repak`):

```bash
# Run read-only against an existing local Linux git repo (zero network fetch):
cargo run --release -p vz-bench --example pak_patch_bench -- --repo /path/to/linux.git
# Or fetch shallow tags into a standalone bare repo:
cargo run --release -p vz-bench --example pak_patch_bench -- --fetch /tmp/vz-linux-corpus
```
