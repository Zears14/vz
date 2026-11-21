# VZ v1.0 Benchmark Report

All results in this report were directly measured on commit `25f0608` across two reference systems—a **12-thread Zen 3 workstation** and a **48-thread Zen 5 EPYC server** (both compiled with default `--release` using runtime SIMD dispatch)—via:
- `cargo run --release -p libvz --all-features --example metrics_runner`
- `cargo run --release -p vz-bench --bin vz-compare` (`allocator: system` / `glibc`)
- `cargo run --release -p vz-bench --features mimalloc --bin vz-compare` (`allocator: mimalloc`)
- `cargo run --release -p vz-bench --features mimalloc --example pak_patch_bench` (`--repo /home/zears/android/kernel/a22-ksun` on 12T; `--fetch /tmp/vz-linux-corpus` on 48T)
- `cargo bench -p libvz --all-features` (`criterion` in [vz_benchmarks.rs](file:///home/zears/vz/crates/libvz/benches/vz_benchmarks.rs))

No numbers are estimated or extrapolated.

---

## Test Environments

| Property | Workstation Rig (Local, 12T) | Server Rig (Colab Enterprise, 48T) |
| :--- | :--- | :--- |
| **CPU** | AMD Ryzen 5 5600H (Zen 3, 6C / 12T) | AMD EPYC 9B45 (Zen 5, 24C / 48T, 1 socket, NUMA node0 `0–47`) |
| **`available_parallelism`** | `12` | `48` |
| **Memory** | Workstation DDR4 | `176 GiB` RAM |
| **OS / Kernel** | Linux `7.3.4-1-cachyos` `x86_64` | Linux `6.6.159+` `x86_64` |
| **Toolchain** | `rustc 1.97.1 (8bab26f4f 2026-07-14)` | `rustc 1.100.0 (0ef1bc386 2026-11-09)` |
| **Compile Profile** | Default `--release` (portable build, runtime SIMD dispatch) | Default `--release` (portable build, runtime SIMD dispatch) |
| **CPU SIMD Flags** | `sse4_2 avx2 pclmulqdq vpclmulqdq aes vaes` | `sse4_2 avx2 avx512f avx512bw avx512vl pclmulqdq vpclmulqdq gfni aes vaes` |
| **Active `crc32c` Tier** | `AVX2 + VPCLMULQDQ` (`>= 256 B`), `SSE4.2` (`< 256 B`) | `AVX-512F/VL + VPCLMULQDQ` (`>= 512 B`), `AVX2 + VPCLMULQDQ` (`256..511 B`), `SSE4.2` (`< 256 B`) |
| **Active `RS_GF256` Tier** | 2×-unrolled `AVX2 vpshufb` + 32 KiB L1/L2 tile blocking | `AVX-512BW/VL + GFNI` (`VGF2P8AFFINEQB` 64 B/iter) + 32 KiB L1/L2 tile blocking |
| **Active `boot_ecc` Tier** | 15-way single-pass `AVX2` XOR + hw `crc32c` | 15-way single-pass `AVX2` XOR + hw `crc32c` |

### Architecture & Benchmark Methodology Highlights

- **Tiered Cross-Architecture Hardware Dispatch:** Runtime CPU feature detection on `x86_64` (`VPCLMULQDQ`, `GFNI`, `AVX-512BW/VL`, `AVX2`, `PCLMULQDQ`, `SSE4.2`, `SSSE3`) and `aarch64` (`crc`, `NEON`), plus compile-time `wasm32 simd128` and `#![no_std]` portable fallbacks. Even without `-C target-cpu=native`, runtime `#[target_feature]` dispatch unlocks `62.4 GB/s` `crc32c` and `49.0 GB/s` `GF(2^8)` Cauchy Reed-Solomon on EPYC 9B45.
- **Persistent Scoped Worker Pool ([parallel.rs](file:///home/zears/vz/crates/libvz/src/parallel.rs)):** Lazily initialized lock-free work-stealing pool with cache-line-aligned per-worker slots (`#[repr(align(64))]`) and selective `unpark()`/`park()`. Keeps per-worker TLS compression/decompression/decryption contexts (`ZSTD_COMP_TLS`, `ZSTD_DCTX_TLS`, `LZ4_COMP_SCRATCH`, `DEC_SCRATCH_TLS`) warm across `VzWriter::add_files_batch`, `LsmAppendWriter::add_files_batch`, `VzReader::extract_all_with`, multi-cluster reads, and `RS_GF256` recovery.
- **Wait-Free 2-Way Set-Associative TLS L1 Node Cache ([lookup.rs](file:///home/zears/vz/crates/libvz/src/reader/lookup.rs)):** 64-set × 2-way (`128`-slot) thread-local L1 cache for both `Mmap` (`VerifiedSlice`) and buffered/`File` (`Arc<CachedNode>` up to `256 KiB` leaf payloads, borrowed in-place with zero `Arc` refcount traffic and zero `RwLock` contention on L1 hits), backed by a sharded cache-padded L2 cache.
- **Dedicated Best-Case ZIP Reader (`BestCaseZipReader<R: RangeReader>` in [main.rs](file:///home/zears/vz/crates/vz-bench/src/main.rs)):** Eliminates `zip::ZipArchive`'s `O(N)` Local-File-Header seek storm (`5,005` seeks on open) and per-read `zstd::stream::Decoder` allocations so `ZIP` vs `VZ` is a pure format comparison:
  - Parses the 22-byte EOCD (`0x06054b50`) + Central Directory (`0x02014b50`) in **2 `read_at` calls**,
  - Performs cold single-file reads (`[3]` & `[6] HTTP Range`) by scanning the Central Directory slice in-place without building a `HashMap` and issuing **1 coalesced `read_at`** for the 30-byte Local File Header + compressed payload (**3 local reads / 4 HTTP requests total**),
  - Shares a single lock-free `Arc<BestCaseZipReader<File>>` (stateless `pread`) or `Arc<BestCaseZipReader<MmapRangeReader>>` (zero-copy `Mmap` slice) across all threads in `[7]` and reuses the exact same thread-local `zstd_safe::DCtx` decompression path as `VzReader`.
- **Realistic Non-Near-Zero Structured Telemetry Corpus:** Both `metrics_runner` and `vz-compare` generate structured JSON telemetry records combining a shared 135-byte JSON schema header with a 64-phrase vocabulary and per-record 64-bit `xorshift64*` hex tokens, yielding realistic compression ratios (`~21.8–33.1%` Zstd, `~26.6–31.3%` Zstd+Dict, `~37.1–62.3%` LZ4) rather than synthetic RLE repetition.
- **Allocator Strategy ([vz-tools](file:///home/zears/vz/crates/vz-tools/Cargo.toml), [vz-bench](file:///home/zears/vz/crates/vz-bench/Cargo.toml)):** `libvz` and `libvz-ffi` remain 100% allocator-agnostic. The `vz` CLI enables `mimalloc` by default (`default = ["mimalloc"]`), and `vz-bench` exposes `--features mimalloc` alongside the default system allocator (`glibc`).

---

## 1. Primitive Throughput & Latency (`metrics_runner [1]`)

### 1.1 Castagnoli `crc32c`

| Buffer Size | Ryzen 5 5600H (12T, `AVX2+VPCLMULQDQ`) | Ryzen 5 5600H Latency | EPYC 9B45 (48T, `AVX-512+VPCLMULQDQ`) | EPYC 9B45 Latency |
| ---: | ---: | ---: | ---: | ---: |
| `64 B` | 18,469.06 MB/s | 3.30 ns/op | **25,142.18 MB/s** | **2.43 ns/op** |
| `4 KiB` | 30,383.99 MB/s | 128.56 ns/op | **60,547.18 MB/s** | **64.52 ns/op** |
| `64 KiB` | **30,703.79 MB/s** | 2,035.58 ns/op | **62,398.39 MB/s** | **1,001.63 ns/op** |
| `1 MiB` | 30,173.76 MB/s | 33,141.38 ns/op | **62,434.09 MB/s** | **16,016.89 ns/op** |
| `16 MiB` | 19,270.00 MB/s | 830,305.97 ns/op | **60,705.80 MB/s** | **263,566.25 ns/op** |

### 1.2 LE-VINT Encode / Decode

| Operation | Ryzen 5 5600H (ns/op) | Ryzen 5 5600H (Mops/s) | EPYC 9B45 (ns/op) | EPYC 9B45 (Mops/s) |
| :--- | ---: | ---: | ---: | ---: |
| `read_levint_fast` (`&[u8; 8]`) | 0.71 ns/op | 1,416.13 Mops/s | **0.50 ns/op** | **2,018.42 Mops/s** |
| `read_levint_safe` (`&[u8]`) | 1.09 ns/op | 919.12 Mops/s | **0.65 ns/op** | **1,543.89 Mops/s** |
| `write_levint` | 1.33 ns/op | 750.15 Mops/s | **0.97 ns/op** | **1,032.54 Mops/s** |

### 1.3 Boot Block 4 KiB ECC (`64 KiB`, 15-Way SIMD XOR + Hardware `crc32c`)

| Operation | Ryzen 5 5600H (µs/op) | EPYC 9B45 (µs/op) |
| :--- | ---: | ---: |
| `boot_ecc_encode` | 3.18 µs/op | **1.67 µs/op** |
| `boot_ecc_verify_clean` (clean fast path) | **2.10 µs/op** | **1.04 µs/op** |
| `boot_ecc_verify_and_repair` (`1` page repair) | 3.14 µs/op | **1.74 µs/op** |

### 1.4 Reed-Solomon `GF(2^8)` Cauchy Erasure Coding (`1 MiB` Clusters)

| Operation | Ryzen 5 5600H (12T, 2× `AVX2 vpshufb`) | EPYC 9B45 (48T, `AVX-512 GFNI` `VGF2P8AFFINEQB`) |
| :--- | ---: | ---: |
| `rs_gf256_madd_slice` (`1 MiB`, 1 thread) | 40,837.81 MB/s | **49,046.87 MB/s** |
| `RS_GF256` `K=8, M=2` encode (data throughput) | 14,505.26 MB/s | **21,987.38 MB/s** |
| `RS_GF256` `K=8, M=2` recover (`2` erasures) | **27,983.02 MB/s** | **36,393.58 MB/s** |
| `RS_GF256` `K=16, M=4` encode (data throughput) | 10,047.75 MB/s | **30,194.32 MB/s** |
| `RS_GF256` `K=16, M=4` recover (`4` erasures) | **23,514.55 MB/s** | **32,710.54 MB/s** |

---

## 2. End-to-End Pack & Unpack Throughput — Non-Near-Zero Structured Corpus (`metrics_runner [2]`)

### 2.1 Many-Small-Files Corpus (`10,000` files, `0 B .. 4 KiB`, `19.54 MiB` total raw)

| Codec / Mode | Archive Size (`% of Raw`) | Ryzen 5 5600H (12T) Pack | Ryzen 5 5600H (12T) Unpack | EPYC 9B45 (48T) Pack | EPYC 9B45 (48T) Unpack |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `CODEC_NONE` | 20.96 MiB (`107.3%`) | **847.67 MB/s** (433,901 f/s) | **5,385.83 MB/s** (2,756,862 f/s) | 1,174.14 MB/s (601,010 f/s) | **11,193.61 MB/s** (5,729,707 f/s) |
| `CODEC_LZ4` | 12.18 MiB (`62.3%`) | 690.24 MB/s (353,317 f/s) | 1,747.60 MB/s (894,552 f/s) | **1,567.70 MB/s** (802,463 f/s) | 7,209.90 MB/s (3,690,553 f/s) |
| `CODEC_ZSTD` | 8.60 MiB (`44.0%`) | 497.42 MB/s (254,617 f/s) | 1,277.49 MB/s (653,914 f/s) | 1,437.08 MB/s (735,604 f/s) | 2,874.57 MB/s (1,471,417 f/s) |
| `ZSTD + Dict` (`CDict`/`DDict`) | **6.11 MiB (`31.3%`)** | 508.38 MB/s (260,224 f/s) | 1,095.15 MB/s (560,578 f/s) | 1,370.36 MB/s (701,448 f/s) | 1,793.80 MB/s (918,199 f/s) |
| `Encrypted (Raw256)` | 21.34 MiB (`109.2%`) | 358.26 MB/s (183,384 f/s) | 2,107.01 MB/s (1,078,521 f/s) | 395.24 MB/s (202,312 f/s) | 5,237.00 MB/s (2,680,678 f/s) |

### 2.2 Large Multi-Cluster Blob (`64 MiB` payload, `1 MiB` clusters)

| Codec / Mode | Archive Size (`% of Raw`) | Ryzen 5 5600H (12T) Pack | Ryzen 5 5600H (12T) Unpack | EPYC 9B45 (48T) Pack | EPYC 9B45 (48T) Unpack |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `CODEC_NONE` | 64.08 MiB (`100.1%`) | **2,506.85 MB/s** | 4,602.76 MB/s | 2,477.35 MB/s | **5,707.15 MB/s** |
| `CODEC_LZ4` | 23.77 MiB (`37.1%`) | 2,039.75 MB/s | **4,842.75 MB/s** | 5,295.20 MB/s | 5,581.91 MB/s |
| `CODEC_ZSTD` | **13.96 MiB (`21.8%`)** | 1,167.59 MB/s | 3,833.04 MB/s | **7,056.44 MB/s** | 5,040.30 MB/s |
| `Encrypted (Raw256)` | 64.08 MiB (`100.1%`) | 1,263.58 MB/s | 2,757.95 MB/s | 1,733.19 MB/s | 4,661.52 MB/s |

*(Note: `metrics_runner` uses `TrackingAllocator` wrapping `glibc`; see Section 8.4 for `32 MiB` multi-cluster unpack reaching **16.70 GB/s** on `VZ (Zstd)` and **15.42 GB/s** on `VZ (LZ4)` under `mimalloc` on EPYC 9B45.)*

---

## 3. Random-Access Lookup, Indexing Latency & Multi-Core Scaling (`metrics_runner [3, 4, 8]`)

### 3.1 Cold Open, `stat`, and `read_file` (`1 KiB` payload): `MmapRangeReader` vs `File`

Because `BUF_NODE_L1` caches verified `Arc<CachedNode>` B+Tree leaves up to `256 KiB` in a 64-set × 2-way thread-local cache, warm `stat` latency on `File` is virtually identical to zero-copy `Mmap`:

| Archive Scale | Tree Height | Rig | Cold Open (`File`) | `stat` (`Mmap`) | `stat` (`File`) | `read_file` (`Mmap`) | `read_file` (`File`) |
| ---: | ---: | :--- | ---: | ---: | ---: | ---: | ---: |
| `100` files | `0` | Ryzen 5 5600H (12T) | 10.32 µs | 0.37 µs | 0.34 µs | 0.26 µs | 0.85 µs |
| `10,000` files | `1` | Ryzen 5 5600H (12T) | 9.69 µs | 0.43 µs | 0.44 µs | 0.33 µs | 0.99 µs |
| `100,000` files | `2` | Ryzen 5 5600H (12T) | 9.52 µs | 0.49 µs | 0.52 µs | 0.38 µs | 1.17 µs |
| `100` files | `0` | **EPYC 9B45 (48T)** | **5.21 µs** | **0.26 µs** | **0.26 µs** | **0.19 µs** | **0.45 µs** |
| `10,000` files | `1` | **EPYC 9B45 (48T)** | **5.09 µs** | **0.33 µs** | **0.34 µs** | **0.26 µs** | **0.53 µs** |
| `100,000` files | `2` | **EPYC 9B45 (48T)** | **5.20 µs** | **0.37 µs** | **0.39 µs** | **0.30 µs** | **0.61 µs** |

### 3.2 `readdir` vs Zero-Copy `readdir_visit` Scaling

| Directory Size | Ryzen 5 5600H Owned `readdir` | Ryzen 5 5600H `readdir_visit` | EPYC 9B45 Owned `readdir` | EPYC 9B45 `readdir_visit` |
| ---: | ---: | ---: | ---: | ---: |
| `10` entries | 1.59 µs/op | **0.50 µs/op** | 1.25 µs/op | **0.35 µs/op** |
| `5,000` entries | 1,607.25 µs/op | **140.62 µs/op** (`11.4×` faster) | 1,071.23 µs/op | **102.21 µs/op** (`10.5×` faster) |

### 3.3 LSM Overlay Read Latency (`1`, `4`, `16` Runs vs Compacted)

| State | Ryzen 5 5600H `read_file` | EPYC 9B45 `read_file` |
| :--- | ---: | ---: |
| `1` run (baseline) | 0.23 µs/op | **0.19 µs/op** |
| `4` runs | 0.35 µs/op | **0.25 µs/op** |
| `16` runs | 0.71 µs/op | **0.49 µs/op** |
| Compacted (`1` run) | **0.26 µs/op** | **0.18 µs/op** |

### 3.4 Multi-Threaded Random I/O Scaling (`10,000` files, `read_file_into` reusing caller buffer, Non-Near-Zero Corpus)

| Rig | Codec | `File` (`1T`) | `File` (`Max T`) | `File` Scale | `Mmap` (`1T`) | `Mmap` (`Max T`) | `Mmap` Scale |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **Ryzen 5 5600H (6C/12T)** | `CODEC_NONE` | 542,872 | **6,151,730 (`12T`)** | **11.33×** | 1,087,878 | **10,180,219 (`12T`)** | **9.18×** |
| **Ryzen 5 5600H (6C/12T)** | `CODEC_LZ4` | 374,884 | 3,322,683 (`12T`) | 8.86× | 646,594 | 4,841,322 (`12T`) | 7.49× |
| **Ryzen 5 5600H (6C/12T)** | `CODEC_ZSTD` | 174,898 | 1,253,227 (`12T`) | 7.17× | 211,007 | 1,335,215 (`12T`) | 6.73× |
| **EPYC 9B45 (24C/48T)** | `CODEC_NONE` | **1,010,909** | **8,983,680 (`48T`)** | 8.89× | **1,636,021** | **48,486,024 (`48T`)** | 29.64× |
| **EPYC 9B45 (24C/48T)** | `CODEC_LZ4` | 738,107 | 8,706,418 (`48T`) | 11.80× | 949,529 | **27,685,815 (`48T`)** | 29.16× |
| **EPYC 9B45 (24C/48T)** | `CODEC_ZSTD` | 270,318 | 6,688,788 (`48T`) | **24.74×** | 293,271 | **10,142,807 (`48T`)** | **34.59×** |

---

## 4. Remote / HTTP Range I/O Efficiency (`CountingRangeReader`, `metrics_runner [3 & 4]`)

Reading a single `1 KiB` external file out of `100`, `10,000`, and `100,000`-file archives (identical deterministic I/O counts across both rigs):

| Archive Scale | Tree Height | Cold RTTs (Open + Lookup + Read) | Cold Bytes Fetched | Cold Read Amp | Warm RTTs (After Open) | Warm Bytes Fetched | Warm Read Amp |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `100` files | `0` | 2 RTTs | 66,560 B | 65.0× | 1 RTT | 1,024 B | **1.0×** |
| `10,000` files | `1` | 3 RTTs | 106,112 B | 103.6× | 1 RTT | 1,024 B | **1.0×** |
| `100,000` files | `2` | 4 RTTs | 109,440 B | 106.9× | 1 RTT | 1,024 B | **1.0×** |

*(For `<= 27 B` inline files when `tree_height == 0`, total cold RTTs is **1 RTT** = `65,536 B`, verified in [range_rtt_tests.rs](file:///home/zears/vz/crates/libvz/tests/range_rtt_tests.rs).)*

---

## 5. Space Overhead & Alignment Efficiency (`metrics_runner [5]`)

| Workload | Raw Payload Size | Archive Size | Ratio (`archive / raw`) | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `5,000` inline files (`1..27 B`) | 69,945 B | 411,776 B | 5.887× | Zero data clusters (`data_clusters = 0`); includes `64 KiB` Boot Block |
| `5,000` external files (`28 B`) | 140,000 B | 731,904 B | 5.228× | Each `28 B` external entry incurs `TAG_DATA_MANIFEST` + 64B alignment |
| Mixed codebase (`500` files, `1..64 KiB`) | 16,355,250 B | 16,456,576 B | 1.0062× | **+0.62%** total metadata + 64B Void alignment overhead |
| `16 MiB` blob (no Boot ECC) | 16,777,216 B | 16,846,400 B | 1.0041× | **+0.412%** (`64 KiB` Boot Block + cluster headers/footers/Void) |
| `16 MiB` blob (+ Boot ECC `4 KiB + 80 B`) | 16,777,216 B | 16,846,400 B | 1.0041× | **+0.412%** (`Boot ECC` fits inside existing fixed `64 KiB` Boot Block) |
| `16 MiB` blob (+ `RS_GF256` `K=8, M=2`) | 16,777,216 B | 21,043,648 B | 1.2543× | **+25.43%** (`M/K = 25%` erasure parity + cluster framing) |

---

## 6. Streaming Memory Footprint (`64 MiB` Payload, `1 MiB` Cluster Size, `metrics_runner [6]`)

Instrumented via `TrackingAllocator` (scoped strictly to section `[6]`) and `/proc/self/status` `VmHWM`:

| Operation | Heap Allocations | Peak Heap Delta | Ryzen 5 5600H `VmHWM` | EPYC 9B45 `VmHWM` |
| :--- | ---: | ---: | ---: | ---: |
| `64 MiB` streaming pipe write (`VzPipeWriter::add_file_reader`) | 157 allocs | **2.00 MiB** | — | — |
| `64 MiB` multi-cluster streaming read (`VzReader::read_file_to_writer`) | 71 allocs | **1.07 MiB** | 314,752 KiB | 404,836 KiB |

---

## 7. FUSE3 VFS Surface (`FuseVolume`, `metrics_runner [7]`)

| Operation | Ryzen 5 5600H (12T) | EPYC 9B45 (48T) | Disk Reads / Amp | Notes |
| :--- | ---: | ---: | :--- | :--- |
| `FuseVolume::mount` (`5,003` entries) | 1.80 ms | **1.50 ms** | `0` reads post-mount | Resolves LSM overlays, hardlink `nlink`, and implicit parents |
| `getattr(ino)` (`O(1)`) | 6.7 ns/op (`149.7 Mops/s`) | **4.4 ns/op** (**`229.4 Mops/s`**) | `0` reads | Direct inode-vec slot access |
| `lookup(parent_ino, name)` (`2k` dir) | 41.6 ns/op (`24.03 Mops/s`) | **34.3 ns/op** (**`29.13 Mops/s`**) | `0` reads | Binary search over flat child arena + 8-byte inline prefix |
| `readdirplus(2,000 entries, batch=64)` | 64.83 µs/scan | **59.25 µs/scan** | `0` reads | Paginated `offset` cursor returning full `FuseAttr` |
| `64 × 4 KiB` seq VFS reads (`256 KiB` Zstd MC, `64 KiB` chunks) | 269.14 µs (`4.21 µs/page`) | **194.88 µs** (**`3.04 µs/page`**) | `4` reads (`58,453 B`) | `FuseFileHandle` single-chunk cache avoids 60/64 chunk decodes |
| `4 KiB` random VFS read (`CODEC_NONE`) | 0.10 µs/op | **0.10 µs/op** | **`1` read (`4,096 B`, `1.00×`)** | Zero read-amplification direct `read_at` |
| `4 KiB` sparse hole read | — | — | **`0` reads (`0 B`)** | Zero-I/O sparse hole fast path |

---

## 8. Cross-Format Comparison (`vz-compare`: `libvz` vs TAR / TAR.GZ / TAR.LZ4 / TAR.ZST / Dedicated Best-Case ZIP)

Measured with the standalone `vz-bench` binary using the **realistic non-near-zero structured corpus** and the **dedicated `BestCaseZipReader<R: RangeReader>`** under both `allocator: system` (`glibc`) and `allocator: mimalloc`:

### 8.1 Tiny File Overhead (`5,000` files × `1..27 B`, `69,945 B` raw)

| Format | Archive Size | Ratio | Ryzen 5 5600H Pack (`sys` / `mi`) | EPYC 9B45 Pack (`sys` / `mi`) |
| :--- | ---: | ---: | ---: | ---: |
| `VZ (None)` | 426,816 B | 6.10× | 4.58 ms / 3.21 ms | 2.61 ms / 2.66 ms |
| `VZ (LZ4)` | 426,816 B | 6.10× | 4.38 ms / **2.62 ms** | 2.48 ms / **1.80 ms** |
| `VZ (Zstd)` | 426,816 B | 6.10× | 3.95 ms / 3.35 ms | 1.91 ms / 1.82 ms |
| `VZ (Zstd+Dict)` | 426,816 B | 6.10× | 4.54 ms / 3.33 ms | 1.99 ms / 2.02 ms |
| `TAR (Uncomp)` | 5,121,024 B | 73.22× | 2.68 ms / 2.84 ms | 2.17 ms / 1.75 ms |
| `TAR.GZ (Deflate)` | 74,897 B | 1.07× | 28.05 ms / 26.34 ms | 15.08 ms / 15.21 ms |
| `TAR.LZ4` | 187,264 B | 2.68× | 2.92 ms / 3.15 ms | 1.97 ms / 1.96 ms |
| `TAR.ZST (Zstd)` | 57,460 B | 0.82× | 4.40 ms / 5.27 ms | 2.79 ms / 3.42 ms |
| `ZIP (Stored)` | 619,967 B | 8.86× | 3.43 ms / **2.16 ms** | 1.72 ms / **1.53 ms** |
| `ZIP (Deflate)` | 574,650 B | 8.22× | 37.98 ms / 43.51 ms | 18.62 ms / 18.86 ms |
| `ZIP (Zstd)` | 630,372 B | 9.01× | 62.59 ms / 64.25 ms | 40.19 ms / 39.80 ms |

### 8.2 Mixed Corpus (`5,000` files, `18.32 MiB` raw, non-near-zero structured data): Pack / Full Unpack / Size

| Format | Size (MiB) | % of Raw | Ryzen 5 5600H Pack (`sys` / `mi`) | Ryzen 5 5600H Unpack (`sys` / `mi`) | EPYC 9B45 Pack (`sys` / `mi`) | EPYC 9B45 Unpack (`sys` / `mi`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None)` | 19.01 | 103.8% | 1,523.7 / 1,373.1 MB/s | 7,679.8 / 6,436.8 MB/s | 2,136.6 / 2,799.8 MB/s | **18,901.7 / 21,074.8 MB/s** |
| `VZ (LZ4)` | 9.24 | 50.4% | **1,186.9 / 1,183.9 MB/s** | **2,670.2 / 2,617.3 MB/s** | 2,356.5 / 2,337.8 MB/s | **12,302.5 / 11,592.9 MB/s** |
| `VZ (Zstd)` | 6.06 | 33.1% | 826.7 / 762.5 MB/s | 1,774.2 / 1,692.1 MB/s | **2,715.7 / 2,633.3 MB/s** | **3,986.1 / 4,145.2 MB/s** |
| `VZ (Zstd+Dict)` | **4.87** | **26.6%** | 814.8 / **893.1 MB/s** | 1,511.5 / 1,005.3 MB/s | **2,884.5 / 2,712.2 MB/s** | 2,853.4 / 2,746.5 MB/s |
| `TAR (Uncomp)` | 22.21 | 121.2% | 1,603.8 / 1,191.4 MB/s | 3,424.0 / 3,483.7 MB/s | 2,614.5 / 4,006.9 MB/s | 5,706.7 / 6,268.1 MB/s |
| `TAR.GZ (Deflate)` | 3.20 | 17.5% | 31.4 / 30.8 MB/s | 656.7 / 660.7 MB/s | 37.8 / 37.9 MB/s | 765.5 / 763.7 MB/s |
| `TAR.LZ4` | 6.98 | 38.1% | 468.5 / 435.5 MB/s | 1,423.0 / 1,437.3 MB/s | 577.7 / 561.2 MB/s | 2,264.2 / 2,246.8 MB/s |
| `TAR.ZST (Zstd)` | 4.07 | 22.2% | 247.1 / 242.4 MB/s | 787.0 / 776.6 MB/s | 348.1 / 341.0 MB/s | 1,300.6 / 1,276.0 MB/s |
| `ZIP (Stored, BestCase)` | 18.90 | 103.1% | 2,034.0 / 1,613.2 MB/s | **8,968.7 / 7,517.0 MB/s** | 2,952.6 / 3,583.1 MB/s | 18,739.4 / 21,039.4 MB/s |
| `ZIP (Deflate, BestCase)` | 5.34 | 29.1% | 52.6 / 51.6 MB/s | 323.6 / 330.2 MB/s | 68.6 / 68.5 MB/s | 396.6 / 396.8 MB/s |
| `ZIP (Zstd, BestCase)` | 5.97 | 32.6% | 126.2 / 122.6 MB/s | 659.4 / 656.8 MB/s | 182.0 / 178.4 MB/s | 934.6 / 941.6 MB/s |

* **Key comparison (`VZ (Zstd)` vs `ZIP (Zstd, BestCase)` & `TAR.ZST`):** On identical per-file Zstd compression (`~6.0 MiB` archive size), `VZ (Zstd)` packs **14.8× faster** (`2,633–2,716 MB/s` vs `178–182 MB/s`) and unpacks **4.4× faster** (`3,986–4,145 MB/s` vs `935–942 MB/s`) than `ZIP (Zstd, BestCase)` on EPYC 9B45, while `VZ (Zstd+Dict)` reduces the indexed random-access archive size by an additional **19.6%** (`4.87 MiB` vs `5.97 MiB`) at **`2,884.5 MB/s` (`787,274 files/s`)**.

### 8.3 Cold Open + Read Single External File (`1,213 B`, 70% offset in `5,000`-file archive) & `readdir`

| Format | Read Calls | Bytes Read | Read Amp | Ryzen 5 5600H Cold Latency (`sys` / `mi`) | EPYC 9B45 Cold Latency (`sys` / `mi`) | `readdir` `2k` Entries (Ryzen / EPYC) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None)` | **3** | 107,837 B | 88.9× | 19.11 / 15.11 µs | 7.41 / 7.09 µs | — |
| `VZ (LZ4)` | **3** | 107,407 B | 88.5× | **14.33 / 14.42 µs** | 8.73 / **6.78 µs** | — |
| `VZ (Zstd)` | **3** | **107,165 B** | **88.3×** | 17.15 / 17.74 µs | **8.53 / 8.62 µs** | 56.28 µs / 41.50 µs (`readdir_visit`) |
| `VZ (Zstd+Dict)` | **3** | 112,052 B | 92.4× | 47.56 / 60.49 µs | 26.39 / 28.09 µs | — |
| `TAR (Uncomp)` | 7,004 | 16,323,773 B | 13,457.4× | 5,840.8 / 5,503.0 µs | 2,752.1 / 2,959.0 µs | — |
| `TAR.GZ` | 72 | 2,359,296 B | 1,945.0× | 19,437.5 / 19,399.4 µs | 16,165.5 / 16,381.8 µs | — |
| `TAR.LZ4` | 502 | 5,143,858 B | 4,240.6× | 9,168.0 / 9,075.3 µs | 5,746.5 / 5,727.0 µs | — |
| `TAR.ZST` | 23 | 3,014,725 B | 2,485.3× | 15,913.5 / 16,443.6 µs | 9,749.3 / 9,859.5 µs | 21,141.4 µs / 13,887.8 µs (full scan) |
| `ZIP (Stored, BestCase)` | **3** | 343,287 B | 283.0× | 49.62 / 55.21 µs | 17.58 / 17.76 µs | — |
| `ZIP (Deflate, BestCase)` | **3** | 342,577 B | 282.4× | 50.27 / 50.14 µs | 22.72 / 22.68 µs | — |
| `ZIP (Zstd, BestCase)` | **3** | 342,616 B | 282.5× | 50.17 / 40.72 µs | 19.94 / 21.06 µs | 48.42 µs / 23.32 µs (2-read CD scan) |

* **Why VZ reads 3.2× fewer bytes on cold open than `BestCaseZipReader` (`107 KB` vs `343 KB`):** Even an optimal ZIP reader (`3` `pread` calls: 22-byte EOCD + Central Directory + coalesced LFH/payload) must fetch and linearly scan the entire monolithic `278 KiB` Central Directory at the end of the archive (`O(N)` metadata bytes), whereas VZ reads only the fixed `64 KiB` Boot Block + the single target B+Tree leaf (`O(log_B N)` metadata bytes, **2.3–2.5× faster** cold lookup on both rigs).
* **Warm `MmapRangeReader` single-file read latency on the same `5,000`-file archive:** Ryzen 5 5600H `VZ (Zstd)` **`2.96–3.36 µs/op`**, `VZ (Zstd+Dict)` **`3.03–3.35 µs/op`**, `ZIP (Zstd, BestCase)` **`2.62–2.93 µs/op`**; EPYC 9B45 `VZ (Zstd)` **`2.28–2.31 µs/op`**, `VZ (Zstd+Dict)` **`2.26–2.28 µs/op`**, `ZIP (Zstd, BestCase)` **`1.94–1.99 µs/op`** (where `BestCaseZipReader` uses an in-memory `HashMap<String, ZipCdEntry>` without checksum verification while `VzReader` traverses its B+Tree and verifies hardware `crc32c`).

### 8.4 Single Large `32 MiB` Blob (Non-Near-Zero Structured Data): Pack / Unpack / Size

| Format | Size (MiB) | % of Raw | Ryzen 5 5600H Pack (`sys` / `mi`) | Ryzen 5 5600H Unpack (`sys` / `mi`) | EPYC 9B45 Pack (`sys` / `mi`) | EPYC 9B45 Unpack (`sys` / `mi`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None)` | 32.07 | 100.2% | 2,938.7 / 2,659.7 MB/s | 4,530.0 / 4,209.0 MB/s | 3,330.1 / 6,394.3 MB/s | 4,734.0 / 14,266.5 MB/s |
| `VZ (LZ4)` | 11.92 | 37.3% | **2,463.6 / 1,982.9 MB/s** | 2,746.2 / **6,767.6 MB/s** | 6,653.8 / 5,162.6 MB/s | **13,512.0 / 15,420.7 MB/s** |
| `VZ (Zstd)` | **7.01** | **21.9%** | **1,059.2 / 1,017.0 MB/s** | **2,831.2 / 3,370.8 MB/s** | **7,558.2 / 5,567.6 MB/s** | **13,238.5 / 16,696.3 MB/s** |
| `TAR (Uncomp)` | 32.00 | 100.0% | 2,843.3 / 3,007.9 MB/s | 2,801.0 / 1,811.6 MB/s | 3,695.9 / 6,837.5 MB/s | 2,015.3 / 4,159.2 MB/s |
| `TAR.GZ (Deflate)` | 5.43 | 17.0% | 31.1 / 31.0 MB/s | 688.3 / 634.1 MB/s | 36.4 / 36.5 MB/s | 765.8 / 760.1 MB/s |
| `TAR.LZ4` | 12.06 | 37.7% | 513.4 / 498.8 MB/s | 1,596.3 / 1,374.7 MB/s | 618.3 / 610.7 MB/s | 2,102.5 / 2,575.8 MB/s |
| `TAR.ZST (Zstd)` | 7.04 | 22.0% | 283.0 / 261.5 MB/s | 775.6 / 627.8 MB/s | 368.2 / 362.6 MB/s | 1,204.2 / 1,365.8 MB/s |
| `ZIP (Stored, BestCase)` | 32.00 | 100.0% | 3,192.0 / 2,214.4 MB/s | **13,189.8 / 13,867.1 MB/s** | 3,785.7 / 6,250.4 MB/s | 3,695.3 / **27,365.2 MB/s** |
| `ZIP (Deflate, BestCase)` | 5.43 | 17.0% | 31.6 / 32.0 MB/s | 784.8 / 767.8 MB/s | 36.6 / 36.7 MB/s | 791.3 / 869.0 MB/s |
| `ZIP (Zstd, BestCase)` | 7.04 | 22.0% | 290.9 / 253.1 MB/s | 840.8 / 1,134.3 MB/s | 371.2 / 366.9 MB/s | 1,260.4 / 1,753.4 MB/s |

* **Multi-cluster parallel Zstd advantage:** Because VZ splits the `32 MiB` file into 32 independent `1 MiB` Zstd clusters (`7.01 MiB` total compressed), on EPYC 9B45 `VZ (Zstd)` packs **15.2–20.4× faster** (`5,568–7,558 MB/s` vs `367–371 MB/s`) and unpacks **9.5–10.5× faster** (`13,239–16,696 MB/s` vs `1,260–1,753 MB/s`) than single-stream `ZIP (Zstd, BestCase)` and `TAR.ZST`.

### 8.5 HTTP/1.1 Range Streaming (`mod_21/item_03501.json`, `1,213 B` inside `5,000`-file archive)

Keep-alive loopback HTTP/1.1 server (`TCP_NODELAY`), using the exact same `HttpRangeReader` for both `VzReader` and `BestCaseZipReader`, and streaming `GET` for `TAR` / `TAR.ZST`:

| Format | HTTP Requests | Transferred | Ryzen 5 5600H `0 ms` / `2 ms` RTT (`mi`) | EPYC 9B45 `0 ms` / `2 ms` RTT (`mi`) |
| :--- | ---: | ---: | ---: | ---: |
| `VZ (Zstd)` | **3** (`1 HEAD + 2 Range`) | **104.7 KB** | **0.42 ms / 6.52 ms** | **0.27 ms / 6.52 ms** |
| `ZIP (Zstd, BestCase)` | 4 (`1 HEAD + 3 Range`) | 334.6 KB (`3.2×` more) | 0.37 ms / 8.65 ms | 0.23 ms / 8.62 ms |
| `TAR (Stream)` | 1 (`GET` stream) | 15,941.2 KB (`152×` more) | 9.83 ms / 11.77 ms | 2.95 ms / 4.75 ms |
| `TAR.ZST (Stream)` | 1 (`GET` stream) | 3,040.1 KB (`29.0×` more) | 15.38 ms / 18.39 ms | 11.15 ms / 12.73 ms |

### 8.6 Random I/O & IOPS (`20,000`-file archive on disk, `read_file` allocating fresh `Vec<u8>` per op)

Both `VzReader` and `BestCaseZipReader` share a single `Arc` reader across all worker threads for both **`File pread`** and **`MmapRangeReader`**, reusing thread-local `zstd_safe::DCtx` contexts:

#### A. Workstation Rig — Ryzen 5 5600H (`1T × 10,000`, `6T × 30,000`, `12T × 60,000` reads)

**With `allocator: system` (`glibc`):**

| Format | `1T` IOPS | `1T` p50 | `1T` p99 | `6T` IOPS | `6T` p50 | `6T` p99 | `12T` IOPS | `12T` p50 | `12T` p99 | Scale (`12T/1T`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None, File pread)` | 388,240 | 2.25 µs | 9.17 µs | 2,975,484 | 1.71 µs | 6.46 µs | 3,528,207 | 2.35 µs | 8.46 µs | **9.09×** |
| `VZ (None, Mmap)` | 561,553 | 1.16 µs | 7.19 µs | 4,652,384 | 0.97 µs | 4.87 µs | 4,793,051 | 1.57 µs | 9.00 µs | 8.54× |
| `VZ (LZ4, File pread)` | 278,249 | 2.88 µs | 10.37 µs | 1,664,472 | 2.69 µs | 11.12 µs | 1,599,136 | 3.65 µs | 14.36 µs | 5.75× |
| `VZ (LZ4, Mmap)` | 350,963 | 2.09 µs | 9.73 µs | 2,387,811 | 1.75 µs | 8.53 µs | 2,271,990 | 2.67 µs | 12.70 µs | 6.47× |
| `VZ (Zstd, File pread)` | 132,355 | 6.50 µs | 21.52 µs | 748,910 | 6.57 µs | 23.43 µs | 847,276 | 10.37 µs | 37.52 µs | 6.40× |
| `VZ (Zstd, Mmap)` | 145,918 | 5.59 µs | 21.66 µs | 817,169 | 5.63 µs | 23.07 µs | 818,680 | 8.92 µs | 36.37 µs | 5.61× |
| `ZIP (Stored, File pread)` | 504,842 | 1.64 µs | 5.88 µs | 2,520,111 | 1.71 µs | 8.61 µs | 3,460,916 | 1.94 µs | 8.98 µs | 6.86× |
| `ZIP (Stored, Mmap)` | 834,523 | 0.62 µs | 7.00 µs | 3,254,122 | 1.16 µs | 7.50 µs | 5,494,943 | 1.28 µs | 7.34 µs | 6.58× |
| `ZIP (Zstd, File pread)` | 141,963 | 5.83 µs | 20.99 µs | 816,319 | 5.70 µs | 21.62 µs | 915,859 | 9.15 µs | 36.36 µs | 6.45× |
| `ZIP (Zstd, Mmap)` | 163,531 | 4.88 µs | 19.76 µs | 869,094 | 5.05 µs | 21.71 µs | 1,050,648 | 7.87 µs | 34.73 µs | 6.42× |
| `TAR.ZST` (10-op sample) | 22.8 | 43,351 µs | 50,596 µs | N/A | — | — | N/A | — | — | — |

**With `allocator: mimalloc` (`--features mimalloc`):**

| Format | `1T` IOPS | `1T` p50 | `1T` p99 | `6T` IOPS | `6T` p50 | `6T` p99 | `12T` IOPS | `12T` p50 | `12T` p99 | Scale (`12T/1T`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None, File pread)` | 407,793 | 2.14 µs | 8.09 µs | 2,366,877 | 1.97 µs | 8.04 µs | 3,346,592 | 2.44 µs | 11.71 µs | 8.21× |
| `VZ (None, Mmap)` | 507,084 | 1.21 µs | 10.69 µs | 4,277,695 | 1.03 µs | 5.26 µs | 3,601,706 | 1.42 µs | 14.34 µs | 7.10× |
| `VZ (LZ4, File pread)` | 283,109 | 2.87 µs | 10.39 µs | 1,587,953 | 2.69 µs | 11.07 µs | 1,749,624 | 3.73 µs | 14.52 µs | 6.18× |
| `VZ (LZ4, Mmap)` | 323,694 | 2.23 µs | 10.91 µs | 2,200,261 | 1.85 µs | 9.00 µs | 2,867,259 | 2.62 µs | 12.10 µs | **8.86×** |
| `VZ (Zstd, File pread)` | 123,028 | 6.76 µs | 25.89 µs | 699,995 | 6.43 µs | 25.25 µs | 761,782 | 10.07 µs | 37.93 µs | 6.19× |
| `VZ (Zstd, Mmap)` | 145,996 | 5.51 µs | 22.30 µs | 828,077 | 5.39 µs | 21.36 µs | 923,840 | 8.97 µs | 36.72 µs | 6.33× |
| `ZIP (Stored, File pread)` | 488,409 | 1.65 µs | 6.51 µs | 3,638,616 | 1.32 µs | 3.91 µs | 3,037,365 | 1.96 µs | 9.43 µs | 6.22× |
| `ZIP (Stored, Mmap)` | 902,997 | 0.63 µs | 5.19 µs | 5,374,779 | 0.75 µs | 4.95 µs | 5,570,072 | 1.23 µs | 8.10 µs | 6.17× |
| `ZIP (Zstd, File pread)` | 145,175 | 5.69 µs | 20.48 µs | 753,067 | 5.74 µs | 21.78 µs | 960,078 | 9.08 µs | 36.16 µs | 6.61× |
| `ZIP (Zstd, Mmap)` | 155,239 | 5.13 µs | 22.48 µs | 886,282 | 4.98 µs | 21.90 µs | 831,615 | 7.49 µs | 34.58 µs | 5.36× |
| `TAR.ZST` (10-op sample) | 23.0 | 43,516 µs | 44,249 µs | N/A | — | — | N/A | — | — | — |

#### B. Server Rig — AMD EPYC 9B45 (`1T × 10,000`, `6T × 30,000`, `48T × 240,000` reads)

On 48 threads, `read_file` allocates and drops a `1–16 KiB` `Vec<u8>` on every operation (~75% of the mixed corpus exceeds `glibc`'s `1,032 B` `tcache` cap, contending on per-arena locks at ~8.5M allocs/s). Linking `mimalloc` (`--features mimalloc`) removes the allocator bottleneck, scaling `VZ (None, Mmap)` from **8.57M -> 38.33M IOPS** (`p99` `76.02 µs -> 2.76 µs`), `VZ (LZ4, Mmap)` from **7.48M -> 18.68M IOPS** (`p99` `57.14 µs -> 7.11 µs`), and `VZ (Zstd, Mmap)` to **6.98M IOPS** (`31.99×` scaling):

**With `allocator: system` (`glibc`):**

| Format | `1T` IOPS | `1T` p50 | `1T` p99 | `6T` IOPS | `6T` p50 | `6T` p99 | `48T` IOPS | `48T` p50 | `48T` p99 | Scale (`48T/1T`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None, File pread)` | 778,881 | 1.15 µs | 2.94 µs | 2,674,326 | 2.06 µs | 6.09 µs | **9,490,953** | 4.65 µs | 15.06 µs | 12.19× |
| `VZ (None, Mmap)` | 1,028,886 | 0.66 µs | 3.53 µs | 4,531,209 | 0.87 µs | 4.47 µs | 8,568,041 | 0.89 µs | 76.02 µs | 8.33× |
| `VZ (LZ4, File pread)` | 498,716 | 1.60 µs | 5.59 µs | 1,752,557 | 2.41 µs | 8.37 µs | 8,314,841 | 4.71 µs | 15.65 µs | 16.67× |
| `VZ (LZ4, Mmap)` | 610,976 | 1.18 µs | 5.58 µs | 2,751,776 | 1.37 µs | 5.45 µs | 7,480,019 | 1.79 µs | 57.14 µs | 12.24× |
| `VZ (Zstd, File pread)` | 201,868 | 4.22 µs | 13.88 µs | 1,010,570 | 4.82 µs | 14.78 µs | 4,998,426 | 7.08 µs | 21.91 µs | 24.76× |
| `VZ (Zstd, Mmap)` | 222,420 | 3.69 µs | 13.40 µs | 1,082,386 | 3.99 µs | 14.22 µs | 6,175,225 | 5.31 µs | 20.45 µs | **27.76×** |
| `ZIP (Stored, File pread)` | 971,569 | 0.89 µs | 2.66 µs | 2,947,742 | 1.82 µs | 5.49 µs | 7,772,909 | 5.17 µs | 9.92 µs | 8.00× |
| `ZIP (Stored, Mmap)` | 1,250,630 | 0.51 µs | 3.29 µs | 8,358,434 | 0.51 µs | 3.12 µs | 34,379,866 | 0.61 µs | 3.24 µs | 27.49× |
| `ZIP (Zstd, File pread)` | 212,713 | 3.92 µs | 13.49 µs | 1,123,545 | 4.19 µs | 13.86 µs | 4,565,772 | 6.64 µs | 21.13 µs | 21.46× |
| `ZIP (Zstd, Mmap)` | 236,163 | 3.41 µs | 13.23 µs | 1,327,985 | 3.45 µs | 13.33 µs | 5,830,409 | 4.55 µs | 19.28 µs | 24.69× |
| `TAR.ZST` (10-op sample) | 35.9 | 27,729 µs | 28,895 µs | N/A | — | — | N/A | — | — | — |

**With `allocator: mimalloc` (`--features mimalloc`):**

| Format | `1T` IOPS | `1T` p50 | `1T` p99 | `6T` IOPS | `6T` p50 | `6T` p99 | `48T` IOPS | `48T` p50 | `48T` p99 | Scale (`48T/1T`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None, File pread)` | 771,183 | 1.16 µs | 3.16 µs | 2,836,592 | 1.92 µs | 5.93 µs | 7,987,370 | 4.05 µs | 8.79 µs | 10.36× |
| `VZ (None, Mmap)` | 984,841 | 0.68 µs | 4.37 µs | 5,586,415 | 0.68 µs | 4.16 µs | **38,332,167** | 0.84 µs | **2.76 µs** | **38.92×** |
| `VZ (LZ4, File pread)` | 469,794 | 1.73 µs | 5.94 µs | 2,252,863 | 2.25 µs | 6.88 µs | **9,233,617** | 4.87 µs | 11.49 µs | 19.65× |
| `VZ (LZ4, Mmap)` | 595,740 | 1.19 µs | 5.90 µs | 3,507,919 | 1.19 µs | 4.93 µs | **18,683,674** | 1.59 µs | 7.11 µs | 31.36× |
| `VZ (Zstd, File pread)` | 200,323 | 4.26 µs | 13.96 µs | 1,024,623 | 4.74 µs | 15.25 µs | 4,214,471 | 6.89 µs | 21.83 µs | 21.04× |
| `VZ (Zstd, Mmap)` | 218,240 | 3.76 µs | 13.62 µs | 1,262,299 | 3.81 µs | 13.71 µs | **6,982,419** | 5.18 µs | 20.34 µs | 31.99× |
| `ZIP (Stored, File pread)` | 951,616 | 0.90 µs | 2.69 µs | 2,972,310 | 1.79 µs | 5.48 µs | 8,541,947 | 5.10 µs | 9.89 µs | 8.98× |
| `ZIP (Stored, Mmap)` | 1,363,635 | 0.44 µs | 3.10 µs | 9,361,338 | 0.44 µs | 3.12 µs | 44,298,996 | 0.61 µs | 3.30 µs | 32.49× |
| `ZIP (Zstd, File pread)` | 213,251 | 3.90 µs | 13.64 µs | 1,168,890 | 4.24 µs | 14.04 µs | 5,803,383 | 6.71 µs | 21.17 µs | 27.21× |
| `ZIP (Zstd, Mmap)` | 235,896 | 3.41 µs | 13.15 µs | 1,369,015 | 3.45 µs | 13.36 µs | 7,793,174 | 4.56 µs | 19.33 µs | **33.04×** |
| `TAR.ZST` (10-op sample) | 35.6 | 28,047 µs | 28,432 µs | N/A | — | — | N/A | — | — | — |

### 8.7 Partial Byte-Range Read inside `32 MiB` Zstd Blob (`64 KiB` window at `24 MiB` offset)

| Format | Read from Archive | Ryzen 5 5600H Latency (`sys` / `mi`) | EPYC 9B45 Latency (`sys` / `mi`) | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `VZ (Zstd, 1 MiB chunks)` | **223.2 KB** | **0.83 ms / 0.87 ms** | **0.54 ms / 0.54 ms** | `read_file_range` decodes **1 overlapping `1 MiB` chunk only** (`28×` faster) |
| `ZIP (Zstd, BestCase)` | 5,440.1 KB (`24.4×` more) | 22.27 ms / 22.70 ms | 15.10 ms / 15.08 ms | Even with 2-read CD locate, must stream-decompress `0..24.06 MiB` |
| `TAR.ZST` | 5,504.1 KB (`24.7×` more) | 22.12 ms / 22.77 ms | 14.96 ms / 15.04 ms | Must decompress solid stream from `0..24.06 MiB` |

### 8.8 Incremental Append & Selective Delete (`+10 × 4 KiB` new files, `-5` deletes on `5,000`-file archive)

| Operation | Bytes Written | Ryzen 5 5600H Time (`sys` / `mi`) | EPYC 9B45 Time (`sys` / `mi`) | Semantics |
| :--- | ---: | ---: | ---: | :--- |
| `VZ (LSM Delta Append)` | **105.3 KB** | **0.34 ms / 0.35 ms** | **0.19 ms / 0.23 ms** | Appends delta + updates Boot Slot; add, overwrite & tombstone delete |
| `ZIP (new_append)` | 347.5 KB | 21.09 ms / 21.12 ms | 9.04 ms / 8.76 ms | Append-only (cannot delete entries without full archive rewrite) |
| `TAR.ZST (Full Rewrite)` | 4,176.0 KB | 94.98 ms / 101.58 ms | 68.41 ms / 66.90 ms | Must decompress and re-pack entire `4.07 MiB` solid archive (`~350×` slower) |

### 8.9 Fault-Injection Self-Healing Recovery (`4 KiB` Boot ECC page + `256 KiB` data cluster wiped)

| Format | Recoverable? | Ryzen 5 5600H Repair (`sys` / `mi`) | EPYC 9B45 Repair (`sys` / `mi`) | Measured Result |
| :--- | :--- | ---: | ---: | :--- |
| `VZ (Boot ECC + RS(4,2))` | **YES (100%)** | **5.43 ms / 6.74 ms** | **2.35 ms / 2.42 ms** | `boot_page=Some(2)`, `data_repaired=2`, `data_100%=true` |
| `TAR.ZST` | NO (Fatal) | — | — | Stream CRC/frame mismatch; remaining entries lost |
| `ZIP (Zstd)` | NO (Fatal) | — | — | Local header / stream corrupted; no redundancy |

### 8.10 Zero-Reencode LSM Compaction (`5,000` Zstd files + `200` overwrites + `100` tombstones -> single run)

| Compaction Mode | Output Size | Ryzen 5 5600H Time (`sys` / `mi`) | EPYC 9B45 Time (`sys` / `mi`) | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `VZ (Zero-Reencode Compact)` | 6.13 MB | **7.88 ms / 11.16 ms** | **6.89 ms / 7.07 ms** | Strips LSM runs `2 -> 1`, drops `100` tombstones, copies compressed chunks verbatim (**13.7–15.1× faster**) |
| `VZ (Full Re-encode Compact)` | 6.13 MB | 118.94 ms / 124.20 ms | 98.57 ms / 96.86 ms | Decompresses and recompresses every live file |

### 8.11 FUSE3 / VFS Simulation (`FuseVolume` vs `BestCaseZipReader` vs `TAR.ZST`)

| Workload | Ryzen 5 5600H (`sys` / `mi`) | EPYC 9B45 (`sys` / `mi`) | Disk I/O | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `VZ (FuseVolume)` `readdirplus` (`2,000` entries) | 122.88 µs / **40.85 µs** | 60.16 µs / **27.31 µs** | **`0` reads (`0 B`)** | Mount: `1.96 ms` (Ryzen) / **`1.34 ms`** (EPYC); lookup: **`91.0 ns`** / **`107.8 ns`** |
| `ZIP (Zstd, BestCase)` `count_dir_prefix` (`2,000` entries) | 68.97 µs / 78.40 µs | 47.09 µs / 46.79 µs | `2` reads (`278 KB`) | Full Central Directory `pread` + linear prefix scan |
| `TAR.ZST` directory scan (`2,000` entries) | 23,051.99 µs / 22,964.19 µs | 13,841.22 µs / 14,349.24 µs | Full stream decode | Solid stream decompression (`525–562×` slower) |
| `VZ (Fuse Zstd 64K MC)` `64 × 4 KiB` seq read @ `1 MiB` | **288.09 µs / 282.21 µs** | **188.50 µs / 186.81 µs** | **`4` reads (`58,573 B`)** | Caches each `64 KiB` chunk across `16` pages (**4.4–4.7× faster**, **5.6× fewer bytes**) |
| `ZIP (Zstd, BestCase)` `64 × 4 KiB` seq read @ `1 MiB` | 1,347.22 µs / 1,330.50 µs | 817.62 µs / 836.56 µs | `8` reads (`327,786 B`) | 2-read CD locate + LFH + stream skip from byte `0..1.25 MiB` |
| `TAR.ZST` `64 × 4 KiB` seq read @ `1 MiB` | 1,214.92 µs / 1,127.60 µs | 799.05 µs / 803.14 µs | `3` reads (`393,225 B`) | Solid stream skip from byte `0..1.25 MiB` |
| `VZ (Fuse CODEC_NONE 4K)` random `4 KiB` read | 1.80 µs / **0.59 µs** | 0.57 µs / **0.42 µs** | **`1` read (`4,096 B`)** | Exact **`1.00×` read amplification** (`read_at`) |

---

## 9. Real-World Game `.pak` Replacement Case Study (Linux Kernel Corpus vs Unreal Engine `.pak`)

Measured with [pak_patch_bench.rs](file:///home/zears/vz/crates/vz-bench/examples/pak_patch_bench.rs) (`--features mimalloc`) across **8 years of Linux kernel source evolution** streamed directly from git tags via 64-SHA pipelined `git cat-file --batch` windows and 1,024-file parallel batches (`VzWriter::add_files_batch` / `LsmAppendWriter::add_files_batch`):
- **Ryzen 5 5600H (`12T`):** Local `korg` repository (`/home/zears/android/kernel/a22-ksun`, `v7.1 -> v7.1.4`, `v6.11 -> v6.12`, `v4.19 -> v7.1`, up to `93,709` files / `1,511.99 MiB` raw).
- **AMD EPYC 9B45 (`48T`):** Shallow upstream fetch (`--fetch /tmp/vz-linux-corpus`, `v7.3 -> v7.3.4`, `v6.11 -> v6.12`, `v4.19 -> v7.3`, up to `96,080` files / `1,565.34 MiB` raw).

### 9.1 Full Container Pack, Cold-Open Overhead & Multi-Threaded IOPS: VZ vs Unreal Engine `.pak` (`repak` V11 Zstd)

| Rig & Base Tag | Format | Archive Size | Pack Time | Cold Open + 1 Read | Cold Bytes Read | `6T` IOPS | `Max T` IOPS (`12T` / `48T`) |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **Ryzen 5 5600H (12T)** `v7.1` (`93,709` files, `1,511.99 MiB`) | `VZ (Zstd 256K cluster)` | **309.24 MiB** (`20.5%`) | **6,626.31 ms** | **203.93 µs** | **141,257 B** | **200,309** | **247,410 (`12T`)** |
| **Ryzen 5 5600H (12T)** `v7.1` (`93,709` files, `1,511.99 MiB`) | `UE .pak (repak V11 Zstd)` | 313.46 MiB | 10,415.09 ms (`1.57×` slower) | 55,781.03 µs (**`273.5×` slower**) | 5,047,104 B (`35.7×` more) | 139,050 | 128,994 (`12T`, `1.92×` slower) |
| **EPYC 9B45 (48T)** `v7.3` (`96,080` files, `1,565.34 MiB`) | `VZ (Zstd 256K cluster)` | **317.93 MiB** (`20.3%`) | **4,427.84 ms** | **45.95 µs** | **111,088 B** | **432,395** | **1,731,634 (`48T`)** |
| **EPYC 9B45 (48T)** `v7.3` (`96,080` files, `1,565.34 MiB`) | `UE .pak (repak V11 Zstd)` | 322.35 MiB | 8,464.03 ms (`1.91×` slower) | 36,170.90 µs (**`787.2×` slower**) | 5,188,174 B (**`46.7×` more**) | 297,701 | 1,216,744 (`48T`, `1.42×` slower) |

* **Why cold open differs by 273–787×:** Opening an Unreal Engine `.pak` must read, parse, and allocate the entire `O(N)` `5.05–5.19 MB` central directory index (`36.2–55.8 ms`) before serving the first asset read; VZ traverses its B+Tree path index in `O(log_B N)` (`111–141 KB`, **`45.95 µs`** on EPYC 9B45).

### 9.2 Three-Tier Patch Matrix (`LsmAppendWriter` Across Real Kernel Releases)

| Tier | Rig | Git Transition | File Churn (`+Add / ~Mod / -Del`) | Raw Changed | Delta Written | Delta Write Time |
| :--- | :--- | :--- | :--- | ---: | ---: | ---: |
| **1. Day-1 Hotfix** | Ryzen 5 5600H (`12T`) | `v7.1 -> v7.1.4` | `+1 / ~658 / -4` | 29.86 MB | **7.89 MB** | **126.19 ms** |
| **1. Day-1 Hotfix** | **EPYC 9B45 (`48T`)** | `v7.3 -> v7.3.4` | `+2 / ~1,531 / -1` | 68.42 MB | **18.04 MB** | **217.02 ms** |
| **2. Seasonal Update** | Ryzen 5 5600H (`12T`) | `v6.11 -> v6.12` | `+1,234 / ~11,506 / -359` | 314.49 MB | **82.49 MB** | **1,989.55 ms** |
| **2. Seasonal Update** | **EPYC 9B45 (`48T`)** | `v6.11 -> v6.12` | `+1,234 / ~11,506 / -359` | 314.49 MB | **82.49 MB** | **1,104.88 ms** |
| **3. Major Expansion** | Ryzen 5 5600H (`12T`) | `v4.19 -> v7.1` | `+50,073 / ~38,358 / -18,098` | 1,463.07 MB | **293.00 MB** | **6,342.14 ms** |
| **3. Major Expansion** | **EPYC 9B45 (`48T`)** | `v4.19 -> v7.3` | `+52,839 / ~38,193 / -18,493` | 1,517.73 MB | **301.73 MB** | **4,198.50 ms** |

*(Base archives before delta on EPYC 9B45: `v7.3` = `96,080` files / `1,565.34 MiB` raw / `317.93 MiB` VZ (`20.3%`) / **`4,427.84 ms`**; `v6.11` = `85,805` files / `1,400.40 MiB` raw / `286.49 MiB` VZ (`20.5%`) / **`4,036.41 ms`**; `v4.19` = `61,734` files / `753.20 MiB` raw / `199.12 MiB` VZ (`26.4%`) / **`2,811.85 ms`**.)*

### 9.3 Tier-1 Hotfix Cross-Format Comparison

| Format | Ryzen 5 5600H (`v7.1->v7.1.4`, `29.9 MB` raw) | Ryzen Bytes Written | EPYC 9B45 (`v7.3->v7.3.4`, `68.4 MB` raw) | EPYC Bytes Written | Deletion Semantics |
| :--- | ---: | ---: | ---: | ---: | :--- |
| `VZ (LsmAppendWriter)` | **126.19 ms** | **7.89 MB** | **217.02 ms** | **18.04 MB** | Appends delta + tombstones (deleted paths hidden atomically) |
| `UE .pak (repak into_writer)` | 411.20 ms (`3.26×` slower) | 12.72 MB | 539.49 ms (`2.49×` slower) | 23.08 MB | Rewrites full `O(N)` trailer; cannot delete stale files in-place |
| `ZIP (raw_copy rewrite)` | 8,100.10 ms (`64.2×` slower) | 301.81 MB | 3,510.73 ms (`16.2×` slower) | 310.32 MB | Full rewrite via `raw_copy_file` (`new_append` rejects mod/del) |
| `TAR.ZST (Full Rewrite)` | 6,564.51 ms (`52.0×` slower) | 226.35 MB | 4,432.83 ms (`20.4×` slower) | 232.85 MB | Must unpack & rewrite full solid archive |

### 9.4 Multi-Patch Stacking, Zero-Reencode Compaction, and Post-Patch Mmap IOPS (`1T` / `6T` / `Max T`)

* **5-Run Point-Release Stack (`lsm_run_count = 5`):**
  * **Ryzen 5 5600H (`v7.1 -> .1 -> .2 -> .3 -> .4`):** 4 incremental patches applied in **143.65 ms** total; `FuseVolume::mount` (`93,709` files) in **114.02 ms**.
  * **EPYC 9B45 (`v7.3 -> .1 -> .2 -> .3 -> .4`):** 4 incremental patches applied in **238.90 ms** total; `FuseVolume::mount` (`96,080` files) in **68.71 ms**.
* **Zero-Reencode Compaction (`lsm_run_count = 2 -> 1`):**
  * **Ryzen 5 5600H (`v4.19 -> v7.1`, `492.06 MiB` -> `300.41 MiB`, `191.65 MiB / 38.9%` reclaimed):** Zero-reencode **483.52 ms** vs full re-encode `5,928.22 ms` (**`12.26×` faster**).
  * **EPYC 9B45 (`v4.19 -> v7.3`, `500.78 MiB` -> `308.79 MiB`, `191.99 MiB / 38.3%` reclaimed):** Zero-reencode **276.49 ms** vs full re-encode `4,474.04 ms` (**`16.18×` faster**).

| Rig | Random-Read Container State (`Mmap`) | `1T` IOPS | `1T` p50 | `1T` p99 | `6T` IOPS | `6T` p50 | `6T` p99 | `Max T` IOPS (`12T` / `48T`) | `Max T` p50 | `Max T` p99 |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Ryzen 5 5600H (12T)** | `Stacked Hotfix (5 runs, v7.1.4)` | 59,053 | 10.32 µs | 102.26 µs | 240,812 | 12.26 µs | 142.27 µs | 267,059 (`12T`) | 15.64 µs | 321.46 µs |
| **Ryzen 5 5600H (12T)** | `Expansion Delta (2 runs, v4.19->v7.1)` | 57,051 | 10.46 µs | 106.69 µs | 309,985 | 9.99 µs | 112.35 µs | 351,305 (`12T`) | 14.66 µs | 226.59 µs |
| **Ryzen 5 5600H (12T)** | `Compacted Single-Run (v7.1)` | 58,003 | **9.99 µs** | 102.92 µs | **315,759** | **9.75 µs** | **112.02 µs** | **365,768 (`12T`)** | **14.22 µs** | **211.67 µs** |
| **EPYC 9B45 (48T)** | `Stacked Hotfix (5 runs, v7.3.4)` | **82,810** | 7.50 µs | 71.39 µs | 462,954 | 7.65 µs | 74.44 µs | **1,976,834 (`48T`)** | 10.43 µs | 121.62 µs |
| **EPYC 9B45 (48T)** | `Expansion Delta (2 runs, v4.19->v7.3)` | 78,891 | 7.29 µs | **66.49 µs** | **470,206** | 7.18 µs | 72.25 µs | **2,288,690 (`48T`)** | 10.03 µs | 116.93 µs |
| **EPYC 9B45 (48T)** | `Compacted Single-Run (v7.3)` | 80,403 | **7.07 µs** | 66.88 µs | 468,902 | **7.08 µs** | **69.38 µs** | **1,911,847 (`48T`)** | **9.91 µs** | **115.85 µs** |

---

## 10. Reproduction

```bash
# Default portable release builds (runtime SIMD dispatch)
cargo run --release -p libvz --all-features --example metrics_runner
cargo run --release -p vz-bench --bin vz-compare
cargo run --release -p vz-bench --features mimalloc --bin vz-compare

# Real-World Linux Kernel vs Unreal Engine .pak Case Study (local git repo or shallow fetch)
cargo run --release -p vz-bench --features mimalloc --example pak_patch_bench -- --repo /home/zears/android/kernel/a22-ksun
cargo run --release -p vz-bench --features mimalloc --example pak_patch_bench -- --fetch /tmp/vz-linux-corpus

# Criterion microbenchmark suite
cargo bench -p libvz --all-features
```
