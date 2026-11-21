# VZ v1.0 Benchmark Report

All results in this report were directly measured on commit `858bea8` across two reference systems—a **12-thread Zen 3 workstation** (default portable release build) and a **48-thread Zen 5 EPYC server** (`RUSTFLAGS="-C target-cpu=native"`)—using:
- `cargo run --release -p libvz --all-features --example metrics_runner`
- `cargo run --release -p vz-bench --bin vz-compare` (`allocator: system` / `glibc`)
- `cargo run --release -p vz-bench --features mimalloc --bin vz-compare` (`allocator: mimalloc`)
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
| **Compile Flags** | Default `--release` (runtime SIMD dispatch) | `--release` with `RUSTFLAGS="-C target-cpu=native"` |
| **CPU SIMD Flags** | `sse4_2 avx2 pclmulqdq vpclmulqdq aes vaes` | `sse4_2 avx2 avx512f avx512bw avx512vl pclmulqdq vpclmulqdq gfni aes vaes` |
| **Active `crc32c` Tier** | `AVX2 + VPCLMULQDQ` (`>= 256 B`), `SSE4.2` (`< 256 B`) | `AVX-512F/VL + VPCLMULQDQ` (`>= 512 B`), `AVX2 + VPCLMULQDQ` (`256..511 B`), `SSE4.2` (`< 256 B`) |
| **Active `RS_GF256` Tier** | 2×-unrolled `AVX2 vpshufb` + 32 KiB L1/L2 tile blocking | `AVX-512BW/VL + GFNI` (`VGF2P8AFFINEQB` 64 B/iter) + 32 KiB L1/L2 tile blocking |
| **Active `boot_ecc` Tier** | 15-way single-pass `AVX2` XOR + hw `crc32c` | 15-way single-pass `AVX-512` / `AVX2` XOR + hw `crc32c` |

### Architecture & Scaling Design Highlights

- **Tiered Cross-Architecture Hardware Dispatch:** Runtime CPU feature detection on `x86_64` (`VPCLMULQDQ`, `GFNI`, `AVX-512BW/VL`, `AVX2`, `PCLMULQDQ`, `SSE4.2`, `SSSE3`) and `aarch64` (`crc`, `NEON`), plus compile-time `wasm32 simd128` and `#![no_std]` portable fallbacks.
- **Persistent Scoped Worker Pool ([parallel.rs](file:///home/zears/vz/crates/libvz/src/parallel.rs)):** Lazily initialized lock-free work-stealing pool with cache-line-aligned per-worker slots (`#[repr(align(64))]`) and selective `unpark()`/`park()`. Keeps per-worker TLS compression/decompression/decryption contexts (`ZSTD_COMP_TLS`, `ZSTD_DCTX_TLS`, `LZ4_COMP_SCRATCH`, `DEC_SCRATCH_TLS`) warm across calls without `pthread_create`/`munmap` churn.
- **Wait-Free 2-Way Set-Associative TLS L1 Node Cache ([lookup.rs](file:///home/zears/vz/crates/libvz/src/reader/lookup.rs)):** 64-set × 2-way (`128`-slot) thread-local L1 cache for both `Mmap` (`VerifiedSlice`) and buffered/`File` (`Arc<CachedNode>` up to `256 KiB` leaf payloads, borrowed in-place with zero `Arc` refcount traffic and zero `RwLock` contention on L1 hits), backed by a sharded cache-padded L2 cache.
- **Allocator Strategy ([vz-tools](file:///home/zears/vz/crates/vz-tools/Cargo.toml), [vz-bench](file:///home/zears/vz/crates/vz-bench/Cargo.toml)):** `libvz` and `libvz-ffi` remain 100% allocator-agnostic (using flat per-worker batch arenas, zero-prezero `resize_for_overwrite` on `read_file_into`, and in-place slice AEAD encryption). The `vz` CLI enables `mimalloc` by default (`default = ["mimalloc"]`), and `vz-bench` exposes `--features mimalloc` alongside the default system allocator to benchmark both stock `glibc` and `mimalloc` behavior transparently.

---

## 1. Primitive Throughput & Latency (`metrics_runner [1]`)

### 1.1 Castagnoli `crc32c`

| Buffer Size | Ryzen 5 5600H (12T, `AVX2+VPCLMULQDQ`) | Ryzen 5 5600H Latency | EPYC 9B45 (48T, `AVX-512+VPCLMULQDQ`, `-C target-cpu=native`) | EPYC 9B45 Latency |
| ---: | ---: | ---: | ---: | ---: |
| `64 B` | 15,876.42 MB/s | 3.84 ns/op | **26,530.10 MB/s** | **2.30 ns/op** |
| `4 KiB` | 29,400.71 MB/s | 132.86 ns/op | **60,310.44 MB/s** | **64.77 ns/op** |
| `64 KiB` | **30,892.29 MB/s** | 2,023.16 ns/op | **62,390.29 MB/s** | **1,001.76 ns/op** |
| `1 MiB` | 28,142.12 MB/s | 35,533.93 ns/op | **62,325.99 MB/s** | **16,044.67 ns/op** |
| `16 MiB` | 19,164.42 MB/s | 834,880.55 ns/op | **60,896.09 MB/s** | **262,742.66 ns/op** |

### 1.2 LE-VINT Encode / Decode

| Operation | Ryzen 5 5600H (ns/op) | Ryzen 5 5600H (Mops/s) | EPYC 9B45 (ns/op) | EPYC 9B45 (Mops/s) |
| :--- | ---: | ---: | ---: | ---: |
| `read_levint_fast` (`&[u8; 8]`) | 0.79 ns/op | 1,266.97 Mops/s | **0.49 ns/op** | **2,031.78 Mops/s** |
| `read_levint_safe` (`&[u8]`) | 1.28 ns/op | 779.55 Mops/s | **0.65 ns/op** | **1,541.56 Mops/s** |
| `write_levint` | 1.60 ns/op | 623.39 Mops/s | **0.74 ns/op** | **1,353.35 Mops/s** |

### 1.3 Boot Block 4 KiB ECC (`64 KiB`, 15-Way SIMD XOR + Hardware `crc32c`)

| Operation | Ryzen 5 5600H (µs/op) | EPYC 9B45 (µs/op) |
| :--- | ---: | ---: |
| `boot_ecc_encode` | 3.17 µs/op | **1.67 µs/op** |
| `boot_ecc_verify_clean` (clean fast path) | **2.07 µs/op** | **1.04 µs/op** |
| `boot_ecc_verify_and_repair` (`1` page repair) | 3.31 µs/op | **1.74 µs/op** |

### 1.4 Reed-Solomon `GF(2^8)` Cauchy Erasure Coding (`1 MiB` Clusters)

| Operation | Ryzen 5 5600H (12T, 2× `AVX2 vpshufb`) | EPYC 9B45 (48T, `AVX-512 GFNI` `VGF2P8AFFINEQB`) |
| :--- | ---: | ---: |
| `rs_gf256_madd_slice` (`1 MiB`, 1 thread) | 35,171.64 MB/s | **51,673.82 MB/s** |
| `RS_GF256` `K=8, M=2` encode (data throughput) | 14,821.40 MB/s | **29,104.14 MB/s** |
| `RS_GF256` `K=8, M=2` recover (`2` erasures) | **24,429.39 MB/s** | **60,284.09 MB/s** |
| `RS_GF256` `K=16, M=4` encode (data throughput) | 10,104.00 MB/s | **38,468.01 MB/s** |
| `RS_GF256` `K=16, M=4` recover (`4` erasures) | **16,432.97 MB/s** | **43,282.44 MB/s** |

---

## 2. End-to-End Pack & Unpack Throughput (`metrics_runner [2]`)

### 2.1 Many-Small-Files Corpus (`10,000` files, `0 B .. 4 KiB`, `19.54 MiB` total raw)

| Codec / Mode | Archive Size | Ryzen 5 5600H Pack | Ryzen 5 5600H Unpack | EPYC 9B45 Pack | EPYC 9B45 Unpack |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `CODEC_NONE` | 20.96 MiB | 812.50 MB/s (415,895 f/s) | **2,647.91 MB/s** (1,355,394 f/s) | 1,216.25 MB/s (622,564 f/s) | **3,380.16 MB/s** (1,730,212 f/s) |
| `CODEC_LZ4` | 2.33 MiB | **1,364.54 MB/s** (698,470 f/s) | 2,043.98 MB/s (1,046,258 f/s) | **2,494.86 MB/s** (1,277,053 f/s) | 3,356.88 MB/s (1,718,299 f/s) |
| `CODEC_ZSTD` | 2.00 MiB | 718.44 MB/s (367,749 f/s) | 1,971.37 MB/s (1,009,092 f/s) | 1,157.46 MB/s (592,475 f/s) | 3,326.02 MB/s (1,702,501 f/s) |
| `ZSTD + Dict` (`CDict`/`DDict`) | **1.50 MiB** | 706.50 MB/s (361,638 f/s) | 1,840.29 MB/s (941,997 f/s) | 1,167.39 MB/s (597,555 f/s) | 2,971.88 MB/s (1,521,225 f/s) |
| `Encrypted (Raw256)` | 21.34 MiB | 359.65 MB/s (184,093 f/s) | 465.12 MB/s (238,085 f/s) | 392.73 MB/s (201,027 f/s) | 510.02 MB/s (261,066 f/s) |

### 2.2 Large Multi-Cluster Blob (`64 MiB` payload, `1 MiB` clusters)

| Codec / Mode | Archive Size | Ryzen 5 5600H (12T) Pack | Ryzen 5 5600H (12T) Unpack | EPYC 9B45 (48T) Pack | EPYC 9B45 (48T) Unpack |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `CODEC_NONE` | 64.08 MiB | 2,176.73 MB/s | 3,691.67 MB/s | 2,347.75 MB/s | 5,561.98 MB/s |
| `CODEC_LZ4` | 0.33 MiB | **10,993.88 MB/s** | 3,890.91 MB/s | **50,746.53 MB/s** | 5,802.67 MB/s |
| `CODEC_ZSTD` | **0.08 MiB** | 9,532.96 MB/s | **3,943.89 MB/s** | 47,024.59 MB/s | **5,927.25 MB/s** |
| `Encrypted (Raw256)` | 64.08 MiB | 993.37 MB/s | 2,967.22 MB/s | 1,593.45 MB/s | 4,572.27 MB/s |

*(Note: `metrics_runner` uses `TrackingAllocator` wrapping the system `glibc` allocator; see Section 8.4 for `32 MiB` multi-cluster unpack reaching **33.48 GB/s** on EPYC 9B45 under `mimalloc`.)*

---

## 3. Random-Access Lookup, Indexing Latency & Multi-Core Scaling (`metrics_runner [3, 4, 8]`)

### 3.1 Cold Open, `stat`, and `read_file` (`1 KiB` payload): `MmapRangeReader` vs `File`

Because `BUF_NODE_L1` caches verified `Arc<CachedNode>` B+Tree leaves up to `256 KiB` in a 64-set × 2-way thread-local cache, warm `stat` latency on `File` is virtually identical to zero-copy `Mmap`:

| Archive Scale | Tree Height | Rig | Cold Open (`File`) | `stat` (`Mmap`) | `stat` (`File`) | `read_file` (`Mmap`) | `read_file` (`File`) |
| ---: | ---: | :--- | ---: | ---: | ---: | ---: | ---: |
| `100` files | `0` | Ryzen 5 5600H (12T) | 10.92 µs | 0.33 µs | 0.34 µs | 0.26 µs | 0.90 µs |
| `10,000` files | `1` | Ryzen 5 5600H (12T) | 9.52 µs | 0.42 µs | 0.44 µs | 0.32 µs | 1.00 µs |
| `100,000` files | `2` | Ryzen 5 5600H (12T) | 10.11 µs | 0.45 µs | 0.49 µs | 0.37 µs | 1.36 µs |
| `100` files | `0` | **EPYC 9B45 (48T)** | **5.06 µs** | **0.26 µs** | **0.26 µs** | **0.19 µs** | **0.46 µs** |
| `10,000` files | `1` | **EPYC 9B45 (48T)** | **5.01 µs** | **0.33 µs** | **0.34 µs** | **0.25 µs** | **0.54 µs** |
| `100,000` files | `2` | **EPYC 9B45 (48T)** | **5.08 µs** | **0.37 µs** | **0.38 µs** | **0.29 µs** | **0.63 µs** |

### 3.2 `readdir` vs Zero-Copy `readdir_visit` Scaling

| Directory Size | Ryzen 5 5600H Owned `readdir` | Ryzen 5 5600H `readdir_visit` | EPYC 9B45 Owned `readdir` | EPYC 9B45 `readdir_visit` |
| ---: | ---: | ---: | ---: | ---: |
| `10` entries | 1.62 µs/op | **0.51 µs/op** | 1.28 µs/op | **0.35 µs/op** |
| `5,000` entries | 1,593.22 µs/op | **146.39 µs/op** (`10.9×` faster) | 1,079.83 µs/op | **101.29 µs/op** (`10.7×` faster) |

### 3.3 LSM Overlay Read Latency (`1`, `4`, `16` Runs vs Compacted)

| State | Ryzen 5 5600H `read_file` | EPYC 9B45 `read_file` |
| :--- | ---: | ---: |
| `1` run (baseline) | 0.27 µs/op | **0.19 µs/op** |
| `4` runs | 0.37 µs/op | **0.25 µs/op** |
| `16` runs | 0.73 µs/op | **0.49 µs/op** |
| Compacted (`1` run) | **0.30 µs/op** | **0.19 µs/op** |

### 3.4 Multi-Threaded Random I/O Scaling (`10,000` files, `read_file_into` reusing caller buffer)

| Rig | Codec | `File` (`1T`) | `File` (`Max T`) | `File` Scale | `Mmap` (`1T`) | `Mmap` (`Max T`) | `Mmap` Scale |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **Ryzen 5 5600H (6C/12T)** | `CODEC_NONE` | 562,237 | 4,061,588 (`12T`) | 7.22× | 1,305,070 | **9,549,797 (`12T`)** | 7.32× |
| **Ryzen 5 5600H (6C/12T)** | `CODEC_LZ4` | 512,865 | **5,230,731 (`12T`)** | **10.20×** | 1,113,604 | 9,143,690 (`12T`) | **8.21×** |
| **Ryzen 5 5600H (6C/12T)** | `CODEC_ZSTD` | 547,380 | 3,683,895 (`12T`) | 6.73× | 1,125,073 | 7,544,683 (`12T`) | 6.71× |
| **EPYC 9B45 (24C/48T)** | `CODEC_NONE` | 945,030 | 8,891,366 (`48T`) | **9.41×** | 1,582,594 | **68,227,756 (`48T`)** | **43.11×** |
| **EPYC 9B45 (24C/48T)** | `CODEC_LZ4` | **1,146,345** | 9,104,469 (`48T`) | 7.94× | **1,810,613** | **61,143,070 (`48T`)** | **33.77×** |
| **EPYC 9B45 (24C/48T)** | `CODEC_ZSTD` | 1,107,605 | **9,117,720 (`48T`)** | 8.23× | 1,745,606 | **57,383,046 (`48T`)** | **32.87×** |

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
| `64 MiB` multi-cluster streaming read (`VzReader::read_file_to_writer`) | 71 allocs | **1.07 MiB** | 288,120 KiB | 332,868 KiB |

---

## 7. FUSE3 VFS Surface (`FuseVolume`, `metrics_runner [7]`)

| Operation | Ryzen 5 5600H (12T) | EPYC 9B45 (48T) | Disk Reads / Amp | Notes |
| :--- | ---: | ---: | :--- | :--- |
| `FuseVolume::mount` (`5,003` entries) | 2.08 ms | **1.52 ms** | `0` reads post-mount | Resolves LSM overlays, hardlink `nlink`, and implicit parents |
| `getattr(ino)` (`O(1)`) | 7.4 ns/op (`135.6 Mops/s`) | **4.4 ns/op** (**`229.1 Mops/s`**) | `0` reads | Direct inode-vec slot access |
| `lookup(parent_ino, name)` (`2k` dir) | 42.6 ns/op (`23.46 Mops/s`) | **35.0 ns/op** (**`28.57 Mops/s`**) | `0` reads | Binary search over flat child arena + 8-byte inline prefix |
| `readdirplus(2,000 entries, batch=64)` | 68.13 µs/scan | **60.50 µs/scan** | `0` reads | Paginated `offset` cursor returning full `FuseAttr` |
| `64 × 4 KiB` seq VFS reads (`256 KiB` Zstd MC, `64 KiB` chunks) | 64.30 µs (`1.00 µs/page`) | **42.59 µs** (**`0.67 µs/page`**) | `4` reads (`309 B`) | `FuseFileHandle` single-chunk cache avoids 60/64 chunk decodes |
| `4 KiB` random VFS read (`CODEC_NONE`) | 0.12 µs/op | **0.10 µs/op** | **`1` read (`4,096 B`, `1.00×`)** | Zero read-amplification direct `read_at` |
| `4 KiB` sparse hole read | — | — | **`0` reads (`0 B`)** | Zero-I/O sparse hole fast path |

---

## 8. Cross-Format Comparison (`vz-compare`: `libvz` vs TAR / TAR.GZ / TAR.LZ4 / TAR.ZST / ZIP)

Measured with the standalone `vz-bench` binary under both the default system allocator (`glibc`) and `--features mimalloc`:

### 8.1 Tiny File Overhead (`5,000` files × `1..27 B`, `69,945 B` raw)

| Format | Archive Size | Ratio | Ryzen 5 5600H Pack (`system` / `mimalloc`) | EPYC 9B45 Pack (`system` / `mimalloc`) |
| :--- | ---: | ---: | ---: | ---: |
| `VZ (None)` | 426,816 B | 6.10× | 4.58 ms / 3.08 ms | 2.71 ms / 2.43 ms |
| `VZ (LZ4)` | 426,816 B | 6.10× | 5.41 ms / 2.56 ms | 2.45 ms / **1.80 ms** |
| `VZ (Zstd)` | 426,816 B | 6.10× | 3.59 ms / 2.62 ms | **1.88 ms** / 1.94 ms |
| `VZ (Zstd+Dict)` | 426,816 B | 6.10× | 4.47 ms / 2.92 ms | 1.95 ms / 1.93 ms |
| `TAR (Uncomp)` | 5,121,024 B | 73.22× | 2.51 ms / 5.10 ms | 2.30 ms / 1.87 ms |
| `TAR.GZ (Deflate)` | 74,897 B | 1.07× | 28.55 ms / 26.65 ms | 15.25 ms / 15.27 ms |
| `TAR.LZ4` | 187,264 B | 2.68× | 2.72 ms / 2.75 ms | 2.01 ms / 1.99 ms |
| `TAR.ZST (Zstd)` | 57,460 B | 0.82× | 5.19 ms / 6.03 ms | 2.80 ms / 3.43 ms |
| `ZIP (Stored)` | 619,967 B | 8.86× | 2.53 ms / 2.29 ms | 1.66 ms / 1.47 ms |
| `ZIP (Deflate)` | 574,650 B | 8.22× | 36.54 ms / 37.80 ms | 18.50 ms / 19.13 ms |
| `ZIP (Zstd)` | 630,372 B | 9.01× | 58.00 ms / 58.18 ms | 39.62 ms / 34.18 ms |

### 8.2 Mixed Corpus (`5,000` files, `18.32 MiB` raw): Pack / Full Unpack / Size

| Format | Size (MiB) | % of Raw | Ryzen 5 5600H Pack (`sys` / `mi`) | Ryzen 5 5600H Unpack (`sys` / `mi`) | EPYC 9B45 Pack (`sys` / `mi`) | EPYC 9B45 Unpack (`sys` / `mi`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None)` | 19.01 | 103.8% | 1,302.8 / 1,349.6 MB/s | 3,790.0 / 5,812.8 MB/s | 2,228.9 / 2,882.1 MB/s | **15,833.5 / 17,592.6 MB/s** |
| `VZ (LZ4)` | 1.39 | 7.6% | **2,255.4 / 2,624.3 MB/s** | **8,376.3 / 7,865.3 MB/s** | **4,252.2 / 4,190.7 MB/s** | 15,231.7 / 15,354.9 MB/s |
| `VZ (Zstd)` | 1.18 | 6.4% | 832.5 / 882.2 MB/s | 2,570.4 / 2,597.9 MB/s | 1,241.1 / 1,270.3 MB/s | 3,513.4 / 3,561.8 MB/s |
| `VZ (Zstd+Dict)` | **0.73** | **4.0%** | 1,348.6 / 1,563.9 MB/s | 5,941.3 / 7,418.6 MB/s | 2,392.5 / 2,451.0 MB/s | 11,694.7 / 11,795.5 MB/s |
| `TAR (Uncomp)` | 22.21 | 121.2% | 1,918.1 / 1,934.9 MB/s | 3,048.6 / 3,705.8 MB/s | 2,477.2 / 4,696.5 MB/s | 5,162.8 / 5,932.8 MB/s |
| `TAR.GZ (Deflate)` | 0.19 | 1.0% | 222.9 / 229.3 MB/s | 1,722.7 / 1,758.1 MB/s | 412.1 / 407.4 MB/s | 2,227.1 / 2,262.7 MB/s |
| `TAR.LZ4` | 0.33 | 1.8% | 3,264.8 / 2,906.0 MB/s | 2,672.8 / 2,870.2 MB/s | 5,278.4 / 5,516.4 MB/s | 4,450.9 / 4,473.9 MB/s |
| `TAR.ZST (Zstd)` | 0.22 | 1.2% | 1,519.6 / 1,667.9 MB/s | 2,566.7 / 2,707.7 MB/s | 2,508.1 / 2,432.5 MB/s | 4,392.3 / 4,359.3 MB/s |
| `ZIP (Stored)` | 18.90 | 103.1% | 2,044.4 / 1,742.8 MB/s | 3,799.1 / 4,272.6 MB/s | 2,565.7 / 4,016.2 MB/s | 5,267.0 / 6,235.7 MB/s |
| `ZIP (Deflate)` | 1.11 | 6.1% | 191.1 / 189.0 MB/s | 636.5 / 662.4 MB/s | 372.0 / 366.2 MB/s | 874.3 / 901.2 MB/s |
| `ZIP (Zstd)` | 1.06 | 5.8% | 252.5 / 269.4 MB/s | 1,572.2 / 1,567.3 MB/s | 365.6 / 342.4 MB/s | 1,133.2 / 1,163.4 MB/s |

### 8.3 Cold Open + Read Single External File (`1,213 B`, 70% offset in `5,000`-file archive) & `readdir`

| Format | Read Calls | Bytes Read | Read Amp | Ryzen 5 5600H Cold Latency (`sys` / `mi`) | EPYC 9B45 Cold Latency (`sys` / `mi`) | `readdir` `2k` Entries (Ryzen / EPYC) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None)` | **3** | 107,837 B | 88.9× | 20.07 / **14.76 µs** | 7.21 / 6.95 µs | — |
| `VZ (LZ4)` | **3** | 106,782 B | **88.0×** | 21.64 / 15.49 µs | **6.59 / 6.61 µs** | — |
| `VZ (Zstd)` | **3** | 106,746 B | **88.0×** | **18.67** / 19.07 µs | 7.71 / 7.60 µs | **60.07 µs / 41.48 µs** (`readdir_visit`) |
| `VZ (Zstd+Dict)` | **3** | 111,771 B | 92.1× | 38.63 / 43.00 µs | 20.40 / 20.56 µs | — |
| `TAR (Uncomp)` | 7,004 | 16,323,773 B | 13,457.4× | 5,008.3 / 5,085.0 µs | 2,980.8 / 2,791.0 µs | — |
| `TAR.GZ` | 5 | 163,840 B | 135.1× | 6,754.3 / 6,813.6 µs | 5,280.3 / 5,233.7 µs | — |
| `TAR.LZ4` | 502 | 240,161 B | 198.0× | 4,098.8 / 4,156.9 µs | 2,675.8 / 2,676.6 µs | — |
| `TAR.ZST` | 2 | 226,472 B | 186.7× | 4,233.8 / 4,313.9 µs | 2,653.5 / 2,677.3 µs | 6,572.9 µs / 3,773.4 µs (full scan) |
| `ZIP (Stored)` | 5,005 | 40,499,926 B | 33,388.2× | 11,450.6 / 11,320.6 µs | 4,152.1 / 3,786.7 µs | — |
| `ZIP (Deflate)` | 5,005 | 40,499,926 B | 33,388.2× | 11,372.3 / 11,874.2 µs | 4,166.0 / 3,784.8 µs | — |
| `ZIP (Zstd)` | 5,005 | 40,499,926 B | 33,388.2× | 11,606.0 / 12,185.7 µs | 4,154.1 / 3,780.2 µs | 11,427.5 µs / 4,004.7 µs (`File+Buf`) |

*(Warm `MmapRangeReader` single-file read latency on the same `5,000`-file archive: Ryzen 5 5600H `VZ (Zstd)` **`1.76 µs/op`**, `VZ (Zstd+Dict)` **`0.68 µs/op`**; EPYC 9B45 `VZ (Zstd)` **`1.40 µs/op`**, `VZ (Zstd+Dict)` **`0.47 µs/op`**.)*

### 8.4 Single Large `32 MiB` Blob: Pack / Unpack / Size

| Format | Size (MiB) | Ryzen 5 5600H Pack (`sys` / `mi`) | Ryzen 5 5600H Unpack (`sys` / `mi`) | EPYC 9B45 Pack (`sys` / `mi`) | EPYC 9B45 Unpack (`sys` / `mi`) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `VZ (None)` | 32.07 | 2,609.5 / 2,178.8 MB/s | 2,958.7 / 3,466.7 MB/s | 3,133.4 / 6,220.9 MB/s | 8,881.8 / 12,882.3 MB/s |
| `VZ (LZ4)` | 0.20 | **7,639.3 / 5,842.4 MB/s** | 3,177.4 / **5,980.6 MB/s** | **41,366.1 / 23,699.7 MB/s** | **15,869.3 / 18,753.5 MB/s** |
| `VZ (Zstd)` | **0.08** | 5,567.0 / 5,787.0 MB/s | **3,549.3 / 5,125.0 MB/s** | 37,006.2 / **38,581.6 MB/s** | 15,722.0 / **33,483.7 MB/s** |
| `TAR (Uncomp)` | 32.00 | 2,360.2 / 1,911.7 MB/s | 2,371.2 / 1,715.6 MB/s | 3,843.6 / 9,054.7 MB/s | 2,159.1 / 3,891.4 MB/s |
| `TAR.GZ (Deflate)` | 0.11 | 387.0 / 375.5 MB/s | 1,617.4 / 1,454.2 MB/s | 790.6 / 792.9 MB/s | 2,139.5 / 2,831.1 MB/s |
| `TAR.LZ4` | 0.20 | 6,100.5 / 8,158.5 MB/s | 3,677.9 / 2,781.7 MB/s | 10,062.5 / 11,355.9 MB/s | 3,945.6 / 5,248.2 MB/s |
| `TAR.ZST (Zstd)` | 0.00 | 3,769.0 / 3,538.9 MB/s | 2,274.0 / 2,090.7 MB/s | 6,439.0 / 6,559.5 MB/s | 3,850.6 / 6,572.6 MB/s |
| `ZIP (Stored)` | 32.00 | 3,703.4 / 2,714.8 MB/s | 1,836.6 / 1,607.7 MB/s | 3,803.6 / 9,431.9 MB/s | 2,023.9 / 4,175.1 MB/s |
| `ZIP (Deflate)` | 0.11 | 408.0 / 391.4 MB/s | 1,610.3 / 1,254.0 MB/s | 835.9 / 834.2 MB/s | 1,896.1 / 2,787.2 MB/s |
| `ZIP (Zstd)` | 0.00 | 3,004.2 / 4,074.7 MB/s | 1,838.4 / 1,516.1 MB/s | 7,009.2 / 7,249.6 MB/s | 3,157.8 / 5,732.7 MB/s |

### 8.5 HTTP/1.1 Range Streaming (`mod_21/item_03501.json`, `1,213 B` inside `5,000`-file archive)

Keep-alive loopback HTTP/1.1 server (`TCP_NODELAY`, `HEAD` + `206 Partial Content` for Range clients, streaming `GET` for TAR; `BufReader<64KiB>` on `ZIP`), measured at `0 ms` loopback and `2 ms` simulated edge/object-store RTT per request:

| Format | HTTP Requests | Transferred | Ryzen 5 5600H `0 ms` / `2 ms` RTT | EPYC 9B45 `0 ms` / `2 ms` RTT |
| :--- | ---: | ---: | ---: | ---: |
| `VZ (Zstd)` | **3** | **104.2 KB** | **0.34 ms / 6.37 ms** | **0.29 ms / 6.37 ms** |
| `ZIP (Zstd)` | 5,006 | 289,406.2 KB | 155.70 ms / 10,559.42 ms | 49.35 ms / 10,436.48 ms |
| `TAR (Stream)` | 1 | 15,941.2 KB | 9.35 ms / 10.62 ms | 2.78 ms / 4.68 ms |
| `TAR.ZST (Stream)` | 1 | 221.2 KB | 4.17 ms / 6.82 ms | 2.74 ms / 5.01 ms |

### 8.6 Random I/O & IOPS (`20,000`-file archive on disk, `read_file` allocating fresh `Vec<u8>` per op)

`VZ` shares a single opened `File` handle across all worker threads via stateless lock-free `pread` (or `Mmap`) with per-thread 2-way L1 + sharded L2 verified B+Tree node caching; `ZIP` opens one independent `File` handle per thread (`Seek+Read` cannot share a `File::try_clone` fd across threads).

#### A. Workstation Rig — Ryzen 5 5600H (`1T × 10,000`, `6T × 30,000`, `12T × 60,000` reads)

**With `allocator: system` (`glibc`):**

| Format | `1T` IOPS | `1T` p50 | `1T` p99 | `6T` IOPS | `6T` p50 | `6T` p99 | `12T` IOPS | `12T` p50 | `12T` p99 | Scale (`12T/1T`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None, File pread)` | 401,399 | 2.18 µs | 8.35 µs | 2,871,482 | 1.69 µs | 5.64 µs | 3,043,182 | 2.25 µs | 8.19 µs | 7.58× |
| `VZ (None, Mmap)` | 606,136 | **1.12 µs** | 5.94 µs | 4,531,913 | 0.96 µs | 4.55 µs | 4,050,164 | 1.61 µs | 9.01 µs | 6.68× |
| `VZ (LZ4, File pread)` | 478,266 | 1.83 µs | 4.65 µs | 3,410,902 | 1.59 µs | 3.42 µs | **4,190,494** | 2.19 µs | 4.71 µs | **8.76×** |
| `VZ (LZ4, Mmap)` | **708,962** | 1.13 µs | **4.21 µs** | **4,831,089** | **0.83 µs** | **2.56 µs** | **5,879,523** | **1.20 µs** | **3.42 µs** | 8.29× |
| `VZ (Zstd, File pread)` | 314,268 | 3.26 µs | 5.68 µs | 2,035,564 | 2.97 µs | 5.20 µs | 2,235,140 | 4.25 µs | 6.78 µs | 7.11× |
| `VZ (Zstd, Mmap)` | 455,851 | 2.21 µs | 4.42 µs | 2,708,517 | 2.08 µs | 4.44 µs | 3,457,634 | 3.05 µs | 5.78 µs | 7.59× |
| `ZIP (Stored, File)` | 99,985 | 4.20 µs | 9.26 µs | 327,264 | 4.86 µs | 13.29 µs | 425,236 | 6.41 µs | 15.97 µs | 4.25× |
| `ZIP (Zstd, File)` | 94,243 | 5.52 µs | 9.01 µs | 330,789 | 5.94 µs | 12.31 µs | 384,872 | 8.43 µs | 14.32 µs | 4.08× |
| `TAR.ZST` (10-op sample) | 75.4 | 13,394 µs | 13,694 µs | N/A | — | — | N/A | — | — | — |

**With `allocator: mimalloc` (`--features mimalloc`):**

| Format | `1T` IOPS | `1T` p50 | `1T` p99 | `6T` IOPS | `6T` p50 | `6T` p99 | `12T` IOPS | `12T` p50 | `12T` p99 | Scale (`12T/1T`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None, File pread)` | 391,262 | 2.18 µs | 7.54 µs | 2,972,652 | 1.69 µs | 3.94 µs | **3,870,398** | 2.26 µs | 7.42 µs | **9.89×** |
| `VZ (None, Mmap)` | 522,939 | **1.17 µs** | 10.68 µs | **4,870,449** | 0.90 µs | 4.97 µs | 4,175,997 | 1.43 µs | 7.88 µs | 7.99× |
| `VZ (LZ4, File pread)` | 474,389 | 1.84 µs | **4.19 µs** | 3,423,628 | 1.54 µs | 3.54 µs | 3,617,045 | 2.04 µs | 4.55 µs | 7.62× |
| `VZ (LZ4, Mmap)` | **624,796** | 1.22 µs | 4.35 µs | 4,373,999 | **0.84 µs** | **2.88 µs** | **6,016,356** | **1.08 µs** | **2.77 µs** | **9.63×** |
| `VZ (Zstd, File pread)` | 285,594 | 3.58 µs | 6.66 µs | 1,569,666 | 3.36 µs | 6.57 µs | 2,387,023 | 4.18 µs | 7.96 µs | 8.36× |
| `VZ (Zstd, Mmap)` | 408,076 | 2.40 µs | 5.21 µs | 2,644,984 | 2.13 µs | 4.16 µs | 2,596,977 | 2.99 µs | 6.25 µs | 6.36× |
| `ZIP (Stored, File)` | 101,710 | 4.22 µs | 9.23 µs | 338,435 | 4.68 µs | 12.88 µs | 411,689 | 6.31 µs | 18.04 µs | 4.05× |
| `ZIP (Zstd, File)` | 92,570 | 5.62 µs | 9.76 µs | 329,535 | 5.78 µs | 12.13 µs | 437,529 | 8.44 µs | 15.20 µs | 4.73× |
| `TAR.ZST` (10-op sample) | 77.2 | 13,018 µs | 13,635 µs | N/A | — | — | N/A | — | — | — |

#### B. Server Rig — AMD EPYC 9B45 (`1T × 10,000`, `6T × 30,000`, `48T × 240,000` reads)

On 48 threads, `read_file` allocates and drops a `1–16 KiB` `Vec<u8>` on every operation (~75% of the mixed corpus exceeds `glibc`'s `1,032 B` `tcache` cap, contending on per-arena locks at ~11M allocs/s). Linking `mimalloc` (`--features mimalloc`) removes the allocator bottleneck, scaling `Mmap` `read_file` from **11.28M -> 47.89M IOPS** and dropping `48T p99` latency from **`58.59 µs` -> `1.46 µs`**:

**With `allocator: system` (`glibc`):**

| Format | `1T` IOPS | `1T` p50 | `1T` p99 | `6T` IOPS | `6T` p50 | `6T` p99 | `48T` IOPS | `48T` p50 | `48T` p99 | Scale (`48T/1T`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None, File pread)` | 772,564 | 1.16 µs | 3.04 µs | 2,686,978 | 2.02 µs | 5.91 µs | 9,213,123 | 4.59 µs | 18.15 µs | 11.93× |
| `VZ (None, Mmap)` | 1,009,271 | 0.69 µs | 3.56 µs | 3,859,931 | 0.93 µs | 5.52 µs | 9,057,250 | 0.90 µs | 66.16 µs | 8.97× |
| `VZ (LZ4, File pread)` | 959,756 | 0.94 µs | 1.97 µs | 2,983,670 | 1.79 µs | 5.10 µs | 8,381,773 | 3.62 µs | 33.89 µs | 8.73× |
| `VZ (LZ4, Mmap)` | **1,569,206** | **0.52 µs** | **1.36 µs** | **7,086,570** | **0.65 µs** | **1.64 µs** | **11,277,326** | **0.76 µs** | 58.59 µs | 7.19× |
| `VZ (Zstd, File pread)` | 545,580 | 1.96 µs | 2.97 µs | 2,183,764 | 2.74 µs | 6.06 µs | 8,557,333 | 4.97 µs | 18.79 µs | **15.68×** |
| `VZ (Zstd, Mmap)` | 687,881 | 1.54 µs | 2.14 µs | 3,232,358 | 1.69 µs | 4.74 µs | 8,580,803 | 2.01 µs | 51.44 µs | 12.47× |
| `ZIP (Stored, File)` | 220,863 | 2.24 µs | 4.89 µs | 247,439 | 7.16 µs | 12.99 µs | 262,724 | 46.86 µs | 94.96 µs | 1.19× |
| `ZIP (Zstd, File)` | 154,436 | 4.62 µs | 6.03 µs | 254,088 | 6.25 µs | 10.69 µs | 249,875 | 50.07 µs | 97.17 µs | 1.62× |
| `TAR.ZST` (10-op sample) | 133.5 | 7,487 µs | 7,632 µs | N/A | — | — | N/A | — | — | — |

**With `allocator: mimalloc` (`--features mimalloc`):**

| Format | `1T` IOPS | `1T` p50 | `1T` p99 | `6T` IOPS | `6T` p50 | `6T` p99 | `48T` IOPS | `48T` p50 | `48T` p99 | Scale (`48T/1T`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None, File pread)` | 747,090 | 1.18 µs | 3.57 µs | 2,701,668 | 2.01 µs | 6.42 µs | 7,983,612 | 4.41 µs | 9.49 µs | 10.69× |
| `VZ (None, Mmap)` | 916,348 | 0.66 µs | 4.62 µs | 6,163,026 | 0.68 µs | 5.00 µs | **37,835,381** | 0.84 µs | 2.75 µs | **41.29×** |
| `VZ (LZ4, File pread)` | 988,680 | 0.93 µs | 1.98 µs | 3,431,980 | 1.72 µs | 3.16 µs | **10,851,445** | 4.52 µs | 8.82 µs | 10.98× |
| `VZ (LZ4, Mmap)` | **1,599,900** | **0.50 µs** | **1.20 µs** | **8,768,494** | **0.51 µs** | **1.33 µs** | **47,888,133** | **0.70 µs** | **1.46 µs** | 29.93× |
| `VZ (Zstd, File pread)` | 553,102 | 1.94 µs | 2.98 µs | 2,519,148 | 2.53 µs | 3.88 µs | 9,932,431 | 5.11 µs | 8.88 µs | 17.96× |
| `VZ (Zstd, Mmap)` | 693,413 | 1.52 µs | 2.08 µs | 3,850,098 | 1.55 µs | 2.52 µs | **22,261,964** | 1.99 µs | 2.67 µs | 32.10× |
| `ZIP (Stored, File)` | 226,873 | 2.28 µs | 5.12 µs | 245,417 | 7.45 µs | 13.28 µs | 263,573 | 45.00 µs | 92.10 µs | 1.16× |
| `ZIP (Zstd, File)` | 157,167 | 4.43 µs | 6.99 µs | 256,789 | 6.09 µs | 10.82 µs | 267,137 | 47.69 µs | 92.83 µs | 1.70× |
| `TAR.ZST` (10-op sample) | 131.5 | 7,567 µs | 7,909 µs | N/A | — | — | N/A | — | — | — |

### 8.7 Partial Byte-Range Read inside `32 MiB` Zstd Blob (`64 KiB` window at `24 MiB` offset)

| Format | Read from Archive | Ryzen 5 5600H Latency (`sys` / `mi`) | EPYC 9B45 Latency (`sys` / `mi`) | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `VZ (Zstd, 1 MiB chunks)` | **1.2 KB** | **0.07 ms / 0.07 ms** | **0.04 ms / 0.04 ms** | `read_file_range` decodes 1 overlapping chunk only |
| `ZIP (Zstd)` | 5.2 KB | 2.86 ms / 2.93 ms | 1.68 ms / 1.71 ms | Must decompress entry stream from `0..24.06 MiB` |
| `TAR.ZST` | 3.2 KB | 2.08 ms / 2.32 ms | 1.25 ms / 1.27 ms | Must decompress solid stream from `0..24.06 MiB` |

### 8.8 Incremental Append & Selective Delete (`+10 × 4 KiB` new files, `-5` deletes on `5,000`-file archive)

| Operation | Bytes Written | Ryzen 5 5600H Time (`sys` / `mi`) | EPYC 9B45 Time (`sys` / `mi`) | Semantics |
| :--- | ---: | ---: | ---: | :--- |
| `VZ (LSM Delta Append)` | **105.3 KB** | **0.33 ms / 0.67 ms** | **0.18 ms / 0.20 ms** | Appends delta + updates Boot Slot; add, overwrite & tombstone delete |
| `ZIP (new_append)` | 336.2 KB | 20.73 ms / 23.24 ms | 9.20 ms / 8.58 ms | Append-only (cannot delete entries without full archive rewrite) |
| `TAR.ZST (Full Rewrite)` | 221.2 KB | 17.83 ms / 20.98 ms | 11.86 ms / 12.21 ms | Must decompress and re-pack entire archive |

### 8.9 Fault-Injection Self-Healing Recovery (`4 KiB` Boot ECC page + `256 KiB` data cluster wiped)

| Format | Recoverable? | Ryzen 5 5600H Repair (`sys` / `mi`) | EPYC 9B45 Repair (`sys` / `mi`) | Measured Result |
| :--- | :--- | ---: | ---: | :--- |
| `VZ (Boot ECC + RS(4,2))` | **YES (100%)** | **3.81 ms / 5.19 ms** | **2.35 ms / 2.29 ms** | `boot_page=Some(2)`, `data_repaired=2`, `data_100%=true` |
| `TAR.ZST` | NO (Fatal) | — | — | Stream CRC/frame mismatch; remaining entries lost |
| `ZIP (Zstd)` | NO (Fatal) | — | — | Local header / stream corrupted; no redundancy |

### 8.10 Zero-Reencode LSM Compaction (`5,000` Zstd files + `200` overwrites + `100` tombstones -> single run)

| Compaction Mode | Output Size | Ryzen 5 5600H Time (`sys` / `mi`) | EPYC 9B45 Time (`sys` / `mi`) | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `VZ (Zero-Reencode Compact)` | 1.19 MB | **4.78 ms / 6.37 ms** | **6.16 ms / 5.34 ms** | Strips LSM runs `2 -> 1`, drops `100` tombstones, copies compressed chunks verbatim |
| `VZ (Full Re-encode Compact)` | 1.19 MB | 33.60 ms / 45.11 ms | 32.53 ms / 31.07 ms | Decompresses and recompresses every live file (`~6–7×` slower) |

### 8.11 FUSE3 / VFS Simulation (`FuseVolume` vs `ZIP` vs `TAR.ZST`)

| Workload | Ryzen 5 5600H (`sys` / `mi`) | EPYC 9B45 (`sys` / `mi`) | Disk I/O | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `VZ (FuseVolume)` `readdirplus` (`2,000` entries) | **76.02 µs / 105.17 µs** | **59.82 µs / 27.38 µs** (`279×` faster than ZIP) | **`0` reads** | Mount: `1.72 ms` (Ryzen) / **`1.29 ms`** (EPYC); lookup: `93.8 ns` / **`105.5 ns`** |
| `ZIP (Zstd)` `readdirplus` (`2,000` entries) | 21,321.43 µs / 23,054.35 µs | 7,907.83 µs / 7,639.84 µs | Full central dir scan | Linear central directory scan |
| `TAR.ZST` `readdirplus` (`2,000` entries) | 5,960.72 µs / 6,236.06 µs | 3,822.89 µs / 3,906.76 µs | Full stream decode | Solid stream decompression |
| `VZ (Fuse Zstd 64K MC)` `64 × 4 KiB` seq read @ `1 MiB` | **52.46 µs / 56.41 µs** | **31.62 µs / 32.56 µs** | `4` reads (`484 B`) | Caches each `64 KiB` chunk across `16` pages |
| `ZIP (Zstd)` `64 × 4 KiB` seq read @ `1 MiB` | 231.21 µs / 189.73 µs | 133.23 µs / 110.89 µs | `6` reads (`1,963 B`) | Stream skip from entry start |
| `TAR.ZST` `64 × 4 KiB` seq read @ `1 MiB` | 128.19 µs / 157.51 µs | 86.37 µs / 83.49 µs | `1` read (`555 B`) | Solid stream skip |
| `VZ (Fuse CODEC_NONE 4K)` random `4 KiB` read | **0.78 µs / 0.80 µs** | **0.54 µs / 0.47 µs** | **`1` read (`4,096 B`)** | Exact **`1.00×` read amplification** (`read_at`) |

---

## 9. Real-World Game `.pak` Replacement Case Study (Linux Kernel Corpus vs Unreal Engine `.pak`)

*(Captured in the standalone [pak_patch_bench.rs](file:///home/zears/vz/crates/vz-bench/examples/pak_patch_bench.rs) case-study run on the Ryzen 5 5600H workstation.)*

This standalone case study evaluates VZ as a drop-in replacement for game asset `.pak` containers across **8 years of Linux kernel source evolution** (`61,734` -> `93,709` files, up to `1,511.99 MiB` raw payload) streamed directly from pre-existing git tags (no double-tree extraction), and directly benchmarks VZ against real **Unreal Engine `.pak` (`repak` V11 Zstd)**, `ZIP`, and `TAR.ZST`.

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

* **5-Run Point-Release Stack (`v7.1 -> .1 -> .2 -> .3 -> .4`, `lsm_run_count = 5`):** Total patch time across all 4 incremental appends = **246.75 ms**; `FuseVolume::mount` builds the merged `93,709`-file in-memory POSIX graph in **116.40 ms**.
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
# Default portable release builds (runtime SIMD dispatch)
cargo run --release -p libvz --all-features --example metrics_runner
cargo run --release -p vz-bench --bin vz-compare
cargo run --release -p vz-bench --features mimalloc --bin vz-compare

# Target-native release builds (recommended on dedicated AVX-512 / GFNI / VPCLMULQDQ servers)
RUSTFLAGS="-C target-cpu=native" cargo run --release -p libvz --all-features --example metrics_runner
RUSTFLAGS="-C target-cpu=native" cargo run --release -p vz-bench --bin vz-compare
RUSTFLAGS="-C target-cpu=native" cargo run --release -p vz-bench --features mimalloc --bin vz-compare

# Criterion microbenchmark suite
cargo bench -p libvz --all-features
```

### Optional Real-World Case Study (`.pak` Patch Benchmark, Outside Main Suite)

The 3-tier Linux kernel `.pak` replacement example ([pak_patch_bench.rs](file:///home/zears/vz/crates/vz-bench/examples/pak_patch_bench.rs)) streams preexisting tags (`v4.19`, `v6.11`, `v6.12`, and `v7.3..v7.3.4` or `v7.1..v7.1.4`) directly from git into `VzWriter`, `LsmAppendWriter`, `compact_archive_with_options`, `FuseVolume`, and Unreal Engine `.pak` (`repak`):

```bash
# Run read-only against an existing local Linux git repo (zero network fetch):
cargo run --release -p vz-bench --features mimalloc --example pak_patch_bench -- --repo /path/to/linux.git
# Or fetch shallow tags into a standalone bare repo:
cargo run --release -p vz-bench --features mimalloc --example pak_patch_bench -- --fetch /tmp/vz-linux-corpus
```
