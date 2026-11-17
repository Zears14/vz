# VZ v1.0 Benchmark Report

All results below were directly measured on this machine using `cargo bench -p libvz --all-features` (`criterion` in `crates/libvz/benches/vz_benchmarks.rs`), `cargo run --release -p libvz --all-features --example metrics_runner`, and `cargo run --release -p vz-bench --bin vz-compare`. No numbers are estimated or extrapolated.

## Environment

- **CPU:** AMD Ryzen 5 5600H with Radeon Graphics (6 cores / 12 threads, x86_64)
- **OS:** Linux `7.3.4-1-cachyos` `x86_64`
- **Toolchain:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`
- **Target Flags:** Default release profile (no custom `RUSTFLAGS`)
- **SIMD / Hardware Acceleration:**
  - `crc32c_hw_active() == true` (runtime `sse4.2` detection -> `_mm_crc32_u64` / `_mm_crc32_u8`)
  - `rs_gf256_madd_slice` runtime `avx2` detection -> 32-byte `vpshufb` (`_mm256_shuffle_epi8`) nibble-table vectorization

---

## 1. Primitive Throughput & Latency

### 1.1 Castagnoli `crc32c` (SSE4.2 Hardware Accelerated)

| Buffer Size | `metrics_runner` (MB/s) | `metrics_runner` (ns/op) | Criterion Median Time | Criterion Throughput |
| ---: | ---: | ---: | ---: | ---: |
| `64 B` | 13,667.68 MB/s | 4.47 ns | 3.2714 ns | 18.220 GiB/s |
| `4 KiB` | 10,507.91 MB/s | 371.74 ns | 367.83 ns | 10.371 GiB/s |
| `64 KiB` | 10,423.12 MB/s | 5,996.28 ns | 5.9812 µs | 10.205 GiB/s |
| `1 MiB` | 10,314.86 MB/s | 96,947.51 ns | 97.674 µs | 9.9981 GiB/s |
| `16 MiB` | 8,696.66 MB/s | 1,839,786.41 ns | 1.8280 ms | 8.5476 GiB/s |

### 1.2 LE-VINT Encode / Decode

| Operation | `metrics_runner` (ns/op) | `metrics_runner` (Mops/s) | Criterion Median Time |
| :--- | ---: | ---: | ---: |
| `read_levint_fast` (`&[u8; 8]`) | 0.70 ns/op | 1,437.51 Mops/s | 1.3835 ns |
| `read_levint_safe` (`&[u8]`) | 1.07 ns/op | 934.71 Mops/s | 1.6209 ns |
| `write_levint` | 1.38 ns/op | 723.41 Mops/s | 1.6019 ns |

### 1.3 Boot Block 4 KiB ECC (`64 KiB`)

| Operation | `metrics_runner` (µs/op) | Criterion Median Time | Criterion Throughput |
| :--- | ---: | ---: | ---: |
| `boot_ecc_encode` | 7.15 µs | 7.1522 µs | 8.5338 GiB/s |
| `boot_ecc_verify_and_repair` (clean) | 5.85 µs | 5.8589 µs | 10.418 GiB/s |
| `boot_ecc_verify_and_repair` (1 page repair) | 7.58 µs | 7.7056 µs | 7.9209 GiB/s |

### 1.4 Reed-Solomon `GF(2^8)` Cauchy Erasure Coding (`1 MiB` Clusters, AVX2 `vpshufb`)

| Operation | `metrics_runner` | Criterion Median Time | Criterion Throughput |
| :--- | ---: | ---: | ---: |
| `rs_gf256_madd_slice` (`1 MiB`) | 34,850.93 MB/s | 29.073 µs | 33.590 GiB/s |
| `RS_GF256` `K=8, M=2` encode | 3,239.93 MB/s (data) | 1.5065 ms | 5.1858 GiB/s |
| `RS_GF256` `K=8, M=2` recover (`2` erasures) | 3,326.76 MB/s (data) | 1.9384 ms | 4.0303 GiB/s |
| `RS_GF256` `K=16, M=4` encode | 2,084.28 MB/s (data) | 5.8359 ms | 2.6774 GiB/s |
| `RS_GF256` `K=16, M=4` recover (`4` erasures) | 1,839.15 MB/s (data) | 7.6887 ms | 2.0322 GiB/s |

---

## 2. End-to-End Pack & Unpack Throughput

### 2.1 Many-Small-Files Corpus (`10,000` files, `0 B .. 4 KiB`, `19.54 MiB` total raw)

| Codec / Mode | Pack Throughput | Pack File Rate | Unpack Throughput | Unpack File Rate | Archive Size |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `CODEC_NONE` | 493.25 MB/s | 252,484 files/s | 1,307.62 MB/s | 669,337 files/s | 20.96 MiB |
| `CODEC_LZ4` | 734.89 MB/s | 376,168 files/s | 1,204.24 MB/s | 616,418 files/s | 2.33 MiB |
| `CODEC_ZSTD` | 579.24 MB/s | 296,497 files/s | **2,077.07 MB/s** | **1,063,198 files/s** | 2.00 MiB |
| `ZSTD + Dict` (`CDict`/`DDict`) | 466.90 MB/s | 238,993 files/s | 1,665.71 MB/s | 852,633 files/s | 1.50 MiB |
| `Encrypted (Raw256)` | 223.61 MB/s | 114,460 files/s | 83.08 MB/s | 42,526 files/s | 21.34 MiB |

*(Criterion `1,000` small files pack: `CODEC_NONE` `390.72 MiB/s`, `CODEC_LZ4` `295.43 MiB/s`, `CODEC_ZSTD` `191.00 MiB/s`, `ZSTD+Dict` `156.37 MiB/s`, `Encrypted(Raw256)` `109.29 MiB/s`.)*

### 2.2 Large-Blob Corpus (`64 MiB` payload)

| Codec / Mode | Pack Throughput | Unpack Throughput | Archive Size |
| :--- | ---: | ---: | ---: |
| `CODEC_NONE` | 1,409.22 MB/s | 1,583.42 MB/s | 64.08 MiB |
| `CODEC_LZ4` | **7,402.89 MB/s** | 1,663.54 MB/s | 0.33 MiB |
| `CODEC_ZSTD` | 4,751.23 MB/s | **2,279.76 MB/s** | 0.08 MiB |
| `Encrypted (Raw256)` | 605.11 MB/s | 750.35 MB/s | 64.08 MiB |

---

## 3. Random-Access Lookup & Indexing Latency

### 3.1 Cold Open, `stat`, and `read_file` (`1 KiB` payload): `MmapRangeReader` vs `File`

| Archive Scale | B+Tree Height | Cold Open (`File`) | `stat` (`Mmap`) | `stat` (`File`) | `read_file` (`Mmap`) | `read_file` (`File`) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `100` files | `0` | 15.07 µs | 1.06 µs | 1.05 µs | 0.24 µs | 0.89 µs |
| `10,000` files | `1` | 15.99 µs | 1.11 µs | 1.10 µs | 0.31 µs | 1.03 µs |
| `100,000` files | `2` | 14.39 µs | 1.23 µs | 1.21 µs | 0.34 µs | 1.15 µs |

*(Criterion on `10,000` files forced to `tree_height >= 2`: `cold_open_file` `14.560 µs`, `stat_10k_h2_mmap` **`703.61 ns`**, `stat_10k_h2_file` **`685.56 ns`**, `read_10k_h2_mmap` **`340.57 ns`**, `read_10k_h2_file` **`1.0527 µs`**.)*

### 3.2 `readdir` vs Zero-Copy `readdir_visit` Scaling

| Directory Size | Owned `readdir` (`metrics_runner`) | Zero-Copy `readdir_visit` (`metrics_runner`) | Criterion Owned | Criterion `readdir_visit` |
| ---: | ---: | ---: | ---: | ---: |
| `10` entries | 1.48 µs/op | 0.52 µs/op | 1.4900 µs | 479.16 ns |
| `5,000` entries | 1,546.60 µs/op | **142.46 µs/op** | 1.4692 ms | **146.82 µs** |

### 3.3 LSM Overlay Read Latency (`1`, `4`, `16` Runs vs Compacted)

| State | `read_file` (`metrics_runner`) | Criterion `stat` (`16` runs vs compacted) |
| :--- | ---: | ---: |
| `1` run (baseline) | 0.25 µs/op | — |
| `4` runs | 0.38 µs/op | — |
| `16` runs | 1.03 µs/op | 1.4353 µs/op |
| Compacted (`1` run) | **0.23 µs/op** | **1.0903 µs/op** |

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
| `64 MiB` streaming pipe write (`VzPipeWriter::add_file_reader`) | 228 allocs | 4.00 MiB | — |
| `64 MiB` multi-cluster streaming read (`VzReader::read_file_to_writer`) | 71 allocs | 1.06 MiB | 334,444 KiB |

---

## 7. FUSE3 VFS Surface (`FuseVolume`)

| Operation | `metrics_runner` | Criterion Median | Disk Reads / Amp | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `FuseVolume::mount` (`5,003` entries) | 3.28 ms | 2.8970 ms | `0` reads post-mount | Resolves LSM overlays, hardlink `nlink`, and implicit parents |
| `getattr(ino)` (`O(1)`) | **5.9 ns/op** (`169.0 Mops/s`) | 13.564 ns | `0` reads | Direct inode-vec slot access |
| `lookup(parent_ino, name)` (`2k` dir) | **71.7 ns/op** (`13.95 Mops/s`) | 95.682 ns | `0` reads | Binary search over sorted directory children |
| `readdirplus(2,000 entries, batch=64)` | **75.48 µs/scan** | 71.840 µs | `0` reads | Paginated `offset` cursor returning full `FuseAttr` |
| `64 × 4 KiB` seq VFS reads (`256 KiB` Zstd MC, `64 KiB` chunks) | **54.99 µs** (`0.86 µs/page`) | **17.618 µs** (**13.858 GiB/s**) | `4` reads (`309 B`) | `FuseFileHandle` single-chunk cache avoids 60/64 chunk decodes |
| `4 KiB` random VFS read (`CODEC_NONE`) | **0.12 µs/op** | **116.28 ns** (**32.805 GiB/s**) | **`1` read (`4,096 B`, `1.00x`)** | Zero read-amplification direct `read_at` |
| `4 KiB` sparse hole read | — | — | **`0` reads (`0 B`)** | Zero-I/O sparse hole fast path |

---

## 8. Cross-Format Comparison (`vz-compare`: `libvz` vs TAR / TAR.GZ / TAR.LZ4 / TAR.ZST / ZIP)

Measured with the standalone `vz-bench` binary (`cargo run --release -p vz-bench --bin vz-compare`):

### 8.1 Tiny File Overhead (`5,000` files × `1..27 B`, `69,945 B` raw)

| Format | Archive Size | Ratio | Pack Time |
| :--- | ---: | ---: | ---: |
| `VZ (None / LZ4 / Zstd / Zstd+Dict)` | 426,816 B | 6.10x | 11.19–16.96 ms |
| `ZIP (Stored)` | 619,967 B | 8.86x | 2.62 ms |
| `ZIP (Deflate)` | 574,650 B | 8.22x | 42.81 ms |
| `ZIP (Zstd)` | 630,372 B | 9.01x | 61.95 ms |
| `TAR (Uncomp)` | 5,121,024 B | 73.22x | 3.63 ms |
| `TAR.GZ` / `TAR.LZ4` / `TAR.ZST` (solid) | 74,897 B / 187,264 B / 57,460 B | 1.07x / 2.68x / 0.82x | 28.72 / 2.72 / 4.74 ms |

### 8.2 Mixed Corpus (`5,000` files, `18.32 MiB` raw): Pack / Full Unpack / Size

| Format | Size (MiB) | % of Raw | Pack MB/s | Unpack MB/s | Pack files/s |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `VZ (None)` | 19.01 | 103.8% | 858.21 | **3,638.93** | 234,232 |
| `VZ (LZ4)` | 1.39 | 7.6% | 1,275.55 | 2,735.66 | 348,140 |
| `VZ (Zstd)` | 1.18 | 6.4% | 692.26 | 2,282.99 | 188,941 |
| `VZ (Zstd+Dict)` | 0.73 | 4.0% | 843.41 | 3,524.19 | 230,194 |
| `TAR (Uncomp)` | 22.21 | 121.2% | 1,949.67 | 3,284.65 | 532,127 |
| `TAR.GZ (Deflate)` | 0.19 | 1.0% | 213.45 | 1,670.42 | 58,259 |
| `TAR.LZ4` | 0.33 | 1.8% | 2,895.41 | 2,779.56 | 790,252 |
| `TAR.ZST (Zstd)` | 0.22 | 1.2% | 1,578.35 | 2,551.66 | 430,783 |
| `ZIP (Stored)` | 18.90 | 103.1% | 2,023.32 | 3,962.76 | 552,230 |
| `ZIP (Deflate)` | 1.11 | 6.1% | 180.32 | 642.66 | 49,215 |
| `ZIP (Zstd)` | 1.06 | 5.8% | 244.53 | 1,460.81 | 66,739 |

### 8.3 Cold Open + Read Single External File (`1,213 B`, 70% offset in `5,000`-file archive) & `readdir`

| Format | Cold Open + Read | Read Calls | Bytes Read | Read Amp | `readdir` (`2,000` entries) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `VZ (None)` | 22.30 µs | 3 | 107,837 B | 88.9x | — |
| `VZ (LZ4)` | 22.14 µs | 3 | 106,782 B | 88.0x | — |
| `VZ (Zstd)` | **21.45 µs** | 3 | 106,746 B | 88.0x | **57.59 µs** (`readdir_visit`) |
| `VZ (Zstd+Dict)` | 41.66 µs | 3 | 111,771 B | 92.1x | — |
| `TAR (Uncomp)` | 5,426.70 µs | 7,004 | 16,323,773 B | 13,457.4x | — |
| `TAR.GZ` | 6,722.91 µs | 5 | 163,840 B | 135.1x | — |
| `TAR.LZ4` | 4,203.59 µs | 502 | 240,161 B | 198.0x | — |
| `TAR.ZST` | 4,442.13 µs | 2 | 226,472 B | 186.7x | 6,467.45 µs (full scan) |
| `ZIP (Stored)` | 12,221.49 µs | 5,005 | 40,499,926 B | 33,388.2x | — |
| `ZIP (Deflate)` | 12,181.37 µs | 5,005 | 40,499,926 B | 33,388.2x | — |
| `ZIP (Zstd)` | 12,061.60 µs | 5,005 | 40,499,926 B | 33,388.2x | 12,065.98 µs (`File+Buf`) |

*(Warm `MmapRangeReader` single-file read latency on the same `5,000`-file archive: `VZ (Zstd)` **`1.71 µs/op`**, `VZ (Zstd+Dict)` **`0.79 µs/op`**.)*

### 8.4 Single Large `32 MiB` Blob: Pack / Unpack / Size

| Format | Size (MiB) | Pack MB/s | Unpack MB/s |
| :--- | ---: | ---: | ---: |
| `VZ (None)` | 32.07 | 1,556.16 | 2,330.10 |
| `VZ (LZ4)` | 0.20 | **7,393.07** | 2,077.60 |
| `VZ (Zstd)` | 0.08 | 4,044.82 | **3,249.23** |
| `TAR (Uncomp)` | 32.00 | 2,604.03 | 1,615.64 |
| `TAR.GZ (Deflate)` | 0.11 | 376.88 | 1,652.71 |
| `TAR.LZ4` | 0.20 | 5,102.22 | 3,580.76 |
| `TAR.ZST (Zstd)` | 0.00 | 3,991.85 | 2,180.37 |
| `ZIP (Stored)` | 32.00 | 3,218.54 | 1,699.50 |
| `ZIP (Deflate)` | 0.11 | 390.01 | 1,482.51 |
| `ZIP (Zstd)` | 0.00 | 3,548.60 | 1,587.23 |

### 8.5 HTTP/1.1 Range Streaming (`mod_21/item_03501.json`, `1,213 B` inside `5,000`-file archive)

Keep-alive loopback HTTP/1.1 server (`TCP_NODELAY`, `HEAD` + `206 Partial Content` for Range clients, streaming `GET` for TAR; `BufReader<64KiB>` on `ZIP`), measured at both `0 ms` loopback and `2 ms` simulated edge/object-store RTT per request:

| Format | HTTP Requests | Transferred | Loopback (`0 ms`) | Simulated WAN (`2 ms` RTT) |
| :--- | ---: | ---: | ---: | ---: |
| `VZ (Zstd)` | **3** | **104.2 KB** | **0.34 ms** | **6.49 ms** |
| `ZIP (Zstd)` | 5,006 | 289,406.2 KB | 164.24 ms | 10,603.96 ms |
| `TAR (Stream)` | 1 | 15,941.2 KB | 13.86 ms | 16.08 ms |
| `TAR.ZST (Stream)` | 1 | 221.2 KB | 5.25 ms | 6.79 ms |

### 8.6 Random I/O & IOPS (`20,000`-file archive: `1T × 10,000` reads, `6T × 30,000` total reads)

`VZ` shares a single opened `File` handle across all 6 worker threads via stateless lock-free `pread` (or `Mmap`) with verified B+Tree node caching; `ZIP` opens one independent `File` handle per thread (`Seek+Read` cannot share a `File::try_clone` fd across threads):

| Format | 1T IOPS | 1T p50 | 1T p99 | 6T IOPS | 6T p50 | 6T p99 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `VZ (None, File pread)` | 386,797 | **2.19 µs** | 7.71 µs | 2,135,551 | **2.13 µs** | 9.45 µs |
| `VZ (LZ4, File pread)` | 340,347 | 2.83 µs | 6.28 µs | 1,779,748 | 3.00 µs | 6.11 µs |
| `VZ (Zstd, File pread)` | 316,512 | 3.19 µs | 5.99 µs | 1,748,005 | 3.22 µs | 5.76 µs |
| `VZ (Zstd, Mmap)` | **423,842** | 2.23 µs | **5.83 µs** | **2,290,044** | 2.30 µs | **5.11 µs** |
| `ZIP (Stored, File)` | 93,488 | 4.32 µs | 10.33 µs | 304,705 | 4.95 µs | 13.71 µs |
| `ZIP (Zstd, File)` | 88,858 | 5.85 µs | 9.97 µs | 265,667 | 6.46 µs | 12.82 µs |
| `TAR.ZST` (10-op sample) | 80.5 | 12,499 µs | 12,957 µs | N/A | — | — |

### 8.7 Partial Byte-Range Read inside `32 MiB` Zstd Blob (`64 KiB` window at `24 MiB` offset)

| Format | Latency | Read from Archive | Notes |
| :--- | ---: | ---: | :--- |
| `VZ (Zstd, 1 MiB chunks)` | **0.07 ms** | **1.2 KB** | `read_file_range` decodes 1 overlapping chunk only |
| `ZIP (Zstd)` | 2.88 ms | 5.2 KB | Must decompress entry stream from `0..24.06 MiB` |
| `TAR.ZST` | 2.10 ms | 3.2 KB | Must decompress solid stream from `0..24.06 MiB` |

### 8.8 Incremental Append & Selective Delete (`+10 × 4 KiB` new files, `-5` deletes on `5,000`-file archive)

| Operation | Time | Bytes Written | Semantics |
| :--- | ---: | ---: | :--- |
| `VZ (LSM Delta Append)` | **1.10 ms** | **105.3 KB** | Appends delta + updates Boot Slot; add, overwrite & tombstone delete |
| `ZIP (new_append)` | 25.85 ms | 336.2 KB | Append-only (cannot delete entries without full archive rewrite) |
| `TAR.ZST (Full Rewrite)` | 18.88 ms | 221.2 KB | Must decompress and re-pack entire archive |

### 8.9 Fault-Injection Self-Healing Recovery (`4 KiB` Boot ECC page + `256 KiB` data cluster wiped)

| Format | Recoverable? | Repair Time | Measured Result |
| :--- | :--- | ---: | :--- |
| `VZ (Boot ECC + RS(4,2))` | **YES (100%)** | **8.34 ms** | `boot_page=Some(2)`, `data_repaired=2`, `data_100%=true` |
| `TAR.ZST` | NO (Fatal) | — | Stream CRC/frame mismatch; remaining entries lost |
| `ZIP (Zstd)` | NO (Fatal) | — | Local header / stream corrupted; no redundancy |

### 8.10 Zero-Reencode LSM Compaction (`5,000` Zstd files + `200` overwrites + `100` tombstones -> single run)

| Compaction Mode | Time | Output Size | Notes |
| :--- | ---: | ---: | :--- |
| `VZ (Zero-Reencode Compact)` | **6.60 ms** | 1.19 MB | Strips LSM runs `2 -> 1`, drops `100` tombstones, copies compressed chunks verbatim |
| `VZ (Full Re-encode Compact)` | 40.27 ms | 1.19 MB | Decompresses and recompresses every live file (`6.10×` slower) |

### 8.11 FUSE3 / VFS Simulation (`FuseVolume` vs `ZIP` vs `TAR.ZST`)

| Workload | `VZ (FuseVolume)` | `ZIP (Zstd)` | `TAR.ZST` | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `readdirplus` (`2,000` entries; mount=2.62 ms, lookup=81.6 ns) | **80.84 µs** (`0` disk I/O) | 21,660.00 µs (268× slower) | 6,083.93 µs (75× slower) | Zero-I/O in-memory POSIX directory/inode graph |
| `64 × 4 KiB` seq VFS reads @ `1 MiB` (`4 MiB` Zstd) | **97.91 µs** (`4` reads, `484 B`) | 256.26 µs (`6` reads, `1,963 B`) | 187.89 µs (`1` read, `555 B`) | `FuseVolume` caches each `64 KiB` chunk across `16` pages |
| `4 KiB` random VFS read (`CODEC_NONE`, `4 MiB` file) | **2.09 µs** (`1` read, `4,096 B`) | — | — | Exact **`1.00×` read amplification** (`read_at`) |

---

## 9. Real-World Game `.pak` Replacement Case Study (Linux Kernel Corpus vs Unreal Engine `.pak`)

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

* **5-Run Point-Release Stack (`v7.1 -> .1 -> .2 -> .3 -> .4`, `lsm_run_count = 5`):** Total patch time across all 4 incremental appends = **236.60 ms**; `FuseVolume::mount` builds the merged `93,709`-file in-memory POSIX graph in **141.07 ms**.
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

