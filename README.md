# VZ (`libvz` v1.0)

**VZ (`.vz`)** is a high-performance, crash-safe, `#![no_std]`-compatible binary container format and storage engine written in Rust with first-class C11 and C++17 ABI bindings.

Designed to unify the roles of cold archives (`.tar.zst`, `.zip`), game asset `.pak` containers, remote HTTP-Range object bundles, and mountable read-only filesystems (FUSE3 / VFS), VZ pairs a fixed-size **64 KiB Boot Block** and **cache-line-aligned (`64 B`) B+Tree directory index** with incremental **LSM overlay deltas**, **zero-reencode compaction**, authenticated **`XChaCha20-Poly1305` encryption**, and two-level **self-healing erasure coding** (Boot Block 4 KiB XOR ECC + Reed-Solomon `GF(2^8)` cluster parity).

* **Binary Wire Specification:** [`SPEC.md`](./SPEC.md)
* **Full Benchmark Report:** [`BENCHMARKS.md`](./BENCHMARKS.md)

---

## Why VZ? (Measured Highlights)

All numbers below are measured on an AMD Ryzen 5 5600H (Linux `x86_64`, default `--release`; see [`BENCHMARKS.md`](./BENCHMARKS.md) for methodology and full tables):

| Capability / Workload | VZ Result | Baseline Comparison |
| :--- | :--- | :--- |
| **Cold Open + Read Single Asset** (`93,709`-file Linux tree) | **148.90 µs** (`141 KB` read) | **448× faster** than Unreal Engine `.pak` (`repak` V11 Zstd: `66.71 ms`, `5.05 MB` index) |
| **Cold Open + Read (`5,000`-file mixed corpus)** | **21.45 µs** (`3` reads) | **207× faster** than `TAR.ZST` (`4.44 ms`); **562× faster** than `ZIP` (`12.06 ms`, `5,005` reads) |
| **HTTP/1.1 Range Read (`2 ms` WAN RTT)** | **6.49 ms** (`3` requests, `104.2 KB`) | **1,634× faster** than `ZIP` (`10,603.96 ms`, `5,006` requests, `289.4 MB`) |
| **6-Thread Random Read IOPS (`20,000` files, Zstd)** | **2,290,044 IOPS** (`Mmap`, `p99 5.11 µs`) / **1,748,005 IOPS** (`File pread`) | **6.6×–8.6× higher** than `ZIP (Zstd, File)` (`265,667 IOPS`) |
| **FUSE3 / VFS `readdir` (`2,000` entries)** | **57.59 µs** (`readdir_visit`) / **75.48 µs** (`FuseVolume::readdirplus`) | **75×–268× faster** than `TAR.ZST` (`6.08 ms`) and `ZIP` (`21.66 ms`) |
| **FUSE3 / VFS `4 KiB` Random Read (`CODEC_NONE`)** | **0.12 µs** (`1` read, exact **`1.00×`** read amplification) | Zero intermediate cluster/stream decode overhead |
| **Tier-1 Hotfix Patch (`+1 / ~658 / -4` on `93,709` files)** | **235.43 ms** (`7.89 MB` delta + tombstones) | UE `.pak` (`435.17 ms`, `12.72 MB`, no deletes); `TAR.ZST` (`6.41 s`, `226 MB`); `ZIP` (`8.18 s`, `302 MB`) |
| **Zero-Reencode LSM Compaction (`v4.19 -> v7.1`, `492 MiB`)** | **724.32 ms** (reclaims `191.65 MiB` / `38.9%`) | **8.75× faster** than full re-encode compaction (`6,339.76 ms`) |
| **Self-Healing Recovery (Boot Page + Cluster Wipe)** | **100% repaired in 8.34 ms** (`RS_GF256(8,2)` `3.33 GB/s` AVX2) | `ZIP` / `TAR.ZST`: unrecoverable (`0%`) |
| **Bounded-Memory `64 MiB` Streaming Pipe** | **4.00 MiB** peak heap delta (`VzPipeWriter`) / **1.06 MiB** decode | Constant memory independent of blob size |
| **SIMD Primitives (`1 MiB` buffer)** | `crc32c` SSE4.2: **10.31 GB/s** · `rs_gf256` AVX2: **34.85 GB/s** | Runtime CPUID detection with safe portable fallbacks |

---

## Key Features

* **`#![no_std]` Zero-Copy Wire Engine:** Core parsers, LE-VINT codecs, `crc32c`, `BootEccDescriptor`, `RouteNodeView`/`LeafNodeView`, and `HASH_ALGO_*` work without `std` or heap allocation (`--no-default-features`, including `wasm32-unknown-unknown`).
* **O(1)-RTT Boot Open & B+Tree Directory Index:** Dual 64-byte commit slots (`Slot A`/`Slot B`, monotonic `generation`, strict `incompat_flags` downgrade guard) + flat Boot Block leaf (`tree_height == 0`) or `4 KiB` internal/leaf nodes for `1`-RTT to `1 + height + 1`-RTT remote reads.
* **Small-File Inlining & Smart Chunking:** Payloads `<= 27 B` inline directly inside directory entries (`data_clusters = 0` possible); large blobs automatically split into multi-cluster chunks with a `TAG_CHUNK_TABLE` seek table for `O(1)` sub-range reads (`read_file_range` / `read_file_range_into`).
* **Sparse Files, POSIX Metadata & Schema/Dictionary Registries:** Built-in sparse extent maps (zero-I/O hole reads), symlinks, hardlinks (`nlink` resolution), special nodes (`FIFO`/`CHR`/`BLK`/`SOCK`), owners (`uid`/`gid`), extended timestamps (`atime`/`ctime`/`btime`), xattrs, tensor metadata TLVs, and shared Zstd dictionaries (`CDict`/`DDict`).
* **Crash-Safe Incremental LSM Overlays & Tombstones:** `LsmAppendWriter` appends deltas without rewriting existing data clusters, supports overwrites and explicit file tombstones (`FLAG_TOMBSTONE`), and updates the Boot Block atomically.
* **Zero-Reencode LSM Compaction:** Merges multi-run archives (`compact_archive_with_options`) by copying surviving compressed/encrypted clusters verbatim—reclaiming dead blocks without decompressing or recompressing live files.
* **Two-Level Self-Healing Erasure Coding:**
  * **Boot ECC (`COMPAT_BOOT_ECC`):** Single-page 4 KiB XOR recovery across the first 15 pages (`0x0000..0xF000`) with automatic repair on open (`~5.85 µs` clean check).
  * **Stream ECC (`RO_COMPAT_STREAM_ECC`):** Reed-Solomon `GF(2^8)` Cauchy stripes `(K, M)` with `K + M <= 256` protecting data clusters against up to `M` arbitrary cluster corruptions/erasures.
* **Authenticated Encryption:** Per-chunk/cluster `XChaCha20-Poly1305` AEAD backed by either `Argon2id` passphrase KDF or raw 256-bit keys (`EncryptionKey`).
* **FUSE3 / VFS Engine (`FuseVolume`):** In-memory POSIX directory/inode graph with `O(1)` `getattr`, `lookup`, `readdir`/`readdirplus`, `readlink`, `getxattr`/`listxattr`, and a per-handle chunk cache for sequential VFS reads.
* **Auto-Generated C11 & C++17 Bindings (`libvz-ffi`):** Shared (`libvz.so`) and static (`libvz.a`) libraries with `cbindgen`-generated `vz.h` and `build.rs`-generated RAII `vz.hpp`.

---

## Workspace Structure

```
vz/
├── Cargo.toml                  # Workspace definition (crates/libvz, libvz-ffi, vz-tools, vz-bench)
├── SPEC.md                     # Binary wire format specification (VZ v1.0)
├── BENCHMARKS.md               # Criterion, cross-format, FUSE3 & UE .pak benchmark report
└── crates/
    ├── libvz/                  # Core Rust library (#![no_std] core + high-level & low-level APIs)
    ├── libvz-ffi/              # C11 / C++17 ABI crate (`cdylib` + `staticlib`)
    │   ├── build.rs            # Auto-generates include/vz.h (cbindgen) & include/vz.hpp (parity-checked)
    │   ├── include/            # Generated vz.h and vz.hpp headers
    │   └── examples/           # Verified C11 (c_example.c) and C++17 (cpp_example.cpp) examples
    ├── vz-tools/               # `vz` CLI binary (pack, unpack, ls, stat, cat, verify, repair, append, compact, inspect)
    └── vz-bench/               # Cross-format comparison suite (`vz-compare`) & UE .pak case study (`pak_patch_bench`)
```

---

## Physical Container Layout

Every `.vz` file starts with a fixed-size **Boot Block** (default `65,536 B` / `64 KiB`, `4 KiB`-aligned) followed by doubly-linked **Clusters** (`64 B` aligned payloads):

```
+-----------------------------------------------------------------------+
| Boot Block (0x0000 .. boot_block_size; default 64 KiB / 16 × 4 KiB)   |
|  ├── 0x0000..0x0040 : HeaderSlot A (64 B, Castagnoli CRC32C)          |
|  ├── 0x0040..0x0080 : HeaderSlot B (64 B, monotonic generation)       |
|  ├── registry_off   : Global Registry TLVs (Zstd Dicts, Schemas, etc.)|
|  ├── root_node_off  : Root B+Tree Node (inline Leaf if height == 0,   |
|  │                    or RouteEntry[] internal root if height >= 1)   |
|  ├── 0xEFB0..0xF000 : BootEccDescriptor (80 B, page CRC32C table)     |
|  └── 0xF000..0x10000: Boot Parity Page 15 (4 KiB XOR across Pages 0..14)|
+-----------------------------------------------------------------------+
| Cluster 0  [ClusterHeader ("VZ_CLUST") | Payloads/TLVs | ClusterFooter ("ENDC")]
| Cluster 1  [...]
| ...
| Cluster N  [Optional RS_GF256 TAG_PARITY_CLUSTER / TAG_ROOT_FALLBACK]
+-----------------------------------------------------------------------+
```

See [`SPEC.md`](./SPEC.md) for byte-level layouts, TLV tags, LE-VINT rules, Boot ECC recovery invariants, and LSM overlay resolution order.

---

## Building & Installing

### Prerequisites

* Rust toolchain (`edition = "2024"`, tested with `rustc 1.97.1`)
* Optional for C/C++ tests: `gcc` (C11) and `g++` (C++17)

### Build Workspace Release Artifacts

```bash
cargo build --workspace --release --all-features
```

Release outputs are placed in `target/release/`:
* `target/release/vz` — CLI utility (`vz-tools`)
* `target/release/vz-compare` — Cross-format benchmark runner (`vz-bench`)
* `target/release/libvz.so` — Dynamic C/C++ shared library (`libvz-ffi`)
* `target/release/libvz.a` — Static C/C++ archive (`libvz-ffi`)
* `crates/libvz-ffi/include/vz.h` & `crates/libvz-ffi/include/vz.hpp` — Auto-generated C and C++ headers

Install the CLI locally:

```bash
cargo install --path crates/vz-tools
```

### Feature Flags (`libvz`)

| Feature | Default | Description |
| :--- | :---: | :--- |
| `std` | Yes | Standard I/O traits (`File`, buffered writers), high-level `api`, `FuseVolume`, readers/writers |
| `compression` | No | `LZ4` (`lz4_flex`) and `Zstd` (`zstd`, including shared `CDict`/`DDict` support) |
| `hashes` | No | `XXH3-64` and `BLAKE3-64` path/integrity hashes (`#![no_std]` compatible) |
| `crypto` | No | `XChaCha20-Poly1305` AEAD, `Argon2id`, `HKDF-SHA256`, random nonces/salts |
| `mmap` | No | Zero-copy `MmapRangeReader` via `memmap2` |
| `cli` | No | `clap` enums (`CliCodec`, `CliHashAlgo`) for `vz-tools` |

Disable defaults (`default-features = false`) for bare-metal / WASM `#![no_std]` builds:

```bash
cargo check -p libvz --no-default-features
cargo check -p libvz --target wasm32-unknown-unknown --no-default-features
```

---

## CLI Usage (`vz`)

```bash
# Pack a directory with Zstd compression and Reed-Solomon K=6, M=3 erasure parity
vz pack ./assets assets.vz --codec zstd --level 3 --rs 6,3

# Pack via streaming pipe (or keep Boot Block unfinalized with --unfinalized-pipe)
vz pack ./assets pipe.vz --codec zstd --pipe

# Pack with Argon2id passphrase encryption and BLAKE3 directory hashes
vz pack ./secrets vault.vz --codec zstd --hash blake3 --password "correct-horse-battery"

# Inspect container headers, registry TLVs, LSM run count, and cluster chain
vz inspect assets.vz

# List entries, view metadata, or stream a file to stdout
vz ls assets.vz -r /
vz stat assets.vz /shaders/water.spv
vz cat assets.vz /config/settings.json

# Verify Boot ECC, cluster CRCs, B+Tree structure, and RS parity; repair damaged sectors
vz verify assets.vz
vz repair assets.vz

# Apply an incremental LSM hotfix (adds/overwrites and tombstone deletions)
vz append assets.vz \
  --add ./hotfix/water.spv:/shaders/water.spv \
  --delete /legacy/unused.bin \
  --codec zstd

# Compact multi-run LSM archive into a single clean run (zero re-encoding by default)
vz compact assets.vz assets_compacted.vz

# Unpack full archive (use --mmap for zero-copy memory-mapped reads)
vz unpack assets_compacted.vz ./out --mmap
```

---

## Rust API (`libvz`)

### High-Level API (`ArchiveBuilder`, `Archive`, `Compression`)

```rust
use libvz::{Archive, ArchiveBuilder, CompactOptions, Compression};

fn main() -> Result<(), libvz::VzError> {
    // 1. Create a Zstd-compressed, Reed-Solomon (6,2) protected archive
    let mut writer = ArchiveBuilder::new()
        .compression(Compression::Zstd { level: 3 })
        .rs_parity(6, 2)
        .create("bundle.vz")?;

    writer
        .add_dir("/assets")?
        .add("/assets/hello.txt", b"small inline payload")?
        .add_file("/assets/mesh.bin", "path/on/disk/mesh.bin")?
        .add_hardlink("/assets/hello_hl.txt", "/assets/hello.txt")?;
    writer.finish()?;

    // 2. Apply an incremental LSM delta patch (overwrite + tombstone delete)
    let mut append = Archive::append_session("bundle.vz", None)?;
    append.add_file("/assets/patch.txt", b"v2 hotfix")?;
    append.delete("/assets/hello.txt")?;
    append.finish()?;

    // 3. Open with memory-mapped zero-copy I/O and inspect/read
    let archive = unsafe { Archive::open_mmap("bundle.vz", None)? };
    assert_eq!(archive.reader().lsm_runs().len(), 2);
    assert!(!archive.exists("/assets/hello.txt")?);
    let data = archive.get("/assets/patch.txt")?;
    assert_eq!(&data, b"v2 hotfix");

    // 4. Zero-reencode compaction (strips LSM runs back to 1)
    archive.compact_to("bundle_clean.vz", CompactOptions::default())?;

    Ok(())
}
```

### Low-Level, HTTP/Custom `RangeReader`, and FUSE3 VFS

* **`libvz::low_level`**: Exposes wire structs (`BootHeader`, `ClusterHeader`, `DirEntry`, `RouteEntry`), `BootEccDescriptor`, `rs_gf256_*`, `VzWriter`, `VzPipeWriter`, `VzReader`, `read_file_range_into`, and the stateless `RangeReader` trait (e.g., implement `RangeReader` over HTTP `Range:` requests for `1`-RTT to `4`-RTT cloud reads).
* **`libvz::fuse::FuseVolume`**: Mounts any `VzReader<R>` as a read-only POSIX VFS graph supporting `getattr`, `lookup`, `readdirplus`, `open`, `read_into`, `readlink`, `getxattr`, and `listxattr`.

---

## C11 & C++17 Bindings (`libvz-ffi`)

Both C and C++ headers are **automatically generated** during `cargo build -p libvz-ffi`:
* [`crates/libvz-ffi/include/vz.h`](crates/libvz-ffi/include/vz.h): Generated by `cbindgen` ([`cbindgen.toml`](crates/libvz-ffi/cbindgen.toml)).
* [`crates/libvz-ffi/include/vz.hpp`](crates/libvz-ffi/include/vz.hpp): Generated by [`build.rs`](crates/libvz-ffi/build.rs), which also verifies 100% wrapper coverage against every `vz_*` symbol in `vz.h`.

### FFI Surface Highlights

* **ABI Versioning:** `#define VZ_ABI_VERSION 1` and runtime `vz_abi_version()` for `dlopen` checks.
* **Zero-Copy Caller Buffers (`_into`):** `vz_archive_read_range_into` and `vz_fuse_read_into` write directly into caller-owned stack/ring buffers with zero per-call heap allocations.
* **Chunked Streaming File Writes:** `vz_writer_file_begin`, `vz_writer_file_write`, `vz_writer_file_end`, and `vz_writer_file_abort` pack multi-gigabyte assets in bounded memory (`4.00 MiB` peak).
* **Full POSIX & FUSE3 Surface:** `vz_fuse_mount`, `vz_fuse_lookup`, `vz_fuse_getattr`, `vz_fuse_readdir`, `vz_fuse_readdirplus`, `vz_fuse_open`, `vz_fuse_read_into`, `vz_fuse_readlink`, `vz_fuse_getxattr`, `vz_fuse_listxattr`, `vz_writer_add_special` (`FIFO`/`CHR`/`BLK`/`SOCK`), and `uid`/`gid`/`btime_ns` via `VzEntryOptionsC`.
* **LSM Patch & Compact:** `vz_append_open`, `vz_append_add_file`, `vz_append_add_symlink`, `vz_append_add_hardlink`, `vz_append_delete`, `vz_archive_compact` (with `rs_parity_k` / `rs_parity_m`), and zero-alloc `vz_archive_readdir_visit`.

### C11 Example ([`c_example.c`](crates/libvz-ffi/examples/c_example.c))

```c
#include "vz.h"
#include <assert.h>
#include <string.h>

int main(void) {
    assert(vz_abi_version() == VZ_ABI_VERSION);

    VzWriterConfigC cfg = vz_writer_config_default();
    cfg.default_codec = VZ_CODEC_ZSTD;
    VzWriterHandle* w = NULL;
    assert(vz_writer_create("demo.vz", &cfg, &w) == VZ_OK);

    VzStreamFileHandle* sf = NULL;
    assert(vz_writer_file_begin(w, "/pak/stream.bin", NULL, &sf) == VZ_OK);
    const uint8_t chunk[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    assert(vz_writer_file_write(w, sf, chunk, sizeof(chunk)) == VZ_OK);
    assert(vz_writer_file_end(w, sf) == VZ_OK);
    assert(vz_writer_finish(w) == VZ_OK);

    VzArchive* arc = NULL;
    assert(vz_archive_open("demo.vz", NULL, &arc) == VZ_OK);

    uint8_t buf[8];
    size_t got = 0;
    assert(vz_archive_read_range_into(arc, "/pak/stream.bin", 0, sizeof(buf), buf, sizeof(buf), &got) == VZ_OK);
    assert(got == sizeof(buf) && memcmp(buf, chunk, sizeof(buf)) == 0);

    vz_archive_close(arc);
    return 0;
}
```

### C++17 RAII Example ([`cpp_example.cpp`](crates/libvz-ffi/examples/cpp_example.cpp))

```cpp
#include "vz.hpp"
#include <cassert>

int main() {
    auto cfg = vz_writer_config_default();
    cfg.default_codec = VZ_CODEC_ZSTD;
    auto w = vz::Writer::create("demo.vz", cfg);
    w.add_dir("/pak", 0755);
    w.add_file("/pak/config.ini", "[render]\nvsync=1\n");
    w.finish();

    auto app = vz::AppendWriter::open("demo.vz");
    app.add_file("/pak/hotfix.txt", "patched-v2");
    app.finish();

    auto arc = vz::Archive::open("demo.vz");
    auto vol = vz::FuseVolume::mount(arc);
    auto pak = vol.lookup(VZ_FUSE_ROOT_ID, "pak");
    auto cfg_attr = vol.lookup(pak.ino, "config.ini");
    auto fh = vol.open(cfg_attr.ino);

    uint8_t out[64];
    size_t n = vol.read_into(fh, 0, sizeof(out), out, sizeof(out));
    assert(n > 0);
    return 0;
}
```

Compile & link against the release libraries:

```bash
gcc -std=c11 -O2 -Icrates/libvz-ffi/include my_app.c target/release/libvz.so -Wl,-rpath,'$ORIGIN' -lm -ldl -lpthread -o my_app
g++ -std=c++17 -O2 -Icrates/libvz-ffi/include my_app.cpp target/release/libvz.a -lm -ldl -lpthread -o my_app_static
```

---

## Testing & Benchmarks

### Run All Tests, Lints & `#![no_std]` Checks

```bash
# Run full workspace tests (unit, property, fuzz, Boot ECC/RS fault injection, FUSE3, CLI, C11/C++17 FFI)
cargo test --workspace --all-features

# Strict lints
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Verify zero std/alloc core + WASM compatibility
cargo check -p libvz --no-default-features
cargo check -p libvz --target wasm32-unknown-unknown --no-default-features
```

### Run Benchmarks

```bash
# Microbenchmarks (Criterion)
cargo bench -p libvz --all-features

# End-to-end metrics suite (throughput, RTT simulation, memory footprint, FUSE3, recovery)
cargo run --release -p libvz --all-features --example metrics_runner

# Cross-format comparison against TAR / TAR.GZ / TAR.LZ4 / TAR.ZST / ZIP
cargo run --release -p vz-bench --bin vz-compare

# Optional real-world UE .pak (repak) + 3-tier Linux kernel patch benchmark
cargo run --release -p vz-bench --example pak_patch_bench -- --repo /path/to/linux.git
# (or fetch shallow tags into a standalone bare repo: --fetch /tmp/vz-linux-corpus)
```

---

## License

Dual-licensed under **MIT OR Apache-2.0** (`license = "MIT OR Apache-2.0"`).
