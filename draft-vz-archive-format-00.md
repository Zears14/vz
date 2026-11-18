%%%
title = "The VZ v1.0 Binary Container and Archive Format"
abbrev = "VZ Archive Format"
category = "info"
docName = "draft-vz-archive-format-00"
date = 2026-11-18T00:00:00Z
submissionType = "independent"
ipr = "trust200902"
area = "Applications and Real-Time"
keyword = ["archive", "container", "erasure-coding", "b-tree", "zstd"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-vz-archive-format-00"
stream = "independent"
status = "informational"

[[author]]
fullname = "Zears"
  [author.address]
  email = "me@zears.xyz"
  uri = "https://github.com/Zears14/vz"
%%%

.# Abstract

This document specifies the VZ v1.0 binary container and archive format
(".vz"). VZ is a little-endian, zero-copy-parsable archive format
engineered for single-round-trip (1-RTT) HTTP Range opening, 64-byte
cache-line payload alignment, crash-safe dual-slot atomic commits,
self-healing Boot Block error correction, Reed-Solomon GF(2^8) erasure
parity, authenticated XChaCha20-Poly1305 encryption, forward-only
streaming pipes, and incremental Log-Structured Merge (LSM) overlays.

{mainmatter}

# Introduction

Traditional archive formats either optimize for sequential streaming
(such as TAR) at the expense of O(N) random-access latency, or place
central directories at the end of the file (such as ZIP), requiring
multiple round trips over high-latency transports and complicating
crash-safe atomic updates.

The VZ v1.0 container format addresses these constraints with a fixed-size
Boot Block at offset 0 followed by a stream of self-describing,
64-byte-aligned Clusters:

* **1-RTT Remote Access:** A single HTTP Range fetch of the Boot Block
  (default 64 KiB) retrieves the dual commit slots, Global Registry,
  and root B+Tree index.
* **Zero-Copy Alignment:** Cluster payloads are aligned to 64-byte
  boundaries for direct memory mapping and SIMD/AVX-512 consumption.
* **Crash Safety & Self-Healing:** Dual alternating HeaderSlots provide
  atomic generation commits, protected by a 4 KiB bitwise XOR parity
  page across the Boot Block and systematic Cauchy Reed-Solomon parity
  clusters across the data stream.
* **Authenticated Encryption:** Optional per-payload XChaCha20-Poly1305
  encryption cryptographically binds every payload chunk to its commit
  generation, cluster sequence number, and 64-bit entry identifier.

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in
all capitals, as shown here.

All multi-byte integer fields in the VZ wire format are encoded in
**Little-Endian (LE)** byte order unless explicitly stated otherwise.
Byte ranges are denoted as half-open intervals `(start .. end)`.

## Constants and Checksum Primitive

| Constant | Wire / LE Value | Description |
| :--- | :--- | :--- |
| `MAGIC_HEADER` | `0x0000000000015A56` (`"VZ\x01\0\0\0\0\0"`) | `HeaderSlot` magic |
| `MAGIC_CLUSTER` | `0x5453554C435F5A56` (`"VZ_CLUST"`) | `ClusterHeader` magic |
| `MAGIC_FOOTER` | `0x43444E45` (`"ENDC"`) | `ClusterFooter` magic |
| `MAGIC_BOOT_ECC` | `0x43434542` (`"BECC"`) | `BootEccDescriptor` magic |
| `DEFAULT_BOOT_SIZE` | `65536` (64 KiB) | Default Boot Block size |
| `PAGE_SIZE` | `4096` (4 KiB) | Boot Block ECC page unit |
| `BOOT_ECC_DESC_OFF` | `0xEFB0` | Offset of `BootEccDescriptor` |
| `BOOT_PARITY_OFFSET` | `0xF000` | Offset of Boot Parity Page 15 |
| `PAYLOAD_ALIGNMENT` | `64` | Payload alignment (bytes) |
| `TREE_HEIGHT_PIPE` | `0xFF` | Unfinalized pipe sentinel |
| `EXT_META_NONE` | `0` | Absent extended metadata |
Table: VZ v1.0 Protocol Constants

All 32-bit cyclic redundancy checks (`crc32c`) in VZ MUST use the
Castagnoli polynomial (`0x1EDC6F41`, reflected `0x82F63B78`) with
initial value `0xFFFFFFFF` and final XOR `0xFFFFFFFF` as defined in
[@!RFC7143] (test vector: `crc32c("123456789") == 0xE3069283`).

# Physical Container Layout

A VZ archive consists of a contiguous Boot Block occupying
`0 .. boot_block_size` immediately followed by zero or more
self-describing Clusters occupying `boot_block_size .. EOF`:

```
+-------------------------------------------------------------------+
| Boot Block (0x0000 .. boot_block_size) (default 65,536 bytes)     |
|  +-- (0x0000 .. 0x0040) : HeaderSlot A (64 bytes)                 |
|  +-- (0x0040 .. 0x0080) : HeaderSlot B (64 bytes)                 |
|  +-- (registry_offset .. +registry_size) : Global Registry TLVs   |
|  +-- (root_node_offset ..) : Root B+Tree Node                     |
|  +-- (optional zero padding)                                      |
|  +-- (0xEFB0 .. 0xF000) : BootEccDescriptor (if COMPAT_BOOT_ECC)  |
|  +-- (0xF000 .. 0x10000): Boot Parity Page 15 (if COMPAT_BOOT_ECC)|
+-------------------------------------------------------------------+
| Cluster 0 (at offset boot_block_size)                             |
| Cluster 1                                                         |
| ...                                                               |
| Cluster N (optional Parity Clusters / TAG_ROOT_FALLBACK at EOF)   |
+-------------------------------------------------------------------+
```

# Boot Header and Feature Flags

## HeaderSlot Structure (64 Bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        magic (64 bits)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     generation (64 bits)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    boot_block_size (32 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      compat_flags (16)        |     ro_compat_flags (16)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     incompat_flags (16)       |tree_height(8) | hash_algo (8) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     lsm_run_count (16)        |     registry_offset (16)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     registry_size (32 bits)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   root_node_offset (32 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    total_entries (64 bits)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  root_fallback_off (64 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   root_entry_count (32 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    header_crc32c (32 bits)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* `magic` (u64): MUST equal `MAGIC_HEADER`.
* `generation` (u64): Monotonically increasing commit counter.
* `boot_block_size` (u32): Total byte length of the Boot Block (`65536`
  by default). MUST be `65536` unless `INCOMPAT_BIG_BOOT` is set.
* `compat_flags` (u16): Compatible feature bitmask. Readers and writers
  MAY safely ignore unknown bits.
* `ro_compat_flags` (u16): Read-only compatible feature bitmask. Readers
  MAY ignore unknown bits; writers modifying the archive in place MUST
  understand all set bits or refuse modification.
* `incompat_flags` (u16): Incompatible feature bitmask. Readers and
  writers MUST abort if any unknown bit is set.
* `tree_height` (u8): `0` when the root node in the Boot Block is a
  flat `LeafNode`; `>= 1` for B+Tree depth; `0xFF` (`TREE_HEIGHT_PIPE`)
  for an unfinalized streaming pipe.
* `hash_algo` (u8): Key hashing function (`0x00` = Built-in, `0x01` =
  XXH3-64, `0x02` = BLAKE3-64).
* `lsm_run_count` (u16): Number of active incremental B+Tree runs (`1`
  for a single-run or compacted archive).
* `registry_offset` (u16): Byte offset within the Boot Block to the
  Global Registry TLV sequence (typically `0x0080`).
* `registry_size` (u32): Byte length of the Global Registry TLV zone.
* `root_node_offset` (u32): Byte offset within the Boot Block to the
  root node.
* `total_entries` (u64): Total count of live entries across the archive.
* `root_fallback_off` (u64): Absolute byte offset to a trailing
  `TAG_ROOT_FALLBACK` cluster, or `0` if none.
* `root_entry_count` (u32): Number of `DirEntry` (`tree_height == 0`) or
  `RouteEntry` (`tree_height >= 1`) records in the root node.
* `header_crc32c` (32 bits): `crc32c` computed over bytes `0 .. 60` of
  the `HeaderSlot`.

## Dual-Slot Atomic Selection Invariant

`HeaderSlot A` occupies `0x0000 .. 0x0040` and `HeaderSlot B` occupies
`0x0040 .. 0x0080`. When opening an archive, a reader MUST execute the
following selection procedure in exact order:

1. Validate `magic == MAGIC_HEADER` and `header_crc32c` independently
   on both `slot_a` and `slot_b`.
2. Among valid slots, select the slot with the strictly higher
   `generation` value. If both slots are valid and have equal
   `generation`, `slot_a` MUST be selected.
3. Evaluate `incompat_flags` on the selected winning slot. If any
   unrecognized bit is set, the reader MUST fail immediately and MUST
   NOT fall back to the older-generation slot.

## Feature Flag Definitions

### Compatible Flags (`compat_flags`)

* `COMPAT_BOOT_ECC` (`1 << 0`): Boot Block contains `BootEccDescriptor`
  at `0xEFB0` and XOR parity at `0xF000`.
* `COMPAT_BLOOM_ROUTES` (`1 << 1`): `RouteEntry.subtree_count_lo` carries
  a legacy 32-bit Bloom filter.
* `COMPAT_COL_STATS` (`1 << 2`): Analytical min/max column statistics
  are present in `TAG_SCHEMA_TABLE` and `TAG_DATA_MANIFEST`.

### Read-Only Compatible Flags (`ro_compat_flags`)

* `RO_COMPAT_STREAM_ECC` (`1 << 0`): Data stream includes
  `TAG_PARITY_CLUSTER` erasure parity clusters.
* `RO_COMPAT_LSM_RUNS` (`1 << 1`): Multi-run incremental LSM B+Tree
  overlay is active (`lsm_run_count > 1`).

### Incompatible Flags (`incompat_flags`)

* `INCOMPAT_ENCRYPTED` (`1 << 0`): Payloads are encrypted using parameters
  in `TAG_CIPHER_HEADER`.
* `INCOMPAT_BIG_BOOT` (`1 << 1`): `boot_block_size > 65536`.
* `INCOMPAT_COMPACTING` (`1 << 2`): Archive is mid-flight during a
  crash-safe in-place compaction (`HeaderSlot.root_fallback_off` points
  to the EOF compaction journal). Normal readers MUST abort until
  compaction completes or resumes.

# Boot Block 4 KiB Self-Healing ECC

When `COMPAT_BOOT_ECC` is set, the first 60 KiB (`Pages 0..14`, offsets
`0x0000 .. 0xF000`) are protected by a 4 KiB bitwise XOR parity page
stored in `Page 15` (`0xF000 .. 0x10000`).

## BootEccDescriptor (80 Bytes at `0xEFB0..0xF000`)

* `ecc_magic` (u32, offset `0`): MUST equal `MAGIC_BOOT_ECC`.
* `protected_pages` (u16, offset `4`): MUST equal `15`.
* `ecc_scheme` (u16, offset `6`): MUST equal `1` (4 KiB bitwise XOR).
* `page_crc32c` (array of 16 `u32` values, offset `8`): Per-page CRCs.
  Elements `0..14` hash full 4,096-byte pages; element `14`
  hashes `0xE000 .. 0xEFAF` (4,016 bytes, excluding the descriptor);
  element `15` hashes `Page 15` (`0xF000 .. 0x10000`).
* `reserved` (u32, offset `72`): MUST equal `0`.
* `desc_crc32c` (u32, offset `76`): `crc32c` over descriptor bytes
  `0 .. 76`.

## Encoding and Recovery Procedure

To encode Boot ECC, a writer MUST compute `page_crc32c` elements `0..15`,
write the descriptor with element `15` set to `0` and `desc_crc32c = 0`,
compute `Page 15` as the bitwise XOR of `Pages 0..15`, populate element
`15` and `desc_crc32c`, and write the finalized descriptor.

During verification or repair:

1. **Corrupt Descriptor (`desc_crc32c` or header fields invalid):** A
   reader MAY attempt recovery by XOR-reconstructing `Page 14` from
   `Pages 0..=13` and `Page 15`. Recovery succeeds if and only if the
   reconstructed descriptor has valid `ecc_magic`, `protected_pages == 15`,
   `ecc_scheme == 1`, `reserved == 0`, `page_crc32c` element `15` equal
   to `0`, `desc_crc32c == 0`, and all 15 `page_crc32c` elements `0..15`
   match.
2. **Valid Descriptor:** Compare computed CRCs for `Pages 0..15` and
   `Page 15` against `page_crc32c` elements `0..16`:
   * If 0 pages fail: Boot Block is intact.
   * If only `Page 15` fails: Recompute `Page 15` parity.
   * If exactly 1 data page (`0..=14`) fails and `Page 15` is valid:
     Zero `page_crc32c` element `15` and `desc_crc32c` in memory,
     XOR-reconstruct the damaged page, restore the descriptor, and verify
     the repaired page against its stored `page_crc32c` entry.
   * If 2 or more pages fail: Return an unrecoverable corruption error.
     (If a torn write occurred during a dual-slot update, a reader MAY
     still attempt `HeaderSlot` selection if one slot remains CRC-valid,
     while reporting the ECC failure.)

# LE-VINT and Context-Free TLV Framing

## LE-VINT Variable-Length Unsigned Integers

`LE-VINT` encodes unsigned integers in `0 .. 2^62` using the two least
significant bits of byte `0` (`byte0 & 0x03`) to signal byte width:

| Low 2 Bits | Width | Value Bits | Value Range | Encoding Formula |
| :--- | :--- | :--- | :--- | :--- |
| `0b00` (`0`) | 1 byte | 6 bits | `0 .. 64` | `(val << 2) \| 0` |
| `0b01` (`1`) | 2 bytes | 14 bits | `64 .. 16,384` | `((val << 2) \| 1).to_le()` |
| `0b10` (`2`) | 4 bytes | 30 bits | `16,384 .. 2^30` | `((val << 2) \| 2).to_le()` |
| `0b11` (`3`) | 8 bytes | 62 bits | `2^30 .. 2^62` | `((val << 2) \| 3).to_le()` |
Table: LE-VINT Wire Encoding

Writers SHOULD emit the minimal canonical byte width for a given value;
readers MUST accept non-minimal encodings up to 8 bytes. Values `>= 2^62`
MUST be rejected with an overflow error.

## Context-Free TLV Framing and Alignment Padding

Every TLV element has the structure `Tag (LE-VINT) || Length (LE-VINT) || Value (Length bytes)`, with one exception:

* `TAG_NOP` (decoded tag `0x00`, wire byte `0x00`): Unconditional 1-byte
  padding element with **no** `Length` field.
* `TAG_VOID` (decoded tag `0x3B`, wire first byte `0xEC`): Standard TLV
  padding `0xEC || LE-VINT(len) || len zero bytes`.

To align an offset to a 64-byte boundary (`pad = (64 - (off % 64)) % 64`),
a writer emits `0` bytes when `pad == 0`, `0x00` (`TAG_NOP`) when
`pad == 1`, and `0xEC || LE-VINT(pad - 2) || zero bytes` when `pad` is in `2..=63`.
Readers MUST skip unknown TLV tags in context-free TLV streams using their
decoded `Length` field unless specified otherwise.

## TLV Tag Registry

| Decoded Tag | Wire Byte 0 | Name | Scope |
| :--- | :--- | :--- | :--- |
| `0x00` | `0x00` | `TAG_NOP` | 1-byte pad / `ExtMetaPool` terminator |
| `0x04` | `0x10` | `TAG_SCHEMA_TABLE` | Boot Registry: tensor & column schemas |
| `0x05` | `0x14` | `TAG_DICT_TABLE` | Boot Registry: Zstd dictionaries |
| `0x06` | `0x18` | `TAG_OWNER_TABLE` | Boot Registry: POSIX UID/GID table |
| `0x07` | `0x1C` | `TAG_LSM_RUNS` | Boot Registry: LSM run descriptors |
| `0x08` | `0x20` | `TAG_DATA_MANIFEST` | Cluster: payload manifest & payload |
| `0x09` | `0x24` | `TAG_DIR_NODE` | Cluster: external B+Tree node |
| `0x0A` | `0x28` | `TAG_PARITY_CLUSTER` | Cluster: Reed-Solomon parity stripe |
| `0x0B` | `0x2C` | `TAG_CHUNK_TABLE` | Cluster: multi-cluster extent map |
| `0x0C` | `0x30` | `TAG_CIPHER_HEADER` | Boot Registry: encryption header |
| `0x0D` | `0x34` | `TAG_ROOT_FALLBACK` | Cluster (EOF): pipe root index |
| `0x10` | `0x40` | `TAG_XATTR_LIST` | `ExtMetaPool`: extended attributes |
| `0x11` | `0x44` | `TAG_SPARSE_EXTENTS` | `ExtMetaPool`: sparse logical map |
| `0x12` | `0x48` | `TAG_EXT_OWNER` | `ExtMetaPool`: extended owner (`255`) |
| `0x13` | `0x4C` | `TAG_EXT_TIME` | `ExtMetaPool`: 24-byte `ExtTime` |
| `0x14` | `0x50` | `TAG_PARENT_PATH` | `ExtMetaPool`: exact parent path |
| `0x15` | `0x54` | `TAG_INODE_HI` | `ExtMetaPool`: upper 32 bits of inode |
| `0x16` | `0x58` | `TAG_EXT_CODEC` | `ExtMetaPool`: extended codec/dict ID |
| `0x17` | `0x5C` | `TAG_SCHEMA_LINK` | `ExtMetaPool`: links `schema_id` |
| `0x3A` | `0xE8` | `TAG_VENDOR_EXT` | Self-identifying vendor TLV extension |
| `0x3B` | `0xEC` | `TAG_VOID` | Context-free multi-byte void padding |
Table: VZ v1.0 TLV Tag Registry

## TLV Tag Allocation, Governance, and Anti-Collision Policy

To prevent silent tag collisions between upstream VZ format revisions and
downstream extensions across the 62-bit decoded tag space (`0x0000`
through `2^62 - 1`), VZ enforces strict partition boundaries across all
TLV contexts (Global Registry, Cluster Body, and `ExtMetaPool`):

| Decoded Range | Wire Width | Allocation Policy | Intended Consumers |
| :--- | :--- | :--- | :--- |
| `0x0000 ..= 0x0FFF` | `1..=2` B | Standards Action | Upstream VZ core format ONLY |
| `0x1000 ..= 0x3BFF` | `2` B | Specification Req | Shared ecosystem extensions |
| `0x3C00 ..= 0x3FFF` | `2` B | Private Use | Closed internal pipelines only |
| `0x1000_0000 ..` | `4` B | Vendor PEN Formula | Deterministic enterprise forks |
Table: VZ v1.0 TLV Allocation Ranges

1. **Upstream Core Reservation (`0x0000 ..= 0x0FFF`, `TLV_CORE_MAX`):**
   Downstream forks, OEMs, and third-party tools MUST NOT allocate or
   assign new decoded tag values inside `0x0000 ..= 0x0FFF`.
2. **Closed Private Use (`0x3C00 ..= 0x3FFF`, `TLV_PRIVATE_MIN..=MAX`):**
   Reserved exclusively for internal pipeline experiments and local
   tooling; archives carrying Private Use tags SHOULD NOT be
   interchanged across independent organizations.
3. **Deterministic Vendor PEN Tags (`0x1000_0000 ..`, `TLV_PEN_BASE`):**
   Implementations holding an IANA Private Enterprise Number (PEN)
   derive collision-free 4-byte LE-VINT tags via:
   `tag = 0x1000_0000 | ((pen & 0x000F_FFFF) << 8) | (sub_tag & 0xFF)`.
4. **Reverse-DNS Vendor Extension Envelope (`TAG_VENDOR_EXT`, `0x3A`):**
   For zero-coordination portability using 1-byte decoded tags without
   registering a PEN, downstream writers SHOULD encapsulate custom
   fields inside `TAG_VENDOR_EXT`:
   `ns_len (LE-VINT) || ns_utf8 || sub_tag (LE-VINT) || payload_bytes`,
   where `ns_utf8` is a reverse-DNS domain prefix owned by the vendor
   (for example, `vendor.example`).
5. **Normative Preservation and Fail-Closed Upgrade Rules:**
   * Compliant compaction and LSM overlay tools MUST preserve unknown
     Global Registry and `ExtMetaPool` TLVs verbatim across runs unless
     explicitly instructed to rewrite or strip them, and SHOULD reject
     downstream tags colliding in `0x0000 ..= 0x0FFF`.
   * Features whose semantics affect data integrity, decryption, path
     resolution, or partial layout MUST NOT rely solely on ignorable
     TLVs; writers MUST concurrently assert an allocated `incompat_flags`
     (fail-closed) or `ro_compat_flags` (write-protect) bit.

# Boot Block Global Registry

The Global Registry occupies `registry_offset .. registry_offset + registry_size`
inside the Boot Block as a sequence of context-free TLVs.

## `TAG_OWNER_TABLE` (`0x06`)

`count (u16)` followed by `count` entries of `uid (u32) || gid (u32) || uname_len (LE-VINT) || uname || gname_len (LE-VINT) || gname`,
indexed by `DirEntry.owner_idx` (`0..=254`).

## `TAG_DICT_TABLE` (`0x05`)

`count (u16)` followed by `count` entries of `dict_id (u32) || codec (u8) || flags (u8) || dict_len (LE-VINT) || dict_bytes`,
where `dict_id != 0`, `codec == 0x02` (Zstd [@!RFC8878]), and `flags == 0`.

## `TAG_SCHEMA_TABLE` (`0x04`)

`count (u32)` followed by `count` entries of `schema_id (u32) || kind (u8) || name_len (LE-VINT) || name_bytes`:

* If `kind == 0x01` (`SCHEMA_TENSOR`): `dtype (u8) || byte_order (u8) || ndim (u16) || dims (ndim * u64) || strides (ndim * u64)`.
* If `kind == 0x02` (`SCHEMA_COLUMN`): `logical_type (u8) || encoding (u8) || has_stats (u8) || row_count (u64) || null_count (u64)`,
  followed by `min_len (LE-VINT) || min_bytes || max_len (LE-VINT) || max_bytes` when `has_stats == 1`.

## `TAG_CIPHER_HEADER` (`0x0C`) and Authenticated Encryption

When `INCOMPAT_ENCRYPTED` is set, the Global Registry MUST contain a
104-byte `TAG_CIPHER_HEADER`:

* `version` (u8, offset `0`): MUST equal `1`.
* `kdf_mode` (u8, offset `1`): `1` = Argon2id [@!RFC9106], `2` = Raw 256-bit key.
* `cipher_suite` (u8, offset `2`): `1` = XChaCha20-Poly1305 [@!I-D.irtf-cfrg-xchacha].
* `reserved` (u8, offset `3`): MUST equal `0`.
* `argon2_m_cost_kib` (u32, offset `4`): Memory cost in KiB (`0` if `kdf_mode == 2`).
* `argon2_t_cost` (u32, offset `8`): Iteration count (`0` if `kdf_mode == 2`).
* `argon2_p_cost` (u32, offset `12`): Parallelism (`0` if `kdf_mode == 2`).
* `salt` (16 bytes, offset `16`): 128-bit random salt.
* `wrap_nonce` (24 bytes, offset `32`): 192-bit nonce for CEK wrapping.
* `wrapped_cek` (48 bytes, offset `56`): 32-byte Content Encryption Key
  encrypted with XChaCha20-Poly1305 plus 16-byte authentication tag.

Key derivation and payload authentication MUST proceed as follows:

1. Derive 32-byte Input Key Material `ikm` via `Argon2id(m_cost_kib, t_cost, p_cost, len=32)` over `(password, salt)` when `kdf_mode == 1`, or `ikm = raw_key_32` when `kdf_mode == 2`.
2. Derive Key Encryption Key `KEK = HKDF-SHA256(salt=salt, ikm=ikm).expand("VZ-v1-KEK", 32)` per [@!RFC5869].
3. Decrypt `CEK = XChaCha20-Poly1305(key=KEK, nonce=wrap_nonce, aad="VZ-CEK-WRAP-v1" || salt).decrypt(wrapped_cek)`. Authentication failure MUST abort immediately.
4. Derive `PayloadKey = HKDF-SHA256(salt=salt, ikm=CEK).expand("VZ-v1-PAYLOAD", 32)`.
5. Each encrypted payload (post-compression) is stored as
   `nonce (24 B) || ciphertext (N B) || poly1305_tag (16 B)` (`stored_size = plaintext_len + 40`)
   authenticated with the exact 24-byte Additional Authenticated Data (AAD):
   `generation.to_le_bytes() || cluster_seq.to_le_bytes() || entry_id.to_le_bytes()`.

## `TAG_LSM_RUNS` (`0x07`)

Required when `RO_COMPAT_LSM_RUNS` is set (`lsm_run_count > 1`):
`run_count (u16) || flags (u16 = 0)` followed by `run_count` 24-byte
descriptors ordered from oldest (`0`) to newest (`run_count - 1`):
`run_generation (u64) || root_offset (u64) || root_entry_count (u32) || tree_height (u8) || root_is_cluster (u8) || reserved (u16 = 0)`.

# Path Normalization, B+Tree Index, and DirEntry

## Path Normalization

All archive paths MUST use `/` as the directory separator. Writers MUST
strip leading `/` and `./`, collapse consecutive `/`, elide `.`
segments, and reject any `..` segment. The root directory is `"/"`. A
path `"a/b/c.txt"` normalizes to `parent_path = "/a/b"` and
`basename = "c.txt"`.

## B+Tree Structure and Pool Offset Scaling

B+Tree keys are 128-bit tuples `(parent_hash: u64, name_hash: u64)`
ordered lexicographically. Entries sharing an identical 128-bit key
MUST NOT be split across leaf boundaries.

For a `LeafNode` string pool (`NamePool` or `ExtMetaPool`) of byte length
`pool_len`, `pool_shift(pool_len)` is `0` if `pool_len <= 65536`, and
`ceil(log2(pool_len / 65536))` otherwise. Byte offsets stored in `u16`
fields are decoded as `(stored_u16 as usize) << pool_shift`.

* **`RouteEntry` (48 bytes):** `min_parent_hash (u64) || min_name_hash (u64) || max_parent_hash (u64) || max_name_hash (u64) || child_cluster_off (u64) || child_cluster_len (u32) || subtree_count_lo (u32)`.
* **`LeafNodeHeader` (16 bytes):** `entry_count (u32) || name_pool_len (u32) || ext_meta_len (u32) || node_crc32c (u32)`, where `node_crc32c` hashes `0..12 || 16..total_node_bytes`. Immediately followed by `entry_count` `DirEntry` records, `NamePool` (`LE-VINT(len) || UTF-8 basename`), and `ExtMetaPool` (byte `0` MUST be `0x00`).

## DirEntry Structure (64 Bytes)

* `parent_hash` (u64, offset `0`), `name_hash` (u64, offset `8`).
* Payload descriptor (28 bytes, offset `16..44`):
  * If `FLAG_INLINE_DATA == 0`: `data_offset (u64) || stored_size (u64) || raw_size (u64) || in_cluster_offset (u32)`.
  * If `FLAG_INLINE_DATA == 1`: `inline_bytes (27 bytes) || inline_len (u8)` (`0 <= inline_len <= 27`).
* `entry_id_lo` (u32, offset `44`): Low 32 bits of 64-bit `entry_id`.
* `mtime_ns` (i64, offset `48`): Modification timestamp in nanoseconds since Unix epoch.
* `name_pool_off` (u16, offset `56`), `ext_meta_off` (u16, offset `58`).
* `posix_mode` (u16, offset `60`): Bits `0..12` store POSIX mode (`07777`); bits `12..16` store `KIND_*` (`FIFO=0x1000`, `CHR=0x2000`, `DIR=0x4000`, `BLK=0x6000`, `REG=0x8000`, `LNK=0xA000`, `SOCK=0xC000`, `TENSOR=0xD000`, `COLUMN=0xE000`).
* `owner_idx` (u8, offset `62`): `0..=254` indexes `TAG_OWNER_TABLE`; `255` indicates `TAG_EXT_OWNER`.
* `flags_and_codec` (u8, offset `63`):
  * Bits `0..2` (`CODEC_*`): `0x00` = None, `0x01` = LZ4, `0x02` = Zstd, `0x03` = Extended (`TAG_EXT_CODEC`).
  * Bits `2..8` (`FLAG_*`): `INLINE_DATA` (`1<<2`), `MULTI_CLUSTER` (`1<<3`), `SPARSE` (`1<<4`), `HASH_COLLISION` (`1<<5`), `TOMBSTONE` (`1<<6`), `INODE_64` (`1<<7`).

# ExtMetaPool TLV Layouts

Byte `0` of `ExtMetaPool` MUST be `0x00` (`EXT_META_NONE`). Each entry's
TLV chain starts at `(ext_meta_off as usize) << pool_shift(ext_meta_len)`
and terminates at the first `TAG_NOP` (`0x00`) byte or end of pool:

* `TAG_XATTR_LIST` (`0x10`): `count (LE-VINT)` followed by `count` pairs of `key_len (LE-VINT) || key || val_len (LE-VINT) || val`.
* `TAG_SPARSE_EXTENTS` (`0x11`): `extent_count (LE-VINT)` followed by `extent_count` sorted, non-overlapping `logical_offset (u64) || length (u64)` records. Concatenated non-zero extent bytes form the stored stream; gaps MUST be zero-filled up to `raw_size`.
* `TAG_EXT_OWNER` (`0x12`): `uid (u32) || gid (u32) || uname_len (LE-VINT) || uname || gname_len (LE-VINT) || gname`.
* `TAG_EXT_TIME` (`0x13`): `mtime_sec (i64) || btime_sec (i64) || mtime_nsec (u32) || btime_nsec (u32)`.
* `TAG_PARENT_PATH` (`0x14`): Exact normalized UTF-8 `parent_path` bytes (no NUL terminator). MUST be checked during path lookup whenever `FLAG_HASH_COLLISION` is set or `TAG_PARENT_PATH` is present.
* `TAG_INODE_HI` (`0x15`): `entry_id_hi (u32)`; `entry_id = ((entry_id_hi as u64) << 32) | entry_id_lo`. REQUIRED when `FLAG_INODE_64` is set.
* `TAG_EXT_CODEC` (`0x16`): `ext_codec_id (u16) || dict_id (u32) || params_len (LE-VINT) || params_bytes` (`0`=None, `1`=LZ4, `2`=Zstd, `3`=ZstdDict).
* `TAG_SCHEMA_LINK` (`0x17`): `schema_id (u32) || extra_len (u16) || extra_bytes`.

# Cluster Framing and Payloads

Every Cluster has a total byte length `cluster_len >= 48` (which MUST be
a multiple of `8`, and SHOULD be a multiple of `64`):

1. `ClusterHeader` (32 bytes, `0 .. 32`):
   `sync_magic (u64 = MAGIC_CLUSTER) || cluster_len (u64) || prev_cluster_len (u64) || cluster_seq (u64)`.
2. Cluster Body (`32 .. cluster_len - 16`): Context-free TLVs and alignment padding.
3. `ClusterFooter` (16 bytes, `cluster_len - 16 .. cluster_len`):
   `cluster_len (u64) || cluster_crc32c (u32) || footer_magic (u32 = MAGIC_FOOTER)`,
   where `cluster_crc32c` is computed over the first `cluster_len - 8`
   bytes of the cluster (from `ClusterHeader` through `ClusterFooter.cluster_len`).

## `TAG_DATA_MANIFEST` (`0x08`)

Value layout: `entry_id (u64) || raw_size (u64) || stored_size (u64) || payload_crc32c (u32) || manifest_flags (u16) || payload_rel_off (u16)`,
followed by optional column stats (if `manifest_flags & 1 != 0`), padding
to `payload_rel_off`, and `stored_size` payload bytes aligned to a
64-byte archive offset. `payload_crc32c` hashes the `stored_size` payload
bytes.

## `TAG_DIR_NODE` (`0x09`)

Value layout: `node_level (u8) || node_flags (u8 = 0) || reserved (u16 = 0) || entry_count (u32)`
followed by a `LeafNode` (`node_level == 0`) or `entry_count` `RouteEntry` records followed by `node_crc32c (u32)` (`node_level >= 1`).

## `TAG_CHUNK_TABLE` (`0x0B`)

When `FLAG_MULTI_CLUSTER` is set, `DirEntry` points to a `TAG_CHUNK_TABLE`
TLV (`chunk_count (u32) || chunk_flags (u32 = 0)` followed by `chunk_count`
28-byte records `cluster_offset (u64) || in_cluster_offset (u32) || stored_size (u64) || raw_size (u64)`).
Each chunk MUST reside in its own cluster with a distinct `cluster_seq`
so AEAD nonces/AAD remain unique per chunk.

## `TAG_ROOT_FALLBACK` (`0x0D`) and Streaming Pipe Mode

In forward-only pipe mode, the Boot Block is written upfront with
`slot_a.generation = 0` and `tree_height = 0xFF`. Clusters are emitted
with `stream_generation = 1`, concluding at EOF with a trailing cluster
containing `TAG_ROOT_FALLBACK` (`stream_generation (u64) || total_entries (u64) || root_cluster_off (u64) || root_entry_count (u32) || tree_height (u8) || hash_algo (u8) || flags (u16)` plus embedded root node when `flags & 1 != 0`). If the output is seekable, `finalize()` updates `slot_b` at `generation = 1`; otherwise, readers walk backward from EOF via `ClusterFooter.cluster_len` to locate `TAG_ROOT_FALLBACK`.

# Multi-Run LSM Overlay Semantics

When `RO_COMPAT_LSM_RUNS` is set (`lsm_run_count > 1`), point lookups MUST
query runs in reverse chronological order (`lsm_run_count - 1` down to
`0`). The first matching entry determines visibility: if `FLAG_TOMBSTONE`
is set, the path is treated as non-existent (`NotFound`) and older runs
MUST NOT be consulted; otherwise, the entry is decrypted using that run's
`run_generation`. Directory listings (`readdir`) merge entries from
newest to oldest, deduplicating by exact `(parent_path, basename)`.

## Crash-Safe Resumable In-Place Compaction (`INCOMPAT_COMPACTING`)

Writers compacting a fragmented or multi-run archive directly in-place
(avoiding `2x` temporary storage duplication) MAY stage compaction via
an EOF append-only journal anchored by `INCOMPAT_COMPACTING` (`1 << 2`):

1. **Journal Staging Before Mutation:** Prior to mutating byte offset
   `0`, the writer reserves a non-overlapping `journal_base` at `>= EOF`
   (and above `estimated_max_compacted_len`), persists a verbatim backup
   of the original Boot Block, two CRC-protected ping-pong checkpoints
   (`VZCMPJ01`), a serialized compaction work plan (`VZPLAN01`), an
   item output log, and a fixed `BounceSlot` matching the streaming
   memory window (`batch_bytes`).
2. **Fail-Closed Activation:** Both `HeaderSlot` entries are updated
   with `INCOMPAT_COMPACTING` set and `root_fallback_off = journal_base`,
   then flushed to storage (`fsync`). Standard readers MUST fail closed
   with `IncompatibleFeature` while this flag is asserted.
3. **Overlap Evacuation & Bounce Window Protocol:** Source live entries
   are processed in ascending physical cluster order in `<= batch_bytes`
   RAM windows. Before overwriting any target span `[start, end)`, any
   not-yet-copied live source cluster intersecting `[start, end)` is
   copied to an append-only `VZEVAC01` region at EOF, the compacted batch
   and updated output slots are synced into `BounceSlot`, a bounce-apply
   checkpoint is committed, the target span is written in place, and an
   advancing completion checkpoint is committed.
4. **Atomic Finalization & Truncation:** Once all data, optional
   `TAG_CHUNK_TABLE`, B+Tree index, and RS parity clusters are flushed,
   the finalized single-run Boot Block (`INCOMPAT_COMPACTING == 0`) is
   staged in `BounceSlot`, written over pages `4096..boot_size` then
   page `0..4096`, synced, and the file is truncated to exact
   `final_len`. Any crash prior to truncation resumes deterministically
   from the highest CRC-valid checkpoint without losing source data.

# Reed-Solomon Erasure Parity

When `RO_COMPAT_STREAM_ECC` is set, `TAG_PARITY_CLUSTER` (`0x0A`) stores
`ecc_codec (u8) || interleave_stride (u8) || data_clusters_k (u16) || parity_clusters_m (u16) || parity_index (u16) || first_cluster_seq (u64) || max_cluster_len (u64) || data_cluster_offset (K * u64) || parity_bytes (max_cluster_len bytes)`,
with `K >= 1`, `M >= 1`, `K + M <= 256`, and `0 <= parity_index < M`.

For `ecc_codec == 0x01` (`ECC_RS_GF256`), arithmetic is performed in
`GF(2^8)` modulo `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`). Using evaluation
points `x_i = i` (`0 <= i < M`) and `y_j = M + j` (`0 <= j < K`), the
systematic Cauchy generator matrix is `G_ij = (x_i XOR y_j)^(-1)` in
`GF(2^8)`. Each data cluster `D_j` (full `ClusterHeader .. ClusterFooter`,
conceptually zero-padded to `max_cluster_len`) contributes to parity
cluster `P_i` via `P_i = XOR_{j=0..K-1} (G_ij * D_j)`. Any subset of up
to `M` damaged clusters in a stripe is recovered by inverting the `K x K`
submatrix corresponding to any `K` intact data or parity clusters.

# IANA Considerations

Per [@!RFC6838], IANA is requested to register the following media type
in the Standards Tree:

* **Type name:** `application`
* **Subtype name:** `vz`
* **Required parameters:** N/A
* **Optional parameters:** N/A
* **Encoding considerations:** binary
* **Security considerations:** See Security Considerations in this document.
* **Interoperability considerations:** Defined by the VZ v1.0 wire
  format specification; all multi-byte integers are little-endian.
* **Published specification:** This document.
* **Applications that use this media type:** Archivers, backup tools,
  dataset distribution pipelines, and content-addressed storage systems.
* **Fragment identifier considerations:** N/A
* **Additional information:**
  * Magic number(s): `56 5A 01 00 00 00 00 00` at byte offset `0`.
  * File extension(s): `.vz`
  * Macintosh file type code(s): N/A
* **Person & email address to contact for further information:** See
  Author's Address.
* **Intended usage:** COMMON
* **Restrictions on usage:** None
* **Author / Change controller:** Author of this document.

# Security Considerations

Implementations parsing untrusted `.vz` archives MUST enforce the
following safeguards in accordance with [@!RFC3552]:

1. **Path Traversal Prevention:** Readers MUST reject entries whose
   normalized paths contain `..` components, NUL bytes, or escape the
   target extraction root via symbolic links (`KIND_LNK`).
2. **Resource Exhaustion and Decompression Bombs:** Readers MUST enforce
   configurable bounds on `boot_block_size`, B+Tree recursion depth,
   `LE-VINT` allocation lengths, sparse extent expansion (`TAG_SPARSE_EXTENTS`),
   and decompressed output size relative to `raw_size`.
3. **Integer Overflow and Offset Bounds:** All offset + length arithmetic
   (`registry_offset + registry_size`, `cluster_offset + cluster_len`,
   `pool_shift` shifts) MUST use checked arithmetic and be validated
   against archive bounds before slicing.
4. **Cryptographic Integrity:** When `INCOMPAT_ENCRYPTED` is enabled,
   implementations MUST verify Poly1305 authentication tags prior to
   releasing any decrypted bytes and MUST validate the 24-byte AAD tuple
   `(generation, cluster_seq, entry_id)` to prevent cross-generation,
   cross-cluster, or cross-entry ciphertext splicing.

{backmatter}