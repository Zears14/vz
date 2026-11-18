# VZ v1.0 Binary Container Specification

**Format Name:** VZ (`.vz`, CLI tool `vz`)  
**Byte Order:** Strictly Little-Endian (`LE`) for all multi-byte integers  
**Design Goals:** 1-RTT HTTP Range boot open, `#![no_std]`-compatible zero-copy wire parsing, 64-byte cache-line / AVX-512 payload alignment, crash-safe dual-slot atomic commits, self-healing Boot Block ECC, Reed-Solomon `GF(2^8)` erasure parity, authenticated `XChaCha20-Poly1305` encryption, streaming pipes, and incremental LSM overlays.

---

## 1. Constants, Magics, and Alignment

| Constant | Value (Wire / LE) | Description |
| :--- | :--- | :--- |
| `MAGIC_HEADER` | `b"VZ\x01\x00\x00\x00\x00\x00"` (`0x0000_0000_0001_5A56`) | `HeaderSlot` magic |
| `MAGIC_CLUSTER` | `b"VZ_CLUST"` (`0x5453_554C_435F_5A56`) | `ClusterHeader` sync magic |
| `MAGIC_FOOTER` | `b"ENDC"` (`0x4344_4E45`) | `ClusterFooter` magic |
| `MAGIC_BOOT_ECC` | `b"BECC"` (`0x4343_4542`) | `BootEccDescriptor` magic |
| `DEFAULT_BOOT_SIZE` | `65,536` (`64 KiB`) | Default Boot Block size (`0x0000..0x10000`) |
| `PAGE_SIZE` | `4,096` (`4 KiB`) | Boot Block ECC page size (`16` pages total) |
| `BOOT_ECC_DESC_OFF` | `0xEFB0` | Byte offset of 80-byte `BootEccDescriptor` in Page 14 |
| `BOOT_PARITY_OFFSET` | `0xF000` | Byte offset of 4 KiB XOR parity page (Page 15) |
| `PAYLOAD_ALIGNMENT` | `64` | Payload & cluster alignment boundary (bytes) |
| `TREE_HEIGHT_PIPE` | `0xFF` | Sentinel `tree_height` for unfinalized streaming pipes |
| `EXT_META_NONE` | `0` | Reserved `ext_meta_off` indicating no extended metadata |

### 1.1 Checksum Algorithm
All CRCs in VZ use **Castagnoli CRC32C** (polynomial `0x1EDC6F41`, reflected `0x82F63B78`, initial `0xFFFF_FFFF`, final XOR `0xFFFF_FFFF`; standard test vector `crc32c(b"123456789") == 0xE306_9283`).

---

## 2. Physical Container Layout

A `.vz` archive consists of a fixed-size **Boot Block** (`[0 .. boot_block_size)`) followed by a contiguous stream of self-describing, doubly-linked **Clusters** (`[boot_block_size .. EOF)`).

```
+-----------------------------------------------------------------------+
| Boot Block (0x0000 .. boot_block_size; default 65,536 bytes = 64 KiB) |
|  +-- 0x0000..0x0040 : HeaderSlot A (64 B)                             |
|  +-- 0x0040..0x0080 : HeaderSlot B (64 B)                             |
|  +-- registry_offset .. +registry_size : Global Registry TLVs         |
|  +-- root_node_offset .. : Root B+Tree Node (Leaf if height==0, else  |
|  |                         RouteEntry[] table)                        |
|  +-- [optional padding]                                               |
|  +-- 0xEFB0..0xF000 : BootEccDescriptor (80 B, if COMPAT_BOOT_ECC)    |
|  +-- 0xF000..0x10000: Boot Parity Page 15 (4096 B, if COMPAT_BOOT_ECC)|
+-----------------------------------------------------------------------+
| Cluster 0 (at boot_block_size)                                        |
| Cluster 1                                                             |
| ...                                                                   |
| Cluster N (optional Parity Clusters / TAG_ROOT_FALLBACK at EOF)       |
+-----------------------------------------------------------------------+
```

---

## 3. Boot Header & Feature Flags

### 3.1 `HeaderSlot` (`64` bytes exact)

| Offset | Size | Type | Field | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0` | `8` | `u64` | `magic` | Must equal `MAGIC_HEADER` (`b"VZ\x01\x00\x00\x00\x00\x00"`) |
| `8` | `8` | `u64` | `generation` | Monotonic commit generation (highest valid wins) |
| `16` | `4` | `u32` | `boot_block_size` | Boot Block size in bytes (`65536` default) |
| `20` | `2` | `u16` | `compat_flags` | Flags safe for readers and writers to ignore |
| `22` | `2` | `u16` | `ro_compat_flags` | Flags safe for read-only access; writers must understand |
| `24` | `2` | `u16` | `incompat_flags` | Flags readers **must** understand or abort |
| `26` | `1` | `u8` | `tree_height` | `0` = flat leaf in Boot Block; `>= 1` = B+Tree depth; `0xFF` = live pipe |
| `27` | `1` | `u8` | `hash_algo` | `0x00` Built-in, `0x01` XXH3-64, `0x02` BLAKE3-64 |
| `28` | `2` | `u16` | `lsm_run_count` | Active incremental B+Tree runs (`1` when compacted) |
| `30` | `2` | `u16` | `registry_offset` | Offset to Global Registry TLV zone (typically `0x0080`) |
| `32` | `4` | `u32` | `registry_size` | Byte length of Global Registry TLV zone |
| `36` | `4` | `u32` | `root_node_offset` | Byte offset inside Boot Block to root node |
| `40` | `8` | `u64` | `total_entries` | Total live files & directories across archive |
| `48` | `8` | `u64` | `root_fallback_off` | Absolute offset to trailing `TAG_ROOT_FALLBACK` cluster (`0` if none) |
| `56` | `4` | `u32` | `root_entry_count` | Number of `DirEntry` (`height==0`) or `RouteEntry` (`height>=1`) items |
| `60` | `4` | `u32` | `header_crc32c` | Castagnoli CRC32C of wire bytes `0..60` |

### 3.2 `BootHeader` (`128` bytes exact)
`slot_a` occupies `0x0000..0x0040`, `slot_b` occupies `0x0040..0x0080`.

**Selection Invariant (`BootHeader::select_active`):**
1. Validate `magic` and `header_crc32c` on **both** `slot_a` and `slot_b` first.
2. Choose the valid slot with the highest `generation` (breaking ties in favor of `slot_a`).
3. Enforce `incompat_flags` **after** slot selection. An older reader **must never** silently downgrade to an older-generation slot if the latest valid slot sets an unknown `incompat_flags` bit.

### 3.3 Feature Flags

- `compat_flags`:
  - `COMPAT_BOOT_ECC = 1 << 0`: Boot Block contains `BootEccDescriptor` at `0xEFB0` and XOR parity at `0xF000`.
  - `COMPAT_BLOOM_ROUTES = 1 << 1`: Legacy 32-bit Bloom filter in `RouteEntry::subtree_count_lo`.
  - `COMPAT_COL_STATS = 1 << 2`: Analytical min/max column statistics present in `TAG_SCHEMA_TABLE` / `TAG_DATA_MANIFEST`.
- `ro_compat_flags`:
  - `RO_COMPAT_STREAM_ECC = 1 << 0`: Stream contains `TAG_PARITY_CLUSTER` erasure parity clusters.
  - `RO_COMPAT_LSM_RUNS = 1 << 1`: Multi-run incremental LSM B+Tree overlay active (`lsm_run_count > 1`).
- `incompat_flags`:
  - `INCOMPAT_ENCRYPTED = 1 << 0`: Payloads are encrypted using `TAG_CIPHER_HEADER`.
  - `INCOMPAT_BIG_BOOT = 1 << 1`: `boot_block_size > 65,536`.
  - `INCOMPAT_COMPACTING = 1 << 2`: Crash-safe in-place compaction journal (`VZCMPJ01`) is active at `HeaderSlot.root_fallback_off`; normal readers MUST fail closed with `IncompatibleFeature` until compaction completes or resumes.

---

## 4. Boot Block 4 KiB Self-Healing ECC (`COMPAT_BOOT_ECC`)

Protects the `15` data pages (`Pages 0..14`, `0x0000..0xF000`) using 4 KiB bitwise XOR parity stored in `Page 15` (`0xF000..0x10000`).

### 4.1 `BootEccDescriptor` (`80` bytes exact at `0xEFB0..0xF000`)

| Offset | Size | Type | Field | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0` | `4` | `u32` | `ecc_magic` | Must equal `MAGIC_BOOT_ECC` (`b"BECC"`) |
| `4` | `2` | `u16` | `protected_pages` | Must equal `15` |
| `6` | `2` | `u16` | `ecc_scheme` | Must equal `1` (4 KiB bitwise XOR parity) |
| `8` | `64` | `[u32; 16]` | `page_crc32c` | CRC32C of each 4 KiB page; `page_crc32c[14]` hashes `0xE000..0xEFAF` (4,016 B) |
| `72` | `4` | `u32` | `reserved` | Must equal `0` |
| `76` | `4` | `u32` | `desc_crc32c` | CRC32C of descriptor bytes `0..76` |

### 4.2 Encoding & Repair Rules
- **Encoding:** Compute `page_crc32c[0..15]`. Write descriptor with `page_crc32c[15] = 0` and `desc_crc32c = 0`. XOR `Pages 0..15` into `Page 15`. Compute `page_crc32c[15] = crc32c(Page 15)`, then `desc_crc32c = crc32c(desc[..76])`, and write the final descriptor.
- **Verification & Repair:**
  - **Case A (`desc` invalid):** Reconstruct Page 14 via XOR of Pages `0..=13` and `15`. Verify `ecc_magic == MAGIC_BOOT_ECC`, `protected_pages == 15`, `ecc_scheme == 1`, `reserved == 0`, **`page_crc32c[15] == 0 && desc_crc32c == 0`**, and all 15 `page_crc32c[0..15]` match. Re-stamp `page_crc32c[15]` and `desc_crc32c`. Any mismatch returns `CorruptUnrecoverable`.
  - **Case B (`desc` valid):** Check CRCs of Pages `0..15` and Page `15`:
    - `0` data pages bad and parity ok -> clean (`Ok(None)`).
    - `0` data pages bad and parity bad -> re-encode Page 15 (`Ok(Some(15))`).
    - `1` data page bad and parity ok -> temporarily zero `page_crc32c[15]` and `desc_crc32c`, XOR-reconstruct the bad page, restore descriptor, verify repaired page CRC (`Ok(Some(page))`).
    - `>= 2` pages bad (or 1 data page + parity bad) -> `Err(CorruptUnrecoverable)`.
  - **Torn Boot Write Fallback:** If `BootEcc` fails with `CorruptUnrecoverable` (e.g. a crash during a dual-slot update before `boot_ecc_encode` finished), `VzReader` may still attempt `BootHeader::select_active` if one slot remains CRC-valid, while reporting the ECC mismatch in `verify`.

---

## 5. LE-VINT & Context-Free TLV Framing

### 5.1 LE-VINT Encoding
Little-endian variable-length unsigned integer (`0 <= val < 2^62`), determined by the lowest 2 bits (`tag = byte[0] & 0x03`):

| Low 2 Bits | Total Width | Value Bits | Range | Wire Formula |
| :--- | :--- | :--- | :--- | :--- |
| `0b00` (`0`) | `1` byte | `6` bits | `0 .. 64` | `(val << 2) \| 0` |
| `0b01` (`1`) | `2` bytes | `14` bits | `64 .. 16,384` | `((val << 2) \| 1).to_le_bytes()` |
| `0b10` (`2`) | `4` bytes | `30` bits | `16,384 .. 2^30` | `((val << 2) \| 2).to_le_bytes()` |
| `0b11` (`3`) | `8` bytes | `62` bits | `2^30 .. 2^62` | `((val << 2) \| 3).to_le_bytes()` |

Values `>= 2^62` return `VzError::ValueOverflow`.

### 5.2 Context-Free TLV & Padding Elements
Every TLV element has the form `[Tag: LE-VINT][Length: LE-VINT][Value: Length bytes]`, **except** `TAG_NOP`:
- **`TAG_NOP` (`0x00` on wire, decoded tag `0x00`):** Unconditional **1-byte** padding element with **no length field**.
- **`TAG_VOID` (`0xEC` on wire, decoded tag `0x3B`):** Standard TLV padding `[0xEC][LE-VINT len][len zero bytes]`.
- `write_void_align64(offset)` emits `0` bytes if `offset % 64 == 0`, `1` byte `0x00` (`TAG_NOP`) if `pad == 1`, or `[0xEC, LE-VINT(pad - 2), 0...]` if `pad in 2..=63`.

### 5.3 Complete TLV Tag Registry

| Decoded Tag | Wire First Byte | Name | Scope |
| :--- | :--- | :--- | :--- |
| `0x00` | `0x00` | `TAG_NOP` | Context-free 1-byte pad / `ExtMetaPool` end-of-chain sentinel |
| `0x04` | `0x10` | `TAG_SCHEMA_TABLE` | Boot Registry: tensor & column schema definitions |
| `0x05` | `0x14` | `TAG_DICT_TABLE` | Boot Registry: compression dictionaries (Zstd) |
| `0x06` | `0x18` | `TAG_OWNER_TABLE` | Boot Registry: POSIX UID/GID/name table (`0..=254`) |
| `0x07` | `0x1C` | `TAG_LSM_RUNS` | Boot Registry: multi-run LSM overlay descriptors |
| `0x08` | `0x20` | `TAG_DATA_MANIFEST` | Cluster body: payload manifest + aligned payload |
| `0x09` | `0x24` | `TAG_DIR_NODE` | Cluster body: external B+Tree internal or leaf node |
| `0x0A` | `0x28` | `TAG_PARITY_CLUSTER` | Cluster body: RS parity manifest + offset table + parity bytes |
| `0x0B` | `0x2C` | `TAG_CHUNK_TABLE` | Cluster body: multi-cluster extent table (`FLAG_MULTI_CLUSTER`) |
| `0x0C` | `0x30` | `TAG_CIPHER_HEADER` | Boot Registry: encryption KDF & wrapped CEK header |
| `0x0D` | `0x34` | `TAG_ROOT_FALLBACK` | Cluster body (EOF): streaming pipe root index |
| `0x10` | `0x40` | `TAG_XATTR_LIST` | `ExtMetaPool`: POSIX extended attributes |
| `0x11` | `0x44` | `TAG_SPARSE_EXTENTS` | `ExtMetaPool`: sparse file logical extent map |
| `0x12` | `0x48` | `TAG_EXT_OWNER` | `ExtMetaPool`: extended owner (`owner_idx == 255`) |
| `0x13` | `0x4C` | `TAG_EXT_TIME` | `ExtMetaPool`: 24-byte `ExtTime` record |
| `0x14` | `0x50` | `TAG_PARENT_PATH` | `ExtMetaPool`: exact UTF-8 parent path (`parent_hash` tie-breaker) |
| `0x15` | `0x54` | `TAG_INODE_HI` | `ExtMetaPool`: upper 32 bits of 64-bit inode (`FLAG_INODE_64`) |
| `0x16` | `0x58` | `TAG_EXT_CODEC` | `ExtMetaPool`: extended codec / Zstd dictionary ID link |
| `0x17` | `0x5C` | `TAG_SCHEMA_LINK` | `ExtMetaPool`: links `KIND_TENSOR`/`KIND_COLUMN` entry to `schema_id` |
| `0x3A` | `0xE8` | `TAG_VENDOR_EXT` | Self-identifying reverse-DNS vendor extension envelope |
| `0x3B` | `0xEC` | `TAG_VOID` | Context-free void padding TLV |

### 5.4 TLV Tag Allocation Governance & Downstream Anti-Collision
- **`0x0000 ..= 0x0FFF` (`TLV_CORE_MAX`):** Reserved exclusively for upstream VZ core standards (`is_downstream_allocatable_tag` returns `false` inside this range except `TAG_VENDOR_EXT`). Downstream forks MUST NOT allocate tags here.
- **`0x1000 ..= 0x3BFF` (`TLV_REGISTERED_MIN..=MAX`):** Shared ecosystem extensions (`2`-byte LE-VINT).
- **`0x3C00 ..= 0x3FFF` (`TLV_PRIVATE_MIN..=MAX`):** Closed Private Use (`2`-byte LE-VINT).
- **`0x1000_0000 ..` (`TLV_PEN_BASE`):** Deterministic 4-byte LE-VINT vendor IANA PEN tags via `vendor_pen_tag(pen, sub_tag) = 0x1000_0000 | ((pen & 0xF_FFFF) << 8) | sub_tag`.
- **`TAG_VENDOR_EXT` (`0x3A`, wire `0xE8`):** Portable reverse-DNS extension wrapper `ns_len (LE-VINT) || ns_utf8 || sub_tag (LE-VINT) || payload_bytes`.
- Writers performing LSM appends or compaction MUST preserve unknown Registry (`extra_registry_tlvs`) and `ExtMetaPool` (`extra_ext_tlvs`) TLVs across runs. Features that alter mandatory parsing or integrity MUST NOT rely on ignorable TLVs alone and MUST assert an `incompat_flags` or `ro_compat_flags` bit.

---

## 6. Boot Block Global Registry Layouts

Located at `BootHeader.registry_offset .. registry_offset + registry_size` as a sequence of context-free TLV elements.

### 6.1 `TAG_OWNER_TABLE` (`0x06`, wire `0x18`)
Value layout:
- `count: u16` (`0..=255`; indexed by `DirEntry::owner_idx` in `0..=254`)
- Repeated `count` times:
  - `uid: u32`
  - `gid: u32`
  - `uname_len: LE-VINT` + `uname: [u8; uname_len]` (UTF-8)
  - `gname_len: LE-VINT` + `gname: [u8; gname_len]` (UTF-8)

### 6.2 `TAG_DICT_TABLE` (`0x05`, wire `0x14`)
Value layout:
- `count: u16`
- Repeated `count` times:
  - `dict_id: u32` (non-zero identifier)
  - `codec: u8` (`CODEC_ZSTD = 0x02`)
  - `flags: u8` (`0`)
  - `dict_len: LE-VINT`
  - `dict_bytes: [u8; dict_len]`

### 6.3 `TAG_SCHEMA_TABLE` (`0x04`, wire `0x10`)
Value layout:
- `count: u32`
- Repeated `count` times:
  - `schema_id: u32`
  - `kind: u8`: `0x01` = `SCHEMA_TENSOR`, `0x02` = `SCHEMA_COLUMN`
  - `name_len: LE-VINT` + `name_bytes: [u8; name_len]` (UTF-8)
  - If `kind == 0x01` (`SCHEMA_TENSOR`):
    - `dtype: u8` (`0=U8, 1=I8, 2=U16, 3=I16, 4=U32, 5=I32, 6=U64, 7=I64, 8=F16, 9=BF16, 10=F32, 11=F64, 12=BOOL`)
    - `byte_order: u8` (`0 = LittleEndian`, `1 = BigEndian`)
    - `ndim: u16`
    - `dims: [u64; ndim]` (`ndim * 8` bytes LE)
    - `strides: [u64; ndim]` (`ndim * 8` bytes LE; `0` indicates packed/unspecified)
  - If `kind == 0x02` (`SCHEMA_COLUMN`):
    - `logical_type: u8` (`0=Null, 1=Bool, 2=Int64, 3=UInt64, 4=Float64, 5=Binary, 6=Utf8, 7=Decimal128, 8=TimestampNs`)
    - `encoding: u8` (`0=Plain, 1=Dictionary, 2=RLE, 3=DeltaBinaryPacked`)
    - `has_stats: u8` (`1` if `COMPAT_COL_STATS` min/max stats follow, else `0`)
    - `row_count: u64`
    - `null_count: u64`
    - If `has_stats == 1`:
      - `min_len: LE-VINT` + `min_bytes: [u8; min_len]`
      - `max_len: LE-VINT` + `max_bytes: [u8; max_len]`

### 6.4 `TAG_CIPHER_HEADER` (`0x0C`, wire `0x30`)
Required in Global Registry when `INCOMPAT_ENCRYPTED` is set. Fixed `104`-byte value layout:

| Offset | Size | Type | Field | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0` | `1` | `u8` | `version` | Must equal `1` |
| `1` | `1` | `u8` | `kdf_mode` | `1` = Argon2id (password), `2` = Raw 256-bit key |
| `2` | `1` | `u8` | `cipher_suite` | `1` = `XChaCha20-Poly1305` |
| `3` | `1` | `u8` | `reserved` | Must equal `0` |
| `4` | `4` | `u32` | `argon2_m_cost_kib` | Argon2id memory cost in KiB (`0` in Raw256 mode) |
| `8` | `4` | `u32` | `argon2_t_cost` | Argon2id time cost / iterations (`0` in Raw256 mode) |
| `12` | `4` | `u32` | `argon2_p_cost` | Argon2id parallelism (`0` in Raw256 mode) |
| `16` | `16` | `[u8; 16]` | `salt` | 128-bit random salt |
| `32` | `24` | `[u8; 24]` | `wrap_nonce` | 192-bit random XChaCha20 nonce for CEK wrap |
| `56` | `48` | `[u8; 48]` | `wrapped_cek` | 32-byte random CEK encrypted under KEK + 16-byte Poly1305 tag |

**Key Derivation & Authenticated Payload Format:**
1. Input Key Material `ikm: [u8; 32]`:
   - `kdf_mode == 1`: `Argon2id(m_cost_kib, t_cost, p_cost, len=32)` over `(password, salt)`.
   - `kdf_mode == 2`: `ikm = raw_key_32`.
2. `KEK = HKDF-SHA256(salt = &salt, ikm = &ikm).expand(b"VZ-v1-KEK", 32)`.
3. `CEK = XChaCha20-Poly1305(key = KEK, nonce = wrap_nonce, aad = b"VZ-CEK-WRAP-v1" || salt).decrypt(wrapped_cek)`. Failure aborts immediately with `VzError::CryptoError`.
4. `PayloadKey = HKDF-SHA256(salt = &salt, ikm = &CEK).expand(b"VZ-v1-PAYLOAD", 32)`.
5. Every encrypted payload is stored (after optional compression) as:
   `[nonce: 24 B][ciphertext: len B][poly1305_tag: 16 B]` (`stored_size = plaintext_len + 40`).
   **AAD (24 bytes exact):**
   `aad[0..8] = generation.to_le_bytes() || aad[8..16] = cluster_seq.to_le_bytes() || aad[16..24] = entry_id.to_le_bytes()`.
   This cryptographically binds every payload (and every chunk of a `FLAG_MULTI_CLUSTER` file) to its archive generation, cluster sequence number, and full 64-bit entry ID, preventing cross-archive, cross-generation, cross-cluster, and cross-file splicing or reordering.

### 6.5 `TAG_LSM_RUNS` (`0x07`, wire `0x1C`)
Present in Global Registry when `RO_COMPAT_LSM_RUNS` is set (`lsm_run_count > 1`).
- `run_count: u16` (must match `HeaderSlot::lsm_run_count`)
- `flags: u16` (`0`)
- Repeated `run_count` times (ordered oldest `0` -> newest `run_count - 1`), `24` bytes each:
  - `run_generation: u64` (generation used for AEAD AAD of clusters written in this run)
  - `root_offset: u64` (Boot Block offset if `root_is_cluster == 0`, or absolute cluster offset if `1`)
  - `root_entry_count: u32`
  - `tree_height: u8`
  - `root_is_cluster: u8` (`0` = inside Boot Block, `1` = `TAG_DIR_NODE` cluster)
  - `reserved: u16` (`0`)

---

## 7. Path Normalization, B+Tree Nodes & `DirEntry`

### 7.1 Path Normalization
- Paths use `/` separators. Leading `/` and `./` are stripped; consecutive `/` are collapsed; `.` segments are removed; `..` segments are rejected (`VzError::InvalidInput`).
- Root directory is `"/"`. Any child entry `a/b/c.txt` has normalized `parent_path = "/a/b"` and `basename = "c.txt"`. Top-level entry `hello.txt` has `parent_path = "/"` and `basename = "hello.txt"`.

### 7.2 B+Tree Invariants
- Keys are 128-bit tuples `(parent_hash: u64, name_hash: u64)` ordered lexicographically.
- Identical 128-bit keys **must never** be split across different leaves.
- Leaves stay bounded (`<= 2048` entries and `<= 64 KiB` pools normally so `pool_shift == 0`).
- `pool_shift(pool_len)`: `0` if `pool_len <= 65536`; otherwise `ceil(log2(pool_len / 65536))`. Offsets in `DirEntry` are `(stored_u16 as usize) << shift`.

### 7.3 `RouteEntry` (`48` bytes exact)

| Offset | Size | Type | Field |
| :--- | :--- | :--- | :--- |
| `0` | `8` | `u64` | `min_parent_hash` |
| `8` | `8` | `u64` | `min_name_hash` |
| `16` | `8` | `u64` | `max_parent_hash` |
| `24` | `8` | `u64` | `max_name_hash` |
| `32` | `8` | `u64` | `child_cluster_off` |
| `40` | `4` | `u32` | `child_cluster_len` |
| `44` | `4` | `u32` | `subtree_count_lo` |

### 7.4 `LeafNodeHeader` (`16` bytes exact)

| Offset | Size | Type | Field |
| :--- | :--- | :--- | :--- |
| `0` | `4` | `u32` | `entry_count` |
| `4` | `4` | `u32` | `name_pool_len` |
| `8` | `4` | `u32` | `ext_meta_len` |
| `12` | `4` | `u32` | `node_crc32c` (CRC32C over `[0..12] \|\| [16..total_size]`) |

Followed immediately by `[DirEntry; entry_count]`, `NamePool` (`[LE-VINT len][UTF-8 basename]`), and `ExtMetaPool` (byte `0` reserved `0x00`).

### 7.5 `DirEntry` (`64` bytes exact)

| Offset | Size | Type | Field |
| :--- | :--- | :--- | :--- |
| `0` | `8` | `u64` | `parent_hash` |
| `8` | `8` | `u64` | `name_hash` |
| `16..44` | `28` | `union` | **External (`FLAG_INLINE_DATA == 0`):** `data_offset: u64` (`16..24`), `stored_size: u64` (`24..32`), `raw_size: u64` (`32..40`), `in_cluster_offset: u32` (`40..44`)<br>**Inline (`FLAG_INLINE_DATA == 1`):** `bytes: [u8; 27]` (`16..43`), `len: u8` (`43`, `0..=27`) |
| `44` | `4` | `u32` | `entry_id_lo` |
| `48` | `8` | `i64` | `mtime_ns` (nanoseconds since Unix epoch) |
| `56` | `2` | `u16` | `name_pool_off` (shifted by `pool_shift(name_pool_len)`) |
| `58` | `2` | `u16` | `ext_meta_off` (`0` = none; shifted by `pool_shift(ext_meta_len)`) |
| `60` | `2` | `u16` | `posix_mode` (`bits 0..12`: mode `07777`; `bits 12..16`: `KIND_*`) |
| `62` | `1` | `u8` | `owner_idx` (`0..=254` in `TAG_OWNER_TABLE`, `255` -> `TAG_EXT_OWNER`) |
| `63` | `1` | `u8` | `flags_and_codec` (`bits 0..2`: `CODEC_*`; `bits 2..8`: `FLAG_*`) |

- `KIND_*`: `FIFO=0x1000`, `CHR=0x2000`, `DIR=0x4000`, `BLK=0x6000`, `REG=0x8000`, `LNK=0xA000`, `SOCK=0xC000`, `TENSOR=0xD000`, `COLUMN=0xE000`.
- `CODEC_*`: `NONE=0x00`, `LZ4=0x01`, `ZSTD=0x02`, `EXT=0x03`.
- `FLAG_*`: `INLINE_DATA=1<<2`, `MULTI_CLUSTER=1<<3`, `SPARSE=1<<4`, `HASH_COLLISION=1<<5`, `TOMBSTONE=1<<6`, `INODE_64=1<<7`.

---

## 8. `ExtMetaPool` TLV Layouts

Byte `0` of `ExtMetaPool` is always `0x00` (`EXT_META_NONE`). Each entry's TLV chain starts at `(ext_meta_off as usize) << pool_shift(ext_meta_len)` and terminates at the first `TAG_NOP` (`0x00`) element (or end of pool).

1. **`TAG_XATTR_LIST` (`0x10`, wire `0x40`):**
   - `count: LE-VINT`, followed by `count` pairs of `[key_len: LE-VINT][key_bytes][val_len: LE-VINT][val_bytes]`.
2. **`TAG_SPARSE_EXTENTS` (`0x11`, wire `0x44`):**
   - `extent_count: LE-VINT`, followed by `extent_count` sorted non-overlapping `16`-byte records `[logical_offset: u64][length: u64]`.
   - The concatenated non-zero extent bytes form the logical stream encoded (compressed/encrypted/chunked) as the file's stored payload; gaps are zero-filled on read up to `DirPayload::Ref.raw_size`.
3. **`TAG_EXT_OWNER` (`0x12`, wire `0x48`):**
   - `[uid: u32][gid: u32][uname_len: LE-VINT][uname][gname_len: LE-VINT][gname]`.
4. **`TAG_EXT_TIME` (`0x13`, wire `0x4C`):**
   - Exact `24`-byte `ExtTime`: `[mtime_sec: i64][btime_sec: i64][mtime_nsec: u32][btime_nsec: u32]`.
5. **`TAG_PARENT_PATH` (`0x14`, wire `0x50`):**
   - Exact normalized UTF-8 `parent_path` bytes (no null terminator). Checked on lookup and `readdir` when `FLAG_HASH_COLLISION` is set or `TAG_PARENT_PATH` is present.
6. **`TAG_INODE_HI` (`0x15`, wire `0x54`):**
   - `entry_id_hi: u32` (`4` bytes). Full 64-bit `entry_id = ((entry_id_hi as u64) << 32) | (entry_id_lo as u64)`. Required when `FLAG_INODE_64` is set.
7. **`TAG_EXT_CODEC` (`0x16`, wire `0x58`):**
   - `[ext_codec_id: u16][dict_id: u32][params_len: LE-VINT][params_bytes]`.
   - `ext_codec_id`: `0 = None`, `1 = LZ4`, `2 = Zstd`, `3 = ZstdDict` (uses `dict_id` from `TAG_DICT_TABLE`).
8. **`TAG_SCHEMA_LINK` (`0x17`, wire `0x5C`):**
   - `[schema_id: u32][extra_len: u16][extra_bytes]`. Links `KIND_TENSOR` or `KIND_COLUMN` entries to `TAG_SCHEMA_TABLE` in the Global Registry.

---

## 9. Cluster Framing & Cluster Payloads

Every Cluster has a 64-byte-aligned total length `cluster_len` (minimum `48` bytes, multiple of `8`; `VzWriter` emits multiples of `64`):
- `0..32`: **`ClusterHeader` (`32` bytes):** `[sync_magic: u64 = MAGIC_CLUSTER][cluster_len: u64][prev_cluster_len: u64][cluster_seq: u64]`
- `32..cluster_len - 16`: **Cluster Body** (sequence of context-free TLVs + optional `TAG_NOP`/`TAG_VOID` alignment padding)
- `cluster_len - 16..cluster_len`: **`ClusterFooter` (`16` bytes):** `[cluster_len: u64][cluster_crc32c: u32][footer_magic: u32 = MAGIC_FOOTER]` where `cluster_crc32c = crc32c(&cluster[..cluster_len - 8])`.

### 9.1 `TAG_DATA_MANIFEST` (`0x08`, wire `0x20`)
Inside the value of `TAG_DATA_MANIFEST`:
- `0..8`: `entry_id: u64`
- `8..16`: `raw_size: u64`
- `16..24`: `stored_size: u64`
- `24..28`: `payload_crc32c: u32` (CRC32C over `value[payload_rel_off .. payload_rel_off + stored_size]`)
- `28..30`: `manifest_flags: u16` (`bit 0` = `has_col_stats`, `bit 1` = `has_payload`)
- `30..32`: `payload_rel_off: u16` (offset from start of `TAG_DATA_MANIFEST` value to the 64-byte-aligned payload)
- `32..`: if `manifest_flags & 1 != 0`: `[col_schema_id: u32][row_count: u64][null_count: u64][min_len: LE-VINT][min_bytes][max_len: LE-VINT][max_bytes]`, followed by `write_void_align64` padding up to `payload_rel_off`, followed by `stored_size` payload bytes aligned to `64` bytes in the archive.
- `DirPayload::Ref.data_offset` = `cluster_start`, `DirPayload::Ref.in_cluster_offset` = `payload_start - cluster_start` (zero-copy direct slice!).

### 9.2 `TAG_DIR_NODE` (`0x09`, wire `0x24`)
Value layout:
- `0`: `node_level: u8` (`0` = Leaf, `>= 1` = Internal)
- `1`: `node_flags: u8` (`0`)
- `2..4`: `reserved: u16` (`0`)
- `4..8`: `entry_count: u32`
- `8..`:
  - If `node_level == 0`: `[LeafNodeHeader (16 B)][DirEntry; entry_count][NamePool][ExtMetaPool]`.
  - If `node_level >= 1`: `[RouteEntry; entry_count][node_crc32c: u32]` where `node_crc32c = crc32c(&value[..8 + entry_count * 48])`.

### 9.3 `TAG_CHUNK_TABLE` (`0x0B`, wire `0x2C`)
For `FLAG_MULTI_CLUSTER` files, `DirPayload::Ref.data_offset` points to the cluster holding the `TAG_CHUNK_TABLE` TLV, and `in_cluster_offset` points to the start of the `TAG_CHUNK_TABLE` TLV header (`0x2C` aligned to `64` B). `DirPayload::Ref.raw_size` and `stored_size` record the full file's logical and total stored sizes.

Value layout of `TAG_CHUNK_TABLE`:
- `0..4`: `chunk_count: u32`
- `4..8`: `chunk_flags: u32` (`0`)
- `8..`: `chunk_count` contiguous `28`-byte extents:
  - `0..8`: `cluster_offset: u64`
  - `8..12`: `in_cluster_offset: u32`
  - `12..20`: `stored_size: u64`
  - `20..28`: `raw_size: u64`

Each chunk occupies its own cluster (unique `cluster_seq`) so AEAD AAD `(generation, cluster_seq, entry_id)` is unique per chunk.

### 9.4 `TAG_ROOT_FALLBACK` (`0x0D`, wire `0x34`) & Streaming Pipe Mode
- During forward-only streaming (`VzPipeWriter`), `BootHeader` is written upfront with `slot_a.generation = 0`, `slot_a.tree_height = TREE_HEIGHT_PIPE (0xFF)`. All stream clusters are written under `stream_generation = 1`.
- At EOF, all B+Tree internal/leaf clusters are written, followed by a trailing cluster containing `TAG_ROOT_FALLBACK`:
  - `0..8`: `stream_generation: u64`
  - `8..16`: `total_entries: u64`
  - `16..24`: `root_cluster_off: u64` (`0` if embedded)
  - `24..28`: `root_entry_count: u32`
  - `28`: `tree_height: u8`
  - `29`: `hash_algo: u8`
  - `30..32`: `flags: u16` (`bit 0 = 1` if root node bytes immediately follow at offset `32`)
  - `32..`: embedded root node (`LeafNode` if `tree_height == 0`, or `[RouteEntry; root_entry_count]` if `tree_height >= 1`) when `flags & 1 != 0`.
- Optional `finalize()` patches the Boot Block (`slot_b` committed at `generation = 1`, `tree_height` & `root_node_offset` populated, `root_fallback_off` set, and `boot_ecc_encode` run if enabled). If `finalize()` is not called (non-seekable pipe), `VzReader` walks backward from EOF via `ClusterFooter::cluster_len` to recover `TAG_ROOT_FALLBACK`.

---

## 10. Multi-Run LSM Overlay Semantics (`RO_COMPAT_LSM_RUNS`)

- When `lsm_run_count > 1`, `TAG_LSM_RUNS` lists runs `0 .. lsm_run_count - 1` from oldest to newest.
- **Point Lookup (`stat`, `read_file`):** Query runs in **reverse order** (newest to oldest). The first run returning a match determines the result:
  - If the match has `FLAG_TOMBSTONE` set, the path is deleted (`NotFound`) and older runs are **not** consulted.
  - Otherwise return the entry, using that run's `run_generation` for AEAD decryption.
- **`readdir(dir)`:** Collect entries across all runs from newest to oldest, deduplicating by exact `(parent_path, basename)` (newest wins; if newest is `FLAG_TOMBSTONE`, suppress the path).
- **Compaction (`compact`):** Materializes the merged live entry set into a fresh single-run (`lsm_run_count = 1`) archive, reclaiming overwritten payloads and tombstoned entries.
- **In-Place Crash-Safe Compaction (`INCOMPAT_COMPACTING`):** `compact_file_in_place` / `resume_in_place_compaction` stage an EOF journal (`VZCMPJ01`, ping-pong CRC checkpoints, `VZPLAN01`, `BounceSlot`, and overlap evacuation `VZEVAC01`) anchored by `HeaderSlot.root_fallback_off`, copy live data in bounded `O(batch_bytes)` RAM/disk windows in ascending physical offset order, atomically commit the final single-run Boot Block, and truncate to `final_len`.

---

## 11. Reed-Solomon Erasure Parity (`RO_COMPAT_STREAM_ECC` + `TAG_PARITY_CLUSTER`)

### 11.1 `ParityManifest` Layout (`24 + K * 8` bytes + `max_cluster_len` parity bytes)
Stored as the value of `TAG_PARITY_CLUSTER` (`0x0A`, wire `0x28`):
- `0`: `ecc_codec: u8` (`0x01` = `ECC_RS_GF256`; `0x02` = `ECC_RS_GF65536` reserved; `0x03` = `ECC_RAPTORQ` reserved)
- `1`: `interleave_stride: u8` (`1` default)
- `2..4`: `data_clusters_k: u16` (`K >= 1`)
- `4..6`: `parity_clusters_m: u16` (`M >= 1`, `K + M <= 256`)
- `6..8`: `parity_index: u16` (`0 <= i < M`)
- `8..16`: `first_cluster_seq: u64`
- `16..24`: `max_cluster_len: u64`
- `24 .. 24 + K * 8`: `[data_cluster_offset: u64; K]`
- `24 + K * 8 .. 24 + K * 8 + max_cluster_len`: Parity bytes `P_i[0..max_cluster_len]`.

### 11.2 `ECC_RS_GF256` Systematic Cauchy Construction
- Finite field: `GF(2^8)` modulo `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`).
- Evaluation points: `x_i = i` (`0 <= i < M`) and `y_j = M + j` (`0 <= j < K`).
- Generator matrix (`M x K`): `G[i][j] = (x_i ^ y_j)^(-1)` in `GF(2^8)`.
- Each data cluster `D_j` (full `ClusterHeader .. ClusterFooter`) is conceptually zero-padded to `max_cluster_len` bytes, and parity cluster `i` computes:
  `P_i = XOR_{j=0..K-1} G[i][j] * D_j`.
- **Stripe Recovery:**
  1. Validate each of the `K` data clusters and `M` parity clusters via `validate_cluster`.
  2. For missing/corrupted data cluster `j` (even if its `ClusterHeader` is zeroed), determine its byte span from `data_cluster_offset[j+1] - data_cluster_offset[j]` (or for `j == K - 1`, from the surviving parity cluster offset `p_surv_off - parity_index * parity_cluster_len - data_cluster_offset[K - 1]`).
  3. Select any `K` intact clusters (data + parity), construct the `K x K` matrix `A` (identity rows for intact data, `G[i]` rows for intact parity), invert `A` via `GF(2^8)` Gauss-Jordan elimination, and solve for every lost `D_j`.
  4. Verify each reconstructed `D_j` using `validate_cluster` (obtaining its exact `cluster_len` from the recovered `ClusterHeader`) and write it back; re-encode any damaged parity clusters.
  5. If more than `M` clusters in a stripe are damaged, return `Err(VzError::CorruptUnrecoverable)`.
