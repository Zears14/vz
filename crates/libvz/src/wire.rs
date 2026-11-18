use crate::crc::crc32c;
use crate::error::VzError;

// ============================================================================
// 1. CONSTANTS, MAGICS, AND FEATURE FLAGS
// ============================================================================

/// Magic bytes for [`HeaderSlot`]: `"VZ\x01\x00\x00\x00\x00\x00"` in little-endian.
pub const MAGIC_HEADER: u64 = u64::from_le_bytes(*b"VZ\x01\x00\x00\x00\x00\x00");
/// Magic bytes for [`ClusterHeader`]: `"VZ_CLUST"` in little-endian.
pub const MAGIC_CLUSTER: u64 = u64::from_le_bytes(*b"VZ_CLUST");
/// Magic bytes for [`ClusterFooter`]: `"ENDC"` in little-endian.
pub const MAGIC_FOOTER: u32 = u32::from_le_bytes(*b"ENDC");
/// Magic bytes for [`BootEccDescriptor`]: `"BECC"` in little-endian.
pub const MAGIC_BOOT_ECC: u32 = u32::from_le_bytes(*b"BECC");

/// Default Boot Block size in bytes (`65,536` = 64 KiB).
pub const DEFAULT_BOOT_SIZE: usize = 65_536;
/// Flash/OS page size used by Boot Block ECC (`4,096` = 4 KiB).
pub const PAGE_SIZE: usize = 4_096;
/// Total number of 4 KiB pages in the default 64 KiB Boot Block (`16`).
pub const BOOT_PAGES: usize = 16;
/// Number of Boot Block data pages protected by XOR parity (`Pages 0..14`).
pub const BOOT_DATA_PAGES: usize = 15;
/// Byte offset of Page 15 (the 4 KiB Boot Block XOR parity page: `0xF000`).
pub const BOOT_PARITY_OFFSET: usize = 0xF000;
/// Byte offset of the 80-byte [`BootEccDescriptor`] at the end of Page 14 (`0xEFB0`).
pub const BOOT_ECC_DESC_OFF: usize = 0xEFB0;
/// Payload alignment boundary for AVX-512 / cache-line zero-copy access (`64` bytes).
pub const PAYLOAD_ALIGNMENT: usize = 64;

/// Sentinel `tree_height` indicating an unfinalized live streaming pipe (`0xFF`).
pub const TREE_HEIGHT_PIPE: u8 = 0xFF;
/// Reserved `ext_meta_off` value indicating no extended metadata (`0`).
pub const EXT_META_NONE: u16 = 0;

// --- Hash Algorithm Identifiers (`HeaderSlot::hash_algo`) ---

/// Built-in 64-bit path/basename mixer (`crate::crc::hash64`).
pub const HASH_ALGO_BUILTIN: u8 = 0x00;
/// Official `XXH3_64bits` hash function.
pub const HASH_ALGO_XXH3_64: u8 = 0x01;
/// BLAKE3 truncated to its leading 64 bits (resists crafted collision attacks).
pub const HASH_ALGO_BLAKE3: u8 = 0x02;

// --- Feature Flags: `compat_flags` (Safe to ignore for read & write) ---

/// 64 KiB Boot Block contains [`BootEccDescriptor`] at `0xEFB0` and XOR parity at `0xF000`.
pub const COMPAT_BOOT_ECC: u16 = 1 << 0;
/// Legacy flag: `RouteEntry::subtree_count_lo` holds a 32-bit Bloom filter.
pub const COMPAT_BLOOM_ROUTES: u16 = 1 << 1;
/// Data manifests/schemas contain min/max analytical column statistics.
pub const COMPAT_COL_STATS: u16 = 1 << 2;

// --- Feature Flags: `ro_compat_flags` (Safe for read-only; writers must understand) ---

/// Stream contains detached erasure parity clusters ([`TAG_PARITY_CLUSTER`]).
pub const RO_COMPAT_STREAM_ECC: u16 = 1 << 0;
/// Multi-run incremental LSM B+Tree overlay is active (`lsm_run_count > 1`).
pub const RO_COMPAT_LSM_RUNS: u16 = 1 << 1;

// --- Feature Flags: `incompat_flags` (Reader MUST abort if any unknown bit is set) ---

/// Payloads are encrypted via [`TAG_CIPHER_HEADER`].
pub const INCOMPAT_ENCRYPTED: u16 = 1 << 0;
/// Archive uses an extended Boot Block larger than 64 KiB (`boot_block_size > 65536`).
pub const INCOMPAT_BIG_BOOT: u16 = 1 << 1;
/// Archive is mid-flight during an in-place compaction (`BootHeader::root_fallback_off` points to the `VZ_CMPJ` journal).
/// Normal readers MUST abort with [`VzError::IncompatibleFeature`] until compaction completes or resumes.
pub const INCOMPAT_COMPACTING: u16 = 1 << 2;

// --- LE-TLV Element Tag IDs (Decoded values after `>> 2`) ---

/// Unconditional 1-byte NOP padding element (`0x00` on wire, **no length field**).
pub const TAG_NOP: u64 = 0x00;
/// Global schema definitions table (`0x10` on wire).
pub const TAG_SCHEMA_TABLE: u64 = 0x04;
/// Global compression/string dictionary table (`0x14` on wire).
pub const TAG_DICT_TABLE: u64 = 0x05;
/// Global POSIX owner UID/GID/name table (`0x18` on wire).
pub const TAG_OWNER_TABLE: u64 = 0x06;
/// Global multi-run LSM overlay descriptor table (`0x1C` on wire).
pub const TAG_LSM_RUNS: u64 = 0x07;
/// Cluster payload manifest (`0x20` on wire).
pub const TAG_DATA_MANIFEST: u64 = 0x08;
/// Directory B+Tree node payload (`0x24` on wire).
pub const TAG_DIR_NODE: u64 = 0x09;
/// Detached erasure parity cluster manifest (`0x28` on wire).
pub const TAG_PARITY_CLUSTER: u64 = 0x0A;
/// Multi-cluster file chunk extent table (`0x2C` on wire).
pub const TAG_CHUNK_TABLE: u64 = 0x0B;
/// Payload encryption key/nonce header (`0x30` on wire).
pub const TAG_CIPHER_HEADER: u64 = 0x0C;
/// Trailing root fallback index for finalized streaming pipes (`0x34` on wire).
pub const TAG_ROOT_FALLBACK: u64 = 0x0D;
/// POSIX extended attributes list inside `ExtMetaPool` (`0x40` on wire).
pub const TAG_XATTR_LIST: u64 = 0x10;
/// Sparse file extent map inside `ExtMetaPool` (`0x44` on wire).
pub const TAG_SPARSE_EXTENTS: u64 = 0x11;
/// Extended UID/GID owner record inside `ExtMetaPool` (`0x48` on wire).
pub const TAG_EXT_OWNER: u64 = 0x12;
/// Extended 64-bit timestamp + birth time ([`ExtTime`]) inside `ExtMetaPool` (`0x4C` on wire).
pub const TAG_EXT_TIME: u64 = 0x13;
/// Exact UTF-8 parent path tie-breaker for `parent_hash` collisions (`0x50` on wire).
pub const TAG_PARENT_PATH: u64 = 0x14;
/// Upper 32 bits of 64-bit inode/entry ID inside `ExtMetaPool` (`0x54` on wire).
pub const TAG_INODE_HI: u64 = 0x15;
/// Extended codec / Zstd dictionary link inside `ExtMetaPool` (`0x58` on wire).
pub const TAG_EXT_CODEC: u64 = 0x16;
/// Tensor/column schema ID link inside `ExtMetaPool` (`0x5C` on wire).
pub const TAG_SCHEMA_LINK: u64 = 0x17;
/// Self-identifying reverse-DNS vendor/downstream TLV extension (`0xE8` on wire).
/// Value layout: `ns_len (LE-VINT) || ns_utf8 || sub_tag (LE-VINT) || payload_bytes`.
pub const TAG_VENDOR_EXT: u64 = 0x3A;
/// Standard LE-TLV Void element (`0xEC` on wire, always `[0xEC][LE-VINT len][bytes]`).
pub const TAG_VOID: u64 = 0x3B;

// --- TLV Governance Range Constants ---

/// Maximum decoded TLV tag reserved exclusively for upstream core VZ Standards Action (`0x0FFF`).
pub const TLV_CORE_MAX: u64 = 0x0FFF;
/// Inclusive minimum decoded TLV tag for registered ecosystem extensions (Spec Required / FCFS).
pub const TLV_REGISTERED_MIN: u64 = 0x1000;
/// Inclusive maximum decoded TLV tag for registered 2-byte ecosystem extensions.
pub const TLV_REGISTERED_MAX: u64 = 0x3BFF;
/// Inclusive minimum decoded TLV tag for closed Private Use pipelines (`2`-byte LE-VINT).
pub const TLV_PRIVATE_MIN: u64 = 0x3C00;
/// Inclusive maximum decoded TLV tag for closed Private Use pipelines (`2`-byte LE-VINT).
pub const TLV_PRIVATE_MAX: u64 = 0x3FFF;
/// Base prefix for deterministic 4-byte IANA Private Enterprise Number (PEN) tags.
pub const TLV_PEN_BASE: u64 = 0x1000_0000;

/// Constructs a collision-free 4-byte LE-VINT TLV tag scoped by an IANA Private Enterprise
/// Number (`pen`, low 20 bits) and a vendor-local `sub_tag` (`0..=255`).
#[inline]
pub const fn vendor_pen_tag(pen: u32, sub_tag: u8) -> u64 {
    TLV_PEN_BASE | (((pen as u64) & 0xF_FFFF) << 8) | (sub_tag as u64)
}

/// Returns `true` if `tag` falls outside the upstream-reserved `0x0000..=0x0FFF` range
/// (or equals [`TAG_VENDOR_EXT`]) and may be allocated cleanly by downstream implementations.
#[inline]
pub const fn is_downstream_allocatable_tag(tag: u64) -> bool {
    tag == TAG_VENDOR_EXT || tag > TLV_CORE_MAX
}

// --- Entry Kinds (Upper 4 bits of `DirEntry::posix_mode`: bits 12..=15) ---

/// Bitmask extracting entry kind from `DirEntry::posix_mode`.
pub const KIND_MASK: u16 = 0xF000;
/// Named pipe (FIFO).
pub const KIND_FIFO: u16 = 0x1000;
/// Character device special file.
pub const KIND_CHR: u16 = 0x2000;
/// Directory.
pub const KIND_DIR: u16 = 0x4000;
/// Block device special file.
pub const KIND_BLK: u16 = 0x6000;
/// Regular file.
pub const KIND_REG: u16 = 0x8000;
/// Symbolic link.
pub const KIND_LNK: u16 = 0xA000;
/// Unix domain socket.
pub const KIND_SOCK: u16 = 0xC000;
/// Zero-copy N-dimensional tensor payload.
pub const KIND_TENSOR: u16 = 0xD000;
/// Analytical columnar payload.
pub const KIND_COLUMN: u16 = 0xE000;

// --- Codec & Entry Flags (`DirEntry::flags_and_codec`) ---

/// Bitmask for the 2-bit compression codec ID (`bits 0..=1`).
pub const CODEC_MASK: u8 = 0x03;
/// Uncompressed raw 64-byte-aligned payload.
pub const CODEC_NONE: u8 = 0x00;
/// Independent LZ4 frames.
pub const CODEC_LZ4: u8 = 0x01;
/// Independent Zstandard frames.
pub const CODEC_ZSTD: u8 = 0x02;
/// Extended codec specified inside `ExtMetaPool` ([`TAG_EXT_CODEC`]).
pub const CODEC_EXT: u8 = 0x03;

/// Payload (`0..=27` bytes) is stored inline inside [`DirPayload::Inline`] (requires `CODEC_NONE`).
pub const FLAG_INLINE_DATA: u8 = 1 << 2;
/// `data_offset` points to a [`TAG_CHUNK_TABLE`] rather than a direct cluster payload.
pub const FLAG_MULTI_CLUSTER: u8 = 1 << 3;
/// File is sparse; `ExtMetaPool` contains [`TAG_SPARSE_EXTENTS`].
pub const FLAG_SPARSE: u8 = 1 << 4;
/// Entry shares its 128-bit `(parent_hash, name_hash)` key (or `parent_hash`) with another entry.
pub const FLAG_HASH_COLLISION: u8 = 1 << 5;
/// Entry is a deletion tombstone in an LSM overlay run.
pub const FLAG_TOMBSTONE: u8 = 1 << 6;
/// Upper 32 bits of the 64-bit inode/track ID are stored in `ExtMetaPool` ([`TAG_INODE_HI`]).
pub const FLAG_INODE_64: u8 = 1 << 7;

// --- ECC Codec Types (`ParityManifest::ecc_codec`) ---

/// Reed-Solomon over GF(2^8) mod `0x11D` (`K + M <= 256`, systematic Cauchy `x_i=i, y_j=M+j`).
pub const ECC_RS_GF256: u8 = 0x01;
/// Reed-Solomon over GF(2^16) (`K + M <= 65536`).
pub const ECC_RS_GF65536: u8 = 0x02;
/// RaptorQ fountain erasure code for lossy transport streams.
pub const ECC_RAPTORQ: u8 = 0x03;

/// Extended codec IDs for [`TAG_EXT_CODEC`].
pub const EXT_CODEC_NONE: u16 = 0;
pub const EXT_CODEC_LZ4: u16 = 1;
pub const EXT_CODEC_ZSTD: u16 = 2;
pub const EXT_CODEC_ZSTD_DICT: u16 = 3;

/// Cipher suite identifiers for [`TAG_CIPHER_HEADER`].
pub const KDF_MODE_ARGON2ID: u8 = 1;
pub const KDF_MODE_RAW_KEY: u8 = 2;
pub const CIPHER_XCHACHA20_POLY1305: u8 = 1;

/// Schema kinds for [`TAG_SCHEMA_TABLE`].
pub const SCHEMA_KIND_TENSOR: u8 = 0x01;
pub const SCHEMA_KIND_COLUMN: u8 = 0x02;

// ============================================================================
// 2. ENDIAN-SAFE WIRE STRUCTURES
// ============================================================================

/// Atomic Superblock Header Slot (`64` bytes exact on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderSlot {
    /// Must equal [`MAGIC_HEADER`] (`"VZ\x01\x00\x00\x00\x00\x00"` LE).
    pub magic: u64,
    /// Monotonic commit sequence ID (higher CRC-valid generation wins).
    pub generation: u64,
    /// Boot Block byte size (`65536` by default; `> 65536` requires [`INCOMPAT_BIG_BOOT`]).
    pub boot_block_size: u32,
    /// Feature flags safe for readers and writers to ignore.
    pub compat_flags: u16,
    /// Feature flags safe for read-only consumers to ignore; writers must understand.
    pub ro_compat_flags: u16,
    /// Feature flags that readers **must** understand or abort with [`VzError::IncompatibleFeature`].
    pub incompat_flags: u16,
    /// B+Tree height (`0` = flat leaf inside Boot Block, `>= 1` = tree depth, `0xFF` = live pipe).
    pub tree_height: u8,
    /// Path/name hash algorithm identifier (`HASH_ALGO_*`).
    pub hash_algo: u8,
    /// Number of active incremental B+Tree overlay runs (`1` for compacted archives).
    pub lsm_run_count: u16,
    /// Byte offset to the Global Registry TLV zone (typically `0x0080`; capped at `0xFFFF`).
    pub registry_offset: u16,
    /// Byte length of the Global Registry TLV zone.
    pub registry_size: u32,
    /// Byte offset to the B+Tree root node inside the Boot Block.
    pub root_node_offset: u32,
    /// Total live files and directories across the archive.
    pub total_entries: u64,
    /// Absolute byte offset to trailing [`TAG_ROOT_FALLBACK`] cluster for finalized pipes.
    pub root_fallback_off: u64,
    /// Number of [`DirEntry`] items (if `tree_height == 0`) or [`RouteEntry`] items (if `>= 1`).
    pub root_entry_count: u32,
    /// Castagnoli CRC32C covering wire bytes `0..60`.
    pub header_crc32c: u32,
}

impl HeaderSlot {
    /// Exact encoded wire size in bytes (`64`).
    pub const SIZE: usize = 64;

    /// Decodes a 64-byte [`HeaderSlot`] from little-endian wire bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        Ok(Self {
            magic: read_le_u64(buf, 0),
            generation: read_le_u64(buf, 8),
            boot_block_size: read_le_u32(buf, 16),
            compat_flags: read_le_u16(buf, 20),
            ro_compat_flags: read_le_u16(buf, 22),
            incompat_flags: read_le_u16(buf, 24),
            tree_height: buf[26],
            hash_algo: buf[27],
            lsm_run_count: read_le_u16(buf, 28),
            registry_offset: read_le_u16(buf, 30),
            registry_size: read_le_u32(buf, 32),
            root_node_offset: read_le_u32(buf, 36),
            total_entries: read_le_u64(buf, 40),
            root_fallback_off: read_le_u64(buf, 48),
            root_entry_count: read_le_u32(buf, 56),
            header_crc32c: read_le_u32(buf, 60),
        })
    }

    /// Serializes this [`HeaderSlot`] into a 64-byte little-endian array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let _ = self.write_bytes(&mut out);
        out
    }

    /// Serializes this [`HeaderSlot`] into `dst[..64]`.
    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        write_le_u64(dst, 0, self.magic);
        write_le_u64(dst, 8, self.generation);
        write_le_u32(dst, 16, self.boot_block_size);
        write_le_u16(dst, 20, self.compat_flags);
        write_le_u16(dst, 22, self.ro_compat_flags);
        write_le_u16(dst, 24, self.incompat_flags);
        dst[26] = self.tree_height;
        dst[27] = self.hash_algo;
        write_le_u16(dst, 28, self.lsm_run_count);
        write_le_u16(dst, 30, self.registry_offset);
        write_le_u32(dst, 32, self.registry_size);
        write_le_u32(dst, 36, self.root_node_offset);
        write_le_u64(dst, 40, self.total_entries);
        write_le_u64(dst, 48, self.root_fallback_off);
        write_le_u32(dst, 56, self.root_entry_count);
        write_le_u32(dst, 60, self.header_crc32c);
        Ok(())
    }

    /// Validates `magic` and `header_crc32c` without inspecting `incompat_flags`.
    pub fn validate_crc(&self) -> Result<(), VzError> {
        if self.magic != MAGIC_HEADER {
            return Err(VzError::BadMagic);
        }
        let raw = self.to_bytes();
        let calc = crc32c(&raw[..60]);
        if calc != self.header_crc32c {
            return Err(VzError::CrcMismatch);
        }
        Ok(())
    }

    /// Validates `magic`, `header_crc32c`, and `incompat_flags` against `supported_incompat_mask`.
    pub fn validate(&self, supported_incompat_mask: u16) -> Result<(), VzError> {
        self.validate_crc()?;
        if (self.incompat_flags & !supported_incompat_mask) != 0 {
            return Err(VzError::IncompatibleFeature);
        }
        Ok(())
    }
}

/// Dual-Slot Boot Header (`128` bytes exact at `0x0000..=0x007F`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootHeader {
    /// Header Slot A (`0x0000..=0x003F`).
    pub slot_a: HeaderSlot,
    /// Header Slot B (`0x0040..=0x007F`).
    pub slot_b: HeaderSlot,
}

impl BootHeader {
    /// Exact encoded wire size in bytes (`128`).
    pub const SIZE: usize = 128;

    /// Decodes a 128-byte [`BootHeader`] from `buf[..128]`.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        Ok(Self {
            slot_a: HeaderSlot::from_bytes(&buf[0..64])?,
            slot_b: HeaderSlot::from_bytes(&buf[64..128])?,
        })
    }

    /// Serializes this [`BootHeader`] into a 128-byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let _ = self.write_bytes(&mut out);
        out
    }

    /// Serializes this [`BootHeader`] into `dst[..128]`.
    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        self.slot_a.write_bytes(&mut dst[0..64])?;
        self.slot_b.write_bytes(&mut dst[64..128])?;
        Ok(())
    }

    /// Selects the active, highest-generation valid [`HeaderSlot`] and its index (`0` or `1`).
    ///
    /// Validates `magic` and `CRC32C` on both slots *before* checking `incompat_flags`, preventing
    /// an older reader from silently downgrading to an obsolete slot.
    pub fn select_active(
        &self,
        supported_incompat_mask: u16,
    ) -> Result<(&HeaderSlot, usize), VzError> {
        let st_a = self.slot_a.validate_crc();
        let st_b = self.slot_b.validate_crc();

        let (chosen, chosen_idx) = match (st_a, st_b) {
            (Ok(()), Ok(())) => {
                if self.slot_b.generation > self.slot_a.generation {
                    (&self.slot_b, 1)
                } else {
                    (&self.slot_a, 0)
                }
            }
            (Ok(()), Err(_)) => (&self.slot_a, 0),
            (Err(_), Ok(())) => (&self.slot_b, 1),
            (Err(ea), Err(eb)) => {
                return Err(if ea == VzError::CrcMismatch || eb == VzError::CrcMismatch {
                    VzError::CrcMismatch
                } else {
                    VzError::BadMagic
                });
            }
        };

        if (chosen.incompat_flags & !supported_incompat_mask) != 0 {
            return Err(VzError::IncompatibleFeature);
        }
        Ok((chosen, chosen_idx))
    }

    /// Stamps `magic`, monotonic `generation`, and `header_crc32c` on `new_state`, writes it
    /// into the inactive slot, and returns the updated slot index (`0` for `slot_a`, `1` for `slot_b`).
    pub fn commit(&mut self, new_state: &HeaderSlot) -> usize {
        let (next_gen, write_idx) = match self.select_active(0xFFFF) {
            Ok((active, active_idx)) => (active.generation.wrapping_add(1), 1 - active_idx),
            Err(_) => (1, 0),
        };

        let mut staged = *new_state;
        staged.magic = MAGIC_HEADER;
        staged.generation = next_gen;
        let prefix = staged.to_bytes();
        staged.header_crc32c = crc32c(&prefix[..60]);

        if write_idx == 0 {
            self.slot_a = staged;
        } else {
            self.slot_b = staged;
        }
        write_idx
    }
}

/// Boot Block ECC Descriptor (`80` bytes exact at `0xEFB0..=0xEFFF`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootEccDescriptor {
    /// Must equal [`MAGIC_BOOT_ECC`] (`"BECC"`).
    pub ecc_magic: u32,
    /// Always `15` (Pages `0..=14`).
    pub protected_pages: u16,
    /// Always `1` (4 KiB bitwise XOR parity at `0xF000`).
    pub ecc_scheme: u16,
    /// Castagnoli CRC32C of each 4 KiB page (`page_crc32c[14]` hashes `0xE000..=0xEFAF`).
    pub page_crc32c: [u32; 16],
    /// Reserved; must be `0`.
    pub reserved: u32,
    /// Castagnoli CRC32C of bytes `0..76` of this descriptor.
    pub desc_crc32c: u32,
}

impl BootEccDescriptor {
    /// Exact encoded wire size in bytes (`80`).
    pub const SIZE: usize = 80;

    /// Decodes an 80-byte [`BootEccDescriptor`] from `buf[..80]`.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        let mut page_crc32c = [0u32; 16];
        for (i, slot) in page_crc32c.iter_mut().enumerate() {
            *slot = read_le_u32(buf, 8 + i * 4);
        }
        Ok(Self {
            ecc_magic: read_le_u32(buf, 0),
            protected_pages: read_le_u16(buf, 4),
            ecc_scheme: read_le_u16(buf, 6),
            page_crc32c,
            reserved: read_le_u32(buf, 72),
            desc_crc32c: read_le_u32(buf, 76),
        })
    }

    /// Serializes this [`BootEccDescriptor`] into an 80-byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let _ = self.write_bytes(&mut out);
        out
    }

    /// Serializes this [`BootEccDescriptor`] into `dst[..80]`.
    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        write_le_u32(dst, 0, self.ecc_magic);
        write_le_u16(dst, 4, self.protected_pages);
        write_le_u16(dst, 6, self.ecc_scheme);
        for (i, &crc) in self.page_crc32c.iter().enumerate() {
            write_le_u32(dst, 8 + i * 4, crc);
        }
        write_le_u32(dst, 72, self.reserved);
        write_le_u32(dst, 76, self.desc_crc32c);
        Ok(())
    }
}

/// Internal B+Tree Routing Entry (`48` bytes exact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteEntry {
    /// Inclusive lower-bound `parent_hash` in child subtree.
    pub min_parent_hash: u64,
    /// Inclusive lower-bound `name_hash` in child subtree.
    pub min_name_hash: u64,
    /// Inclusive upper-bound `parent_hash` in child subtree.
    pub max_parent_hash: u64,
    /// Inclusive upper-bound `name_hash` in child subtree.
    pub max_name_hash: u64,
    /// Absolute byte offset of the child `DirNode` cluster.
    pub child_cluster_off: u64,
    /// Exact byte length of the child cluster (`<= 4 GiB - 1`).
    pub child_cluster_len: u32,
    /// Subtree entry count (or legacy 32-bit Bloom filter when [`COMPAT_BLOOM_ROUTES`] is set).
    pub subtree_count_lo: u32,
}

impl RouteEntry {
    /// Exact encoded wire size in bytes (`48`).
    pub const SIZE: usize = 48;

    /// Decodes a 48-byte [`RouteEntry`] from `buf[..48]`.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        Ok(Self {
            min_parent_hash: read_le_u64(buf, 0),
            min_name_hash: read_le_u64(buf, 8),
            max_parent_hash: read_le_u64(buf, 16),
            max_name_hash: read_le_u64(buf, 24),
            child_cluster_off: read_le_u64(buf, 32),
            child_cluster_len: read_le_u32(buf, 40),
            subtree_count_lo: read_le_u32(buf, 44),
        })
    }

    /// Serializes this [`RouteEntry`] into a 48-byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let _ = self.write_bytes(&mut out);
        out
    }

    /// Serializes this [`RouteEntry`] into `dst[..48]`.
    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        write_le_u64(dst, 0, self.min_parent_hash);
        write_le_u64(dst, 8, self.min_name_hash);
        write_le_u64(dst, 16, self.max_parent_hash);
        write_le_u64(dst, 24, self.max_name_hash);
        write_le_u64(dst, 32, self.child_cluster_off);
        write_le_u32(dst, 40, self.child_cluster_len);
        write_le_u32(dst, 44, self.subtree_count_lo);
        Ok(())
    }
}

/// Payload representation inside a 64-byte [`DirEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirPayload {
    /// External payload stored inside a data cluster (or [`TAG_CHUNK_TABLE`] if multi-cluster).
    Ref {
        /// Absolute byte offset of the Cluster.
        data_offset: u64,
        /// Compressed/encrypted byte size on disk.
        stored_size: u64,
        /// Logical uncompressed byte size.
        raw_size: u64,
        /// 64-byte-aligned offset within the cluster.
        in_cluster_offset: u32,
    },
    /// Small file or symlink payload (`0..=27` bytes) stored directly inside the [`DirEntry`].
    Inline {
        /// Inline resident bytes (`bytes[..len as usize]` are valid).
        bytes: [u8; 27],
        /// Valid byte count (`0..=27`).
        len: u8,
    },
}

/// Zero-copy payload result returned by [`DirEntry::resolve_payload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedPayload<'a> {
    /// Payload stored inline inside the [`DirEntry`] (`0..=27` bytes).
    Inline(&'a [u8]),
    /// Contiguous stored payload slice borrowed directly from the mapped archive buffer.
    ArchiveSlice(&'a [u8]),
}

impl<'a> ResolvedPayload<'a> {
    /// Returns the underlying byte slice regardless of whether it was inline or cluster-backed.
    pub fn as_slice(&self) -> &'a [u8] {
        match *self {
            Self::Inline(s) | Self::ArchiveSlice(s) => s,
        }
    }
}

/// Leaf Directory Entry (`64` bytes exact = 1 CPU cache line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirEntry {
    /// 64-bit hash of the normalized parent directory path.
    pub parent_hash: u64,
    /// 64-bit hash of the entry basename.
    pub name_hash: u64,
    /// Either external cluster reference or inline 0..=27-byte resident payload.
    pub payload: DirPayload,
    /// Lower 32 bits of Inode/Entry ID (upper 32b in ExtMeta via [`FLAG_INODE_64`]).
    pub entry_id_lo: u32,
    /// Signed nanoseconds since Unix epoch.
    pub mtime_ns: i64,
    /// Scaled offset into the Leaf's `NamePool`.
    pub name_pool_off: u16,
    /// Scaled offset into the Leaf's `ExtMetaPool` (`0` = none).
    pub ext_meta_off: u16,
    /// Lower 12 bits: POSIX permissions (`07777`); upper 4 bits: `KIND_*`.
    pub posix_mode: u16,
    /// Owner index (`0..=254` in Boot `OwnerTable`, `255` = extended owner in `ExtMetaPool`).
    pub owner_idx: u8,
    /// Compression codec (`CODEC_*` in bits `0..=1`) and `FLAG_*` bits (`2..=7`).
    pub flags_and_codec: u8,
}

impl DirEntry {
    /// Exact encoded wire size in bytes (`64`).
    pub const SIZE: usize = 64;

    /// Decodes a 64-byte [`DirEntry`] from `buf[..64]`.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        let flags_and_codec = buf[63];
        let payload = if (flags_and_codec & FLAG_INLINE_DATA) != 0 {
            let len = buf[43];
            if len > 27 {
                return Err(VzError::BadFormat);
            }
            let mut bytes = [0u8; 27];
            bytes.copy_from_slice(&buf[16..43]);
            DirPayload::Inline { bytes, len }
        } else {
            DirPayload::Ref {
                data_offset: read_le_u64(buf, 16),
                stored_size: read_le_u64(buf, 24),
                raw_size: read_le_u64(buf, 32),
                in_cluster_offset: read_le_u32(buf, 40),
            }
        };

        Ok(Self {
            parent_hash: read_le_u64(buf, 0),
            name_hash: read_le_u64(buf, 8),
            payload,
            entry_id_lo: read_le_u32(buf, 44),
            mtime_ns: read_le_i64(buf, 48),
            name_pool_off: read_le_u16(buf, 56),
            ext_meta_off: read_le_u16(buf, 58),
            posix_mode: read_le_u16(buf, 60),
            owner_idx: buf[62],
            flags_and_codec,
        })
    }

    /// Serializes this [`DirEntry`] into a 64-byte array.
    pub fn to_bytes(&self) -> Result<[u8; Self::SIZE], VzError> {
        let mut out = [0u8; Self::SIZE];
        self.write_bytes(&mut out)?;
        Ok(out)
    }

    /// Serializes this [`DirEntry`] into `dst[..64]`.
    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        let inline_flag = (self.flags_and_codec & FLAG_INLINE_DATA) != 0;
        match (&self.payload, inline_flag) {
            (DirPayload::Inline { bytes, len }, true) => {
                if *len > 27 {
                    return Err(VzError::BadFormat);
                }
                dst[16..43].copy_from_slice(bytes);
                dst[43] = *len;
            }
            (
                DirPayload::Ref {
                    data_offset,
                    stored_size,
                    raw_size,
                    in_cluster_offset,
                },
                false,
            ) => {
                write_le_u64(dst, 16, *data_offset);
                write_le_u64(dst, 24, *stored_size);
                write_le_u64(dst, 32, *raw_size);
                write_le_u32(dst, 40, *in_cluster_offset);
            }
            _ => return Err(VzError::BadFormat),
        }

        write_le_u64(dst, 0, self.parent_hash);
        write_le_u64(dst, 8, self.name_hash);
        write_le_u32(dst, 44, self.entry_id_lo);
        write_le_i64(dst, 48, self.mtime_ns);
        write_le_u16(dst, 56, self.name_pool_off);
        write_le_u16(dst, 58, self.ext_meta_off);
        write_le_u16(dst, 60, self.posix_mode);
        dst[62] = self.owner_idx;
        dst[63] = self.flags_and_codec;
        Ok(())
    }

    /// Returns the entry kind (`KIND_*`, upper 4 bits of `posix_mode`).
    pub fn kind(&self) -> u16 {
        self.posix_mode & KIND_MASK
    }

    /// Returns the POSIX permission bits (`07777`, lower 12 bits of `posix_mode`).
    pub fn permissions(&self) -> u16 {
        self.posix_mode & 0x0FFF
    }

    /// Returns the 2-bit compression codec identifier (`CODEC_*`).
    pub fn codec(&self) -> u8 {
        self.flags_and_codec & CODEC_MASK
    }

    /// Returns `true` if the payload is stored inline (`FLAG_INLINE_DATA`).
    pub fn is_inline(&self) -> bool {
        (self.flags_and_codec & FLAG_INLINE_DATA) != 0
    }

    /// Returns `true` if this entry is an LSM deletion tombstone (`FLAG_TOMBSTONE`).
    pub fn is_tombstone(&self) -> bool {
        (self.flags_and_codec & FLAG_TOMBSTONE) != 0
    }

    /// Returns `true` if the payload spans multiple clusters via a `ChunkTable`.
    pub fn is_multi_cluster(&self) -> bool {
        (self.flags_and_codec & FLAG_MULTI_CLUSTER) != 0
    }

    /// Returns `true` if the payload has sparse holes (`FLAG_SPARSE`).
    pub fn is_sparse(&self) -> bool {
        (self.flags_and_codec & FLAG_SPARSE) != 0
    }

    /// Returns `true` if this entry shares its 128-bit key or `parent_hash`.
    pub fn has_hash_collision(&self) -> bool {
        (self.flags_and_codec & FLAG_HASH_COLLISION) != 0
    }

    /// Returns `true` if the entry has extended metadata (`ext_meta_off != 0`).
    pub fn has_ext_meta(&self) -> bool {
        self.ext_meta_off != EXT_META_NONE
    }

    /// Returns the logical uncompressed size of this entry's payload.
    pub fn raw_size(&self) -> u64 {
        match self.payload {
            DirPayload::Inline { len, .. } => len as u64,
            DirPayload::Ref { raw_size, .. } => raw_size,
        }
    }

    /// Returns the resident inline slice if [`DirPayload::Inline`] with valid length `<= 27`.
    pub fn inline_slice(&self) -> Option<&[u8]> {
        match &self.payload {
            DirPayload::Inline { bytes, len } if *len <= 27 => Some(&bytes[..*len as usize]),
            _ => None,
        }
    }

    /// Decodes the entry's UTF-8 basename slice from the Leaf's `name_pool`.
    pub fn entry_name<'a>(&self, name_pool: &'a [u8]) -> Result<&'a [u8], VzError> {
        let pool_len = u32::try_from(name_pool.len()).map_err(|_| VzError::ValueOverflow)?;
        let shift = pool_shift(pool_len);
        let off = (self.name_pool_off as usize)
            .checked_shl(shift as u32)
            .ok_or(VzError::ValueOverflow)?;
        if off >= name_pool.len() {
            return Err(VzError::BufferTooSmall);
        }
        let (nlen, vint_w) = read_levint_safe(&name_pool[off..])?;
        let nlen_usize = usize::try_from(nlen).map_err(|_| VzError::ValueOverflow)?;
        let start = off.checked_add(vint_w).ok_or(VzError::ValueOverflow)?;
        let end = start.checked_add(nlen_usize).ok_or(VzError::ValueOverflow)?;
        if end > name_pool.len() {
            return Err(VzError::BufferTooSmall);
        }
        Ok(&name_pool[start..end])
    }

    /// Returns the slice of `ext_meta_pool` starting at this entry's TLV metadata chain.
    ///
    /// Returns [`VzError::NotFound`] when `ext_meta_off == 0`.
    pub fn entry_ext_meta<'a>(&self, ext_meta_pool: &'a [u8]) -> Result<&'a [u8], VzError> {
        if self.ext_meta_off == EXT_META_NONE {
            return Err(VzError::NotFound);
        }
        let pool_len = u32::try_from(ext_meta_pool.len()).map_err(|_| VzError::ValueOverflow)?;
        let shift = pool_shift(pool_len);
        let off = (self.ext_meta_off as usize)
            .checked_shl(shift as u32)
            .ok_or(VzError::ValueOverflow)?;
        if off >= ext_meta_pool.len() {
            return Err(VzError::BufferTooSmall);
        }
        Ok(&ext_meta_pool[off..])
    }

    /// Extracts [`TAG_PARENT_PATH`] from this entry's `ext_meta_pool` chain if present.
    pub fn entry_parent_path<'a>(
        &self,
        ext_meta_pool: &'a [u8],
    ) -> Result<Option<&'a [u8]>, VzError> {
        if self.ext_meta_off == EXT_META_NONE {
            return Ok(None);
        }
        let chain = self.entry_ext_meta(ext_meta_pool)?;
        for elem in TlvIter::new(chain) {
            let elem = elem?;
            if elem.tag == TAG_NOP {
                break;
            }
            if elem.tag == TAG_PARENT_PATH {
                return Ok(Some(elem.value));
            }
        }
        Ok(None)
    }

    /// Returns the full 64-bit entry/inode ID, reading [`TAG_INODE_HI`] when [`FLAG_INODE_64`] is set.
    pub fn full_entry_id(&self, ext_meta_pool: &[u8]) -> Result<u64, VzError> {
        if (self.flags_and_codec & FLAG_INODE_64) == 0 {
            return Ok(self.entry_id_lo as u64);
        }
        let chain = self.entry_ext_meta(ext_meta_pool)?;
        for elem in TlvIter::new(chain) {
            let elem = elem?;
            if elem.tag == TAG_NOP {
                break;
            }
            if elem.tag == TAG_INODE_HI {
                if elem.value.len() < 4 {
                    return Err(VzError::BadFormat);
                }
                let hi = read_le_u32(elem.value, 0) as u64;
                return Ok((hi << 32) | (self.entry_id_lo as u64));
            }
        }
        Err(VzError::BadFormat)
    }

    /// Resolves a zero-copy slice of an external (non-inline) payload from `archive`.
    pub fn resolve_external<'a>(&self, archive: &'a [u8]) -> Result<&'a [u8], VzError> {
        if (self.flags_and_codec
            & (FLAG_TOMBSTONE | FLAG_MULTI_CLUSTER | FLAG_SPARSE | FLAG_INLINE_DATA))
            != 0
        {
            return Err(VzError::BadFormat);
        }
        match self.payload {
            DirPayload::Ref {
                data_offset,
                stored_size,
                in_cluster_offset,
                ..
            } => {
                let abs_u64 = data_offset
                    .checked_add(in_cluster_offset as u64)
                    .ok_or(VzError::ValueOverflow)?;
                let end_u64 = abs_u64
                    .checked_add(stored_size)
                    .ok_or(VzError::ValueOverflow)?;
                let start = usize::try_from(abs_u64).map_err(|_| VzError::ValueOverflow)?;
                let end = usize::try_from(end_u64).map_err(|_| VzError::ValueOverflow)?;
                if end > archive.len() {
                    return Err(VzError::BufferTooSmall);
                }
                Ok(&archive[start..end])
            }
            DirPayload::Inline { .. } => Err(VzError::BadFormat),
        }
    }

    /// Resolves a zero-copy payload slice from either inline bytes or the mapped `archive` buffer.
    pub fn resolve_payload<'s, 'a>(
        &'s self,
        archive: &'a [u8],
    ) -> Result<ResolvedPayload<'s>, VzError>
    where
        'a: 's,
    {
        if (self.flags_and_codec & (FLAG_TOMBSTONE | FLAG_MULTI_CLUSTER | FLAG_SPARSE)) != 0 {
            return Err(VzError::BadFormat);
        }
        if let Some(inline) = self.inline_slice() {
            return Ok(ResolvedPayload::Inline(inline));
        }
        Ok(ResolvedPayload::ArchiveSlice(self.resolve_external(archive)?))
    }
}

/// Computes the automatic offset shift (`0..=16`) for a Leaf Node's `NamePool` or `ExtMetaPool`.
#[inline]
pub fn pool_shift(pool_len: u32) -> u8 {
    if pool_len <= 0x1_0000 {
        return 0;
    }
    let mut v = (pool_len - 1) >> 16;
    let mut shift = 0u8;
    while v != 0 {
        v >>= 1;
        shift += 1;
    }
    shift
}

/// Leaf DirNode Header (`16` bytes exact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafNodeHeader {
    /// Number of 64-byte [`DirEntry`] records in this leaf.
    pub entry_count: u32,
    /// Byte length of the `NamePool` immediately following the entries.
    pub name_pool_len: u32,
    /// Byte length of the `ExtMetaPool` immediately following `NamePool`.
    pub ext_meta_len: u32,
    /// Castagnoli CRC32C of bytes `[0..12]` concatenated with `[16..total_size]`.
    pub node_crc32c: u32,
}

impl LeafNodeHeader {
    /// Exact encoded wire size in bytes (`16`).
    pub const SIZE: usize = 16;

    /// Decodes a 16-byte [`LeafNodeHeader`] from `buf[..16]`.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        Ok(Self {
            entry_count: read_le_u32(buf, 0),
            name_pool_len: read_le_u32(buf, 4),
            ext_meta_len: read_le_u32(buf, 8),
            node_crc32c: read_le_u32(buf, 12),
        })
    }

    /// Serializes this [`LeafNodeHeader`] into a 16-byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let _ = self.write_bytes(&mut out);
        out
    }

    /// Serializes this [`LeafNodeHeader`] into `dst[..16]`.
    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        write_le_u32(dst, 0, self.entry_count);
        write_le_u32(dst, 4, self.name_pool_len);
        write_le_u32(dst, 8, self.ext_meta_len);
        write_le_u32(dst, 12, self.node_crc32c);
        Ok(())
    }

    /// Computes total byte size of the complete Leaf Node (`Header + Entries + Pools`).
    pub fn total_size(&self) -> Result<usize, VzError> {
        let entries_bytes = (self.entry_count as u64)
            .checked_mul(DirEntry::SIZE as u64)
            .ok_or(VzError::ValueOverflow)?;
        let total = (Self::SIZE as u64)
            .checked_add(entries_bytes)
            .and_then(|v| v.checked_add(self.name_pool_len as u64))
            .and_then(|v| v.checked_add(self.ext_meta_len as u64))
            .ok_or(VzError::ValueOverflow)?;
        usize::try_from(total).map_err(|_| VzError::ValueOverflow)
    }

    /// Computes and writes `node_crc32c` into a mutable serialized Leaf Node buffer.
    pub fn stamp_crc(node_buf: &mut [u8]) -> Result<u32, VzError> {
        use crate::crc::crc32c_update;
        let hdr = Self::from_bytes(node_buf)?;
        let total = hdr.total_size()?;
        if node_buf.len() < total {
            return Err(VzError::BufferTooSmall);
        }
        let mut crc = crc32c_update(0xFFFF_FFFF, &node_buf[..12]);
        crc = crc32c_update(crc, &node_buf[Self::SIZE..total]);
        let final_crc = !crc;
        write_le_u32(node_buf, 12, final_crc);
        Ok(final_crc)
    }
}

/// Extended Timestamp TLV payload (`24` bytes exact, tag [`TAG_EXT_TIME`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtTime {
    /// Signed 64-bit modification time seconds relative to Unix epoch.
    pub mtime_sec: i64,
    /// Signed 64-bit birth/creation time seconds relative to Unix epoch.
    pub btime_sec: i64,
    /// Modification sub-second nanoseconds (`0..=999_999_999`).
    pub mtime_nsec: u32,
    /// Birth/creation sub-second nanoseconds (`0..=999_999_999`).
    pub btime_nsec: u32,
}

impl ExtTime {
    /// Exact encoded wire size in bytes (`24`).
    pub const SIZE: usize = 24;

    /// Decodes a 24-byte [`ExtTime`] from `buf[..24]`.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        Ok(Self {
            mtime_sec: read_le_i64(buf, 0),
            btime_sec: read_le_i64(buf, 8),
            mtime_nsec: read_le_u32(buf, 16),
            btime_nsec: read_le_u32(buf, 20),
        })
    }

    /// Serializes this [`ExtTime`] into a 24-byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let _ = self.write_bytes(&mut out);
        out
    }

    /// Serializes this [`ExtTime`] into `dst[..24]`.
    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        write_le_i64(dst, 0, self.mtime_sec);
        write_le_i64(dst, 8, self.btime_sec);
        write_le_u32(dst, 16, self.mtime_nsec);
        write_le_u32(dst, 20, self.btime_nsec);
        Ok(())
    }
}

/// Cluster Sync Header (`32` bytes exact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterHeader {
    /// Must equal [`MAGIC_CLUSTER`] (`"VZ_CLUST"` LE).
    pub sync_magic: u64,
    /// Total cluster byte length including header & footer (multiple of 8; 64 recommended).
    pub cluster_len: u64,
    /// Byte length of the immediately preceding cluster (`0` for Cluster `0`).
    pub prev_cluster_len: u64,
    /// Monotonic 0-based cluster sequence identifier.
    pub cluster_seq: u64,
}

impl ClusterHeader {
    /// Exact encoded wire size in bytes (`32`).
    pub const SIZE: usize = 32;

    /// Decodes a 32-byte [`ClusterHeader`] from `buf[..32]`.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        Ok(Self {
            sync_magic: read_le_u64(buf, 0),
            cluster_len: read_le_u64(buf, 8),
            prev_cluster_len: read_le_u64(buf, 16),
            cluster_seq: read_le_u64(buf, 24),
        })
    }

    /// Serializes this [`ClusterHeader`] into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let _ = self.write_bytes(&mut out);
        out
    }

    /// Serializes this [`ClusterHeader`] into `dst[..32]`.
    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        write_le_u64(dst, 0, self.sync_magic);
        write_le_u64(dst, 8, self.cluster_len);
        write_le_u64(dst, 16, self.prev_cluster_len);
        write_le_u64(dst, 24, self.cluster_seq);
        Ok(())
    }
}

/// Cluster Footer (`16` bytes exact, located at `cluster_start + cluster_len - 16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterFooter {
    /// Mirrors [`ClusterHeader::cluster_len`] for reverse backward traversal from EOF.
    pub cluster_len: u64,
    /// Castagnoli CRC32C covering cluster bytes `0 .. cluster_len - 8`.
    pub cluster_crc32c: u32,
    /// Must equal [`MAGIC_FOOTER`] (`"ENDC"` LE).
    pub footer_magic: u32,
}

impl ClusterFooter {
    /// Exact encoded wire size in bytes (`16`).
    pub const SIZE: usize = 16;

    /// Decodes a 16-byte [`ClusterFooter`] from `buf[..16]`.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        Ok(Self {
            cluster_len: read_le_u64(buf, 0),
            cluster_crc32c: read_le_u32(buf, 8),
            footer_magic: read_le_u32(buf, 12),
        })
    }

    /// Serializes this [`ClusterFooter`] into a 16-byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let _ = self.write_bytes(&mut out);
        out
    }

    /// Serializes this [`ClusterFooter`] into `dst[..16]`.
    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::SIZE {
            return Err(VzError::BufferTooSmall);
        }
        write_le_u64(dst, 0, self.cluster_len);
        write_le_u32(dst, 8, self.cluster_crc32c);
        write_le_u32(dst, 12, self.footer_magic);
        Ok(())
    }
}

/// Detached Parity Cluster Manifest Header (`24` bytes fixed + `K * 8` offset bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParityManifest {
    /// Erasure codec identifier (`ECC_RS_GF256`, `ECC_RS_GF65536`, or `ECC_RAPTORQ`).
    pub ecc_codec: u8,
    /// Burst-error interleave stride (`1`, `2`, `4`, `8`, ...).
    pub interleave_stride: u8,
    /// Number of data clusters `K` in the parity stripe.
    pub data_clusters_k: u16,
    /// Number of parity clusters `M` in the parity stripe.
    pub parity_clusters_m: u16,
    /// Index of this parity slice (`0..M`).
    pub parity_index: u16,
    /// Sequence ID of the first data cluster in the stripe.
    pub first_cluster_seq: u64,
    /// Byte size of the parity payload in this cluster.
    pub max_cluster_len: u64,
}

impl ParityManifest {
    /// Fixed header wire size in bytes (`24`), followed immediately by `K` little-endian `u64` offsets.
    pub const FIXED_SIZE: usize = 24;

    /// Decodes the 24-byte fixed header of a [`ParityManifest`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self, VzError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(VzError::BufferTooSmall);
        }
        Ok(Self {
            ecc_codec: buf[0],
            interleave_stride: buf[1],
            data_clusters_k: read_le_u16(buf, 2),
            parity_clusters_m: read_le_u16(buf, 4),
            parity_index: read_le_u16(buf, 6),
            first_cluster_seq: read_le_u64(buf, 8),
            max_cluster_len: read_le_u64(buf, 16),
        })
    }

    /// Decodes a [`ParityManifest`] and returns the trailing raw `u64` offset table bytes
    /// (`data_clusters_k * 8` bytes).
    pub fn parse_with_offsets(buf: &[u8]) -> Result<(Self, &[u8]), VzError> {
        let hdr = Self::from_bytes(buf)?;
        let table_bytes = (hdr.data_clusters_k as usize)
            .checked_mul(8)
            .ok_or(VzError::ValueOverflow)?;
        let total = Self::FIXED_SIZE
            .checked_add(table_bytes)
            .ok_or(VzError::ValueOverflow)?;
        if buf.len() < total {
            return Err(VzError::BufferTooSmall);
        }
        Ok((hdr, &buf[Self::FIXED_SIZE..total]))
    }

    /// Serializes the 24-byte fixed header into an array.
    pub fn to_bytes(&self) -> [u8; Self::FIXED_SIZE] {
        let mut out = [0u8; Self::FIXED_SIZE];
        let _ = self.write_bytes(&mut out);
        out
    }

    /// Serializes the 24-byte fixed header into `dst[..24]`.
    pub fn write_bytes(&self, dst: &mut [u8]) -> Result<(), VzError> {
        if dst.len() < Self::FIXED_SIZE {
            return Err(VzError::BufferTooSmall);
        }
        dst[0] = self.ecc_codec;
        dst[1] = self.interleave_stride;
        write_le_u16(dst, 2, self.data_clusters_k);
        write_le_u16(dst, 4, self.parity_clusters_m);
        write_le_u16(dst, 6, self.parity_index);
        write_le_u64(dst, 8, self.first_cluster_seq);
        write_le_u64(dst, 16, self.max_cluster_len);
        Ok(())
    }
}

// ============================================================================
// 3. ENDIAN-SAFE LOAD / STORE HELPERS (NO ALIGNMENT UB, HOST-ENDIAN AGNOSTIC)
// ============================================================================

/// Multi-byte element byte-order indicator (`TensorMeta::byte_order` in `SPEC.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ByteOrder {
    /// Least-significant byte first (canonical VZ wire metadata byte order).
    LittleEndian = 0,
    /// Most-significant byte first (network / big-endian payload byte order).
    BigEndian = 1,
}

impl TryFrom<u8> for ByteOrder {
    type Error = VzError;

    #[inline]
    fn try_from(value: u8) -> Result<Self, VzError> {
        match value {
            0 => Ok(Self::LittleEndian),
            1 => Ok(Self::BigEndian),
            _ => Err(VzError::BadFormat),
        }
    }
}

impl ByteOrder {
    /// Returns the native byte order of the compiling CPU architecture.
    #[inline]
    pub const fn host() -> Self {
        #[cfg(target_endian = "big")]
        {
            Self::BigEndian
        }
        #[cfg(not(target_endian = "big"))]
        {
            Self::LittleEndian
        }
    }

    #[inline(always)]
    pub fn read_u16(self, buf: &[u8], off: usize) -> u16 {
        match self {
            Self::LittleEndian => read_le_u16(buf, off),
            Self::BigEndian => read_be_u16(buf, off),
        }
    }

    #[inline(always)]
    pub fn read_i16(self, buf: &[u8], off: usize) -> i16 {
        self.read_u16(buf, off) as i16
    }

    #[inline(always)]
    pub fn read_u32(self, buf: &[u8], off: usize) -> u32 {
        match self {
            Self::LittleEndian => read_le_u32(buf, off),
            Self::BigEndian => read_be_u32(buf, off),
        }
    }

    #[inline(always)]
    pub fn read_i32(self, buf: &[u8], off: usize) -> i32 {
        self.read_u32(buf, off) as i32
    }

    #[inline(always)]
    pub fn read_u64(self, buf: &[u8], off: usize) -> u64 {
        match self {
            Self::LittleEndian => read_le_u64(buf, off),
            Self::BigEndian => read_be_u64(buf, off),
        }
    }

    #[inline(always)]
    pub fn read_i64(self, buf: &[u8], off: usize) -> i64 {
        self.read_u64(buf, off) as i64
    }

    #[inline(always)]
    pub fn read_f32(self, buf: &[u8], off: usize) -> f32 {
        f32::from_bits(self.read_u32(buf, off))
    }

    #[inline(always)]
    pub fn read_f64(self, buf: &[u8], off: usize) -> f64 {
        f64::from_bits(self.read_u64(buf, off))
    }

    #[inline(always)]
    pub fn write_u16(self, dst: &mut [u8], off: usize, v: u16) {
        match self {
            Self::LittleEndian => write_le_u16(dst, off, v),
            Self::BigEndian => write_be_u16(dst, off, v),
        }
    }

    #[inline(always)]
    pub fn write_i16(self, dst: &mut [u8], off: usize, v: i16) {
        self.write_u16(dst, off, v as u16);
    }

    #[inline(always)]
    pub fn write_u32(self, dst: &mut [u8], off: usize, v: u32) {
        match self {
            Self::LittleEndian => write_le_u32(dst, off, v),
            Self::BigEndian => write_be_u32(dst, off, v),
        }
    }

    #[inline(always)]
    pub fn write_i32(self, dst: &mut [u8], off: usize, v: i32) {
        self.write_u32(dst, off, v as u32);
    }

    #[inline(always)]
    pub fn write_u64(self, dst: &mut [u8], off: usize, v: u64) {
        match self {
            Self::LittleEndian => write_le_u64(dst, off, v),
            Self::BigEndian => write_be_u64(dst, off, v),
        }
    }

    #[inline(always)]
    pub fn write_i64(self, dst: &mut [u8], off: usize, v: i64) {
        self.write_u64(dst, off, v as u64);
    }

    #[inline(always)]
    pub fn write_f32(self, dst: &mut [u8], off: usize, v: f32) {
        self.write_u32(dst, off, v.to_bits());
    }

    #[inline(always)]
    pub fn write_f64(self, dst: &mut [u8], off: usize, v: f64) {
        self.write_u64(dst, off, v.to_bits());
    }
}

#[inline(always)]
pub fn read_le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline(always)]
pub fn read_le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline(always)]
pub fn read_le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

#[inline(always)]
pub fn read_le_i64(buf: &[u8], off: usize) -> i64 {
    read_le_u64(buf, off) as i64
}

#[inline(always)]
pub fn read_be_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

#[inline(always)]
pub fn read_be_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline(always)]
pub fn read_be_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

#[inline(always)]
pub fn read_be_i64(buf: &[u8], off: usize) -> i64 {
    read_be_u64(buf, off) as i64
}

#[inline(always)]
pub fn write_le_u16(dst: &mut [u8], off: usize, v: u16) {
    dst[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline(always)]
pub fn write_le_u32(dst: &mut [u8], off: usize, v: u32) {
    dst[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline(always)]
pub fn write_le_u64(dst: &mut [u8], off: usize, v: u64) {
    dst[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

#[inline(always)]
pub fn write_le_i64(dst: &mut [u8], off: usize, v: i64) {
    write_le_u64(dst, off, v as u64);
}

#[inline(always)]
pub fn write_be_u16(dst: &mut [u8], off: usize, v: u16) {
    dst[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

#[inline(always)]
pub fn write_be_u32(dst: &mut [u8], off: usize, v: u32) {
    dst[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

#[inline(always)]
pub fn write_be_u64(dst: &mut [u8], off: usize, v: u64) {
    dst[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

#[inline(always)]
pub fn write_be_i64(dst: &mut [u8], off: usize, v: i64) {
    write_be_u64(dst, off, v as u64);
}

// ============================================================================
// 4. BRANCHLESS LE-VINT, CONTEXT-FREE TLV, AND 64-BYTE ALIGNMENT PADDING
// ============================================================================

/// Returns the encoded byte length (`1`, `2`, `4`, or `8`) of `val` as an LE-VINT.
#[inline]
pub fn levint_len(val: u64) -> Result<usize, VzError> {
    if val < (1u64 << 6) {
        Ok(1)
    } else if val < (1u64 << 14) {
        Ok(2)
    } else if val < (1u64 << 30) {
        Ok(4)
    } else if val < (1u64 << 62) {
        Ok(8)
    } else {
        Err(VzError::ValueOverflow)
    }
}

/// Branchless LE-VINT decoder for buffers with at least 8 readable bytes.
///
/// Returns `(decoded_value, bytes_consumed)` where `bytes_consumed` is `1`, `2`, `4`, or `8`.
#[inline]
pub fn read_levint_fast(buf: &[u8; 8]) -> (u64, usize) {
    const WIDTHS: [usize; 4] = [1, 2, 4, 8];
    const MASKS: [u64; 4] = [
        0x0000_0000_0000_00FF,
        0x0000_0000_0000_FFFF,
        0x0000_0000_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    let tag = (buf[0] & 0x03) as usize;
    let val = (u64::from_le_bytes(*buf) & MASKS[tag]) >> 2;
    (val, WIDTHS[tag])
}

/// Bounds-checked LE-VINT decoder returning `(decoded_value, bytes_consumed)`.
#[inline]
pub fn read_levint_safe(buf: &[u8]) -> Result<(u64, usize), VzError> {
    if buf.is_empty() {
        return Err(VzError::BufferTooSmall);
    }
    if let Ok(arr) = <&[u8; 8]>::try_from(&buf[..buf.len().min(8)]) {
        return Ok(read_levint_fast(arr));
    }
    const WIDTHS: [usize; 4] = [1, 2, 4, 8];
    let w = WIDTHS[(buf[0] & 0x03) as usize];
    if buf.len() < w {
        return Err(VzError::BufferTooSmall);
    }
    let mut raw = [0u8; 8];
    raw[..w].copy_from_slice(&buf[..w]);
    Ok((u64::from_le_bytes(raw) >> 2, w))
}

/// Encodes an unsigned 62-bit integer (`< 2^62`) as a compact LE-VINT (`1`, `2`, `4`, or `8` bytes).
#[inline]
pub fn write_levint(dst: &mut [u8], val: u64) -> Result<usize, VzError> {
    if val < (1u64 << 6) {
        if dst.is_empty() {
            return Err(VzError::BufferTooSmall);
        }
        dst[0] = (val as u8) << 2;
        Ok(1)
    } else if val < (1u64 << 14) {
        if dst.len() < 2 {
            return Err(VzError::BufferTooSmall);
        }
        write_le_u16(dst, 0, ((val as u16) << 2) | 0x01);
        Ok(2)
    } else if val < (1u64 << 30) {
        if dst.len() < 4 {
            return Err(VzError::BufferTooSmall);
        }
        write_le_u32(dst, 0, ((val as u32) << 2) | 0x02);
        Ok(4)
    } else if val < (1u64 << 62) {
        if dst.len() < 8 {
            return Err(VzError::BufferTooSmall);
        }
        write_le_u64(dst, 0, (val << 2) | 0x03);
        Ok(8)
    } else {
        Err(VzError::ValueOverflow)
    }
}

/// Writes `0..=63` context-free padding bytes into `dst` to align `current_file_offset` to `64` B.
pub fn write_void_align64(dst: &mut [u8], current_file_offset: u64) -> Result<usize, VzError> {
    let rem = (current_file_offset & 63) as usize;
    if rem == 0 {
        return Ok(0);
    }
    let pad = 64 - rem;
    if dst.len() < pad {
        return Err(VzError::BufferTooSmall);
    }
    if pad == 1 {
        dst[0] = 0x00;
        return Ok(1);
    }
    dst[0] = 0xEC;
    dst[1] = ((pad - 2) as u8) << 2;
    dst[2..pad].fill(0);
    Ok(pad)
}

/// Context-free skipper for `0x00` ([`TAG_NOP`]) or `0xEC` ([`TAG_VOID`]) padding elements.
pub fn skip_padding(buf: &[u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }
    if buf[0] == 0x00 {
        return 1;
    }
    if buf[0] != 0xEC {
        return 0;
    }
    let Ok((payload_len, vint_w)) = read_levint_safe(&buf[1..]) else {
        return 0;
    };
    let hdr = 1 + vint_w;
    let Ok(payload_usize) = usize::try_from(payload_len) else {
        return 0;
    };
    match hdr.checked_add(payload_usize) {
        Some(total) if total <= buf.len() => total,
        _ => 0,
    }
}

/// Borrowed LE-TLV element produced by [`tlv_next`] or [`TlvIter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlvElement<'a> {
    /// Decoded tag identifier (`TAG_*`).
    pub tag: u64,
    /// Borrowed value slice (empty for [`TAG_NOP`]).
    pub value: &'a [u8],
}

/// Parses a single context-free LE-TLV element from `buf`, returning `(element, remainder)`.
pub fn tlv_next(buf: &[u8]) -> Result<(TlvElement<'_>, &[u8]), VzError> {
    if buf.is_empty() {
        return Err(VzError::BufferTooSmall);
    }
    if buf[0] == 0x00 {
        return Ok((
            TlvElement {
                tag: TAG_NOP,
                value: &[],
            },
            &buf[1..],
        ));
    }
    let (tag, tag_w) = read_levint_safe(buf)?;
    let (len, len_w) = read_levint_safe(&buf[tag_w..])?;
    let hdr = tag_w + len_w;
    let len_usize = usize::try_from(len).map_err(|_| VzError::ValueOverflow)?;
    let end = hdr.checked_add(len_usize).ok_or(VzError::ValueOverflow)?;
    if end > buf.len() {
        return Err(VzError::BufferTooSmall);
    }
    Ok((
        TlvElement {
            tag,
            value: &buf[hdr..end],
        },
        &buf[end..],
    ))
}

/// Streaming iterator over context-free LE-TLV elements inside a byte slice.
#[derive(Debug, Clone, Copy)]
pub struct TlvIter<'a> {
    rem: &'a [u8],
}

impl<'a> TlvIter<'a> {
    /// Creates a new TLV iterator over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { rem: buf }
    }

    /// Returns the unparsed trailing slice.
    pub fn remaining(&self) -> &'a [u8] {
        self.rem
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<TlvElement<'a>, VzError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rem.is_empty() {
            return None;
        }
        match tlv_next(self.rem) {
            Ok((elem, rest)) => {
                self.rem = rest;
                Some(Ok(elem))
            }
            Err(e) => {
                self.rem = &[];
                Some(Err(e))
            }
        }
    }
}
