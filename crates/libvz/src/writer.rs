use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::btree::{LeafNodeView, key128_cmp};
use crate::codec::{
    CryptoContext, EncryptionKey, ZstdDictCache, compress_payload, compress_payload_with_cache,
};
use crate::crc::crc32c;
use crate::ecc::boot_ecc_encode;
use crate::error::VzError;
use crate::ext_meta::{
    ChunkExtent, CipherHeader, ColChunkStats, DataManifestHeader, DictEntry, ExtCodecMeta,
    LsmRunDesc, OwnerEntry, RootFallback, SchemaEntry, SchemaLinkMeta, SparseExtent, Xattr,
    encode_chunk_table,
    encode_dict_table, encode_ext_codec, encode_ext_owner, encode_lsm_runs, encode_owner_table,
    encode_root_fallback, encode_schema_link, encode_schema_table, encode_sparse_extents,
    encode_xattr_list, push_levint, push_lp_bytes, push_tlv, split_archive_path,
};
use crate::hash::{AlgoHasher, PathHasher};
use crate::io::RangeReader;
use crate::reader::{VzReader, VzReaderOptions};
use crate::rs::{build_cluster_from_body, encode_rs_gf256_stripe};
use crate::wire::{
    BOOT_ECC_DESC_OFF, BootHeader, CODEC_EXT, CODEC_MASK, CODEC_NONE, COMPAT_BOOT_ECC,
    COMPAT_COL_STATS, ClusterFooter, ClusterHeader, DEFAULT_BOOT_SIZE, DirEntry, DirPayload,
    EXT_CODEC_ZSTD_DICT, ExtTime, FLAG_HASH_COLLISION, FLAG_INLINE_DATA, FLAG_INODE_64,
    FLAG_MULTI_CLUSTER, FLAG_SPARSE, FLAG_TOMBSTONE, HASH_ALGO_BUILTIN, HeaderSlot,
    INCOMPAT_BIG_BOOT, INCOMPAT_ENCRYPTED, KIND_DIR, KIND_MASK, KIND_REG, LeafNodeHeader,
    MAGIC_FOOTER, MAGIC_HEADER, RO_COMPAT_LSM_RUNS, RO_COMPAT_STREAM_ECC, RouteEntry,
    TAG_CHUNK_TABLE, TAG_CIPHER_HEADER, TAG_DATA_MANIFEST, TAG_DICT_TABLE, TAG_DIR_NODE,
    TAG_EXT_CODEC, TAG_EXT_OWNER, TAG_EXT_TIME, TAG_INODE_HI, TAG_LSM_RUNS, TAG_NOP,
    TAG_OWNER_TABLE, TAG_PARENT_PATH, TAG_ROOT_FALLBACK, TAG_SCHEMA_LINK, TAG_SCHEMA_TABLE,
    TAG_SPARSE_EXTENTS, TAG_XATTR_LIST, TREE_HEIGHT_PIPE, levint_len, pool_shift,
};

/// Configuration options for [`VzWriter`] and [`VzPipeWriter`].
#[derive(Debug, Clone)]
pub struct VzWriterConfig {
    /// Boot Block size in bytes (default `65_536`).
    pub boot_block_size: u32,
    /// Enables self-healing 4 KiB Boot Block ECC (`COMPAT_BOOT_ECC`) when `boot_block_size == 65_536`.
    pub enable_boot_ecc: bool,
    /// Hash algorithm (`HASH_ALGO_BUILTIN`, `HASH_ALGO_XXH3_64`, `HASH_ALGO_BLAKE3`).
    pub hash_algo: u8,
    /// Default payload compression codec (`CODEC_NONE`, `CODEC_LZ4`, `CODEC_ZSTD`).
    pub default_codec: u8,
    /// Zstd compression level (default `3`).
    pub zstd_level: i32,
    /// Target cluster payload grouping size in bytes (default `1 MiB`).
    pub target_cluster_size: usize,
    /// Files exceeding this uncompressed size are split into `FLAG_MULTI_CLUSTER` chunks (default `1 MiB`).
    pub multi_cluster_threshold: usize,
    /// Maximum entries per B+Tree leaf (`1..=2048`, default `512`).
    pub max_leaf_entries: usize,
    /// Maximum `RouteEntry` children per internal B+Tree node (`2..=1024`, default `128`).
    pub max_route_entries: usize,
    /// Optional authenticated encryption key (`INCOMPAT_ENCRYPTED`).
    pub encryption: Option<EncryptionKey>,
    /// Optional Reed-Solomon `GF(2^8)` stripe parameters `(K, M)` (`K + M <= 256`).
    pub rs_parity: Option<(u16, u16)>,
    /// Shared Zstd dictionaries stored in `TAG_DICT_TABLE`.
    pub dicts: Vec<DictEntry>,
    /// Tensor/column schemas stored in `TAG_SCHEMA_TABLE`.
    pub schemas: Vec<SchemaEntry>,
    /// Pre-populated POSIX owner table (optional).
    pub owners: Vec<OwnerEntry>,
    /// Enables `COMPAT_COL_STATS` flag when analytical column statistics are present.
    pub enable_col_stats: bool,
}

impl Default for VzWriterConfig {
    fn default() -> Self {
        Self {
            boot_block_size: DEFAULT_BOOT_SIZE as u32,
            enable_boot_ecc: true,
            hash_algo: HASH_ALGO_BUILTIN,
            default_codec: CODEC_NONE,
            zstd_level: 3,
            target_cluster_size: 1024 * 1024,
            multi_cluster_threshold: 1024 * 1024,
            max_leaf_entries: 512,
            max_route_entries: 128,
            encryption: None,
            rs_parity: None,
            dicts: Vec::new(),
            schemas: Vec::new(),
            owners: Vec::new(),
            enable_col_stats: false,
        }
    }
}

/// Per-entry creation metadata passed to [`VzWriter`] / [`VzPipeWriter`].
#[derive(Debug, Clone)]
pub struct EntryOptions {
    /// Entry kind (`KIND_REG`, `KIND_DIR`, `KIND_LNK`, `KIND_TENSOR`, `KIND_COLUMN`, ...).
    pub kind: u16,
    /// POSIX permission bits (`0o7777`).
    pub mode: u16,
    /// Modification time in nanoseconds since Unix epoch.
    pub mtime_ns: i64,
    /// Optional extended 64-bit timestamps + birth time (`TAG_EXT_TIME`).
    pub ext_time: Option<ExtTime>,
    /// Optional POSIX owner (`TAG_OWNER_TABLE` or `TAG_EXT_OWNER`).
    pub owner: Option<OwnerEntry>,
    /// Optional POSIX extended attributes (`TAG_XATTR_LIST`).
    pub xattrs: Vec<Xattr>,
    /// Optional per-entry compression codec override (`CODEC_*`).
    pub codec: Option<u8>,
    /// Optional Zstd dictionary ID (`TAG_DICT_TABLE` + `TAG_EXT_CODEC`).
    pub dict_id: Option<u32>,
    /// Optional explicit 64-bit inode/entry ID (sets `FLAG_INODE_64` + `TAG_INODE_HI` if > `u32::MAX`).
    pub entry_id: Option<u64>,
    /// Optional schema ID linking `KIND_TENSOR` or `KIND_COLUMN` to `TAG_SCHEMA_TABLE`.
    pub schema_id: Option<u32>,
    /// Optional extra bytes inside `TAG_SCHEMA_LINK`.
    pub schema_extra: Vec<u8>,
    /// Optional analytical column chunk stats inside `TAG_DATA_MANIFEST`.
    pub col_stats: Option<ColChunkStats>,
    /// Optional sparse extents (`TAG_SPARSE_EXTENTS`) and logical file size (`FLAG_SPARSE`).
    pub sparse: Option<(u64, Vec<SparseExtent>)>,
}

impl Default for EntryOptions {
    fn default() -> Self {
        Self {
            kind: KIND_REG,
            mode: 0o644,
            mtime_ns: 0,
            ext_time: None,
            owner: None,
            xattrs: Vec::new(),
            codec: None,
            dict_id: None,
            entry_id: None,
            schema_id: None,
            schema_extra: Vec::new(),
            col_stats: None,
            sparse: None,
        }
    }
}

#[derive(Debug, Clone)]
struct StagedEntry {
    parent_path: String,
    basename: String,
    parent_hash: u64,
    name_hash: u64,
    payload: DirPayload,
    entry_id: u64,
    mtime_ns: i64,
    posix_mode: u16,
    owner_idx: u8,
    flags_and_codec: u8,
    ext_time: Option<ExtTime>,
    ext_owner: Option<OwnerEntry>,
    xattrs: Vec<Xattr>,
    ext_codec: Option<ExtCodecMeta>,
    schema_link: Option<SchemaLinkMeta>,
    sparse_extents: Option<Vec<SparseExtent>>,
}

struct ClusterEmitter<W: Write> {
    writer: W,
    current_offset: u64,
    cluster_seq: u64,
    prev_cluster_len: u64,
    rs_parity: Option<(u16, u16)>,
    pending_body: Vec<u8>,
    target_cluster_size: usize,
    stripe_clusters: Vec<Vec<u8>>,
    stripe_offsets: Vec<u64>,
    stripe_first_seq: u64,
}

impl<W: Write> ClusterEmitter<W> {
    fn new(
        writer: W,
        start_offset: u64,
        start_seq: u64,
        prev_cluster_len: u64,
        target_cluster_size: usize,
        rs_parity: Option<(u16, u16)>,
    ) -> Result<Self, VzError> {
        if let Some((k, m)) = rs_parity
            && (k == 0 || m == 0 || (k as usize + m as usize) > 256)
        {
            return Err(VzError::InvalidInput);
        }
        Ok(Self {
            writer,
            current_offset: start_offset,
            cluster_seq: start_seq,
            prev_cluster_len,
            rs_parity,
            pending_body: Vec::new(),
            target_cluster_size: target_cluster_size.max(4096),
            stripe_clusters: Vec::new(),
            stripe_offsets: Vec::new(),
            stripe_first_seq: start_seq,
        })
    }

    fn emit_raw_cluster_bytes(&mut self, cluster: Vec<u8>) -> Result<(u64, u32), VzError> {
        let off = self.current_offset;
        let len = u32::try_from(cluster.len()).map_err(|_| VzError::ValueOverflow)?;
        self.writer.write_all(&cluster).map_err(|_| VzError::IoError)?;
        self.current_offset = self
            .current_offset
            .checked_add(len as u64)
            .ok_or(VzError::ValueOverflow)?;
        self.prev_cluster_len = len as u64;
        self.cluster_seq += 1;

        if let Some((k, _m)) = self.rs_parity {
            if self.stripe_clusters.is_empty() {
                self.stripe_first_seq = self.cluster_seq - 1;
            }
            self.stripe_offsets.push(off);
            self.stripe_clusters.push(cluster);
            if self.stripe_clusters.len() == k as usize {
                self.flush_parity_stripe()?;
            }
        }
        Ok((off, len))
    }

    fn emit_cluster_body(&mut self, body_tlv: &[u8]) -> Result<(u64, u32), VzError> {
        let cluster = build_cluster_from_body(body_tlv, self.prev_cluster_len, self.cluster_seq)?;
        self.emit_raw_cluster_bytes(cluster)
    }

    fn flush_parity_stripe(&mut self) -> Result<(), VzError> {
        let Some((_k, m)) = self.rs_parity else {
            return Ok(());
        };
        if self.stripe_clusters.is_empty() {
            return Ok(());
        }
        let refs: Vec<&[u8]> = self.stripe_clusters.iter().map(Vec::as_slice).collect();
        let (parities, new_prev_len) = encode_rs_gf256_stripe(
            &refs,
            &self.stripe_offsets,
            self.stripe_first_seq,
            m,
            self.cluster_seq,
            self.prev_cluster_len,
        )?;
        for p in parities {
            let len = p.len() as u64;
            self.writer.write_all(&p).map_err(|_| VzError::IoError)?;
            self.current_offset = self
                .current_offset
                .checked_add(len)
                .ok_or(VzError::ValueOverflow)?;
            self.cluster_seq += 1;
        }
        self.prev_cluster_len = new_prev_len;
        self.stripe_clusters.clear();
        self.stripe_offsets.clear();
        Ok(())
    }

    fn flush_pending_data_cluster(&mut self) -> Result<(), VzError> {
        if self.pending_body.is_empty() {
            return Ok(());
        }
        let body = core::mem::take(&mut self.pending_body);
        self.emit_cluster_body(&body)?;
        Ok(())
    }

    /// Appends a `TAG_DATA_MANIFEST` + 64-byte-aligned payload to the current shared data cluster,
    /// returning `(cluster_offset, in_cluster_offset, cluster_seq)`.
    fn append_data_payload(
        &mut self,
        entry_id: u64,
        raw_size: u64,
        stored_payload: &[u8],
        col_stats: Option<&ColChunkStats>,
    ) -> Result<(u64, u32, u64), VzError> {
        let stats_bytes = encode_col_chunk_stats(col_stats)?;
        let manifest_flags: u16 = 0x0002 | u16::from(col_stats.is_some());
        let prefix_len = DataManifestHeader::SIZE + stats_bytes.len();
        let stored_len = stored_payload.len();

        // Check if adding to current pending cluster would exceed target_cluster_size.
        let est_add = 16 + prefix_len + 64 + stored_len;
        if !self.pending_body.is_empty() && self.pending_body.len() + est_add > self.target_cluster_size {
            self.flush_pending_data_cluster()?;
        }

        let cluster_off = self.current_offset;
        let seq = self.cluster_seq;
        let body_pos = self.pending_body.len();
        let file_pos_before_tlv = cluster_off + ClusterHeader::SIZE as u64 + body_pos as u64;

        // Tag `TAG_DATA_MANIFEST` (0x08 -> 0x20, 1 byte LE-VINT).
        let (vint_w, pad) = solve_manifest_align64(file_pos_before_tlv, prefix_len, stored_len)?;
        let val_len = prefix_len + pad + stored_len;
        if levint_len(val_len as u64)? != vint_w {
            return Err(VzError::BadFormat);
        }
        let payload_rel_off = u16::try_from(prefix_len + pad).map_err(|_| VzError::ValueOverflow)?;
        let in_cluster_offset = u32::try_from(
            ClusterHeader::SIZE + body_pos + 1 + vint_w + prefix_len + pad,
        )
        .map_err(|_| VzError::ValueOverflow)?;

        debug_assert_eq!((cluster_off + in_cluster_offset as u64) & 63, 0);

        let hdr = DataManifestHeader {
            entry_id,
            raw_size,
            stored_size: stored_len as u64,
            payload_crc32c: crc32c(stored_payload),
            manifest_flags,
            payload_rel_off,
        };

        push_levint(&mut self.pending_body, TAG_DATA_MANIFEST)?;
        push_levint(&mut self.pending_body, val_len as u64)?;
        self.pending_body.extend_from_slice(&hdr.to_bytes());
        self.pending_body.extend_from_slice(&stats_bytes);
        write_padding_bytes(&mut self.pending_body, pad)?;
        self.pending_body.extend_from_slice(stored_payload);

        if self.pending_body.len() >= self.target_cluster_size {
            self.flush_pending_data_cluster()?;
        }

        Ok((cluster_off, in_cluster_offset, seq))
    }

    /// Writes a dedicated standalone cluster containing a single `TAG_DATA_MANIFEST` (for multi-cluster chunks).
    fn emit_dedicated_data_cluster(
        &mut self,
        entry_id: u64,
        raw_size: u64,
        stored_payload: &[u8],
        col_stats: Option<&ColChunkStats>,
    ) -> Result<(u64, u32, u64), VzError> {
        self.flush_pending_data_cluster()?;
        let stats_bytes = encode_col_chunk_stats(col_stats)?;
        let manifest_flags: u16 = 0x0002 | u16::from(col_stats.is_some());
        let prefix_len = DataManifestHeader::SIZE + stats_bytes.len();
        let stored_len = stored_payload.len();
        let cluster_off = self.current_offset;
        let seq = self.cluster_seq;
        let file_pos_before_tlv = cluster_off + ClusterHeader::SIZE as u64;

        let (vint_w, pad) = solve_manifest_align64(file_pos_before_tlv, prefix_len, stored_len)?;
        let val_len = prefix_len + pad + stored_len;
        let payload_rel_off = u16::try_from(prefix_len + pad).map_err(|_| VzError::ValueOverflow)?;
        let in_cluster_offset =
            u32::try_from(ClusterHeader::SIZE + 1 + vint_w + prefix_len + pad)
                .map_err(|_| VzError::ValueOverflow)?;

        let hdr = DataManifestHeader {
            entry_id,
            raw_size,
            stored_size: stored_len as u64,
            payload_crc32c: crc32c(stored_payload),
            manifest_flags,
            payload_rel_off,
        };

        let mut body = Vec::with_capacity(1 + vint_w + val_len);
        push_levint(&mut body, TAG_DATA_MANIFEST)?;
        push_levint(&mut body, val_len as u64)?;
        body.extend_from_slice(&hdr.to_bytes());
        body.extend_from_slice(&stats_bytes);
        write_padding_bytes(&mut body, pad)?;
        body.extend_from_slice(stored_payload);

        self.emit_cluster_body(&body)?;
        Ok((cluster_off, in_cluster_offset, seq))
    }

    /// Writes a standalone cluster containing a 64-byte-aligned `TAG_CHUNK_TABLE` TLV.
    fn emit_chunk_table_cluster(&mut self, extents: &[ChunkExtent]) -> Result<(u64, u32), VzError> {
        self.flush_pending_data_cluster()?;
        let table = encode_chunk_table(extents)?;
        let cluster_off = self.current_offset;
        let mut body = Vec::with_capacity(64 + table.len());
        // Pad inside cluster body to 64-byte align the TAG_CHUNK_TABLE TLV header itself.
        let file_pos = cluster_off + ClusterHeader::SIZE as u64;
        let rem = (file_pos & 63) as usize;
        let pad = if rem == 0 { 0 } else { 64 - rem };
        write_padding_bytes(&mut body, pad)?;
        let in_cluster_offset =
            u32::try_from(ClusterHeader::SIZE + body.len()).map_err(|_| VzError::ValueOverflow)?;
        push_tlv(&mut body, TAG_CHUNK_TABLE, &table)?;
        self.emit_cluster_body(&body)?;
        Ok((cluster_off, in_cluster_offset))
    }
}

fn solve_manifest_align64(
    file_pos_before_tlv: u64,
    prefix_len: usize,
    stored_len: usize,
) -> Result<(usize, usize), VzError> {
    for &vint_w in &[1usize, 2, 4, 8] {
        let base_pos = file_pos_before_tlv + 1 + vint_w as u64 + prefix_len as u64;
        let rem = (base_pos & 63) as usize;
        let mut pad = if rem == 0 { 0 } else { 64 - rem };
        let val_len = prefix_len + pad + stored_len;
        let needed_w = levint_len(val_len as u64)?;
        if needed_w == vint_w {
            return Ok((vint_w, pad));
        }
        if needed_w < vint_w {
            pad += 64;
            let val_len2 = prefix_len + pad + stored_len;
            if levint_len(val_len2 as u64)? == vint_w {
                return Ok((vint_w, pad));
            }
        }
    }
    Err(VzError::ValueOverflow)
}

fn write_padding_bytes(out: &mut Vec<u8>, pad: usize) -> Result<(), VzError> {
    if pad == 0 {
        return Ok(());
    }
    if pad == 1 {
        out.push(0x00);
        return Ok(());
    }
    out.push(0xEC);
    let inner = (pad - 2) as u64;
    let w = levint_len(inner)?;
    if pad < 1 + w {
        return Err(VzError::BadFormat);
    }
    let payload_len = (pad - 1 - w) as u64;
    // Re-check width if subtracting w changed threshold
    if levint_len(payload_len)? == w {
        push_levint(out, payload_len)?;
        out.resize(out.len() + payload_len as usize, 0);
    } else {
        // Fall back to leading 0x00 NOP + Void
        out.pop();
        out.push(0x00);
        write_padding_bytes(out, pad - 1)?;
    }
    Ok(())
}

fn encode_col_chunk_stats(stats: Option<&ColChunkStats>) -> Result<Vec<u8>, VzError> {
    let Some(s) = stats else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&s.col_schema_id.to_le_bytes());
    out.extend_from_slice(&s.row_count.to_le_bytes());
    out.extend_from_slice(&s.null_count.to_le_bytes());
    push_lp_bytes(&mut out, &s.min_bytes)?;
    push_lp_bytes(&mut out, &s.max_bytes)?;
    Ok(out)
}

/// Active incremental streaming file state created by [`VzWriter::begin_streamed_file`].
pub struct VzStreamedFile {
    path: String,
    parent_path: String,
    basename: String,
    parent_hash: u64,
    name_hash: u64,
    entry_id: u64,
    effective_codec: u8,
    ext_codec: Option<ExtCodecMeta>,
    chunk_cap: usize,
    opts: EntryOptions,
    pending: Vec<u8>,
    extents: Vec<ChunkExtent>,
    total_raw: u64,
    total_stored: u64,
}

/// Streaming, bounded-memory archive builder writing `.vz` containers to any `Write + Seek`.
pub struct VzWriter<W: Write + Seek> {
    config: VzWriterConfig,
    hasher: Box<dyn PathHasher>,
    emitter: ClusterEmitter<W>,
    crypto: Option<(crate::ext_meta::CipherHeader, CryptoContext)>,
    dict_cache: ZstdDictCache,
    target_generation: u64,
    entries: Vec<StagedEntry>,
    seen_paths: HashSet<(String, String)>,
    path_to_idx: HashMap<String, usize>,
    owners: Vec<OwnerEntry>,
    owner_map: HashMap<(u32, u32, String, String), u8>,
    next_entry_id: u64,
    has_col_stats: bool,
}

impl<W: Write + Seek> VzWriter<W> {
    /// Creates a new [`VzWriter`] using the configured hash algorithm.
    pub fn new(writer: W, config: VzWriterConfig) -> Result<Self, VzError> {
        let hasher = AlgoHasher::new(config.hash_algo)?;
        Self::with_hasher(writer, config, Box::new(hasher))
    }

    /// Creates a new [`VzWriter`] with a custom [`PathHasher`] (e.g., for collision testing).
    pub fn with_hasher(
        mut writer: W,
        config: VzWriterConfig,
        hasher: Box<dyn PathHasher>,
    ) -> Result<Self, VzError> {
        if config.boot_block_size < DEFAULT_BOOT_SIZE as u32 || (config.boot_block_size & 63) != 0 {
            return Err(VzError::InvalidInput);
        }
        if config.max_leaf_entries == 0 || config.max_leaf_entries > 2048 {
            return Err(VzError::InvalidInput);
        }
        if config.max_route_entries < 2 || config.max_route_entries > 1024 {
            return Err(VzError::InvalidInput);
        }

        let crypto = match &config.encryption {
            Some(key) => Some(CryptoContext::create(key)?),
            None => None,
        };

        // Reserve Boot Block space upfront so clusters stream sequentially at boot_block_size..EOF.
        let zeros = vec![0u8; config.boot_block_size as usize];
        writer.seek(SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
        writer.write_all(&zeros).map_err(|_| VzError::IoError)?;

        let mut owners = Vec::new();
        let mut owner_map = HashMap::new();
        for o in &config.owners {
            if owners.len() < 255 {
                let idx = owners.len() as u8;
                owner_map.insert(
                    (o.uid, o.gid, o.uname.clone(), o.gname.clone()),
                    idx,
                );
                owners.push(o.clone());
            }
        }

        let target_cluster_size = config.target_cluster_size;
        let rs_parity = config.rs_parity;
        let boot_size = config.boot_block_size as u64;
        let dict_cache = ZstdDictCache::new(&config.dicts, config.zstd_level);

        Ok(Self {
            config,
            hasher,
            emitter: ClusterEmitter::new(writer, boot_size, 0, 0, target_cluster_size, rs_parity)?,
            crypto,
            dict_cache,
            target_generation: 1,
            entries: Vec::new(),
            seen_paths: HashSet::new(),
            path_to_idx: HashMap::new(),
            owners,
            owner_map,
            next_entry_id: 1,
            has_col_stats: false,
        })
    }

    fn alloc_entry_id(&mut self, explicit: Option<u64>) -> u64 {
        if let Some(id) = explicit {
            if id >= self.next_entry_id {
                self.next_entry_id = id.saturating_add(1);
            }
            id
        } else {
            let id = self.next_entry_id;
            self.next_entry_id += 1;
            id
        }
    }

    fn register_owner(&mut self, owner: Option<OwnerEntry>) -> (u8, Option<OwnerEntry>) {
        let Some(o) = owner else {
            return (0, None);
        };
        let key = (o.uid, o.gid, o.uname.clone(), o.gname.clone());
        if let Some(&idx) = self.owner_map.get(&key) {
            return (idx, None);
        }
        if self.owners.len() < 255 {
            let idx = self.owners.len() as u8;
            self.owner_map.insert(key, idx);
            self.owners.push(o);
            (idx, None)
        } else {
            (255, Some(o))
        }
    }

    /// Adds a directory entry (`KIND_DIR`).
    pub fn add_dir(&mut self, path: &str, mode: u16, mtime_ns: i64) -> Result<(), VzError> {
        let opts = EntryOptions {
            kind: KIND_DIR,
            mode,
            mtime_ns,
            ..Default::default()
        };
        self.add_entry_bytes(path, &[], opts)
    }

    /// Adds a regular file with default options (`0o644`).
    pub fn add_file(&mut self, path: &str, data: &[u8]) -> Result<(), VzError> {
        self.add_entry_bytes(path, data, EntryOptions::default())
    }

    /// Adds a regular file, symlink, tensor, column, or special entry with full options.
    pub fn add_file_with_options(
        &mut self,
        path: &str,
        data: &[u8],
        opts: EntryOptions,
    ) -> Result<(), VzError> {
        self.add_entry_bytes(path, data, opts)
    }

    /// Adds a sparse file with explicit non-zero `(logical_offset, slice)` extents and `logical_size`.
    pub fn add_sparse_file(
        &mut self,
        path: &str,
        logical_size: u64,
        extents: &[(u64, &[u8])],
        mut opts: EntryOptions,
    ) -> Result<(), VzError> {
        let mut sparse_meta = Vec::with_capacity(extents.len());
        let mut packed = Vec::new();
        let mut last_end = 0u64;
        for &(off, bytes) in extents {
            if off < last_end {
                return Err(VzError::InvalidInput);
            }
            let end = off
                .checked_add(bytes.len() as u64)
                .ok_or(VzError::ValueOverflow)?;
            if end > logical_size {
                return Err(VzError::InvalidInput);
            }
            sparse_meta.push(SparseExtent {
                logical_offset: off,
                length: bytes.len() as u64,
            });
            packed.extend_from_slice(bytes);
            last_end = end;
        }
        opts.sparse = Some((logical_size, sparse_meta));
        self.add_entry_bytes(path, &packed, opts)
    }

    /// Adds a hardlink sharing the exact inode (`entry_id`) and payload of an already-added entry.
    pub fn add_hardlink(&mut self, link_path: &str, target_path: &str) -> Result<(), VzError> {
        let (t_parent, t_base) = split_archive_path(target_path)?;
        let norm_target = if t_parent == "/" {
            format!("/{t_base}")
        } else {
            format!("{t_parent}/{t_base}")
        };
        let &idx = self.path_to_idx.get(&norm_target).ok_or(VzError::NotFound)?;
        let target = self.entries[idx].clone();

        let (parent_path, basename) = split_archive_path(link_path)?;
        if !self.seen_paths.insert((parent_path.clone(), basename.clone())) {
            return Err(VzError::AlreadyExists);
        }
        let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
        let name_hash = self.hasher.hash(basename.as_bytes())?;
        let norm_link = if parent_path == "/" {
            format!("/{basename}")
        } else {
            format!("{parent_path}/{basename}")
        };
        let new_idx = self.entries.len();
        self.path_to_idx.insert(norm_link, new_idx);
        self.entries.push(StagedEntry {
            parent_path,
            basename,
            parent_hash,
            name_hash,
            payload: target.payload,
            entry_id: target.entry_id,
            mtime_ns: target.mtime_ns,
            posix_mode: target.posix_mode,
            owner_idx: target.owner_idx,
            flags_and_codec: target.flags_and_codec & !FLAG_HASH_COLLISION,
            ext_time: target.ext_time,
            ext_owner: target.ext_owner,
            xattrs: target.xattrs,
            ext_codec: target.ext_codec,
            schema_link: target.schema_link,
            sparse_extents: target.sparse_extents,
        });
        Ok(())
    }

    /// Streams a large file from `reader` in `O(cluster_size)` bounded memory using `FLAG_MULTI_CLUSTER`.
    pub fn add_file_reader<R: Read>(
        &mut self,
        path: &str,
        mut reader: R,
        opts: EntryOptions,
    ) -> Result<(), VzError> {
        let mut sf = self.begin_streamed_file(path, opts)?;
        let chunk_cap = sf.chunk_cap;
        let mut buf = vec![0u8; chunk_cap];
        loop {
            let mut filled = 0usize;
            while filled < chunk_cap {
                let n = reader.read(&mut buf[filled..]).map_err(|_| VzError::IoError)?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            self.write_streamed_chunk(&mut sf, &buf[..filled])?;
        }
        self.finish_streamed_file(sf)
    }

    /// Starts writing a potentially multi-GB file incrementally via [`VzWriter::write_streamed_chunk`]
    /// and [`VzWriter::finish_streamed_file`] using `O(cluster_size)` bounded memory.
    pub fn begin_streamed_file(
        &mut self,
        path: &str,
        opts: EntryOptions,
    ) -> Result<VzStreamedFile, VzError> {
        if (opts.kind & KIND_MASK) == KIND_DIR {
            return Err(VzError::InvalidInput);
        }
        let (parent_path, basename) = split_archive_path(path)?;
        if !self.seen_paths.insert((parent_path.clone(), basename.clone())) {
            return Err(VzError::AlreadyExists);
        }
        let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
        let name_hash = self.hasher.hash(basename.as_bytes())?;
        let entry_id = self.alloc_entry_id(opts.entry_id);
        let codec = opts.codec.unwrap_or(self.config.default_codec) & CODEC_MASK;
        let ext_codec = opts.dict_id.map(|dict_id| ExtCodecMeta {
            ext_codec_id: EXT_CODEC_ZSTD_DICT,
            dict_id,
            params: Vec::new(),
        });
        let effective_codec = if ext_codec.is_some() { CODEC_EXT } else { codec };
        let chunk_cap = self.config.target_cluster_size.max(4096);

        Ok(VzStreamedFile {
            path: path.to_string(),
            parent_path,
            basename,
            parent_hash,
            name_hash,
            entry_id,
            effective_codec,
            ext_codec,
            chunk_cap,
            opts,
            pending: Vec::with_capacity(chunk_cap),
            extents: Vec::new(),
            total_raw: 0,
            total_stored: 0,
        })
    }

    fn emit_streamed_chunk_block(
        &mut self,
        sf: &mut VzStreamedFile,
        len: usize,
    ) -> Result<(), VzError> {
        let compressed = compress_payload_with_cache(
            &sf.pending[..len],
            sf.effective_codec,
            sf.ext_codec.as_ref(),
            &self.config.dicts,
            Some(&self.dict_cache),
            self.config.zstd_level,
        )?;
        self.emitter.flush_pending_data_cluster()?;
        let target_gen = self.target_generation;
        let next_seq = self.emitter.cluster_seq;
        let stored = match &self.crypto {
            Some((_, ctx)) => {
                ctx.encrypt_payload(target_gen, next_seq, sf.entry_id, &compressed)?
            }
            None => compressed,
        };
        let stored_len = stored.len() as u64;
        let (cluster_offset, in_cluster_offset, actual_seq) =
            self.emitter.emit_dedicated_data_cluster(
                sf.entry_id,
                len as u64,
                &stored,
                sf.opts.col_stats.as_ref(),
            )?;
        if actual_seq != next_seq {
            return Err(VzError::BadFormat);
        }
        sf.total_stored = sf
            .total_stored
            .checked_add(stored_len)
            .ok_or(VzError::ValueOverflow)?;
        sf.extents.push(ChunkExtent {
            cluster_offset,
            in_cluster_offset,
            stored_size: stored_len,
            raw_size: len as u64,
        });
        Ok(())
    }

    /// Feeds an arbitrary-sized byte slice into an active [`VzStreamedFile`], flushing full
    /// `target_cluster_size` chunks as dedicated data clusters immediately.
    pub fn write_streamed_chunk(
        &mut self,
        sf: &mut VzStreamedFile,
        mut data: &[u8],
    ) -> Result<(), VzError> {
        while !data.is_empty() {
            let space = sf.chunk_cap - sf.pending.len();
            let take = space.min(data.len());
            sf.pending.extend_from_slice(&data[..take]);
            sf.total_raw = sf
                .total_raw
                .checked_add(take as u64)
                .ok_or(VzError::ValueOverflow)?;
            data = &data[take..];

            if sf.pending.len() == sf.chunk_cap {
                let cap = sf.chunk_cap;
                self.emit_streamed_chunk_block(sf, cap)?;
                sf.pending.clear();
            }
        }
        Ok(())
    }

    /// Finalizes a chunk-streamed [`VzStreamedFile`], automatically using inline or single-cluster
    /// encoding if fewer than 1 full chunk was written, or writing `TAG_CHUNK_TABLE` for multi-cluster.
    pub fn finish_streamed_file(&mut self, mut sf: VzStreamedFile) -> Result<(), VzError> {
        if sf.extents.is_empty() {
            self.seen_paths
                .remove(&(sf.parent_path.clone(), sf.basename.clone()));
            return self.add_entry_bytes(&sf.path, &sf.pending, sf.opts);
        }
        if !sf.pending.is_empty() {
            let rem = sf.pending.len();
            self.emit_streamed_chunk_block(&mut sf, rem)?;
            sf.pending.clear();
        }
        if sf.opts.col_stats.is_some() {
            self.has_col_stats = true;
        }
        let (table_cluster_off, table_in_cluster_off) =
            self.emitter.emit_chunk_table_cluster(&sf.extents)?;
        let (owner_idx, ext_owner) = self.register_owner(sf.opts.owner);
        let mut flags_and_codec = sf.effective_codec | FLAG_MULTI_CLUSTER;
        if sf.entry_id > u32::MAX as u64 {
            flags_and_codec |= FLAG_INODE_64;
        }
        let schema_link = sf.opts.schema_id.map(|schema_id| SchemaLinkMeta {
            schema_id,
            extra: sf.opts.schema_extra,
        });
        let norm_path = if sf.parent_path == "/" {
            format!("/{}", sf.basename)
        } else {
            format!("{}/{}", sf.parent_path, sf.basename)
        };
        let new_idx = self.entries.len();
        self.path_to_idx.insert(norm_path, new_idx);
        self.entries.push(StagedEntry {
            parent_path: sf.parent_path,
            basename: sf.basename,
            parent_hash: sf.parent_hash,
            name_hash: sf.name_hash,
            payload: DirPayload::Ref {
                data_offset: table_cluster_off,
                stored_size: sf.total_stored,
                raw_size: sf.total_raw,
                in_cluster_offset: table_in_cluster_off,
            },
            entry_id: sf.entry_id,
            mtime_ns: sf.opts.mtime_ns,
            posix_mode: (sf.opts.kind & KIND_MASK) | (sf.opts.mode & 0x0FFF),
            owner_idx,
            flags_and_codec,
            ext_time: sf.opts.ext_time,
            ext_owner,
            xattrs: sf.opts.xattrs,
            ext_codec: sf.ext_codec,
            schema_link,
            sparse_extents: None,
        });
        Ok(())
    }

    fn add_entry_bytes(
        &mut self,
        path: &str,
        data: &[u8],
        opts: EntryOptions,
    ) -> Result<(), VzError> {
        let (parent_path, basename) = split_archive_path(path)?;
        if !self.seen_paths.insert((parent_path.clone(), basename.clone())) {
            return Err(VzError::AlreadyExists);
        }
        let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
        let name_hash = self.hasher.hash(basename.as_bytes())?;
        let entry_id = self.alloc_entry_id(opts.entry_id);
        let is_dir = (opts.kind & KIND_MASK) == KIND_DIR;
        let is_special = matches!(
            opts.kind & KIND_MASK,
            KIND_DIR | crate::wire::KIND_FIFO | crate::wire::KIND_CHR | crate::wire::KIND_BLK | crate::wire::KIND_SOCK
        );

        let (owner_idx, ext_owner) = self.register_owner(opts.owner);
        let codec = opts.codec.unwrap_or(self.config.default_codec) & CODEC_MASK;
        let ext_codec = opts.dict_id.map(|dict_id| ExtCodecMeta {
            ext_codec_id: EXT_CODEC_ZSTD_DICT,
            dict_id,
            params: Vec::new(),
        });
        let effective_codec = if ext_codec.is_some() { CODEC_EXT } else { codec };

        if opts.col_stats.is_some() {
            self.has_col_stats = true;
        }

        let (logical_raw_size, sparse_extents, is_sparse) = match opts.sparse {
            Some((logical_sz, exts)) => (logical_sz, Some(exts), true),
            None => (data.len() as u64, None, false),
        };

        let mut flags_and_codec: u8 = 0;
        if entry_id > u32::MAX as u64 {
            flags_and_codec |= FLAG_INODE_64;
        }
        if is_sparse {
            flags_and_codec |= FLAG_SPARSE;
        }

        let payload = if is_special {
            let bytes = [0u8; 27];
            flags_and_codec |= CODEC_NONE | FLAG_INLINE_DATA;
            DirPayload::Inline { bytes, len: 0 }
        } else if !is_sparse && self.crypto.is_none() && data.len() <= 27 && opts.col_stats.is_none()
        {
            // Auto-inline <= 27-byte payloads (CODEC_NONE + FLAG_INLINE_DATA).
            let mut bytes = [0u8; 27];
            bytes[..data.len()].copy_from_slice(data);
            flags_and_codec |= CODEC_NONE | FLAG_INLINE_DATA;
            DirPayload::Inline {
                bytes,
                len: data.len() as u8,
            }
        } else if is_sparse && data.is_empty() && self.crypto.is_none() {
            // Pure-zero sparse file needs zero cluster bytes!
            flags_and_codec |= CODEC_NONE;
            DirPayload::Ref {
                data_offset: 0,
                stored_size: 0,
                raw_size: logical_raw_size,
                in_cluster_offset: 0,
            }
        } else if !is_sparse && data.len() > self.config.multi_cluster_threshold {
            // Multi-cluster chunking for large in-memory blobs.
            let chunk_cap = self.config.target_cluster_size.max(4096);
            let mut extents = Vec::new();
            let mut total_stored = 0u64;
            for chunk in data.chunks(chunk_cap) {
                let compressed = compress_payload_with_cache(
                    chunk,
                    effective_codec,
                    ext_codec.as_ref(),
                    &self.config.dicts,
                    Some(&self.dict_cache),
                    self.config.zstd_level,
                )?;
                self.emitter.flush_pending_data_cluster()?;
                let target_gen = self.target_generation;
                let seq = self.emitter.cluster_seq;
                let stored = match &self.crypto {
                    Some((_, ctx)) => ctx.encrypt_payload(target_gen, seq, entry_id, &compressed)?,
                    None => compressed,
                };
                let stored_len = stored.len() as u64;
                let (cluster_offset, in_cluster_offset, actual_seq) = self
                    .emitter
                    .emit_dedicated_data_cluster(
                        entry_id,
                        chunk.len() as u64,
                        &stored,
                        opts.col_stats.as_ref(),
                    )?;
                if actual_seq != seq {
                    return Err(VzError::BadFormat);
                }
                total_stored = total_stored
                    .checked_add(stored_len)
                    .ok_or(VzError::ValueOverflow)?;
                extents.push(ChunkExtent {
                    cluster_offset,
                    in_cluster_offset,
                    stored_size: stored_len,
                    raw_size: chunk.len() as u64,
                });
            }
            let (table_cluster_off, table_in_cluster_off) =
                self.emitter.emit_chunk_table_cluster(&extents)?;
            flags_and_codec |= effective_codec | FLAG_MULTI_CLUSTER;
            DirPayload::Ref {
                data_offset: table_cluster_off,
                stored_size: total_stored,
                raw_size: logical_raw_size,
                in_cluster_offset: table_in_cluster_off,
            }
        } else {
            // Single-cluster payload (compressed + optionally encrypted).
            let compressed = compress_payload_with_cache(
                data,
                effective_codec,
                ext_codec.as_ref(),
                &self.config.dicts,
                Some(&self.dict_cache),
                self.config.zstd_level,
            )?;
            let target_gen = self.target_generation;
            // Ensure seq matches where append_data_payload places it (may flush first if full).
            let stats_len_est = opts.col_stats.as_ref().map_or(0, |_| 64);
            let est_add = 16 + DataManifestHeader::SIZE + stats_len_est + 64 + compressed.len() + 40;
            if !self.emitter.pending_body.is_empty()
                && self.emitter.pending_body.len() + est_add > self.emitter.target_cluster_size
            {
                self.emitter.flush_pending_data_cluster()?;
            }
            let seq = self.emitter.cluster_seq;
            let stored = match &self.crypto {
                Some((_, ctx)) => ctx.encrypt_payload(target_gen, seq, entry_id, &compressed)?,
                None => compressed,
            };
            let stored_len = stored.len() as u64;
            let (cluster_off, in_cluster_offset, actual_seq) = self.emitter.append_data_payload(
                entry_id,
                logical_raw_size,
                &stored,
                opts.col_stats.as_ref(),
            )?;
            if actual_seq != seq {
                return Err(VzError::BadFormat);
            }
            flags_and_codec |= effective_codec;
            DirPayload::Ref {
                data_offset: cluster_off,
                stored_size: stored_len,
                raw_size: logical_raw_size,
                in_cluster_offset,
            }
        };

        let _ = is_dir;
        let schema_link = opts.schema_id.map(|schema_id| SchemaLinkMeta {
            schema_id,
            extra: opts.schema_extra,
        });
        let norm_path = if parent_path == "/" {
            format!("/{basename}")
        } else {
            format!("{parent_path}/{basename}")
        };
        let new_idx = self.entries.len();
        self.path_to_idx.insert(norm_path, new_idx);
        self.entries.push(StagedEntry {
            parent_path,
            basename,
            parent_hash,
            name_hash,
            payload,
            entry_id,
            mtime_ns: opts.mtime_ns,
            posix_mode: (opts.kind & KIND_MASK) | (opts.mode & 0x0FFF),
            owner_idx,
            flags_and_codec,
            ext_time: opts.ext_time,
            ext_owner,
            xattrs: opts.xattrs,
            ext_codec: if (flags_and_codec & FLAG_INLINE_DATA) != 0 {
                None
            } else {
                ext_codec
            },
            schema_link,
            sparse_extents,
        });
        Ok(())
    }

    /// Flushes all pending clusters, builds the B+Tree index, writes the Boot Block + ECC,
    /// and returns the inner writer.
    pub fn finish(mut self) -> Result<W, VzError> {
        self.emitter.flush_pending_data_cluster()?;

        mark_hash_collisions(&mut self.entries);
        self.entries.sort_by(|a, b| {
            key128_cmp(a.parent_hash, a.name_hash, b.parent_hash, b.name_hash)
                .then_with(|| a.parent_path.cmp(&b.parent_path))
                .then_with(|| a.basename.cmp(&b.basename))
        });

        let total_entries = self
            .entries
            .iter()
            .filter(|e| (e.flags_and_codec & FLAG_TOMBSTONE) == 0)
            .count() as u64;

        let registry_bytes = build_registry_bytes(
            &self.owners,
            &self.config.dicts,
            &self.config.schemas,
            self.crypto.as_ref().map(|(h, _)| h),
            None,
        )?;

        let boot_size = self.config.boot_block_size as usize;
        let ecc_active = self.config.enable_boot_ecc && boot_size == DEFAULT_BOOT_SIZE;
        let boot_limit = if ecc_active {
            BOOT_ECC_DESC_OFF
        } else {
            boot_size
        };
        let registry_offset = 0x0080usize;
        let root_node_offset = align_up_64(registry_offset + registry_bytes.len());
        if root_node_offset > boot_limit {
            return Err(VzError::BufferTooSmall);
        }
        let available_boot = boot_limit - root_node_offset;

        let tree_built = build_btree_index(
            &self.entries,
            self.config.max_leaf_entries,
            self.config.max_route_entries,
            available_boot,
            &mut self.emitter,
        )?;
        self.emitter.flush_parity_stripe()?;

        let mut compat_flags = 0u16;
        if ecc_active {
            compat_flags |= COMPAT_BOOT_ECC;
        }
        if self.has_col_stats || self.config.enable_col_stats {
            compat_flags |= COMPAT_COL_STATS;
        }
        let mut ro_compat_flags = 0u16;
        if self.config.rs_parity.is_some() {
            ro_compat_flags |= RO_COMPAT_STREAM_ECC;
        }
        let mut incompat_flags = 0u16;
        if self.crypto.is_some() {
            incompat_flags |= INCOMPAT_ENCRYPTED;
        }
        if self.config.boot_block_size > DEFAULT_BOOT_SIZE as u32 {
            incompat_flags |= INCOMPAT_BIG_BOOT;
        }

        let slot = HeaderSlot {
            magic: MAGIC_HEADER,
            generation: 0,
            boot_block_size: self.config.boot_block_size,
            compat_flags,
            ro_compat_flags,
            incompat_flags,
            tree_height: tree_built.tree_height,
            hash_algo: self.hasher.algo_id(),
            lsm_run_count: 1,
            registry_offset: registry_offset as u16,
            registry_size: registry_bytes.len() as u32,
            root_node_offset: root_node_offset as u32,
            total_entries,
            root_fallback_off: 0,
            root_entry_count: tree_built.root_entry_count,
            header_crc32c: 0,
        };

        let mut boot_block = vec![0u8; boot_size];
        let mut boot_hdr = BootHeader {
            slot_a: slot,
            slot_b: HeaderSlot::from_bytes(&[0u8; 64])?,
        };
        boot_hdr.commit(&slot);
        boot_hdr.write_bytes(&mut boot_block[..BootHeader::SIZE])?;
        boot_block[registry_offset..registry_offset + registry_bytes.len()]
            .copy_from_slice(&registry_bytes);
        boot_block[root_node_offset..root_node_offset + tree_built.root_bytes.len()]
            .copy_from_slice(&tree_built.root_bytes);

        if ecc_active {
            boot_ecc_encode(&mut boot_block)?;
        }

        let mut writer = self.emitter.writer;
        writer.seek(SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
        writer
            .write_all(&boot_block)
            .map_err(|_| VzError::IoError)?;
        writer.flush().map_err(|_| VzError::IoError)?;
        Ok(writer)
    }
}

// ============================================================================
// B+TREE BUILDER HELPERS
// ============================================================================

struct BuiltTree {
    tree_height: u8,
    root_entry_count: u32,
    root_bytes: Vec<u8>,
}

fn align_up_64(v: usize) -> usize {
    (v + 63) & !63
}

fn mark_hash_collisions(entries: &mut [StagedEntry]) {
    let mut parent_paths_by_hash: HashMap<u64, HashSet<String>> = HashMap::new();
    let mut key128_counts: HashMap<(u64, u64), usize> = HashMap::new();
    for e in entries.iter() {
        parent_paths_by_hash
            .entry(e.parent_hash)
            .or_default()
            .insert(e.parent_path.clone());
        *key128_counts.entry((e.parent_hash, e.name_hash)).or_insert(0) += 1;
    }
    for e in entries.iter_mut() {
        let p_coll = parent_paths_by_hash
            .get(&e.parent_hash)
            .is_some_and(|s| s.len() > 1);
        let k_coll = key128_counts
            .get(&(e.parent_hash, e.name_hash))
            .is_some_and(|&c| c > 1);
        if p_coll || k_coll {
            e.flags_and_codec |= FLAG_HASH_COLLISION;
        }
    }
}

fn build_registry_bytes(
    owners: &[OwnerEntry],
    dicts: &[DictEntry],
    schemas: &[SchemaEntry],
    cipher_hdr: Option<&crate::ext_meta::CipherHeader>,
    lsm_runs: Option<&[LsmRunDesc]>,
) -> Result<Vec<u8>, VzError> {
    let mut reg = Vec::new();
    if !owners.is_empty() {
        let val = encode_owner_table(owners)?;
        push_tlv(&mut reg, TAG_OWNER_TABLE, &val)?;
    }
    if !dicts.is_empty() {
        let val = encode_dict_table(dicts)?;
        push_tlv(&mut reg, TAG_DICT_TABLE, &val)?;
    }
    if !schemas.is_empty() {
        let val = encode_schema_table(schemas)?;
        push_tlv(&mut reg, TAG_SCHEMA_TABLE, &val)?;
    }
    if let Some(ch) = cipher_hdr {
        push_tlv(&mut reg, TAG_CIPHER_HEADER, &ch.to_bytes())?;
    }
    if let Some(runs) = lsm_runs {
        let val = encode_lsm_runs(runs)?;
        push_tlv(&mut reg, TAG_LSM_RUNS, &val)?;
    }
    Ok(reg)
}

fn build_entry_ext_chain(e: &StagedEntry) -> Result<Vec<u8>, VzError> {
    let mut chain = Vec::new();
    if (e.flags_and_codec & FLAG_HASH_COLLISION) != 0 {
        push_tlv(&mut chain, TAG_PARENT_PATH, e.parent_path.as_bytes())?;
    }
    if (e.flags_and_codec & FLAG_INODE_64) != 0 {
        let hi = (e.entry_id >> 32) as u32;
        push_tlv(&mut chain, TAG_INODE_HI, &hi.to_le_bytes())?;
    }
    if let Some(ref time) = e.ext_time {
        push_tlv(&mut chain, TAG_EXT_TIME, &time.to_bytes())?;
    }
    if let Some(ref owner) = e.ext_owner {
        let val = encode_ext_owner(owner)?;
        push_tlv(&mut chain, TAG_EXT_OWNER, &val)?;
    }
    if !e.xattrs.is_empty() {
        let val = encode_xattr_list(&e.xattrs)?;
        push_tlv(&mut chain, TAG_XATTR_LIST, &val)?;
    }
    if let Some(ref ext_codec) = e.ext_codec {
        let val = encode_ext_codec(ext_codec)?;
        push_tlv(&mut chain, TAG_EXT_CODEC, &val)?;
    }
    if let Some(ref link) = e.schema_link {
        let val = encode_schema_link(link)?;
        push_tlv(&mut chain, TAG_SCHEMA_LINK, &val)?;
    }
    if let Some(ref extents) = e.sparse_extents {
        let val = encode_sparse_extents(extents)?;
        push_tlv(&mut chain, TAG_SPARSE_EXTENTS, &val)?;
    }
    if !chain.is_empty() {
        chain.push(TAG_NOP as u8);
    }
    Ok(chain)
}

fn serialize_leaf_node(entries: &[StagedEntry]) -> Result<Vec<u8>, VzError> {
    let mut name_raws = Vec::with_capacity(entries.len());
    let mut ext_raws = Vec::with_capacity(entries.len());
    let mut total_name_bytes = 0usize;
    let mut total_ext_bytes = 1usize; // byte 0 reserved EXT_META_NONE

    for e in entries {
        let mut nb = Vec::with_capacity(8 + e.basename.len());
        push_lp_bytes(&mut nb, e.basename.as_bytes())?;
        total_name_bytes += nb.len();
        name_raws.push(nb);

        let eb = build_entry_ext_chain(e)?;
        total_ext_bytes += eb.len();
        ext_raws.push(eb);
    }

    // Converge on pool_shift for NamePool and ExtMetaPool.
    let (name_pool, name_offs) = pack_pool(&name_raws, total_name_bytes, false)?;
    let (ext_meta_pool, ext_offs) = pack_pool(&ext_raws, total_ext_bytes, true)?;

    let entries_len = entries.len() * DirEntry::SIZE;
    let total_len = LeafNodeHeader::SIZE + entries_len + name_pool.len() + ext_meta_pool.len();
    let mut out = vec![0u8; total_len];

    let hdr = LeafNodeHeader {
        entry_count: entries.len() as u32,
        name_pool_len: name_pool.len() as u32,
        ext_meta_len: ext_meta_pool.len() as u32,
        node_crc32c: 0,
    };
    hdr.write_bytes(&mut out[..LeafNodeHeader::SIZE])?;

    for (i, e) in entries.iter().enumerate() {
        let de = DirEntry {
            parent_hash: e.parent_hash,
            name_hash: e.name_hash,
            payload: e.payload,
            entry_id_lo: e.entry_id as u32,
            mtime_ns: e.mtime_ns,
            name_pool_off: name_offs[i],
            ext_meta_off: ext_offs[i],
            posix_mode: e.posix_mode,
            owner_idx: e.owner_idx,
            flags_and_codec: e.flags_and_codec,
        };
        let off = LeafNodeHeader::SIZE + i * DirEntry::SIZE;
        de.write_bytes(&mut out[off..off + DirEntry::SIZE])?;
    }

    let names_start = LeafNodeHeader::SIZE + entries_len;
    out[names_start..names_start + name_pool.len()].copy_from_slice(&name_pool);
    let ext_start = names_start + name_pool.len();
    out[ext_start..ext_start + ext_meta_pool.len()].copy_from_slice(&ext_meta_pool);

    LeafNodeHeader::stamp_crc(&mut out)?;
    Ok(out)
}

fn pack_pool(
    items: &[Vec<u8>],
    est_bytes: usize,
    reserve_zero_byte: bool,
) -> Result<(Vec<u8>, Vec<u16>), VzError> {
    let mut shift = pool_shift(u32::try_from(est_bytes).map_err(|_| VzError::ValueOverflow)?);
    loop {
        let align = 1usize << shift;
        let mut pool = Vec::with_capacity(est_bytes + items.len() * align);
        if reserve_zero_byte {
            pool.push(0x00);
        }
        let mut offs = Vec::with_capacity(items.len());
        for item in items {
            if item.is_empty() {
                offs.push(0);
                continue;
            }
            if align > 1 {
                let rem = pool.len() & (align - 1);
                if rem != 0 {
                    pool.resize(pool.len() + (align - rem), 0x00);
                }
            }
            let scaled = pool.len() >> shift;
            offs.push(u16::try_from(scaled).map_err(|_| VzError::ValueOverflow)?);
            pool.extend_from_slice(item);
        }
        if !reserve_zero_byte && pool.is_empty() {
            return Ok((pool, offs));
        }
        if reserve_zero_byte && pool.len() == 1 && items.iter().all(Vec::is_empty) {
            return Ok((Vec::new(), offs));
        }
        let actual_shift = pool_shift(u32::try_from(pool.len()).map_err(|_| VzError::ValueOverflow)?);
        if actual_shift <= shift {
            return Ok((pool, offs));
        }
        shift = actual_shift;
    }
}

fn partition_leaves(entries: &[StagedEntry], max_leaf_entries: usize) -> Vec<(usize, usize)> {
    if entries.is_empty() {
        return vec![(0, 0)];
    }
    let mut ranges = Vec::new();
    let mut start = 0usize;
    while start < entries.len() {
        let mut end = (start + max_leaf_entries).min(entries.len());
        // Bound pools <= 65,536 bytes whenever possible so pool_shift == 0.
        let mut est_names = 0usize;
        let mut est_ext = 1usize;
        let mut fit_end = start;
        for (i, e) in entries[start..end].iter().enumerate() {
            let n_sz = 2 + e.basename.len();
            let e_sz = if (e.flags_and_codec & FLAG_HASH_COLLISION) != 0
                || e.ext_time.is_some()
                || e.ext_owner.is_some()
                || !e.xattrs.is_empty()
                || e.ext_codec.is_some()
                || e.schema_link.is_some()
                || e.sparse_extents.is_some()
                || (e.flags_and_codec & FLAG_INODE_64) != 0
            {
                64
            } else {
                0
            };
            if i > 0 && (est_names + n_sz > 60_000 || est_ext + e_sz > 60_000) {
                break;
            }
            est_names += n_sz;
            est_ext += e_sz;
            fit_end = start + i + 1;
        }
        end = fit_end.max(start + 1);

        // NEVER split identical 128-bit (parent_hash, name_hash) keys across leaves!
        if end < entries.len()
            && entries[end - 1].parent_hash == entries[end].parent_hash
            && entries[end - 1].name_hash == entries[end].name_hash
        {
            let kp = entries[end - 1].parent_hash;
            let kn = entries[end - 1].name_hash;
            // Try shrinking back before the collision group first.
            let mut back = end - 1;
            while back > start && entries[back - 1].parent_hash == kp && entries[back - 1].name_hash == kn
            {
                back -= 1;
            }
            if back > start {
                end = back;
            } else {
                // Collision group starts at `start`; extend past the entire group.
                while end < entries.len()
                    && entries[end].parent_hash == kp
                    && entries[end].name_hash == kn
                {
                    end += 1;
                }
            }
        }
        ranges.push((start, end));
        start = end;
    }
    ranges
}

fn serialize_dir_node_tlv(node_level: u8, entry_count: u32, payload: &[u8]) -> Result<Vec<u8>, VzError> {
    let mut val = Vec::with_capacity(8 + payload.len() + 4);
    val.push(node_level);
    val.push(0);
    val.extend_from_slice(&0u16.to_le_bytes());
    val.extend_from_slice(&entry_count.to_le_bytes());
    val.extend_from_slice(payload);
    if node_level >= 1 {
        let crc = crc32c(&val);
        val.extend_from_slice(&crc.to_le_bytes());
    }
    let mut body = Vec::new();
    push_tlv(&mut body, TAG_DIR_NODE, &val)?;
    Ok(body)
}

fn build_btree_index<W: Write>(
    entries: &[StagedEntry],
    max_leaf_entries: usize,
    max_route_entries: usize,
    available_boot: usize,
    emitter: &mut ClusterEmitter<W>,
) -> Result<BuiltTree, VzError> {
    let leaf_ranges = partition_leaves(entries, max_leaf_entries);
    if leaf_ranges.len() == 1 {
        let (s, e) = leaf_ranges[0];
        let leaf_bytes = serialize_leaf_node(&entries[s..e])?;
        if leaf_bytes.len() <= available_boot {
            return Ok(BuiltTree {
                tree_height: 0,
                root_entry_count: (e - s) as u32,
                root_bytes: leaf_bytes,
            });
        }
    }

    let mut routes = Vec::with_capacity(leaf_ranges.len());
    for (s, e) in leaf_ranges {
        let slice = &entries[s..e];
        let leaf_bytes = serialize_leaf_node(slice)?;
        let body = serialize_dir_node_tlv(0, slice.len() as u32, &leaf_bytes)?;
        let (off, clen) = emitter.emit_cluster_body(&body)?;
        let first = &slice[0];
        let last = &slice[slice.len() - 1];
        routes.push(RouteEntry {
            min_parent_hash: first.parent_hash,
            min_name_hash: first.name_hash,
            max_parent_hash: last.parent_hash,
            max_name_hash: last.name_hash,
            child_cluster_off: off,
            child_cluster_len: clen,
            subtree_count_lo: slice.len() as u32,
        });
    }

    let mut level = 1u8;
    loop {
        let needed_bytes = routes.len() * RouteEntry::SIZE;
        if routes.len() <= max_route_entries && needed_bytes <= available_boot {
            let mut root_bytes = vec![0u8; needed_bytes];
            for (i, r) in routes.iter().enumerate() {
                r.write_bytes(&mut root_bytes[i * RouteEntry::SIZE..(i + 1) * RouteEntry::SIZE])?;
            }
            return Ok(BuiltTree {
                tree_height: level,
                root_entry_count: routes.len() as u32,
                root_bytes,
            });
        }

        let mut next_routes = Vec::new();
        for chunk in routes.chunks(max_route_entries) {
            let mut raw = vec![0u8; chunk.len() * RouteEntry::SIZE];
            let mut sub_sum = 0u32;
            for (i, r) in chunk.iter().enumerate() {
                r.write_bytes(&mut raw[i * RouteEntry::SIZE..(i + 1) * RouteEntry::SIZE])?;
                sub_sum = sub_sum.saturating_add(r.subtree_count_lo);
            }
            let body = serialize_dir_node_tlv(level, chunk.len() as u32, &raw)?;
            let (off, clen) = emitter.emit_cluster_body(&body)?;
            let first = chunk[0];
            let last = chunk[chunk.len() - 1];
            next_routes.push(RouteEntry {
                min_parent_hash: first.min_parent_hash,
                min_name_hash: first.min_name_hash,
                max_parent_hash: last.max_parent_hash,
                max_name_hash: last.max_name_hash,
                child_cluster_off: off,
                child_cluster_len: clen,
                subtree_count_lo: sub_sum,
            });
        }
        routes = next_routes;
        level = level.checked_add(1).ok_or(VzError::ValueOverflow)?;
    }
}

// ============================================================================
// STREAMING PIPE WRITER (`Write` ONLY, ZERO BACK-SEEKING)
// ============================================================================

/// Finalization metadata emitted by [`VzPipeWriter::finish`] so a seekable file can optionally
/// patch its Boot Block via [`finalize_pipe_archive`].
#[derive(Debug, Clone)]
pub struct PipeFinalizeInfo {
    pub boot_block_size: u32,
    pub compat_flags: u16,
    pub ro_compat_flags: u16,
    pub incompat_flags: u16,
    pub hash_algo: u8,
    pub tree_height: u8,
    pub registry_offset: u16,
    pub registry_bytes: Vec<u8>,
    pub root_node_bytes: Vec<u8>,
    pub root_entry_count: u32,
    pub total_entries: u64,
    pub root_fallback_off: u64,
}

/// Forward-only streaming `.vz` writer requiring only `std::io::Write` (zero `Seek` calls).
pub struct VzPipeWriter<W: Write> {
    config: VzWriterConfig,
    hasher: Box<dyn PathHasher>,
    emitter: ClusterEmitter<W>,
    crypto: Option<(crate::ext_meta::CipherHeader, CryptoContext)>,
    dict_cache: ZstdDictCache,
    registry_bytes: Vec<u8>,
    stream_generation: u64,
    entries: Vec<StagedEntry>,
    seen_paths: HashSet<(String, String)>,
    next_entry_id: u64,
    has_col_stats: bool,
}

impl<W: Write> VzPipeWriter<W> {
    /// Creates a forward-only streaming [`VzPipeWriter`], immediately writing the pipe Boot Block.
    pub fn new(mut writer: W, config: VzWriterConfig) -> Result<Self, VzError> {
        if config.boot_block_size < DEFAULT_BOOT_SIZE as u32 || (config.boot_block_size & 63) != 0 {
            return Err(VzError::InvalidInput);
        }
        let hasher = Box::new(AlgoHasher::new(config.hash_algo)?);
        let crypto = match &config.encryption {
            Some(key) => Some(CryptoContext::create(key)?),
            None => None,
        };
        let registry_bytes = build_registry_bytes(
            &config.owners,
            &config.dicts,
            &config.schemas,
            crypto.as_ref().map(|(h, _)| h),
            None,
        )?;
        let boot_size = config.boot_block_size as usize;
        if 0x0080 + registry_bytes.len() > boot_size {
            return Err(VzError::BufferTooSmall);
        }

        let mut incompat_flags = 0u16;
        if crypto.is_some() {
            incompat_flags |= INCOMPAT_ENCRYPTED;
        }
        if config.boot_block_size > DEFAULT_BOOT_SIZE as u32 {
            incompat_flags |= INCOMPAT_BIG_BOOT;
        }
        let mut ro_compat_flags = 0u16;
        if config.rs_parity.is_some() {
            ro_compat_flags |= RO_COMPAT_STREAM_ECC;
        }

        let mut pipe_slot = HeaderSlot {
            magic: MAGIC_HEADER,
            generation: 0,
            boot_block_size: config.boot_block_size,
            compat_flags: 0,
            ro_compat_flags,
            incompat_flags,
            tree_height: TREE_HEIGHT_PIPE,
            hash_algo: hasher.algo_id(),
            lsm_run_count: 1,
            registry_offset: 0x0080,
            registry_size: registry_bytes.len() as u32,
            root_node_offset: 0,
            total_entries: 0,
            root_fallback_off: 0,
            root_entry_count: 0,
            header_crc32c: 0,
        };
        let raw = pipe_slot.to_bytes();
        pipe_slot.header_crc32c = crc32c(&raw[..60]);

        let mut boot_block = vec![0u8; boot_size];
        pipe_slot.write_bytes(&mut boot_block[..HeaderSlot::SIZE])?;
        boot_block[0x0080..0x0080 + registry_bytes.len()].copy_from_slice(&registry_bytes);
        writer.write_all(&boot_block).map_err(|_| VzError::IoError)?;

        let target_cluster_size = config.target_cluster_size;
        let rs_parity = config.rs_parity;
        let dict_cache = ZstdDictCache::new(&config.dicts, config.zstd_level);
        Ok(Self {
            config,
            hasher,
            emitter: ClusterEmitter::new(
                writer,
                boot_size as u64,
                0,
                0,
                target_cluster_size,
                rs_parity,
            )?,
            crypto,
            dict_cache,
            registry_bytes,
            stream_generation: 1,
            entries: Vec::new(),
            seen_paths: HashSet::new(),
            next_entry_id: 1,
            has_col_stats: false,
        })
    }

    /// Adds a directory entry to the stream.
    pub fn add_dir(&mut self, path: &str, mode: u16, mtime_ns: i64) -> Result<(), VzError> {
        self.add_file_with_options(
            path,
            &[],
            EntryOptions {
                kind: KIND_DIR,
                mode,
                mtime_ns,
                ..Default::default()
            },
        )
    }

    /// Adds a file to the forward-only stream.
    pub fn add_file(&mut self, path: &str, data: &[u8]) -> Result<(), VzError> {
        self.add_file_with_options(path, data, EntryOptions::default())
    }

    /// Adds an entry with full options to the forward-only stream.
    pub fn add_file_with_options(
        &mut self,
        path: &str,
        data: &[u8],
        opts: EntryOptions,
    ) -> Result<(), VzError> {
        let (parent_path, basename) = split_archive_path(path)?;
        if !self.seen_paths.insert((parent_path.clone(), basename.clone())) {
            return Err(VzError::AlreadyExists);
        }
        let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
        let name_hash = self.hasher.hash(basename.as_bytes())?;
        let entry_id = opts.entry_id.unwrap_or_else(|| {
            let id = self.next_entry_id;
            self.next_entry_id += 1;
            id
        });
        let is_special = matches!(
            opts.kind & KIND_MASK,
            KIND_DIR | crate::wire::KIND_FIFO | crate::wire::KIND_CHR | crate::wire::KIND_BLK | crate::wire::KIND_SOCK
        );
        let codec = opts.codec.unwrap_or(self.config.default_codec) & CODEC_MASK;
        let ext_codec = opts.dict_id.map(|dict_id| ExtCodecMeta {
            ext_codec_id: EXT_CODEC_ZSTD_DICT,
            dict_id,
            params: Vec::new(),
        });
        let effective_codec = if ext_codec.is_some() { CODEC_EXT } else { codec };
        if opts.col_stats.is_some() {
            self.has_col_stats = true;
        }
        let (owner_idx, ext_owner) = match opts.owner {
            None => (0, None),
            Some(o) => (255, Some(o)),
        };

        let mut flags_and_codec = 0u8;
        if entry_id > u32::MAX as u64 {
            flags_and_codec |= FLAG_INODE_64;
        }

        let payload = if is_special {
            flags_and_codec |= CODEC_NONE | FLAG_INLINE_DATA;
            DirPayload::Inline {
                bytes: [0u8; 27],
                len: 0,
            }
        } else if self.crypto.is_none() && data.len() <= 27 && opts.col_stats.is_none() {
            let mut bytes = [0u8; 27];
            bytes[..data.len()].copy_from_slice(data);
            flags_and_codec |= CODEC_NONE | FLAG_INLINE_DATA;
            DirPayload::Inline {
                bytes,
                len: data.len() as u8,
            }
        } else if data.len() > self.config.multi_cluster_threshold {
            let chunk_cap = self.config.target_cluster_size.max(4096);
            let mut extents = Vec::new();
            let mut total_stored = 0u64;
            for chunk in data.chunks(chunk_cap) {
                let compressed = compress_payload_with_cache(
                    chunk,
                    effective_codec,
                    ext_codec.as_ref(),
                    &self.config.dicts,
                    Some(&self.dict_cache),
                    self.config.zstd_level,
                )?;
                self.emitter.flush_pending_data_cluster()?;
                let seq = self.emitter.cluster_seq;
                let stored = match &self.crypto {
                    Some((_, ctx)) => {
                        ctx.encrypt_payload(self.stream_generation, seq, entry_id, &compressed)?
                    }
                    None => compressed,
                };
                let slen = stored.len() as u64;
                let (coff, ioff, actual_seq) = self.emitter.emit_dedicated_data_cluster(
                    entry_id,
                    chunk.len() as u64,
                    &stored,
                    opts.col_stats.as_ref(),
                )?;
                if actual_seq != seq {
                    return Err(VzError::BadFormat);
                }
                total_stored += slen;
                extents.push(ChunkExtent {
                    cluster_offset: coff,
                    in_cluster_offset: ioff,
                    stored_size: slen,
                    raw_size: chunk.len() as u64,
                });
            }
            let (t_off, t_ioff) = self.emitter.emit_chunk_table_cluster(&extents)?;
            flags_and_codec |= effective_codec | FLAG_MULTI_CLUSTER;
            DirPayload::Ref {
                data_offset: t_off,
                stored_size: total_stored,
                raw_size: data.len() as u64,
                in_cluster_offset: t_ioff,
            }
        } else {
            let compressed = compress_payload_with_cache(
                data,
                effective_codec,
                ext_codec.as_ref(),
                &self.config.dicts,
                Some(&self.dict_cache),
                self.config.zstd_level,
            )?;
            let est_add = 16 + DataManifestHeader::SIZE + 64 + compressed.len() + 40;
            if !self.emitter.pending_body.is_empty()
                && self.emitter.pending_body.len() + est_add > self.emitter.target_cluster_size
            {
                self.emitter.flush_pending_data_cluster()?;
            }
            let seq = self.emitter.cluster_seq;
            let stored = match &self.crypto {
                Some((_, ctx)) => {
                    ctx.encrypt_payload(self.stream_generation, seq, entry_id, &compressed)?
                }
                None => compressed,
            };
            let slen = stored.len() as u64;
            let (coff, ioff, actual_seq) = self.emitter.append_data_payload(
                entry_id,
                data.len() as u64,
                &stored,
                opts.col_stats.as_ref(),
            )?;
            if actual_seq != seq {
                return Err(VzError::BadFormat);
            }
            flags_and_codec |= effective_codec;
            DirPayload::Ref {
                data_offset: coff,
                stored_size: slen,
                raw_size: data.len() as u64,
                in_cluster_offset: ioff,
            }
        };

        self.entries.push(StagedEntry {
            parent_path,
            basename,
            parent_hash,
            name_hash,
            payload,
            entry_id,
            mtime_ns: opts.mtime_ns,
            posix_mode: (opts.kind & KIND_MASK) | (opts.mode & 0x0FFF),
            owner_idx,
            flags_and_codec,
            ext_time: opts.ext_time,
            ext_owner,
            xattrs: opts.xattrs,
            ext_codec: if (flags_and_codec & FLAG_INLINE_DATA) != 0 {
                None
            } else {
                ext_codec
            },
            schema_link: opts.schema_id.map(|schema_id| SchemaLinkMeta {
                schema_id,
                extra: opts.schema_extra,
            }),
            sparse_extents: None,
        });
        Ok(())
    }

    /// Streams a reader into the pipe in `O(cluster_size)` memory without knowing total size upfront.
    pub fn add_file_reader<R: Read>(
        &mut self,
        path: &str,
        mut reader: R,
        opts: EntryOptions,
    ) -> Result<(), VzError> {
        let (parent_path, basename) = split_archive_path(path)?;
        if !self.seen_paths.insert((parent_path.clone(), basename.clone())) {
            return Err(VzError::AlreadyExists);
        }
        let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
        let name_hash = self.hasher.hash(basename.as_bytes())?;
        let entry_id = opts.entry_id.unwrap_or_else(|| {
            let id = self.next_entry_id;
            self.next_entry_id += 1;
            id
        });
        let codec = opts.codec.unwrap_or(self.config.default_codec) & CODEC_MASK;
        let ext_codec = opts.dict_id.map(|dict_id| ExtCodecMeta {
            ext_codec_id: EXT_CODEC_ZSTD_DICT,
            dict_id,
            params: Vec::new(),
        });
        let effective_codec = if ext_codec.is_some() { CODEC_EXT } else { codec };
        let chunk_cap = self.config.target_cluster_size.max(4096);
        let mut buf = vec![0u8; chunk_cap];
        let mut extents = Vec::new();
        let mut total_raw = 0u64;
        let mut total_stored = 0u64;
        loop {
            let mut filled = 0usize;
            while filled < chunk_cap {
                let n = reader.read(&mut buf[filled..]).map_err(|_| VzError::IoError)?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            let compressed = compress_payload_with_cache(
                &buf[..filled],
                effective_codec,
                ext_codec.as_ref(),
                &self.config.dicts,
                Some(&self.dict_cache),
                self.config.zstd_level,
            )?;
            self.emitter.flush_pending_data_cluster()?;
            let seq = self.emitter.cluster_seq;
            let stored = match &self.crypto {
                Some((_, ctx)) => {
                    ctx.encrypt_payload(self.stream_generation, seq, entry_id, &compressed)?
                }
                None => compressed,
            };
            let slen = stored.len() as u64;
            let (coff, ioff, actual_seq) = self.emitter.emit_dedicated_data_cluster(
                entry_id,
                filled as u64,
                &stored,
                opts.col_stats.as_ref(),
            )?;
            if actual_seq != seq {
                return Err(VzError::BadFormat);
            }
            total_raw += filled as u64;
            total_stored += slen;
            extents.push(ChunkExtent {
                cluster_offset: coff,
                in_cluster_offset: ioff,
                stored_size: slen,
                raw_size: filled as u64,
            });
        }
        let (t_off, t_ioff) = self.emitter.emit_chunk_table_cluster(&extents)?;
        let mut flags_and_codec = effective_codec | FLAG_MULTI_CLUSTER;
        if entry_id > u32::MAX as u64 {
            flags_and_codec |= FLAG_INODE_64;
        }
        self.entries.push(StagedEntry {
            parent_path,
            basename,
            parent_hash,
            name_hash,
            payload: DirPayload::Ref {
                data_offset: t_off,
                stored_size: total_stored,
                raw_size: total_raw,
                in_cluster_offset: t_ioff,
            },
            entry_id,
            mtime_ns: opts.mtime_ns,
            posix_mode: (opts.kind & KIND_MASK) | (opts.mode & 0x0FFF),
            owner_idx: 0,
            flags_and_codec,
            ext_time: opts.ext_time,
            ext_owner: None,
            xattrs: opts.xattrs,
            ext_codec,
            schema_link: None,
            sparse_extents: None,
        });
        Ok(())
    }

    /// Finishes the forward-only stream by writing B+Tree index clusters and trailing
    /// `TAG_ROOT_FALLBACK` cluster at EOF.
    pub fn finish(mut self) -> Result<(W, PipeFinalizeInfo), VzError> {
        self.emitter.flush_pending_data_cluster()?;
        mark_hash_collisions(&mut self.entries);
        self.entries.sort_by(|a, b| {
            key128_cmp(a.parent_hash, a.name_hash, b.parent_hash, b.name_hash)
                .then_with(|| a.parent_path.cmp(&b.parent_path))
                .then_with(|| a.basename.cmp(&b.basename))
        });

        let total_entries = self.entries.len() as u64;
        let boot_size = self.config.boot_block_size as usize;
        let ecc_active = self.config.enable_boot_ecc && boot_size == DEFAULT_BOOT_SIZE;
        let boot_limit = if ecc_active {
            BOOT_ECC_DESC_OFF
        } else {
            boot_size
        };
        let registry_offset = 0x0080usize;
        let root_node_offset = align_up_64(registry_offset + self.registry_bytes.len());
        let available_boot = boot_limit.saturating_sub(root_node_offset);

        let tree_built = build_btree_index(
            &self.entries,
            self.config.max_leaf_entries,
            self.config.max_route_entries,
            available_boot,
            &mut self.emitter,
        )?;
        self.emitter.flush_parity_stripe()?;

        // Also write a root cluster if we want external cluster fallback, OR embed root directly
        // inside TAG_ROOT_FALLBACK (embedded_root = Some(...)) so EOF recovery works in 1 cluster!
        let fb = RootFallback {
            stream_generation: self.stream_generation,
            total_entries,
            root_cluster_off: 0,
            root_entry_count: tree_built.root_entry_count,
            tree_height: tree_built.tree_height,
            hash_algo: self.hasher.algo_id(),
            embedded_root: Some(tree_built.root_bytes.clone()),
        };
        let fb_val = encode_root_fallback(&fb);
        let mut fb_body = Vec::new();
        push_tlv(&mut fb_body, TAG_ROOT_FALLBACK, &fb_val)?;
        let (fb_off, _) = self.emitter.emit_cluster_body(&fb_body)?;
        self.emitter.flush_parity_stripe()?;

        let mut compat_flags = 0u16;
        if ecc_active {
            compat_flags |= COMPAT_BOOT_ECC;
        }
        if self.has_col_stats || self.config.enable_col_stats {
            compat_flags |= COMPAT_COL_STATS;
        }
        let mut ro_compat_flags = 0u16;
        if self.config.rs_parity.is_some() {
            ro_compat_flags |= RO_COMPAT_STREAM_ECC;
        }
        let mut incompat_flags = 0u16;
        if self.crypto.is_some() {
            incompat_flags |= INCOMPAT_ENCRYPTED;
        }
        if self.config.boot_block_size > DEFAULT_BOOT_SIZE as u32 {
            incompat_flags |= INCOMPAT_BIG_BOOT;
        }

        self.emitter.writer.flush().map_err(|_| VzError::IoError)?;
        let info = PipeFinalizeInfo {
            boot_block_size: self.config.boot_block_size,
            compat_flags,
            ro_compat_flags,
            incompat_flags,
            hash_algo: self.hasher.algo_id(),
            tree_height: tree_built.tree_height,
            registry_offset: registry_offset as u16,
            registry_bytes: self.registry_bytes,
            root_node_bytes: tree_built.root_bytes,
            root_entry_count: tree_built.root_entry_count,
            total_entries,
            root_fallback_off: fb_off,
        };
        Ok((self.emitter.writer, info))
    }
}

/// Optional Boot Block patcher for finalized streaming pipes on seekable storage (`File` / `Cursor`).
pub fn finalize_pipe_archive<W: Read + Write + Seek>(
    mut stream: W,
    info: &PipeFinalizeInfo,
) -> Result<(), VzError> {
    let boot_size = info.boot_block_size as usize;
    let mut boot_block = vec![0u8; boot_size];
    stream.seek(SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
    stream
        .read_exact(&mut boot_block)
        .map_err(|_| VzError::IoError)?;
    let mut boot_hdr = BootHeader::from_bytes(&boot_block)?;

    let root_node_offset = align_up_64(info.registry_offset as usize + info.registry_bytes.len());
    let slot = HeaderSlot {
        magic: MAGIC_HEADER,
        generation: 0,
        boot_block_size: info.boot_block_size,
        compat_flags: info.compat_flags,
        ro_compat_flags: info.ro_compat_flags,
        incompat_flags: info.incompat_flags,
        tree_height: info.tree_height,
        hash_algo: info.hash_algo,
        lsm_run_count: 1,
        registry_offset: info.registry_offset,
        registry_size: info.registry_bytes.len() as u32,
        root_node_offset: root_node_offset as u32,
        total_entries: info.total_entries,
        root_fallback_off: info.root_fallback_off,
        root_entry_count: info.root_entry_count,
        header_crc32c: 0,
    };
    boot_hdr.commit(&slot);
    boot_hdr.write_bytes(&mut boot_block[..BootHeader::SIZE])?;
    let reg_off = info.registry_offset as usize;
    boot_block[reg_off..reg_off + info.registry_bytes.len()].copy_from_slice(&info.registry_bytes);
    boot_block[root_node_offset..root_node_offset + info.root_node_bytes.len()]
        .copy_from_slice(&info.root_node_bytes);
    if (info.compat_flags & COMPAT_BOOT_ECC) != 0 && boot_size == DEFAULT_BOOT_SIZE {
        boot_ecc_encode(&mut boot_block)?;
    }
    stream.seek(SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
    stream
        .write_all(&boot_block)
        .map_err(|_| VzError::IoError)?;
    stream.flush().map_err(|_| VzError::IoError)?;
    Ok(())
}

// ============================================================================
// LSM INCREMENTAL APPEND WRITER & COMPACTION
// ============================================================================

fn find_tail_cluster_info<R: RangeReader>(
    reader: &R,
    boot_block_size: u64,
    file_len: u64,
) -> Result<(u64, u64), VzError> {
    if file_len <= boot_block_size {
        return Ok((0, 0));
    }
    if file_len < boot_block_size + (ClusterHeader::SIZE + ClusterFooter::SIZE) as u64 {
        return Err(VzError::BadFormat);
    }
    let mut ftr_buf = [0u8; ClusterFooter::SIZE];
    reader.read_at(file_len - ClusterFooter::SIZE as u64, &mut ftr_buf)?;
    let ftr = ClusterFooter::from_bytes(&ftr_buf)?;
    if ftr.footer_magic != MAGIC_FOOTER {
        return Err(VzError::BadMagic);
    }
    let hdr_off = file_len
        .checked_sub(ftr.cluster_len)
        .ok_or(VzError::BadFormat)?;
    let mut hdr_buf = [0u8; ClusterHeader::SIZE];
    reader.read_at(hdr_off, &mut hdr_buf)?;
    let chdr = ClusterHeader::from_bytes(&hdr_buf)?;
    Ok((chdr.cluster_seq + 1, ftr.cluster_len))
}

/// Incremental LSM delta overlay writer appending a new B+Tree run (`RO_COMPAT_LSM_RUNS`)
/// onto an existing `.vz` archive without rewriting existing data clusters.
pub struct LsmAppendWriter<F: Read + Write + Seek + RangeReader> {
    boot_hdr: BootHeader,
    active_slot: HeaderSlot,
    owners: Vec<OwnerEntry>,
    owner_map: HashMap<(u32, u32, String, String), u8>,
    dicts: Vec<DictEntry>,
    schemas: Vec<SchemaEntry>,
    cipher_hdr: Option<crate::ext_meta::CipherHeader>,
    crypto: Option<CryptoContext>,
    encryption_key: Option<EncryptionKey>,
    prev_runs: Vec<LsmRunDesc>,
    hasher: Box<dyn PathHasher>,
    new_generation: u64,
    emitter: ClusterEmitter<F>,
    entries: Vec<StagedEntry>,
    seen_paths: HashSet<(String, String)>,
    next_entry_id: u64,
    max_leaf_entries: usize,
    max_route_entries: usize,
}

impl<F: Read + Write + Seek + RangeReader> LsmAppendWriter<F> {
    /// Opens an existing archive `file` for incremental LSM delta overlay append.
    pub fn open(
        mut file: F,
        encryption: Option<EncryptionKey>,
        max_leaf_entries: usize,
        max_route_entries: usize,
    ) -> Result<Self, VzError> {
        if max_leaf_entries == 0 || max_leaf_entries > 2048 {
            return Err(VzError::InvalidInput);
        }
        if !(2..=1024).contains(&max_route_entries) {
            return Err(VzError::InvalidInput);
        }

        let opts = VzReaderOptions {
            encryption: encryption.clone(),
            repair_boot_ecc: true,
        };
        let (
            active_slot,
            mut prev_runs,
            owners,
            dicts,
            schemas,
            cipher_hdr,
            crypto,
            next_entry_id,
        ) = {
            let reader = VzReader::open_with_options(&file, opts)?;
            let active_slot = *reader.active_slot();
            if active_slot.tree_height == TREE_HEIGHT_PIPE {
                return Err(VzError::BadFormat);
            }
            let prev_runs = reader.lsm_runs().to_vec();
            let owners = reader.owners().to_vec();
            let dicts = reader.dicts().to_vec();
            let schemas = reader.schemas().to_vec();
            let cipher_hdr = reader.cipher_header().copied();
            let crypto = reader.crypto_context().cloned();
            let next_entry_id = reader.max_entry_id()?.saturating_add(1).max(1);
            (
                active_slot,
                prev_runs,
                owners,
                dicts,
                schemas,
                cipher_hdr,
                crypto,
                next_entry_id,
            )
        };

        let file_len = file.total_len()?;
        let mut boot_block = vec![0u8; active_slot.boot_block_size as usize];
        file.seek(SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
        file.read_exact(&mut boot_block)
            .map_err(|_| VzError::IoError)?;
        let boot_hdr = BootHeader::from_bytes(&boot_block)?;

        let (next_seq, prev_len) =
            find_tail_cluster_info(&file, active_slot.boot_block_size as u64, file_len)?;
        let new_generation = active_slot.generation.wrapping_add(1);
        let hasher = Box::new(AlgoHasher::new(active_slot.hash_algo)?);

        let mut owner_map = HashMap::new();
        for (i, o) in owners.iter().enumerate() {
            if i < 255 {
                owner_map.insert((o.uid, o.gid, o.uname.clone(), o.gname.clone()), i as u8);
            }
        }

        let last_run_idx = prev_runs.len() - 1;
        let existing_root_bytes = {
            let root_off = active_slot.root_node_offset as usize;
            if active_slot.tree_height == 0 {
                let leaf = LeafNodeView::parse(&boot_block[root_off..])?;
                let sz = leaf.header().total_size()?;
                boot_block[root_off..root_off + sz].to_vec()
            } else {
                let sz = active_slot.root_entry_count as usize * RouteEntry::SIZE;
                boot_block[root_off..root_off + sz].to_vec()
            }
        };

        file.seek(SeekFrom::End(0)).map_err(|_| VzError::IoError)?;
        let mut emitter = ClusterEmitter::new(
            file,
            file_len,
            next_seq,
            prev_len,
            1024 * 1024,
            None,
        )?;
        if !prev_runs[last_run_idx].root_is_cluster {
            let body = serialize_dir_node_tlv(
                active_slot.tree_height,
                active_slot.root_entry_count,
                &existing_root_bytes,
            )?;
            let (coff, _) = emitter.emit_cluster_body(&body)?;
            prev_runs[last_run_idx].root_offset = coff;
            prev_runs[last_run_idx].root_is_cluster = true;
        }

        Ok(Self {
            boot_hdr,
            active_slot,
            owners,
            owner_map,
            dicts,
            schemas,
            cipher_hdr,
            crypto,
            encryption_key: encryption,
            prev_runs,
            hasher,
            new_generation,
            emitter,
            entries: Vec::new(),
            seen_paths: HashSet::new(),
            next_entry_id,
            max_leaf_entries,
            max_route_entries,
        })
    }

    fn register_owner(&mut self, owner: Option<OwnerEntry>) -> (u8, Option<OwnerEntry>) {
        let Some(o) = owner else {
            return (0, None);
        };
        let key = (o.uid, o.gid, o.uname.clone(), o.gname.clone());
        if let Some(&idx) = self.owner_map.get(&key) {
            return (idx, None);
        }
        if self.owners.len() < 255 {
            let idx = self.owners.len() as u8;
            self.owner_map.insert(key, idx);
            self.owners.push(o);
            (idx, None)
        } else {
            (255, Some(o))
        }
    }

    /// Appends or overwrites a directory (`KIND_DIR`) in the delta run.
    pub fn add_dir(&mut self, path: &str, mode: u16, mtime_ns: i64) -> Result<(), VzError> {
        self.add_file_with_options(
            path,
            &[],
            EntryOptions {
                kind: KIND_DIR,
                mode,
                mtime_ns,
                ..Default::default()
            },
        )
    }

    /// Appends or overwrites a symbolic link (`KIND_LNK`) in the delta run.
    pub fn add_symlink(
        &mut self,
        link_path: &str,
        target: &str,
        mode: u16,
        mtime_ns: i64,
    ) -> Result<(), VzError> {
        self.add_file_with_options(
            link_path,
            target.as_bytes(),
            EntryOptions {
                kind: crate::wire::KIND_LNK,
                mode,
                mtime_ns,
                ..Default::default()
            },
        )
    }

    /// Appends a hardlink sharing an existing entry's payload/entry_id (either staged in this
    /// delta run or resolved live from the base archive).
    pub fn add_hardlink(&mut self, link_path: &str, target_path: &str) -> Result<(), VzError> {
        let (t_parent, t_base) = split_archive_path(target_path)?;
        if let Some(target) = self
            .entries
            .iter()
            .find(|e| e.parent_path == t_parent && e.basename == t_base)
            .cloned()
        {
            if (target.flags_and_codec & FLAG_TOMBSTONE) != 0 {
                return Err(VzError::NotFound);
            }
            let (parent_path, basename) = split_archive_path(link_path)?;
            if !self.seen_paths.insert((parent_path.clone(), basename.clone())) {
                return Err(VzError::AlreadyExists);
            }
            let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
            let name_hash = self.hasher.hash(basename.as_bytes())?;
            self.entries.push(StagedEntry {
                parent_path,
                basename,
                parent_hash,
                name_hash,
                payload: target.payload,
                entry_id: target.entry_id,
                mtime_ns: target.mtime_ns,
                posix_mode: target.posix_mode,
                owner_idx: target.owner_idx,
                flags_and_codec: target.flags_and_codec & !FLAG_HASH_COLLISION,
                ext_time: target.ext_time,
                ext_owner: target.ext_owner,
                xattrs: target.xattrs,
                ext_codec: target.ext_codec,
                schema_link: target.schema_link,
                sparse_extents: target.sparse_extents,
            });
            return Ok(());
        }

        // Resolve target from base archive and copy into this delta run so payload remains valid
        // even under per-generation encryption AAD rules.
        let (raw, opts) = {
            let base = VzReader::open_with_options(
                &self.emitter.writer,
                VzReaderOptions {
                    encryption: self.encryption_key.clone(),
                    repair_boot_ecc: true,
                },
            )?;
            let res = base.resolve_entry(target_path)?;
            let raw = base.read_resolved_payload(&res)?;
            let opts = EntryOptions {
                kind: res.stat.kind,
                mode: res.stat.mode,
                mtime_ns: res.stat.mtime_ns,
                ext_time: res.stat.ext_time,
                owner: res.stat.owner.clone(),
                xattrs: res.stat.xattrs.clone(),
                codec: if res.dir_entry.codec() != crate::wire::CODEC_EXT {
                    Some(res.dir_entry.codec())
                } else {
                    None
                },
                entry_id: Some(res.stat.entry_id),
                ..Default::default()
            };
            (raw, opts)
        };
        self.add_file_with_options(link_path, &raw, opts)
    }

    /// Appends or overwrites a regular file in the delta run.
    pub fn add_file(&mut self, path: &str, data: &[u8]) -> Result<(), VzError> {
        self.add_file_with_options(path, data, EntryOptions::default())
    }

    /// Appends or overwrites an entry with full options in the delta run.
    pub fn add_file_with_options(
        &mut self,
        path: &str,
        data: &[u8],
        opts: EntryOptions,
    ) -> Result<(), VzError> {
        let (parent_path, basename) = split_archive_path(path)?;
        if !self.seen_paths.insert((parent_path.clone(), basename.clone())) {
            return Err(VzError::AlreadyExists);
        }
        let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
        let name_hash = self.hasher.hash(basename.as_bytes())?;
        let entry_id = opts.entry_id.unwrap_or_else(|| {
            let id = self.next_entry_id;
            self.next_entry_id += 1;
            id
        });
        let is_special = matches!(
            opts.kind & KIND_MASK,
            KIND_DIR | crate::wire::KIND_FIFO | crate::wire::KIND_CHR | crate::wire::KIND_BLK | crate::wire::KIND_SOCK
        );
        let (owner_idx, ext_owner) = self.register_owner(opts.owner);
        let codec = opts.codec.unwrap_or(CODEC_NONE) & CODEC_MASK;
        let ext_codec = opts.dict_id.map(|dict_id| ExtCodecMeta {
            ext_codec_id: EXT_CODEC_ZSTD_DICT,
            dict_id,
            params: Vec::new(),
        });
        let effective_codec = if ext_codec.is_some() { CODEC_EXT } else { codec };

        let mut flags_and_codec = 0u8;
        if entry_id > u32::MAX as u64 {
            flags_and_codec |= FLAG_INODE_64;
        }

        let payload = if is_special {
            flags_and_codec |= CODEC_NONE | FLAG_INLINE_DATA;
            DirPayload::Inline {
                bytes: [0u8; 27],
                len: 0,
            }
        } else if self.crypto.is_none() && data.len() <= 27 && opts.col_stats.is_none() {
            let mut bytes = [0u8; 27];
            bytes[..data.len()].copy_from_slice(data);
            flags_and_codec |= CODEC_NONE | FLAG_INLINE_DATA;
            DirPayload::Inline {
                bytes,
                len: data.len() as u8,
            }
        } else {
            let compressed = compress_payload(data, effective_codec, ext_codec.as_ref(), &self.dicts, 3)?;
            let est_add = 16 + DataManifestHeader::SIZE + 64 + compressed.len() + 40;
            if !self.emitter.pending_body.is_empty()
                && self.emitter.pending_body.len() + est_add > self.emitter.target_cluster_size
            {
                self.emitter.flush_pending_data_cluster()?;
            }
            let seq = self.emitter.cluster_seq;
            let stored = match &self.crypto {
                Some(ctx) => ctx.encrypt_payload(self.new_generation, seq, entry_id, &compressed)?,
                None => compressed,
            };
            let slen = stored.len() as u64;
            let (coff, ioff, actual_seq) = self.emitter.append_data_payload(
                entry_id,
                data.len() as u64,
                &stored,
                opts.col_stats.as_ref(),
            )?;
            if actual_seq != seq {
                return Err(VzError::BadFormat);
            }
            flags_and_codec |= effective_codec;
            DirPayload::Ref {
                data_offset: coff,
                stored_size: slen,
                raw_size: data.len() as u64,
                in_cluster_offset: ioff,
            }
        };

        self.entries.push(StagedEntry {
            parent_path,
            basename,
            parent_hash,
            name_hash,
            payload,
            entry_id,
            mtime_ns: opts.mtime_ns,
            posix_mode: (opts.kind & KIND_MASK) | (opts.mode & 0x0FFF),
            owner_idx,
            flags_and_codec,
            ext_time: opts.ext_time,
            ext_owner,
            xattrs: opts.xattrs,
            ext_codec: if (flags_and_codec & FLAG_INLINE_DATA) != 0 {
                None
            } else {
                ext_codec
            },
            schema_link: opts.schema_id.map(|schema_id| SchemaLinkMeta {
                schema_id,
                extra: opts.schema_extra,
            }),
            sparse_extents: None,
        });
        Ok(())
    }

    /// Emits a `FLAG_TOMBSTONE` deletion entry in the delta run, hiding `path` from older runs.
    pub fn delete(&mut self, path: &str) -> Result<(), VzError> {
        let (parent_path, basename) = split_archive_path(path)?;
        if !self.seen_paths.insert((parent_path.clone(), basename.clone())) {
            return Err(VzError::AlreadyExists);
        }
        let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
        let name_hash = self.hasher.hash(basename.as_bytes())?;
        let entry_id = self.next_entry_id;
        self.next_entry_id += 1;

        self.entries.push(StagedEntry {
            parent_path,
            basename,
            parent_hash,
            name_hash,
            payload: DirPayload::Inline {
                bytes: [0u8; 27],
                len: 0,
            },
            entry_id,
            mtime_ns: 0,
            posix_mode: KIND_REG | 0o644,
            owner_idx: 0,
            flags_and_codec: CODEC_NONE | FLAG_INLINE_DATA | FLAG_TOMBSTONE,
            ext_time: None,
            ext_owner: None,
            xattrs: Vec::new(),
            ext_codec: None,
            schema_link: None,
            sparse_extents: None,
        });
        Ok(())
    }

    /// Finalizes the delta run, writes `TAG_LSM_RUNS`, commits the new `BootHeader` slot,
    /// and updates Boot Block ECC.
    pub fn finish(mut self) -> Result<F, VzError> {
        self.emitter.flush_pending_data_cluster()?;

        // Compute exact live total_entries delta before modifying Boot Block.
        let base_reader = VzReader::open_with_options(
            &self.emitter.writer,
            VzReaderOptions {
                encryption: self.encryption_key.clone(),
                repair_boot_ecc: true,
            },
        )?;
        let mut delta_count = 0i64;
        for e in &self.entries {
            let full = if e.parent_path == "/" {
                format!("/{}", e.basename)
            } else {
                format!("{}/{}", e.parent_path, e.basename)
            };
            let was_live = matches!(
                base_reader.resolve_raw_for_append(&full)?,
                Some(ref r) if !r.dir_entry.is_tombstone()
            );
            let is_tomb = (e.flags_and_codec & FLAG_TOMBSTONE) != 0;
            if was_live && is_tomb {
                delta_count -= 1;
            } else if !was_live && !is_tomb {
                delta_count += 1;
            }
        }
        drop(base_reader);

        mark_hash_collisions(&mut self.entries);
        self.entries.sort_by(|a, b| {
            key128_cmp(a.parent_hash, a.name_hash, b.parent_hash, b.name_hash)
                .then_with(|| a.parent_path.cmp(&b.parent_path))
                .then_with(|| a.basename.cmp(&b.basename))
        });

        let boot_size = self.active_slot.boot_block_size as usize;
        let ecc_active =
            (self.active_slot.compat_flags & COMPAT_BOOT_ECC) != 0 && boot_size == DEFAULT_BOOT_SIZE;
        let boot_limit = if ecc_active {
            BOOT_ECC_DESC_OFF
        } else {
            boot_size
        };

        // Pre-calculate registry size including the new run entry so root_node_offset stays exact.
        let mut all_runs = self.prev_runs;
        let new_run_placeholder = LsmRunDesc {
            run_generation: self.new_generation,
            root_offset: 0,
            root_entry_count: 0,
            tree_height: 0,
            root_is_cluster: false,
        };
        all_runs.push(new_run_placeholder);

        let registry_bytes = build_registry_bytes(
            &self.owners,
            &self.dicts,
            &self.schemas,
            self.cipher_hdr.as_ref(),
            Some(&all_runs),
        )?;
        let registry_offset = 0x0080usize;
        let root_node_offset = align_up_64(registry_offset + registry_bytes.len());
        if root_node_offset > boot_limit {
            return Err(VzError::BufferTooSmall);
        }
        let available_boot = boot_limit - root_node_offset;

        let tree_built = build_btree_index(
            &self.entries,
            self.max_leaf_entries,
            self.max_route_entries,
            available_boot,
            &mut self.emitter,
        )?;
        self.emitter.flush_parity_stripe()?;

        let last_idx = all_runs.len() - 1;
        all_runs[last_idx].root_offset = root_node_offset as u64;
        all_runs[last_idx].root_entry_count = tree_built.root_entry_count;
        all_runs[last_idx].tree_height = tree_built.tree_height;
        all_runs[last_idx].root_is_cluster = false;

        let final_registry = build_registry_bytes(
            &self.owners,
            &self.dicts,
            &self.schemas,
            self.cipher_hdr.as_ref(),
            Some(&all_runs),
        )?;
        if final_registry.len() != registry_bytes.len() {
            return Err(VzError::BadFormat);
        }

        let new_total = ((self.active_slot.total_entries as i64) + delta_count).max(0) as u64;
        let lsm_run_count = u16::try_from(all_runs.len()).map_err(|_| VzError::ValueOverflow)?;
        let ro_compat_flags = if lsm_run_count > 1 {
            self.active_slot.ro_compat_flags | RO_COMPAT_LSM_RUNS
        } else {
            self.active_slot.ro_compat_flags
        };

        let slot = HeaderSlot {
            magic: MAGIC_HEADER,
            generation: 0,
            boot_block_size: self.active_slot.boot_block_size,
            compat_flags: self.active_slot.compat_flags,
            ro_compat_flags,
            incompat_flags: self.active_slot.incompat_flags,
            tree_height: tree_built.tree_height,
            hash_algo: self.active_slot.hash_algo,
            lsm_run_count,
            registry_offset: registry_offset as u16,
            registry_size: final_registry.len() as u32,
            root_node_offset: root_node_offset as u32,
            total_entries: new_total,
            root_fallback_off: 0,
            root_entry_count: tree_built.root_entry_count,
            header_crc32c: 0,
        };

        let mut boot_block = vec![0u8; boot_size];
        self.boot_hdr.commit(&slot);
        self.boot_hdr
            .write_bytes(&mut boot_block[..BootHeader::SIZE])?;
        boot_block[registry_offset..registry_offset + final_registry.len()]
            .copy_from_slice(&final_registry);
        boot_block[root_node_offset..root_node_offset + tree_built.root_bytes.len()]
            .copy_from_slice(&tree_built.root_bytes);

        if ecc_active {
            boot_ecc_encode(&mut boot_block)?;
        }

        let mut writer = self.emitter.writer;
        writer.seek(SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
        writer
            .write_all(&boot_block)
            .map_err(|_| VzError::IoError)?;
        writer.flush().map_err(|_| VzError::IoError)?;
        Ok(writer)
    }
}

/// Controls [`compact_archive_with_options`] compaction behavior.
#[derive(Debug, Clone)]
pub struct CompactOptions {
    /// Override Boot Block ECC (`None` inherits source `COMPAT_BOOT_ECC` setting).
    pub enable_boot_ecc: Option<bool>,
    /// Target cluster payload grouping size (`None` defaults to `1 MiB`).
    pub target_cluster_size: Option<usize>,
    /// Maximum entries per B+Tree leaf (`None` defaults to `512`).
    pub max_leaf_entries: Option<usize>,
    /// Maximum child routes per B+Tree internal node (`None` defaults to `128`).
    pub max_route_entries: Option<usize>,
    /// Optional Reed-Solomon `GF(2^8)` stripe parameters `(K, M)` on the compacted archive.
    pub rs_parity: Option<(u16, u16)>,
    /// Optional new encryption key (when `None` and source is encrypted, re-tags using source CEK).
    pub encryption: Option<EncryptionKey>,
    /// When `None` (default), compacts **without decompressing or re-encoding** payloads
    /// (preserving every entry's original codec and dictionary). Set `Some(codec)` to re-encode.
    pub reencode_codec: Option<u8>,
    /// Zstd compression level used only when `reencode_codec == Some(CODEC_ZSTD)` (default `3`).
    pub zstd_level: i32,
}

impl Default for CompactOptions {
    fn default() -> Self {
        Self {
            enable_boot_ecc: None,
            target_cluster_size: None,
            max_leaf_entries: None,
            max_route_entries: None,
            rs_parity: None,
            encryption: None,
            reencode_codec: None,
            zstd_level: 3,
        }
    }
}

/// Compacts a multi-run (or fragmented) `.vz` archive into a fresh single-run (`lsm_run_count == 1`)
/// archive without decompressing or re-encoding live file payloads.
///
/// Strips all LSM overlay runs back to 1, permanently removes tombstoned and shadowed entries,
/// deduplicates hardlinks, preserves hardlinks/xattrs/sparse extents/schemas/dictionaries/ext-times,
/// and writes a fresh single-run Boot Block + B+Tree index.
pub fn compact_archive<R: RangeReader, W: Write + Seek>(
    reader: &VzReader<R>,
    writer: W,
    config: VzWriterConfig,
) -> Result<W, VzError> {
    let opts = CompactOptions {
        enable_boot_ecc: Some(config.enable_boot_ecc),
        target_cluster_size: Some(config.target_cluster_size),
        max_leaf_entries: Some(config.max_leaf_entries),
        max_route_entries: Some(config.max_route_entries),
        rs_parity: config.rs_parity,
        encryption: config.encryption,
        reencode_codec: None,
        zstd_level: config.zstd_level,
    };
    compact_archive_with_options(reader, writer, opts)
}

/// Compacts `reader` into `writer` with explicit [`CompactOptions`].
///
/// By default (`reencode_codec == None`), copies already-compressed/encoded payloads directly
/// without decompressing or re-compressing.
pub fn compact_archive_with_options<R: RangeReader, W: Write + Seek>(
    reader: &VzReader<R>,
    mut writer: W,
    options: CompactOptions,
) -> Result<W, VzError> {
    if let Some(new_codec) = options.reencode_codec {
        let mut cfg = VzWriterConfig {
            enable_boot_ecc: options
                .enable_boot_ecc
                .unwrap_or((reader.active_slot().compat_flags & COMPAT_BOOT_ECC) != 0),
            default_codec: new_codec,
            zstd_level: options.zstd_level,
            target_cluster_size: options.target_cluster_size.unwrap_or(1024 * 1024),
            max_leaf_entries: options.max_leaf_entries.unwrap_or(512),
            max_route_entries: options.max_route_entries.unwrap_or(128),
            rs_parity: options.rs_parity,
            encryption: options.encryption,
            ..Default::default()
        };
        return compact_reencode_inner(reader, writer, &mut cfg);
    }

    let src_slot = reader.active_slot();
    let boot_size = src_slot.boot_block_size as usize;
    let ecc_active = options
        .enable_boot_ecc
        .unwrap_or((src_slot.compat_flags & COMPAT_BOOT_ECC) != 0)
        && boot_size == DEFAULT_BOOT_SIZE;
    let boot_limit = if ecc_active {
        BOOT_ECC_DESC_OFF
    } else {
        boot_size
    };

    let target_cluster_size = options.target_cluster_size.unwrap_or(1024 * 1024);
    let max_leaf_entries = options.max_leaf_entries.unwrap_or(512);
    let max_route_entries = options.max_route_entries.unwrap_or(128);

    // Reserve Boot Block space before streaming compacted clusters forward-only.
    writer.seek(SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
    writer
        .write_all(&vec![0u8; boot_size])
        .map_err(|_| VzError::IoError)?;

    let out_crypto: Option<(CipherHeader, CryptoContext)> = match options.encryption {
        Some(ref key) => Some(CryptoContext::create(key)?),
        None => match (reader.cipher_header(), reader.crypto_context()) {
            (Some(hdr), Some(ctx)) => Some((*hdr, ctx.clone())),
            (Some(_), None) => return Err(VzError::CryptoError),
            _ => None,
        },
    };
    // A compacted archive starts a fresh single-run BootHeader whose initial committed slot is gen=1.
    let target_generation = 1u64;

    let mut emitter = ClusterEmitter::new(
        writer,
        boot_size as u64,
        0,
        0,
        target_cluster_size,
        options.rs_parity,
    )?;

    let owners = reader.owners().to_vec();
    let dicts = reader.dicts().to_vec();
    let schemas = reader.schemas().to_vec();
    let hasher = AlgoHasher::new(src_slot.hash_algo)?;

    let mut live = reader.list_all_live()?;
    live.sort_by(|a, b| {
        a.stat
            .parent_path
            .cmp(&b.stat.parent_path)
            .then_with(|| a.stat.name.cmp(&b.stat.name))
    });

    // Deduplicate identical hardlink payloads by (entry_id, data_offset, in_cluster_offset).
    let mut copied_payloads: HashMap<(u64, u64, u32), DirPayload> = HashMap::new();
    let mut staged: Vec<StagedEntry> = Vec::with_capacity(live.len());

    for entry in live {
        let de = entry.dir_entry;
        let flags_clean = de.flags_and_codec & !(FLAG_HASH_COLLISION | FLAG_TOMBSTONE);
        let parent_hash = if !entry.stat.parent_path.is_empty() {
            hasher.hash(entry.stat.parent_path.as_bytes())?
        } else {
            de.parent_hash
        };
        let name_hash = if !entry.stat.name.is_empty() {
            hasher.hash(entry.stat.name.as_bytes())?
        } else {
            de.name_hash
        };

        let new_payload = match de.payload {
            DirPayload::Inline { bytes, len } => DirPayload::Inline { bytes, len },
            DirPayload::Ref {
                data_offset,
                stored_size,
                raw_size,
                in_cluster_offset,
            } => {
                if de.is_sparse() && stored_size == 0 {
                    DirPayload::Ref {
                        data_offset: 0,
                        stored_size: 0,
                        raw_size,
                        in_cluster_offset: 0,
                    }
                } else {
                    let dedup_key = (entry.stat.entry_id, data_offset, in_cluster_offset);
                    if let Some(&existing) = copied_payloads.get(&dedup_key) {
                        existing
                    } else if de.is_multi_cluster() {
                        let extents = reader.read_chunk_table_at(data_offset, in_cluster_offset)?;
                        let mut new_extents = Vec::with_capacity(extents.len());
                        let mut total_stored = 0u64;
                        for ext in extents {
                            let slen = usize::try_from(ext.stored_size)
                                .map_err(|_| VzError::ValueOverflow)?;
                            let compressed_bytes = if reader.crypto_context().is_some() {
                                reader.read_encrypted_cluster_chunk(
                                    ext.cluster_offset,
                                    ext.in_cluster_offset,
                                    slen,
                                    entry.run_generation,
                                    entry.stat.entry_id,
                                )?
                            } else {
                                let src_off = ext
                                    .cluster_offset
                                    .checked_add(ext.in_cluster_offset as u64)
                                    .ok_or(VzError::ValueOverflow)?;
                                reader.read_raw_stored_bytes(src_off, slen)?
                            };
                            emitter.flush_pending_data_cluster()?;
                            let seq = emitter.cluster_seq;
                            let out_stored = match &out_crypto {
                                Some((_, ctx)) => ctx.encrypt_payload(
                                    target_generation,
                                    seq,
                                    entry.stat.entry_id,
                                    &compressed_bytes,
                                )?,
                                None => compressed_bytes,
                            };
                            let out_slen = out_stored.len() as u64;
                            let (coff, ioff, actual_seq) = emitter.emit_dedicated_data_cluster(
                                entry.stat.entry_id,
                                ext.raw_size,
                                &out_stored,
                                None,
                            )?;
                            if actual_seq != seq {
                                return Err(VzError::BadFormat);
                            }
                            total_stored = total_stored
                                .checked_add(out_slen)
                                .ok_or(VzError::ValueOverflow)?;
                            new_extents.push(ChunkExtent {
                                cluster_offset: coff,
                                in_cluster_offset: ioff,
                                stored_size: out_slen,
                                raw_size: ext.raw_size,
                            });
                        }
                        let (t_off, t_ioff) = emitter.emit_chunk_table_cluster(&new_extents)?;
                        let p = DirPayload::Ref {
                            data_offset: t_off,
                            stored_size: total_stored,
                            raw_size,
                            in_cluster_offset: t_ioff,
                        };
                        copied_payloads.insert(dedup_key, p);
                        p
                    } else {
                        let slen =
                            usize::try_from(stored_size).map_err(|_| VzError::ValueOverflow)?;
                        let logical_or_packed_raw = if de.is_sparse() {
                            entry
                                .sparse_extents
                                .as_deref()
                                .map(|exs| exs.iter().map(|x| x.length).sum())
                                .unwrap_or(raw_size)
                        } else {
                            raw_size
                        };
                        let compressed_bytes = if reader.crypto_context().is_some() {
                            reader.read_encrypted_cluster_chunk(
                                data_offset,
                                in_cluster_offset,
                                slen,
                                entry.run_generation,
                                entry.stat.entry_id,
                            )?
                        } else {
                            let src_off = data_offset
                                .checked_add(in_cluster_offset as u64)
                                .ok_or(VzError::ValueOverflow)?;
                            reader.read_raw_stored_bytes(src_off, slen)?
                        };
                        let est_add = 16 + DataManifestHeader::SIZE + 64 + compressed_bytes.len() + 40;
                        if !emitter.pending_body.is_empty()
                            && emitter.pending_body.len() + est_add > emitter.target_cluster_size
                        {
                            emitter.flush_pending_data_cluster()?;
                        }
                        let seq = emitter.cluster_seq;
                        let out_stored = match &out_crypto {
                            Some((_, ctx)) => ctx.encrypt_payload(
                                target_generation,
                                seq,
                                entry.stat.entry_id,
                                &compressed_bytes,
                            )?,
                            None => compressed_bytes,
                        };
                        let out_slen = out_stored.len() as u64;
                        let (coff, ioff, actual_seq) = emitter.append_data_payload(
                            entry.stat.entry_id,
                            logical_or_packed_raw,
                            &out_stored,
                            None,
                        )?;
                        if actual_seq != seq {
                            return Err(VzError::BadFormat);
                        }
                        let p = DirPayload::Ref {
                            data_offset: coff,
                            stored_size: out_slen,
                            raw_size,
                            in_cluster_offset: ioff,
                        };
                        copied_payloads.insert(dedup_key, p);
                        p
                    }
                }
            }
        };

        let (owner_idx, ext_owner) = if de.owner_idx < 255 && (de.owner_idx as usize) < owners.len()
        {
            (de.owner_idx, None)
        } else {
            (255, entry.stat.owner.clone())
        };
        let schema_link = entry.stat.schema_id.map(|schema_id| SchemaLinkMeta {
            schema_id,
            extra: entry.schema_extra,
        });

        staged.push(StagedEntry {
            parent_path: entry.stat.parent_path,
            basename: entry.stat.name,
            parent_hash,
            name_hash,
            payload: new_payload,
            entry_id: entry.stat.entry_id,
            mtime_ns: entry.stat.mtime_ns,
            posix_mode: (entry.stat.kind & KIND_MASK) | (entry.stat.mode & 0x0FFF),
            owner_idx,
            flags_and_codec: flags_clean,
            ext_time: entry.stat.ext_time,
            ext_owner,
            xattrs: entry.stat.xattrs,
            ext_codec: entry.ext_codec,
            schema_link,
            sparse_extents: entry.sparse_extents,
        });
    }

    emitter.flush_pending_data_cluster()?;
    mark_hash_collisions(&mut staged);
    staged.sort_by(|a, b| {
        key128_cmp(a.parent_hash, a.name_hash, b.parent_hash, b.name_hash)
            .then_with(|| a.parent_path.cmp(&b.parent_path))
            .then_with(|| a.basename.cmp(&b.basename))
    });

    let total_entries = staged.len() as u64;
    let registry_bytes = build_registry_bytes(
        &owners,
        &dicts,
        &schemas,
        out_crypto.as_ref().map(|(h, _)| h),
        None,
    )?;
    let registry_offset = 0x0080usize;
    let root_node_offset = align_up_64(registry_offset + registry_bytes.len());
    if root_node_offset > boot_limit {
        return Err(VzError::BufferTooSmall);
    }
    let available_boot = boot_limit - root_node_offset;

    let tree_built = build_btree_index(
        &staged,
        max_leaf_entries,
        max_route_entries,
        available_boot,
        &mut emitter,
    )?;
    emitter.flush_parity_stripe()?;

    let mut compat_flags = src_slot.compat_flags & !COMPAT_BOOT_ECC;
    if ecc_active {
        compat_flags |= COMPAT_BOOT_ECC;
    }
    let mut ro_compat_flags = 0u16;
    if options.rs_parity.is_some() {
        ro_compat_flags |= RO_COMPAT_STREAM_ECC;
    }
    let mut incompat_flags = 0u16;
    if out_crypto.is_some() {
        incompat_flags |= INCOMPAT_ENCRYPTED;
    }
    if boot_size > DEFAULT_BOOT_SIZE {
        incompat_flags |= INCOMPAT_BIG_BOOT;
    }

    let slot = HeaderSlot {
        magic: MAGIC_HEADER,
        generation: target_generation,
        boot_block_size: boot_size as u32,
        compat_flags,
        ro_compat_flags,
        incompat_flags,
        tree_height: tree_built.tree_height,
        hash_algo: src_slot.hash_algo,
        lsm_run_count: 1,
        registry_offset: registry_offset as u16,
        registry_size: registry_bytes.len() as u32,
        root_node_offset: root_node_offset as u32,
        total_entries,
        root_fallback_off: 0,
        root_entry_count: tree_built.root_entry_count,
        header_crc32c: 0,
    };

    let mut boot_block = vec![0u8; boot_size];
    let mut boot_hdr = BootHeader {
        slot_a: slot,
        slot_b: HeaderSlot::from_bytes(&[0u8; 64])?,
    };
    boot_hdr.commit(&slot);
    boot_hdr.write_bytes(&mut boot_block[..BootHeader::SIZE])?;
    boot_block[registry_offset..registry_offset + registry_bytes.len()]
        .copy_from_slice(&registry_bytes);
    boot_block[root_node_offset..root_node_offset + tree_built.root_bytes.len()]
        .copy_from_slice(&tree_built.root_bytes);
    if ecc_active {
        boot_ecc_encode(&mut boot_block)?;
    }

    let mut out_writer = emitter.writer;
    out_writer.seek(SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
    out_writer.write_all(&boot_block).map_err(|_| VzError::IoError)?;
    out_writer.flush().map_err(|_| VzError::IoError)?;
    Ok(out_writer)
}

fn compact_reencode_inner<R: RangeReader, W: Write + Seek>(
    reader: &VzReader<R>,
    writer: W,
    config: &mut VzWriterConfig,
) -> Result<W, VzError> {
    config.hash_algo = reader.active_slot().hash_algo;
    if config.dicts.is_empty() {
        config.dicts = reader.dicts().to_vec();
    }
    if config.schemas.is_empty() {
        config.schemas = reader.schemas().to_vec();
    }
    if config.owners.is_empty() {
        config.owners = reader.owners().to_vec();
    }

    let mut live = reader.list_all_live()?;
    live.sort_by(|a, b| {
        let a_dir = (a.stat.kind & KIND_MASK) == KIND_DIR;
        let b_dir = (b.stat.kind & KIND_MASK) == KIND_DIR;
        b_dir
            .cmp(&a_dir)
            .then_with(|| a.stat.parent_path.cmp(&b.stat.parent_path))
            .then_with(|| a.stat.name.cmp(&b.stat.name))
    });

    let mut vz_writer = VzWriter::new(writer, config.clone())?;
    let mut hardlink_first_idx: HashMap<u64, usize> = HashMap::new();

    for entry in live {
        let full_path = if entry.stat.parent_path == "/" || entry.stat.parent_path.is_empty() {
            format!("/{}", entry.stat.name)
        } else {
            format!("{}/{}", entry.stat.parent_path, entry.stat.name)
        };
        let is_special = matches!(
            entry.stat.kind & KIND_MASK,
            KIND_DIR | crate::wire::KIND_FIFO | crate::wire::KIND_CHR | crate::wire::KIND_BLK | crate::wire::KIND_SOCK
        );

        let orig_parent_hash = entry.dir_entry.parent_hash;
        let orig_name_hash = entry.dir_entry.name_hash;

        if !is_special && let Some(&target_idx) = hardlink_first_idx.get(&entry.stat.entry_id) {
            let target = vz_writer.entries[target_idx].clone();
            let (owner_idx, ext_owner) = vz_writer.register_owner(entry.stat.owner.clone());
            vz_writer.entries.push(StagedEntry {
                parent_path: entry.stat.parent_path,
                basename: entry.stat.name,
                parent_hash: orig_parent_hash,
                name_hash: orig_name_hash,
                payload: target.payload,
                entry_id: target.entry_id,
                mtime_ns: entry.stat.mtime_ns,
                posix_mode: (entry.stat.kind & KIND_MASK) | (entry.stat.mode & 0x0FFF),
                owner_idx,
                flags_and_codec: target.flags_and_codec & !FLAG_HASH_COLLISION,
                ext_time: entry.stat.ext_time,
                ext_owner,
                xattrs: entry.stat.xattrs,
                ext_codec: target.ext_codec,
                schema_link: entry.stat.schema_id.map(|schema_id| SchemaLinkMeta {
                    schema_id,
                    extra: entry.schema_extra,
                }),
                sparse_extents: target.sparse_extents,
            });
            continue;
        }

        // Prevent duplicate empty-parent fallback collisions in seen_paths by deduplicating
        // using a unique internal synthetic path when `parent_path` wasn't recorded.
        let stage_path = if entry.stat.parent_path.is_empty() {
            format!("/__implicit_{:016x}/{}", orig_parent_hash, entry.stat.name)
        } else {
            full_path
        };

        let opts = EntryOptions {
            kind: entry.stat.kind,
            mode: entry.stat.mode,
            mtime_ns: entry.stat.mtime_ns,
            ext_time: entry.stat.ext_time,
            owner: entry.stat.owner.clone(),
            xattrs: entry.stat.xattrs.clone(),
            codec: Some(config.default_codec),
            dict_id: entry.ext_codec.as_ref().map(|c| c.dict_id),
            entry_id: Some(entry.stat.entry_id),
            schema_id: entry.stat.schema_id,
            schema_extra: entry.schema_extra.clone(),
            col_stats: None,
            sparse: None,
        };

        let staged_idx = vz_writer.entries.len();
        if is_special {
            vz_writer.add_file_with_options(&stage_path, &[], opts)?;
        } else if entry.stat.is_sparse {
            let full_bytes = reader.read_resolved_payload(&entry)?;
            let exts = entry.sparse_extents.unwrap_or_default();
            let mut slices: Vec<(u64, &[u8])> = Vec::with_capacity(exts.len());
            for ext in &exts {
                let s = ext.logical_offset as usize;
                let e = s + ext.length as usize;
                slices.push((ext.logical_offset, &full_bytes[s..e]));
            }
            vz_writer.add_sparse_file(&stage_path, entry.stat.size, &slices, opts)?;
        } else {
            let data = reader.read_resolved_payload(&entry)?;
            vz_writer.add_file_with_options(&stage_path, &data, opts)?;
        }

        if let Some(staged_entry) = vz_writer.entries.get_mut(staged_idx) {
            if entry.stat.parent_path.is_empty() {
                staged_entry.parent_path.clear();
                staged_entry.parent_hash = orig_parent_hash;
                staged_entry.name_hash = orig_name_hash;
            }
            if !is_special {
                hardlink_first_idx.insert(entry.stat.entry_id, staged_idx);
            }
        }
    }

    vz_writer.finish()
}

