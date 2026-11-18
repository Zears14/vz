mod btree_build;
mod compact;
mod emitter;
mod lsm_append;
mod pipe;

pub use compact::{CompactOptions, compact_archive, compact_archive_with_options};
pub use lsm_append::LsmAppendWriter;
pub use pipe::{PipeFinalizeInfo, VzPipeWriter, finalize_pipe_archive};

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};

use btree_build::{
    BootCommitSpec, align_up_64, build_btree_index, build_registry_bytes, commit_boot_block,
    mark_hash_collisions,
};
use emitter::{ClusterEmitter, StagedEntry};
use crate::btree::key128_cmp;
use crate::codec::{CryptoContext, EncryptionKey, ZstdDictCache, compress_payload_with_cache};
use crate::error::VzError;
use crate::ext_meta::{
    ChunkExtent, ColChunkStats, DataManifestHeader, DictEntry, ExtCodecMeta, OwnerEntry, RawTlv,
    SchemaEntry, SchemaLinkMeta, SparseExtent, Xattr, split_archive_path,
};
use crate::hash::{AlgoHasher, PathHasher};
use crate::wire::{
    BOOT_ECC_DESC_OFF, BootHeader, CODEC_EXT, CODEC_MASK, CODEC_NONE, COMPAT_BOOT_ECC,
    COMPAT_COL_STATS, DEFAULT_BOOT_SIZE, DirPayload, EXT_CODEC_ZSTD_DICT, ExtTime,
    FLAG_HASH_COLLISION, FLAG_INLINE_DATA, FLAG_INODE_64, FLAG_MULTI_CLUSTER, FLAG_SPARSE,
    FLAG_TOMBSTONE, HASH_ALGO_BUILTIN, HeaderSlot, INCOMPAT_BIG_BOOT, INCOMPAT_ENCRYPTED,
    KIND_DIR, KIND_MASK, KIND_REG, RO_COMPAT_STREAM_ECC,
};

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
    /// Optional custom / downstream Global Registry TLVs (e.g. `TAG_VENDOR_EXT`).
    pub extra_registry_tlvs: Vec<RawTlv>,
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
            extra_registry_tlvs: Vec::new(),
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
    /// Optional custom / downstream per-entry `ExtMetaPool` TLVs (e.g. `TAG_VENDOR_EXT`).
    pub extra_ext_tlvs: Vec<RawTlv>,
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
            extra_ext_tlvs: Vec::new(),
        }
    }
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
            extra_ext_tlvs: target.extra_ext_tlvs,
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
            extra_ext_tlvs: sf.opts.extra_ext_tlvs,
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
            extra_ext_tlvs: opts.extra_ext_tlvs,
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
            &self.config.extra_registry_tlvs,
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

        let mut boot_hdr = BootHeader {
            slot_a: HeaderSlot::from_bytes(&[0u8; 64])?,
            slot_b: HeaderSlot::from_bytes(&[0u8; 64])?,
        };
        let mut writer = self.emitter.writer;
        commit_boot_block(
            &mut writer,
            &mut boot_hdr,
            boot_size,
            ecc_active,
            BootCommitSpec {
                compat_flags,
                ro_compat_flags,
                incompat_flags,
                tree_height: tree_built.tree_height,
                hash_algo: self.hasher.algo_id(),
                lsm_run_count: 1,
                registry_offset,
                registry_bytes: &registry_bytes,
                root_node_offset,
                root_bytes: &tree_built.root_bytes,
                root_entry_count: tree_built.root_entry_count,
                total_entries,
                root_fallback_off: 0,
            },
        )?;
        Ok(writer)
    }
}

