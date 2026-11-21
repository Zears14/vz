use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom, Write};

use super::btree_build::{
    align_up_64, build_btree_index, build_registry_bytes, sort_and_mark_hash_collisions,
};
use super::emitter::{ClusterEmitter, StagedEntry};
use super::{EntryOptions, VzWriterConfig};
use crate::codec::{CryptoContext, ZstdDictCache, compress_payload_with_cache};
use crate::crc::crc32c;
use crate::ecc::boot_ecc_encode;
use crate::error::VzError;
use crate::ext_meta::{
    ChunkExtent, DataManifestHeader, ExtCodecMeta, RootFallback, SchemaLinkMeta,
    encode_root_fallback, push_tlv, split_archive_path,
};
use crate::hash::{AlgoHasher, PathHasher};
use crate::wire::{
    BOOT_ECC_DESC_OFF, BootHeader, CODEC_EXT, CODEC_MASK, CODEC_NONE, COMPAT_BOOT_ECC,
    COMPAT_COL_STATS, DEFAULT_BOOT_SIZE, DirPayload, EXT_CODEC_ZSTD_DICT, FLAG_INLINE_DATA,
    FLAG_INODE_64, FLAG_MULTI_CLUSTER, HeaderSlot, INCOMPAT_BIG_BOOT, INCOMPAT_ENCRYPTED,
    KIND_DIR, KIND_MASK, MAGIC_HEADER, RO_COMPAT_STREAM_ECC, TAG_ROOT_FALLBACK, TREE_HEIGHT_PIPE,
};

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
            &config.extra_registry_tlvs,
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
            self.emitter.ensure_pending_capacity(est_add)?;
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
            extra_ext_tlvs: opts.extra_ext_tlvs,
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
            extra_ext_tlvs: opts.extra_ext_tlvs,
        });
        Ok(())
    }

    /// Finishes the forward-only stream by writing B+Tree index clusters and trailing
    /// `TAG_ROOT_FALLBACK` cluster at EOF.
    pub fn finish(mut self) -> Result<(W, PipeFinalizeInfo), VzError> {
        self.emitter.flush_pending_data_cluster()?;
        sort_and_mark_hash_collisions(&mut self.entries);

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

