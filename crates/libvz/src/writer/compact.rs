use std::collections::HashMap;
use std::io::{Seek, SeekFrom, Write};

use super::btree_build::{
    BootCommitSpec, align_up_64, build_btree_index, build_registry_bytes, commit_boot_block,
    mark_hash_collisions,
};
use super::emitter::{ClusterEmitter, StagedEntry};
use super::{EntryOptions, VzWriter, VzWriterConfig};
use crate::btree::key128_cmp;
use crate::codec::{CryptoContext, EncryptionKey};
use crate::error::VzError;
use crate::ext_meta::{ChunkExtent, CipherHeader, DataManifestHeader, SchemaLinkMeta};
use crate::hash::{AlgoHasher, PathHasher};
use crate::io::RangeReader;
use crate::reader::VzReader;
use crate::wire::{
    BOOT_ECC_DESC_OFF, BootHeader, COMPAT_BOOT_ECC, DEFAULT_BOOT_SIZE, DirPayload,
    FLAG_HASH_COLLISION, FLAG_TOMBSTONE, HeaderSlot, INCOMPAT_BIG_BOOT, INCOMPAT_ENCRYPTED,
    KIND_DIR, KIND_MASK, RO_COMPAT_STREAM_ECC,
};

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
            extra_ext_tlvs: entry.extra_ext_tlvs.clone(),
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
        reader.extra_registry_tlvs(),
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

    let mut out_writer = emitter.writer;
    let mut boot_hdr = BootHeader {
        slot_a: HeaderSlot::from_bytes(&[0u8; 64])?,
        slot_b: HeaderSlot::from_bytes(&[0u8; 64])?,
    };
    commit_boot_block(
        &mut out_writer,
        &mut boot_hdr,
        boot_size,
        ecc_active,
        BootCommitSpec {
            compat_flags,
            ro_compat_flags,
            incompat_flags,
            tree_height: tree_built.tree_height,
            hash_algo: src_slot.hash_algo,
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
    if config.extra_registry_tlvs.is_empty() {
        config.extra_registry_tlvs = reader.extra_registry_tlvs().to_vec();
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
                extra_ext_tlvs: entry.extra_ext_tlvs.clone(),
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
            extra_ext_tlvs: entry.extra_ext_tlvs.clone(),
        };

        let staged_idx = vz_writer.entries.len();
        if is_special {
            vz_writer.add_file_with_options(&stage_path, &[], opts)?;
        } else if entry.stat.is_sparse {
            let full_bytes = reader.read_resolved_payload(&entry)?;
            let exts = entry.sparse_extents.unwrap_or_default();
            let mut slices: Vec<(u64, &[u8])> = Vec::with_capacity(exts.len());
            for ext in &exts {
                let s = usize::try_from(ext.logical_offset).map_err(|_| VzError::ValueOverflow)?;
                let len = usize::try_from(ext.length).map_err(|_| VzError::ValueOverflow)?;
                let e = s.checked_add(len).ok_or(VzError::ValueOverflow)?;
                let slice = full_bytes.get(s..e).ok_or(VzError::BadFormat)?;
                slices.push((ext.logical_offset, slice));
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

