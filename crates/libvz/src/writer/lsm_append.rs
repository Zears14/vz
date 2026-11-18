use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};

use super::btree_build::{
    BootCommitSpec, align_up_64, build_btree_index, build_registry_bytes, commit_boot_block,
    mark_hash_collisions, serialize_dir_node_tlv,
};
use super::emitter::{ClusterEmitter, StagedEntry};
use super::EntryOptions;
use crate::btree::{LeafNodeView, key128_cmp};
use crate::codec::{CryptoContext, EncryptionKey, compress_payload};
use crate::error::VzError;
use crate::ext_meta::{
    DataManifestHeader, DictEntry, ExtCodecMeta, LsmRunDesc, OwnerEntry, RawTlv, SchemaEntry,
    SchemaLinkMeta, split_archive_path,
};
use crate::hash::{AlgoHasher, PathHasher};
use crate::io::RangeReader;
use crate::reader::{VzReader, VzReaderOptions};
use crate::wire::{
    BOOT_ECC_DESC_OFF, BootHeader, CODEC_EXT, CODEC_MASK, CODEC_NONE, COMPAT_BOOT_ECC,
    ClusterFooter, ClusterHeader, DEFAULT_BOOT_SIZE, DirPayload, EXT_CODEC_ZSTD_DICT,
    FLAG_HASH_COLLISION, FLAG_INLINE_DATA, FLAG_INODE_64, FLAG_TOMBSTONE, HeaderSlot, KIND_DIR,
    KIND_MASK, KIND_REG, MAGIC_FOOTER, RO_COMPAT_LSM_RUNS, RouteEntry, TREE_HEIGHT_PIPE,
};

// ============================================================================
// LSM INCREMENTAL APPEND WRITER & COMPACTION
// ============================================================================

pub(super) fn find_tail_cluster_info<R: RangeReader>(
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
    extra_registry_tlvs: Vec<RawTlv>,
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
            extra_registry_tlvs,
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
            let extra_registry_tlvs = reader.extra_registry_tlvs().to_vec();
            let cipher_hdr = reader.cipher_header().copied();
            let crypto = reader.crypto_context().cloned();
            let next_entry_id = reader.max_entry_id()?.saturating_add(1).max(1);
            (
                active_slot,
                prev_runs,
                owners,
                dicts,
                schemas,
                extra_registry_tlvs,
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
            extra_registry_tlvs,
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
                extra_ext_tlvs: target.extra_ext_tlvs,
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
            extra_ext_tlvs: opts.extra_ext_tlvs,
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
            extra_ext_tlvs: Vec::new(),
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
            &self.extra_registry_tlvs,
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
            &self.extra_registry_tlvs,
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

        let mut writer = self.emitter.writer;
        commit_boot_block(
            &mut writer,
            &mut self.boot_hdr,
            boot_size,
            ecc_active,
            BootCommitSpec {
                compat_flags: self.active_slot.compat_flags,
                ro_compat_flags,
                incompat_flags: self.active_slot.incompat_flags,
                tree_height: tree_built.tree_height,
                hash_algo: self.active_slot.hash_algo,
                lsm_run_count,
                registry_offset,
                registry_bytes: &final_registry,
                root_node_offset,
                root_bytes: &tree_built.root_bytes,
                root_entry_count: tree_built.root_entry_count,
                total_entries: new_total,
                root_fallback_off: 0,
            },
        )?;
        Ok(writer)
    }
}

