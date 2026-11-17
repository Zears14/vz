use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, RwLock};

use crate::btree::{LeafNodeView, RouteTableView, validate_cluster};
use crate::codec::{
    CryptoContext, EncryptionKey, ZstdDictCache, decompress_payload_into,
};
use crate::crc::crc32c;
use crate::ecc::boot_ecc_verify_and_repair;
use crate::error::VzError;
use crate::ext_meta::{
    ChunkExtent, CipherHeader, ColumnMeta, DataManifestHeader, DictEntry, ExtCodecMeta, LsmRunDesc,
    OwnerEntry, SchemaEntry, SparseExtent, TensorMeta, Xattr, decode_chunk_table,
    decode_dict_table, decode_ext_codec, decode_ext_owner, decode_lsm_runs, decode_owner_table,
    decode_root_fallback, decode_schema_link, decode_schema_table, decode_sparse_extents,
    decode_xattr_list, normalize_dir_path, split_archive_path, split_archive_path_borrowed,
};
use crate::hash::{AlgoHasher, PathHasher};
use crate::io::RangeReader;
use crate::rs::{encode_rs_gf256_stripe, parse_parity_cluster_body, recover_rs_gf256_stripe};
use crate::wire::{
    BootHeader, COMPAT_BOOT_ECC, ClusterFooter, ClusterHeader, DEFAULT_BOOT_SIZE, DirEntry,
    DirPayload, ExtTime, FLAG_INODE_64, HeaderSlot, INCOMPAT_BIG_BOOT, INCOMPAT_ENCRYPTED,
    KIND_MASK, MAGIC_CLUSTER, MAGIC_FOOTER, RO_COMPAT_LSM_RUNS, RouteEntry, TAG_CHUNK_TABLE,
    TAG_CIPHER_HEADER, TAG_DATA_MANIFEST, TAG_DICT_TABLE, TAG_DIR_NODE, TAG_EXT_CODEC,
    TAG_EXT_OWNER, TAG_EXT_TIME, TAG_LSM_RUNS, TAG_NOP, TAG_OWNER_TABLE, TAG_PARENT_PATH,
    TAG_PARITY_CLUSTER, TAG_ROOT_FALLBACK, TAG_SCHEMA_LINK, TAG_SCHEMA_TABLE, TAG_SPARSE_EXTENTS,
    TAG_XATTR_LIST, TREE_HEIGHT_PIPE, TlvIter, read_le_u32,
};

const SUPPORTED_INCOMPAT: u16 = INCOMPAT_ENCRYPTED | INCOMPAT_BIG_BOOT;

/// Options controlling [`VzReader::open_with_options`].
#[derive(Debug, Clone)]
pub struct VzReaderOptions {
    /// Optional decryption key (`INCOMPAT_ENCRYPTED`).
    pub encryption: Option<EncryptionKey>,
    /// Attempt in-memory single-page Boot ECC repair if `COMPAT_BOOT_ECC` detects damage.
    pub repair_boot_ecc: bool,
}

impl Default for VzReaderOptions {
    fn default() -> Self {
        Self {
            encryption: None,
            repair_boot_ecc: true,
        }
    }
}

/// Decoded metadata for a single directory entry returned by [`VzReader::stat`] / [`VzReader::readdir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VzStat {
    pub name: String,
    pub parent_path: String,
    pub kind: u16,
    pub mode: u16,
    pub size: u64,
    pub stored_size: u64,
    pub entry_id: u64,
    pub mtime_ns: i64,
    pub ext_time: Option<ExtTime>,
    pub owner: Option<OwnerEntry>,
    pub codec: u8,
    pub is_inline: bool,
    pub is_sparse: bool,
    pub is_multi_cluster: bool,
    pub has_hash_collision: bool,
    pub xattrs: Vec<Xattr>,
    pub schema_id: Option<u32>,
}

/// Full parsed entry details used for compaction and inspection.
#[derive(Debug, Clone)]
pub struct ResolvedEntry {
    pub stat: VzStat,
    pub dir_entry: DirEntry,
    pub run_generation: u64,
    pub ext_codec: Option<ExtCodecMeta>,
    pub sparse_extents: Option<Vec<SparseExtent>>,
    pub schema_extra: Vec<u8>,
}

/// Archive integrity verification report returned by [`verify_archive`].
#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    pub boot_ecc_repaired_page: Option<usize>,
    pub boot_ecc_ok: bool,
    pub clusters_checked: usize,
    pub parity_stripes_checked: usize,
    pub errors: Vec<String>,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.boot_ecc_ok && self.boot_ecc_repaired_page.is_none() && self.errors.is_empty()
    }
}

/// Repair summary returned by [`repair_file`] / [`repair_slice`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairReport {
    pub boot_page_repaired: Option<usize>,
    pub data_clusters_repaired: usize,
    pub parity_clusters_repaired: usize,
}

#[derive(Clone, Copy)]
struct NodeRef {
    off: u64,
    is_cluster: bool,
    cluster_len: Option<u32>,
    height: u8,
    entry_count: usize,
}

/// Zero-copy borrowed directory entry yielded by [`VzReader::readdir_visit`].
#[derive(Debug, Clone, Copy)]
pub struct DirEntryRef<'a> {
    /// UTF-8 basename borrowed directly from the leaf's `NamePool`.
    pub name: &'a str,
    /// Decoded 64-byte [`DirEntry`] record.
    pub entry: DirEntry,
    /// Leaf's `ExtMetaPool` slice for optional extended metadata inspection.
    pub ext_meta_pool: &'a [u8],
}

struct CachedNode {
    level: u8,
    entry_count: u32,
    payload: Arc<[u8]>,
}

struct LookupTarget {
    dir_entry: DirEntry,
    entry_id: u64,
    run_generation: u64,
    ext_codec: Option<ExtCodecMeta>,
    sparse_extents: Option<Vec<SparseExtent>>,
}

/// Random-access, HTTP-Range-friendly `.vz` reader.
pub struct VzReader<R: RangeReader> {
    reader: R,
    boot_block: Vec<u8>,
    active_slot: HeaderSlot,
    hasher: Box<dyn PathHasher>,
    owners: Vec<OwnerEntry>,
    dicts: Vec<DictEntry>,
    dict_cache: ZstdDictCache,
    schemas: Vec<SchemaEntry>,
    cipher_hdr: Option<CipherHeader>,
    crypto: Option<CryptoContext>,
    lsm_runs: Vec<LsmRunDesc>,
    /// Embedded root bytes when opened from an unfinalized pipe via `TAG_ROOT_FALLBACK`.
    pipe_root: Option<(u8, u32, Vec<u8>)>,
    /// Verified B+Tree internal/leaf node cache populated lazily on first cluster validation.
    node_cache: RwLock<HashMap<u64, Arc<CachedNode>>>,
}

impl<R: RangeReader> VzReader<R> {
    /// Opens an unencrypted archive with default options (`1 RTT` for standard 64 KiB Boot Block).
    pub fn open(reader: R) -> Result<Self, VzError> {
        Self::open_with_options(reader, VzReaderOptions::default())
    }

    /// Opens an archive with [`VzReaderOptions`].
    pub fn open_with_options(reader: R, opts: VzReaderOptions) -> Result<Self, VzError> {
        Self::open_inner(reader, opts, None)
    }

    /// Opens an archive with a custom [`PathHasher`] (e.g., for synthetic collision testing).
    pub fn open_with_hasher(
        reader: R,
        opts: VzReaderOptions,
        hasher: Box<dyn PathHasher>,
    ) -> Result<Self, VzError> {
        Self::open_inner(reader, opts, Some(hasher))
    }

    fn open_inner(
        reader: R,
        opts: VzReaderOptions,
        custom_hasher: Option<Box<dyn PathHasher>>,
    ) -> Result<Self, VzError> {
        // 1 RTT: fetch the 64 KiB Boot Block.
        let mut boot_block = vec![0u8; DEFAULT_BOOT_SIZE];
        reader.read_at(0, &mut boot_block)?;

        let pre_header = BootHeader::from_bytes(&boot_block);
        let pre_active = pre_header
            .as_ref()
            .ok()
            .and_then(|h| h.select_active(0xFFFF).ok().map(|(s, _)| *s));

        // Attempt Boot ECC verify-and-repair when enabled (or when BootHeader itself is damaged).
        if opts.repair_boot_ecc
            && (pre_active.is_none()
                || pre_active
                    .is_some_and(|s| (s.compat_flags & COMPAT_BOOT_ECC) != 0 && s.boot_block_size as usize == DEFAULT_BOOT_SIZE))
        {
            let mut candidate = boot_block.clone();
            if boot_ecc_verify_and_repair(&mut candidate).is_ok() {
                boot_block = candidate;
            }
        }

        let boot_hdr = BootHeader::from_bytes(&boot_block)?;
        let (active_ref, _) = boot_hdr.select_active(SUPPORTED_INCOMPAT)?;
        let active_slot = *active_ref;

        if active_slot.boot_block_size < DEFAULT_BOOT_SIZE as u32
            || (active_slot.boot_block_size & 7) != 0
        {
            return Err(VzError::BadFormat);
        }
        if active_slot.boot_block_size as usize > DEFAULT_BOOT_SIZE {
            let full_len = active_slot.boot_block_size as usize;
            let mut full_boot = vec![0u8; full_len];
            full_boot[..DEFAULT_BOOT_SIZE].copy_from_slice(&boot_block);
            reader.read_at(
                DEFAULT_BOOT_SIZE as u64,
                &mut full_boot[DEFAULT_BOOT_SIZE..],
            )?;
            boot_block = full_boot;
        }

        // Parse Global Registry.
        let reg_off = active_slot.registry_offset as usize;
        let reg_len = active_slot.registry_size as usize;
        let reg_end = reg_off.checked_add(reg_len).ok_or(VzError::ValueOverflow)?;
        if reg_end > boot_block.len() {
            return Err(VzError::BufferTooSmall);
        }
        let reg_slice = &boot_block[reg_off..reg_end];

        let mut owners = Vec::new();
        let mut dicts = Vec::new();
        let mut schemas = Vec::new();
        let mut cipher_hdr = None;
        let mut lsm_runs = Vec::new();

        for elem in TlvIter::new(reg_slice) {
            let elem = elem?;
            match elem.tag {
                TAG_NOP | crate::wire::TAG_VOID => {}
                TAG_OWNER_TABLE => owners = decode_owner_table(elem.value)?,
                TAG_DICT_TABLE => dicts = decode_dict_table(elem.value)?,
                TAG_SCHEMA_TABLE => schemas = decode_schema_table(elem.value)?,
                TAG_CIPHER_HEADER => cipher_hdr = Some(CipherHeader::from_bytes(elem.value)?),
                TAG_LSM_RUNS => lsm_runs = decode_lsm_runs(elem.value)?,
                _ => {}
            }
        }

        let crypto = if (active_slot.incompat_flags & INCOMPAT_ENCRYPTED) != 0 {
            let ch = cipher_hdr.as_ref().ok_or(VzError::BadFormat)?;
            let key = opts.encryption.as_ref().ok_or(VzError::CryptoError)?;
            Some(CryptoContext::unlock(ch, key)?)
        } else {
            None
        };

        let hasher: Box<dyn PathHasher> = match custom_hasher {
            Some(h) => h,
            None => Box::new(AlgoHasher::new(active_slot.hash_algo)?),
        };

        let mut pipe_root = None;
        if active_slot.tree_height == TREE_HEIGHT_PIPE {
            // Unfinalized streaming pipe: recover root from trailing TAG_ROOT_FALLBACK cluster.
            let total_len = reader.total_len()?;
            if total_len < active_slot.boot_block_size as u64 + ClusterFooter::SIZE as u64 {
                return Err(VzError::BadFormat);
            }
            let fb_cluster_bytes = read_tail_cluster(&reader, total_len)?;
            let (hdr, body, _) = validate_cluster(&fb_cluster_bytes)?;
            let _ = hdr;
            let mut found_fb = None;
            for elem in TlvIter::new(body) {
                let elem = elem?;
                if elem.tag == TAG_ROOT_FALLBACK {
                    found_fb = Some(decode_root_fallback(elem.value)?);
                    break;
                }
            }
            let fb = found_fb.ok_or(VzError::NotFound)?;
            let root_bytes = if let Some(embedded) = fb.embedded_root {
                embedded
            } else if fb.root_cluster_off != 0 {
                let cbytes = read_cluster_at(&reader, fb.root_cluster_off)?;
                let (_, cbody, _) = validate_cluster(&cbytes)?;
                let (_, _, payload) = parse_dir_node_body(cbody)?;
                payload.to_vec()
            } else {
                return Err(VzError::BadFormat);
            };
            lsm_runs.push(LsmRunDesc {
                run_generation: fb.stream_generation,
                root_offset: 0,
                root_entry_count: fb.root_entry_count,
                tree_height: fb.tree_height,
                root_is_cluster: false,
            });
            pipe_root = Some((fb.tree_height, fb.root_entry_count, root_bytes));
        } else if (active_slot.ro_compat_flags & RO_COMPAT_LSM_RUNS) == 0 || active_slot.lsm_run_count <= 1 {
            lsm_runs = vec![LsmRunDesc {
                run_generation: active_slot.generation,
                root_offset: active_slot.root_node_offset as u64,
                root_entry_count: active_slot.root_entry_count,
                tree_height: active_slot.tree_height,
                root_is_cluster: false,
            }];
        } else if lsm_runs.len() != active_slot.lsm_run_count as usize {
            return Err(VzError::BadFormat);
        }

        let dict_cache = ZstdDictCache::new(&dicts, 3);
        Ok(Self {
            reader,
            boot_block,
            active_slot,
            hasher,
            owners,
            dicts,
            dict_cache,
            schemas,
            cipher_hdr,
            crypto,
            lsm_runs,
            pipe_root,
            node_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Clears the in-memory verified B+Tree node cache.
    pub fn clear_index_cache(&self) {
        if let Ok(mut g) = self.node_cache.write() {
            g.clear();
        }
    }

    pub fn active_slot(&self) -> &HeaderSlot {
        &self.active_slot
    }

    pub fn owners(&self) -> &[OwnerEntry] {
        &self.owners
    }

    pub fn dicts(&self) -> &[DictEntry] {
        &self.dicts
    }

    pub fn schemas(&self) -> &[SchemaEntry] {
        &self.schemas
    }

    pub fn cipher_header(&self) -> Option<&CipherHeader> {
        self.cipher_hdr.as_ref()
    }

    pub fn crypto_context(&self) -> Option<&CryptoContext> {
        self.crypto.as_ref()
    }

    pub fn lsm_runs(&self) -> &[LsmRunDesc] {
        &self.lsm_runs
    }

    pub fn reader(&self) -> &R {
        &self.reader
    }

    /// Returns `true` if `path` currently exists (and is not tombstoned).
    pub fn exists(&self, path: &str) -> Result<bool, VzError> {
        match self.resolve_target(path) {
            Ok(_) => Ok(true),
            Err(VzError::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Resolves full metadata for `path` (checking LSM runs newest-to-oldest).
    pub fn stat(&self, path: &str) -> Result<VzStat, VzError> {
        Ok(self.resolve_entry(path)?.stat)
    }

    /// Reads the POSIX extended attributes (`TAG_XATTR_LIST`) for `path`.
    pub fn read_xattrs(&self, path: &str) -> Result<Vec<Xattr>, VzError> {
        Ok(self.stat(path)?.xattrs)
    }

    /// Reads the [`TensorMeta`] linked to a `KIND_TENSOR` entry at `path`.
    pub fn read_tensor_meta(&self, path: &str) -> Result<TensorMeta, VzError> {
        let st = self.stat(path)?;
        let sid = st.schema_id.ok_or(VzError::NotFound)?;
        for s in &self.schemas {
            if let SchemaEntry::Tensor(t) = s
                && t.schema_id == sid
            {
                return Ok(t.clone());
            }
        }
        Err(VzError::NotFound)
    }

    /// Reads the [`ColumnMeta`] linked to a `KIND_COLUMN` entry at `path`.
    pub fn read_column_meta(&self, path: &str) -> Result<ColumnMeta, VzError> {
        let st = self.stat(path)?;
        let sid = st.schema_id.ok_or(VzError::NotFound)?;
        for s in &self.schemas {
            if let SchemaEntry::Column(c) = s
                && c.schema_id == sid
            {
                return Ok(c.clone());
            }
        }
        Err(VzError::NotFound)
    }

    /// Zero-allocation directory iteration yielding borrowed [`DirEntryRef`] slices directly
    /// from each leaf's `NamePool` (disambiguating `parent_hash` collisions and merging LSM runs).
    pub fn readdir_visit<F>(&self, dir_path: &str, mut visitor: F) -> Result<(), VzError>
    where
        F: FnMut(DirEntryRef<'_>) -> Result<(), VzError>,
    {
        let norm_dir = normalize_dir_path(dir_path)?;
        let parent_hash = self.hasher.hash(norm_dir.as_bytes())?;

        if self.lsm_runs.len() == 1 {
            let run = &self.lsm_runs[0];
            let mut scratch = Vec::new();
            return self.visit_leaves_for_parent_with_scratch(
                NodeRef {
                    off: run.root_offset,
                    is_cluster: run.root_is_cluster,
                    cluster_len: None,
                    height: run.tree_height,
                    entry_count: run.root_entry_count as usize,
                },
                parent_hash,
                &mut scratch,
                &mut |leaf| {
                    let name_pool = leaf.name_pool();
                    let ext_pool = leaf.ext_meta_pool();
                    for item in leaf.iter_dir(parent_hash)? {
                        let de = item?;
                        if de.is_tombstone() {
                            continue;
                        }
                        if de.has_hash_collision()
                            && let Some(stored_parent) = de.entry_parent_path(ext_pool)?
                            && stored_parent != norm_dir.as_bytes()
                        {
                            continue;
                        }
                        let name_b = de.entry_name(name_pool)?;
                        let name = core::str::from_utf8(name_b).map_err(|_| VzError::BadFormat)?;
                        visitor(DirEntryRef {
                            name,
                            entry: de,
                            ext_meta_pool: ext_pool,
                        })?;
                    }
                    Ok(())
                },
            );
        }

        let mut seen: HashSet<String> = HashSet::new();
        for run in self.lsm_runs.iter().rev() {
            self.visit_leaves_for_parent(
                NodeRef {
                    off: run.root_offset,
                    is_cluster: run.root_is_cluster,
                    cluster_len: None,
                    height: run.tree_height,
                    entry_count: run.root_entry_count as usize,
                },
                parent_hash,
                &mut |leaf| {
                    let name_pool = leaf.name_pool();
                    let ext_pool = leaf.ext_meta_pool();
                    for item in leaf.iter_dir(parent_hash)? {
                        let de = item?;
                        if de.has_hash_collision()
                            && let Some(stored_parent) = de.entry_parent_path(ext_pool)?
                            && stored_parent != norm_dir.as_bytes()
                        {
                            continue;
                        }
                        let name_b = de.entry_name(name_pool)?;
                        let name = core::str::from_utf8(name_b).map_err(|_| VzError::BadFormat)?;
                        if seen.contains(name) {
                            continue;
                        }
                        seen.insert(name.to_string());
                        if de.is_tombstone() {
                            continue;
                        }
                        visitor(DirEntryRef {
                            name,
                            entry: de,
                            ext_meta_pool: ext_pool,
                        })?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    /// Lists all live entries in directory `dir_path`, disambiguating `parent_hash` collisions
    /// and merging LSM overlay runs (newest-wins, tombstone-filtered).
    pub fn readdir(&self, dir_path: &str) -> Result<Vec<VzStat>, VzError> {
        let norm_dir = normalize_dir_path(dir_path)?;
        let parent_hash = self.hasher.hash(norm_dir.as_bytes())?;

        if self.lsm_runs.len() == 1 {
            let run = &self.lsm_runs[0];
            let mut results = Vec::new();
            let mut scratch = Vec::new();
            self.visit_leaves_for_parent_with_scratch(
                NodeRef {
                    off: run.root_offset,
                    is_cluster: run.root_is_cluster,
                    cluster_len: None,
                    height: run.tree_height,
                    entry_count: run.root_entry_count as usize,
                },
                parent_hash,
                &mut scratch,
                &mut |leaf| {
                    let name_pool = leaf.name_pool();
                    let ext_pool = leaf.ext_meta_pool();
                    for item in leaf.iter_dir(parent_hash)? {
                        let de = item?;
                        if de.is_tombstone() {
                            continue;
                        }
                        if de.has_hash_collision()
                            && let Some(stored_parent) = de.entry_parent_path(ext_pool)?
                            && stored_parent != norm_dir.as_bytes()
                        {
                            continue;
                        }
                        let res = self.decode_resolved_entry(
                            &de,
                            name_pool,
                            ext_pool,
                            &norm_dir,
                            run.run_generation,
                        )?;
                        results.push(res.stat);
                    }
                    Ok(())
                },
            )?;
            results.sort_by(|a, b| a.name.cmp(&b.name));
            return Ok(results);
        }

        let mut seen: HashSet<String> = HashSet::new();
        let mut results: Vec<VzStat> = Vec::new();

        for run in self.lsm_runs.iter().rev() {
            let run_entries = self.collect_dir_in_run(run, &norm_dir, parent_hash)?;
            for (name, resolved) in run_entries {
                if !seen.insert(name) {
                    continue;
                }
                if resolved.dir_entry.is_tombstone() {
                    continue;
                }
                results.push(resolved.stat);
            }
        }
        results.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(results)
    }

    /// Reads and decodes the entire payload of `path` into memory (decompressing, decrypting,
    /// zero-filling sparse holes, and stitching multi-cluster chunks).
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, VzError> {
        let mut out = Vec::new();
        self.read_file_into(path, &mut out)?;
        Ok(out)
    }

    /// Reads and decodes the entire payload of `path` directly into `out` (clearing `out` first).
    pub fn read_file_into(&self, path: &str, out: &mut Vec<u8>) -> Result<(), VzError> {
        out.clear();
        let target = self.resolve_target(path)?;
        let de = &target.dir_entry;

        if let Some(inline) = de.inline_slice() {
            out.extend_from_slice(inline);
            return Ok(());
        }

        let DirPayload::Ref {
            data_offset,
            stored_size,
            raw_size,
            in_cluster_offset,
        } = de.payload
        else {
            return Err(VzError::BadFormat);
        };

        let codec = de.codec();
        let ext_codec = target.ext_codec.as_ref();

        if !de.is_sparse() && !de.is_multi_cluster() {
            return self.read_single_cluster_payload_into(
                data_offset,
                in_cluster_offset,
                stored_size,
                raw_size,
                codec,
                ext_codec,
                target.run_generation,
                target.entry_id,
                out,
            );
        }

        // Sparse or multi-cluster path delegates cleanly to streaming writer.
        self.decode_ref_to_writer(&target, out).map(|_| ())
    }

    /// Reads `[offset, offset + dst.len())` directly into caller-provided `dst` (clamped at EOF),
    /// returning the actual byte count written.
    pub fn read_file_range_into(
        &self,
        path: &str,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, VzError> {
        let len = dst.len();
        if len == 0 {
            return Ok(0);
        }
        let resolved = self.resolve_target(path)?;
        let de = &resolved.dir_entry;
        let codec = de.codec();
        let ext_codec = resolved.ext_codec.as_ref();

        if let Some(inline) = de.inline_slice() {
            let total = inline.len() as u64;
            if offset >= total {
                return Ok(0);
            }
            let start = usize::try_from(offset).map_err(|_| VzError::ValueOverflow)?;
            let take = len.min(inline.len() - start);
            dst[..take].copy_from_slice(&inline[start..start + take]);
            return Ok(take);
        }

        let DirPayload::Ref {
            data_offset,
            stored_size,
            raw_size,
            in_cluster_offset,
        } = de.payload
        else {
            return Err(VzError::BadFormat);
        };

        if offset >= raw_size {
            return Ok(0);
        }
        let end = offset.saturating_add(len as u64).min(raw_size);
        let want_len = usize::try_from(end - offset).map_err(|_| VzError::ValueOverflow)?;

        let is_plain_uncompressed = self.crypto.is_none()
            && !de.is_sparse()
            && codec == crate::wire::CODEC_NONE
            && ext_codec.is_none();

        if is_plain_uncompressed && !de.is_multi_cluster() {
            let payload_off = data_offset
                .checked_add(in_cluster_offset as u64)
                .and_then(|v| v.checked_add(offset))
                .ok_or(VzError::ValueOverflow)?;
            if offset + want_len as u64 > stored_size {
                return Err(VzError::BadFormat);
            }
            self.reader.read_at(payload_off, &mut dst[..want_len])?;
            return Ok(want_len);
        }

        if is_plain_uncompressed && de.is_multi_cluster() {
            let extents = self.read_chunk_table_at(data_offset, in_cluster_offset)?;
            let mut written = 0usize;
            let mut cur_raw = 0u64;
            for ext in extents {
                let chunk_end = cur_raw
                    .checked_add(ext.raw_size)
                    .ok_or(VzError::ValueOverflow)?;
                if chunk_end <= offset {
                    cur_raw = chunk_end;
                    continue;
                }
                if cur_raw >= end {
                    break;
                }
                let ov_start = cur_raw.max(offset);
                let ov_end = chunk_end.min(end);
                let s =
                    usize::try_from(ov_start - cur_raw).map_err(|_| VzError::ValueOverflow)?;
                let e = usize::try_from(ov_end - cur_raw).map_err(|_| VzError::ValueOverflow)?;
                let take = e - s;
                let read_off = ext
                    .cluster_offset
                    .checked_add(ext.in_cluster_offset as u64)
                    .and_then(|v| v.checked_add(s as u64))
                    .ok_or(VzError::ValueOverflow)?;
                self.reader
                    .read_at(read_off, &mut dst[written..written + take])?;
                written += take;
                cur_raw = chunk_end;
            }
            if written != want_len {
                return Err(VzError::BadFormat);
            }
            return Ok(written);
        }

        // Compressed/encrypted/sparse paths reuse `read_file_range_resolved` cleanly.
        let tmp = self.read_file_range_resolved(&resolved, offset, len)?;
        dst[..tmp.len()].copy_from_slice(&tmp);
        Ok(tmp.len())
    }

    /// Reads `[offset, offset + len)` of `path` (clamped at EOF).
    ///
    /// For multi-cluster non-sparse files, only the chunk cluster(s) overlapping
    /// the requested byte range are fetched and decoded.
    pub fn read_file_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, VzError> {
        let resolved = self.resolve_target(path)?;
        self.read_file_range_resolved(&resolved, offset, len)
    }

    fn read_file_range_resolved(
        &self,
        resolved: &LookupTarget,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, VzError> {
        let de = &resolved.dir_entry;
        let codec = de.codec();
        let ext_codec = resolved.ext_codec.as_ref();

        if let Some(inline) = de.inline_slice() {
            let total = inline.len() as u64;
            if offset >= total || len == 0 {
                return Ok(Vec::new());
            }
            let start = usize::try_from(offset).map_err(|_| VzError::ValueOverflow)?;
            let take = len.min(inline.len() - start);
            return Ok(inline[start..start + take].to_vec());
        }

        let DirPayload::Ref {
            data_offset,
            stored_size,
            raw_size,
            in_cluster_offset,
        } = de.payload
        else {
            return Err(VzError::BadFormat);
        };

        if offset >= raw_size || len == 0 {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(len as u64).min(raw_size);
        let want_len = usize::try_from(end - offset).map_err(|_| VzError::ValueOverflow)?;

        if de.is_sparse() {
            let extents = resolved
                .sparse_extents
                .as_deref()
                .ok_or(VzError::BadFormat)?;
            let total_sparse_data: u64 = extents
                .iter()
                .try_fold(0u64, |acc, e| acc.checked_add(e.length))
                .ok_or(VzError::ValueOverflow)?;
            let packed = if stored_size == 0 && total_sparse_data == 0 {
                Vec::new()
            } else {
                self.read_non_inline_bytes(
                    de.is_multi_cluster(),
                    data_offset,
                    in_cluster_offset,
                    stored_size,
                    total_sparse_data,
                    codec,
                    ext_codec,
                    resolved.run_generation,
                    resolved.entry_id,
                )?
            };
            if packed.len() as u64 != total_sparse_data {
                return Err(VzError::BadFormat);
            }
            let mut out = vec![0u8; want_len];
            let mut src_pos = 0u64;
            for ext in extents {
                let ext_start = ext.logical_offset;
                let ext_end = ext_start
                    .checked_add(ext.length)
                    .ok_or(VzError::ValueOverflow)?;
                if ext_end > raw_size {
                    return Err(VzError::BadFormat);
                }
                if ext_end > offset && ext_start < end {
                    let ov_start = ext_start.max(offset);
                    let ov_end = ext_end.min(end);
                    let src_off = usize::try_from(src_pos + (ov_start - ext_start))
                        .map_err(|_| VzError::ValueOverflow)?;
                    let dst_off =
                        usize::try_from(ov_start - offset).map_err(|_| VzError::ValueOverflow)?;
                    let cp_len =
                        usize::try_from(ov_end - ov_start).map_err(|_| VzError::ValueOverflow)?;
                    out[dst_off..dst_off + cp_len]
                        .copy_from_slice(&packed[src_off..src_off + cp_len]);
                }
                src_pos += ext.length;
            }
            return Ok(out);
        }

        let is_plain_uncompressed = self.crypto.is_none()
            && codec == crate::wire::CODEC_NONE
            && ext_codec.is_none();

        if de.is_multi_cluster() {
            let extents = self.read_chunk_table_at(data_offset, in_cluster_offset)?;
            let mut out = Vec::with_capacity(want_len);
            let mut cur_raw = 0u64;
            for ext in extents {
                let chunk_end = cur_raw
                    .checked_add(ext.raw_size)
                    .ok_or(VzError::ValueOverflow)?;
                if chunk_end <= offset {
                    cur_raw = chunk_end;
                    continue;
                }
                if cur_raw >= end {
                    break;
                }
                let ov_start = cur_raw.max(offset);
                let ov_end = chunk_end.min(end);
                let s =
                    usize::try_from(ov_start - cur_raw).map_err(|_| VzError::ValueOverflow)?;
                let e = usize::try_from(ov_end - cur_raw).map_err(|_| VzError::ValueOverflow)?;
                let take = e - s;
                if is_plain_uncompressed {
                    let read_off = ext
                        .cluster_offset
                        .checked_add(ext.in_cluster_offset as u64)
                        .and_then(|v| v.checked_add(s as u64))
                        .ok_or(VzError::ValueOverflow)?;
                    let old_len = out.len();
                    out.resize(old_len + take, 0);
                    self.reader.read_at(read_off, &mut out[old_len..])?;
                } else {
                    let chunk = self.read_single_cluster_payload(
                        ext.cluster_offset,
                        ext.in_cluster_offset,
                        ext.stored_size,
                        ext.raw_size,
                        codec,
                        ext_codec,
                        resolved.run_generation,
                        resolved.entry_id,
                    )?;
                    if e > chunk.len() {
                        return Err(VzError::BadFormat);
                    }
                    out.extend_from_slice(&chunk[s..e]);
                }
                cur_raw = chunk_end;
            }
            if out.len() != want_len {
                return Err(VzError::BadFormat);
            }
            return Ok(out);
        }

        if is_plain_uncompressed {
            let payload_off = data_offset
                .checked_add(in_cluster_offset as u64)
                .and_then(|v| v.checked_add(offset))
                .ok_or(VzError::ValueOverflow)?;
            if offset + want_len as u64 > stored_size {
                return Err(VzError::BadFormat);
            }
            let mut out = vec![0u8; want_len];
            self.reader.read_at(payload_off, &mut out)?;
            return Ok(out);
        }

        let plain = self.read_single_cluster_payload(
            data_offset,
            in_cluster_offset,
            stored_size,
            raw_size,
            codec,
            ext_codec,
            resolved.run_generation,
            resolved.entry_id,
        )?;
        let s = usize::try_from(offset).map_err(|_| VzError::ValueOverflow)?;
        let e = usize::try_from(end).map_err(|_| VzError::ValueOverflow)?;
        if e > plain.len() {
            return Err(VzError::BadFormat);
        }
        Ok(plain[s..e].to_vec())
    }

    /// Streams the decoded payload of `path` into `out` in `O(cluster_size)` memory for
    /// multi-cluster non-sparse files.
    pub fn read_file_to_writer(&self, path: &str, out: &mut dyn Write) -> Result<u64, VzError> {
        let target = self.resolve_target(path)?;
        if let Some(inline) = target.dir_entry.inline_slice() {
            out.write_all(inline).map_err(|_| VzError::IoError)?;
            return Ok(inline.len() as u64);
        }
        self.decode_ref_to_writer(&target, out)
    }

    fn decode_ref_to_writer(&self, target: &LookupTarget, out: &mut dyn Write) -> Result<u64, VzError> {
        let de = &target.dir_entry;
        let codec = de.codec();
        let ext_codec = target.ext_codec.as_ref();

        let DirPayload::Ref {
            data_offset,
            stored_size,
            raw_size,
            in_cluster_offset,
        } = de.payload
        else {
            return Err(VzError::BadFormat);
        };

        if de.is_sparse() {
            let extents = target
                .sparse_extents
                .as_deref()
                .ok_or(VzError::BadFormat)?;
            let total_sparse_data: u64 = extents.iter().map(|e| e.length).sum();
            let packed = if stored_size == 0 && total_sparse_data == 0 {
                Vec::new()
            } else {
                self.read_non_inline_bytes(
                    de.is_multi_cluster(),
                    data_offset,
                    in_cluster_offset,
                    stored_size,
                    total_sparse_data,
                    codec,
                    ext_codec,
                    target.run_generation,
                    target.entry_id,
                )?
            };
            if packed.len() as u64 != total_sparse_data {
                return Err(VzError::BadFormat);
            }
            let raw_usize = usize::try_from(raw_size).map_err(|_| VzError::ValueOverflow)?;
            let mut full = vec![0u8; raw_usize];
            let mut src_pos = 0usize;
            for ext in extents {
                let dst_start =
                    usize::try_from(ext.logical_offset).map_err(|_| VzError::ValueOverflow)?;
                let len = usize::try_from(ext.length).map_err(|_| VzError::ValueOverflow)?;
                let dst_end = dst_start.checked_add(len).ok_or(VzError::ValueOverflow)?;
                if dst_end > full.len() || src_pos + len > packed.len() {
                    return Err(VzError::BadFormat);
                }
                full[dst_start..dst_end].copy_from_slice(&packed[src_pos..src_pos + len]);
                src_pos += len;
            }
            out.write_all(&full).map_err(|_| VzError::IoError)?;
            return Ok(raw_size);
        }

        if de.is_multi_cluster() {
            let extents = self.read_chunk_table_at(data_offset, in_cluster_offset)?;
            let mut written = 0u64;
            for ext in extents {
                let chunk = self.read_single_cluster_payload(
                    ext.cluster_offset,
                    ext.in_cluster_offset,
                    ext.stored_size,
                    ext.raw_size,
                    codec,
                    ext_codec,
                    target.run_generation,
                    target.entry_id,
                )?;
                out.write_all(&chunk).map_err(|_| VzError::IoError)?;
                written += chunk.len() as u64;
            }
            if written != raw_size {
                return Err(VzError::BadFormat);
            }
            return Ok(written);
        }

        let plain = self.read_single_cluster_payload(
            data_offset,
            in_cluster_offset,
            stored_size,
            raw_size,
            codec,
            ext_codec,
            target.run_generation,
            target.entry_id,
        )?;
        out.write_all(&plain).map_err(|_| VzError::IoError)?;
        Ok(plain.len() as u64)
    }

    /// Streams all live files/entries in cluster-batched sequential order, verifying each cluster
    /// CRC32C once and reusing a single decompression scratch buffer.
    ///
    /// Special entries (`KIND_DIR` etc.) yield empty slices `&[]`; `KIND_REG`/`KIND_LNK`/
    /// `KIND_TENSOR`/`KIND_COLUMN` yield decoded payload bytes.
    pub fn extract_all_with<F>(&self, mut visitor: F) -> Result<(), VzError>
    where
        F: FnMut(&ResolvedEntry, &[u8]) -> Result<(), VzError>,
    {
        let live = self.list_all_live()?;
        let mut by_cluster: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        let mut complex_idxs: Vec<usize> = Vec::new();

        for (idx, entry) in live.iter().enumerate() {
            if let Some(inline) = entry.dir_entry.inline_slice() {
                visitor(entry, inline)?;
                continue;
            }
            if entry.dir_entry.is_sparse() || entry.dir_entry.is_multi_cluster() {
                complex_idxs.push(idx);
                continue;
            }
            if let DirPayload::Ref { data_offset, .. } = entry.dir_entry.payload {
                by_cluster.entry(data_offset).or_default().push(idx);
            } else {
                return Err(VzError::BadFormat);
            }
        }

        let contig = self.reader.contiguous_bytes();
        let mut cluster_buf = Vec::new();
        let mut out_buf = Vec::new();

        for (cluster_off, idxs) in by_cluster {
            let cluster_slice: &[u8] = if let Some(all) = contig {
                let off_u = usize::try_from(cluster_off).map_err(|_| VzError::ValueOverflow)?;
                let chdr = ClusterHeader::from_bytes(all.get(off_u..).ok_or(VzError::BufferTooSmall)?)?;
                let clen = usize::try_from(chdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
                all.get(off_u..off_u + clen).ok_or(VzError::BufferTooSmall)?
            } else {
                let mut hdr_buf = [0u8; ClusterHeader::SIZE];
                self.reader.read_at(cluster_off, &mut hdr_buf)?;
                let chdr = ClusterHeader::from_bytes(&hdr_buf)?;
                let clen = usize::try_from(chdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
                if clen < ClusterHeader::SIZE + ClusterFooter::SIZE {
                    return Err(VzError::BadFormat);
                }
                cluster_buf.resize(clen, 0);
                cluster_buf[..ClusterHeader::SIZE].copy_from_slice(&hdr_buf);
                self.reader
                    .read_at(cluster_off + ClusterHeader::SIZE as u64, &mut cluster_buf[ClusterHeader::SIZE..])?;
                &cluster_buf
            };

            let (chdr, _, _) = validate_cluster(cluster_slice)?;
            for idx in idxs {
                let entry = &live[idx];
                let DirPayload::Ref {
                    stored_size,
                    raw_size,
                    in_cluster_offset,
                    ..
                } = entry.dir_entry.payload
                else {
                    return Err(VzError::BadFormat);
                };
                let slen = usize::try_from(stored_size).map_err(|_| VzError::ValueOverflow)?;
                let rlen = usize::try_from(raw_size).map_err(|_| VzError::ValueOverflow)?;
                let ioff = in_cluster_offset as usize;
                let end = ioff.checked_add(slen).ok_or(VzError::ValueOverflow)?;
                let stored_slice = cluster_slice.get(ioff..end).ok_or(VzError::BufferTooSmall)?;

                let codec = entry.dir_entry.codec();
                let ext_codec = entry.ext_codec.as_ref();
                if let Some(ref ctx) = self.crypto {
                    let dec = ctx.decrypt_payload(
                        entry.run_generation,
                        chdr.cluster_seq,
                        entry.stat.entry_id,
                        stored_slice,
                    )?;
                    decompress_payload_into(
                        &dec,
                        &mut out_buf,
                        rlen,
                        codec,
                        ext_codec,
                        &self.dicts,
                        Some(&self.dict_cache),
                    )?;
                } else {
                    decompress_payload_into(
                        stored_slice,
                        &mut out_buf,
                        rlen,
                        codec,
                        ext_codec,
                        &self.dicts,
                        Some(&self.dict_cache),
                    )?;
                }
                visitor(entry, &out_buf)?;
            }
        }

        for idx in complex_idxs {
            let entry = &live[idx];
            out_buf.clear();
            let target = LookupTarget {
                dir_entry: entry.dir_entry,
                entry_id: entry.stat.entry_id,
                run_generation: entry.run_generation,
                ext_codec: entry.ext_codec.clone(),
                sparse_extents: entry.sparse_extents.clone(),
            };
            self.decode_ref_to_writer(&target, &mut out_buf)?;
            visitor(entry, &out_buf)?;
        }

        Ok(())
    }

    /// Decodes the full payload of an already-resolved [`ResolvedEntry`] directly without re-traversing the B+Tree.
    pub fn read_resolved_payload(&self, resolved: &ResolvedEntry) -> Result<Vec<u8>, VzError> {
        let mut out = Vec::new();
        if let Some(inline) = resolved.dir_entry.inline_slice() {
            out.extend_from_slice(inline);
            return Ok(out);
        }
        let target = LookupTarget {
            dir_entry: resolved.dir_entry,
            entry_id: resolved.stat.entry_id,
            run_generation: resolved.run_generation,
            ext_codec: resolved.ext_codec.clone(),
            sparse_extents: resolved.sparse_extents.clone(),
        };
        self.decode_ref_to_writer(&target, &mut out)?;
        Ok(out)
    }

    /// Returns all live entries across the archive (used by compaction, bulk extraction, and FUSE).
    pub fn list_all_live(&self) -> Result<Vec<ResolvedEntry>, VzError> {
        // Collect newest-to-oldest so global directory BFS resolves parent paths for overlay
        // tombstones and updates emitted without redundant KIND_DIR headers in delta runs.
        let mut runs_rev: Vec<Vec<ResolvedEntry>> = Vec::with_capacity(self.lsm_runs.len());
        for run in self.lsm_runs.iter().rev() {
            runs_rev.push(self.collect_all_in_run_raw(run)?);
        }

        let mut dir_paths_by_hash: HashMap<u64, String> = HashMap::new();
        let root_h = self.hasher.hash(b"/")?;
        dir_paths_by_hash.insert(root_h, "/".to_string());
        loop {
            let mut progressed = false;
            for run_items in &runs_rev {
                for item in run_items {
                    if (item.stat.kind & KIND_MASK) == crate::wire::KIND_DIR
                        && !item.dir_entry.is_tombstone()
                        && let Some(parent_str) =
                            dir_paths_by_hash.get(&item.dir_entry.parent_hash).cloned()
                    {
                        let full = if parent_str == "/" {
                            format!("/{}", item.stat.name)
                        } else {
                            format!("{parent_str}/{}", item.stat.name)
                        };
                        let h = self.hasher.hash(full.as_bytes())?;
                        if let std::collections::hash_map::Entry::Vacant(e) =
                            dir_paths_by_hash.entry(h)
                        {
                            e.insert(full);
                            progressed = true;
                        }
                    }
                }
            }
            if !progressed {
                break;
            }
        }

        let mut seen: HashSet<(u64, String, String)> = HashSet::new();
        let mut out = Vec::new();
        for run_items in runs_rev {
            for mut entry in run_items {
                if entry.stat.parent_path.is_empty()
                    && let Some(p) = dir_paths_by_hash.get(&entry.dir_entry.parent_hash)
                {
                    entry.stat.parent_path = p.clone();
                }
                let key = (
                    entry.dir_entry.parent_hash,
                    entry.stat.parent_path.clone(),
                    entry.stat.name.clone(),
                );
                if !seen.insert(key) {
                    continue;
                }
                if entry.dir_entry.is_tombstone() {
                    continue;
                }
                out.push(entry);
            }
        }
        Ok(out)
    }

    pub(crate) fn max_entry_id(&self) -> Result<u64, VzError> {
        let mut max_id = 0u64;
        for run in &self.lsm_runs {
            for entry in self.collect_all_in_run_raw(run)? {
                max_id = max_id.max(entry.stat.entry_id);
            }
        }
        Ok(max_id)
    }

    /// Resolves raw entry (including tombstones) for `path` in `self.lsm_runs`, newest-first.
    pub(crate) fn resolve_raw_for_append(&self, path: &str) -> Result<Option<ResolvedEntry>, VzError> {
        let (parent_path, basename) = split_archive_path(path)?;
        let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
        let name_hash = self.hasher.hash(basename.as_bytes())?;
        for run in self.lsm_runs.iter().rev() {
            if let Some(res) =
                self.lookup_in_run(run, &parent_path, &basename, parent_hash, name_hash)?
            {
                return Ok(Some(res));
            }
        }
        Ok(None)
    }

    /// Resolves a live entry for `path`, checking runs newest-to-oldest.
    pub fn resolve_entry(&self, path: &str) -> Result<ResolvedEntry, VzError> {
        let (parent_path, basename) = split_archive_path(path)?;
        let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
        let name_hash = self.hasher.hash(basename.as_bytes())?;

        for run in self.lsm_runs.iter().rev() {
            if let Some(res) =
                self.lookup_in_run(run, &parent_path, &basename, parent_hash, name_hash)?
            {
                if res.dir_entry.is_tombstone() {
                    return Err(VzError::NotFound);
                }
                return Ok(res);
            }
        }
        Err(VzError::NotFound)
    }

    fn read_cluster_node_cached(
        &self,
        offset: u64,
        expected_len: Option<u32>,
    ) -> Result<Arc<CachedNode>, VzError> {
        if let Ok(guard) = self.node_cache.read()
            && let Some(hit) = guard.get(&offset)
        {
            return Ok(Arc::clone(hit));
        }

        let validated = if let Some(all) = self.reader.contiguous_bytes() {
            let off_u = usize::try_from(offset).map_err(|_| VzError::ValueOverflow)?;
            let slice = match expected_len {
                Some(clen) => {
                    let end = off_u
                        .checked_add(clen as usize)
                        .ok_or(VzError::ValueOverflow)?;
                    all.get(off_u..end).ok_or(VzError::BufferTooSmall)?
                }
                None => {
                    let hdr = ClusterHeader::from_bytes(
                        all.get(off_u..).ok_or(VzError::BufferTooSmall)?,
                    )?;
                    let clen =
                        usize::try_from(hdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
                    let end = off_u.checked_add(clen).ok_or(VzError::ValueOverflow)?;
                    all.get(off_u..end).ok_or(VzError::BufferTooSmall)?
                }
            };
            let (_, body, _) = validate_cluster(slice)?;
            let (level, count, payload) = parse_dir_node_body(body)?;
            Arc::new(CachedNode {
                level,
                entry_count: count,
                payload: Arc::from(payload),
            })
        } else {
            let cluster_buf = match expected_len {
                Some(clen) => {
                    let mut buf = vec![0u8; clen as usize];
                    self.reader.read_at(offset, &mut buf)?;
                    buf
                }
                None => read_cluster_at(&self.reader, offset)?,
            };
            let (_, body, _) = validate_cluster(&cluster_buf)?;
            let (level, count, payload) = parse_dir_node_body(body)?;
            Arc::new(CachedNode {
                level,
                entry_count: count,
                payload: Arc::from(payload),
            })
        };

        if let Ok(mut guard) = self.node_cache.write() {
            let entry = guard
                .entry(offset)
                .or_insert_with(|| Arc::clone(&validated));
            return Ok(Arc::clone(entry));
        }
        Ok(validated)
    }

    fn resolve_target(&self, path: &str) -> Result<LookupTarget, VzError> {
        let (parent_path, basename) = split_archive_path_borrowed(path)?;
        let parent_hash = self.hasher.hash(parent_path.as_bytes())?;
        let name_hash = self.hasher.hash(basename.as_bytes())?;

        for run in self.lsm_runs.iter().rev() {
            if let Some(target) = self.lookup_target_in_run(
                run,
                parent_path.as_ref(),
                basename.as_ref(),
                parent_hash,
                name_hash,
            )? {
                if target.dir_entry.is_tombstone() {
                    return Err(VzError::NotFound);
                }
                return Ok(target);
            }
        }
        Err(VzError::NotFound)
    }

    fn decode_lookup_target(
        &self,
        de: DirEntry,
        ext_meta_pool: &[u8],
        run_generation: u64,
    ) -> Result<LookupTarget, VzError> {
        let mut entry_id = de.entry_id_lo as u64;
        let mut ext_codec = None;
        let mut sparse_extents = None;
        let has_inode64 = (de.flags_and_codec & FLAG_INODE_64) != 0;
        let mut saw_inode_hi = false;

        if de.has_ext_meta() {
            let chain = de.entry_ext_meta(ext_meta_pool)?;
            for elem in TlvIter::new(chain) {
                let elem = elem?;
                if elem.tag == TAG_NOP {
                    break;
                }
                match elem.tag {
                    crate::wire::TAG_INODE_HI => {
                        if elem.value.len() < 4 {
                            return Err(VzError::BadFormat);
                        }
                        let hi = read_le_u32(elem.value, 0) as u64;
                        entry_id = (hi << 32) | (de.entry_id_lo as u64);
                        saw_inode_hi = true;
                    }
                    TAG_EXT_CODEC => ext_codec = Some(decode_ext_codec(elem.value)?),
                    TAG_SPARSE_EXTENTS => sparse_extents = Some(decode_sparse_extents(elem.value)?),
                    _ => {}
                }
            }
        }
        if has_inode64 && !saw_inode_hi {
            entry_id = de.full_entry_id(ext_meta_pool)?;
        }

        Ok(LookupTarget {
            dir_entry: de,
            entry_id,
            run_generation,
            ext_codec,
            sparse_extents,
        })
    }

    fn lookup_target_in_run(
        &self,
        run: &LsmRunDesc,
        parent_path: &str,
        basename: &str,
        parent_hash: u64,
        name_hash: u64,
    ) -> Result<Option<LookupTarget>, VzError> {
        let mut cur_off = run.root_offset;
        let mut cur_is_cluster = run.root_is_cluster;
        let mut cur_cluster_len: Option<u32> = None;
        let mut cur_height = run.tree_height;
        let mut cur_count = run.root_entry_count as usize;

        loop {
            if cur_height == 0 {
                if cur_is_cluster {
                    let cached = self.read_cluster_node_cached(cur_off, cur_cluster_len)?;
                    // Cluster CRC32C was already validated when populating `node_cache`.
                    let leaf = LeafNodeView::parse_trusted(&cached.payload)?;
                    if let Some(de) = leaf.lookup_raw_exact(
                        parent_hash,
                        name_hash,
                        Some(basename.as_bytes()),
                        Some(parent_path.as_bytes()),
                    )? {
                        return Ok(Some(self.decode_lookup_target(
                            de,
                            leaf.ext_meta_pool(),
                            run.run_generation,
                        )?));
                    }
                    return Ok(None);
                } else if let Some((_, _, ref pipe_bytes)) = self.pipe_root {
                    let leaf = LeafNodeView::parse(pipe_bytes)?;
                    if let Some(de) = leaf.lookup_raw_exact(
                        parent_hash,
                        name_hash,
                        Some(basename.as_bytes()),
                        Some(parent_path.as_bytes()),
                    )? {
                        return Ok(Some(self.decode_lookup_target(
                            de,
                            leaf.ext_meta_pool(),
                            run.run_generation,
                        )?));
                    }
                    return Ok(None);
                } else {
                    let off = usize::try_from(cur_off).map_err(|_| VzError::ValueOverflow)?;
                    if off >= self.boot_block.len() {
                        return Err(VzError::BufferTooSmall);
                    }
                    // Boot Block already passed HeaderSlot CRC32C + Boot ECC on open.
                    let leaf = LeafNodeView::parse_trusted(&self.boot_block[off..])?;
                    if let Some(de) = leaf.lookup_raw_exact(
                        parent_hash,
                        name_hash,
                        Some(basename.as_bytes()),
                        Some(parent_path.as_bytes()),
                    )? {
                        return Ok(Some(self.decode_lookup_target(
                            de,
                            leaf.ext_meta_pool(),
                            run.run_generation,
                        )?));
                    }
                    return Ok(None);
                }
            }

            // Internal node: `RouteTableView`.
            let route = if cur_is_cluster {
                let cached = self.read_cluster_node_cached(cur_off, cur_cluster_len)?;
                let table = RouteTableView::new(&cached.payload, cached.entry_count as usize)?;
                table.lookup(parent_hash, name_hash)?
            } else if let Some((_, cnt, ref pipe_bytes)) = self.pipe_root {
                let table = RouteTableView::new(pipe_bytes, cnt as usize)?;
                table.lookup(parent_hash, name_hash)?
            } else {
                let off = usize::try_from(cur_off).map_err(|_| VzError::ValueOverflow)?;
                let table = RouteTableView::new(&self.boot_block[off..], cur_count)?;
                table.lookup(parent_hash, name_hash)?
            };

            let Some((_idx, r)) = route else {
                return Ok(None);
            };
            cur_off = r.child_cluster_off;
            cur_is_cluster = true;
            cur_cluster_len = Some(r.child_cluster_len);
            cur_height -= 1;
            cur_count = r.subtree_count_lo as usize;
        }
    }

    fn read_node_bytes(&self, offset: u64, is_cluster: bool, expected_len: Option<u32>) -> Result<(u8, u32, Vec<u8>), VzError> {
        if let Some((h, cnt, ref root_bytes)) = self.pipe_root
            && !is_cluster
            && offset == 0
        {
            return Ok((h, cnt, root_bytes.clone()));
        }
        if !is_cluster {
            let off = usize::try_from(offset).map_err(|_| VzError::ValueOverflow)?;
            if off >= self.boot_block.len() {
                return Err(VzError::BufferTooSmall);
            }
            return Ok((0, 0, self.boot_block[off..].to_vec()));
        }
        let cached = self.read_cluster_node_cached(offset, expected_len)?;
        Ok((cached.level, cached.entry_count, cached.payload.to_vec()))
    }

    fn lookup_in_run(
        &self,
        run: &LsmRunDesc,
        parent_path: &str,
        basename: &str,
        parent_hash: u64,
        name_hash: u64,
    ) -> Result<Option<ResolvedEntry>, VzError> {
        let mut cur_off = run.root_offset;
        let mut cur_is_cluster = run.root_is_cluster;
        let mut cur_cluster_len: Option<u32> = None;
        let mut cur_height = run.tree_height;
        let mut cur_count = run.root_entry_count as usize;

        loop {
            if cur_height == 0 {
                let leaf_slice = if cur_is_cluster {
                    let (_, _, bytes) = self.read_node_bytes(cur_off, true, cur_cluster_len)?;
                    bytes
                } else if let Some((_, _, ref pipe_bytes)) = self.pipe_root {
                    pipe_bytes.clone()
                } else {
                    let off = usize::try_from(cur_off).map_err(|_| VzError::ValueOverflow)?;
                    if off >= self.boot_block.len() {
                        return Err(VzError::BufferTooSmall);
                    }
                    // Only slice Boot Block directly!
                    let leaf = LeafNodeView::parse(&self.boot_block[off..])?;
                    if let Some(de) = leaf.lookup_raw_exact(
                        parent_hash,
                        name_hash,
                        Some(basename.as_bytes()),
                        Some(parent_path.as_bytes()),
                    )? {
                        return Ok(Some(self.decode_resolved_entry(
                            &de,
                            leaf.name_pool(),
                            leaf.ext_meta_pool(),
                            parent_path,
                            run.run_generation,
                        )?));
                    }
                    return Ok(None);
                };

                let leaf = LeafNodeView::parse_trusted(&leaf_slice)?;
                if let Some(de) = leaf.lookup_raw_exact(
                    parent_hash,
                    name_hash,
                    Some(basename.as_bytes()),
                    Some(parent_path.as_bytes()),
                )? {
                    return Ok(Some(self.decode_resolved_entry(
                        &de,
                        leaf.name_pool(),
                        leaf.ext_meta_pool(),
                        parent_path,
                        run.run_generation,
                    )?));
                }
                return Ok(None);
            }

            // Internal node: `RouteTableView`.
            let route = if cur_is_cluster {
                let (_, cnt, bytes) = self.read_node_bytes(cur_off, true, cur_cluster_len)?;
                let table = RouteTableView::new(&bytes, cnt as usize)?;
                table.lookup(parent_hash, name_hash)?
            } else if let Some((_, cnt, ref pipe_bytes)) = self.pipe_root {
                let table = RouteTableView::new(pipe_bytes, cnt as usize)?;
                table.lookup(parent_hash, name_hash)?
            } else {
                let off = usize::try_from(cur_off).map_err(|_| VzError::ValueOverflow)?;
                let table = RouteTableView::new(&self.boot_block[off..], cur_count)?;
                table.lookup(parent_hash, name_hash)?
            };

            let Some((_idx, r)) = route else {
                return Ok(None);
            };
            cur_off = r.child_cluster_off;
            cur_is_cluster = true;
            cur_cluster_len = Some(r.child_cluster_len);
            cur_height -= 1;
            cur_count = r.subtree_count_lo as usize;
        }
    }

    fn collect_dir_in_run(
        &self,
        run: &LsmRunDesc,
        target_parent: &str,
        parent_hash: u64,
    ) -> Result<Vec<(String, ResolvedEntry)>, VzError> {
        let mut out = Vec::new();
        self.visit_leaves_for_parent(
            NodeRef {
                off: run.root_offset,
                is_cluster: run.root_is_cluster,
                cluster_len: None,
                height: run.tree_height,
                entry_count: run.root_entry_count as usize,
            },
            parent_hash,
            &mut |leaf| {
                for item in leaf.iter_dir(parent_hash)? {
                    let de = item?;
                    if let Some(stored_parent) = de.entry_parent_path(leaf.ext_meta_pool())?
                        && stored_parent != target_parent.as_bytes()
                    {
                        continue;
                    }
                    let res = self.decode_resolved_entry(
                        &de,
                        leaf.name_pool(),
                        leaf.ext_meta_pool(),
                        target_parent,
                        run.run_generation,
                    )?;
                    out.push((res.stat.name.clone(), res));
                }
                Ok(())
            },
        )?;
        Ok(out)
    }

    fn visit_leaves_for_parent<F>(
        &self,
        node: NodeRef,
        parent_hash: u64,
        visitor: &mut F,
    ) -> Result<(), VzError>
    where
        F: FnMut(&LeafNodeView<'_>) -> Result<(), VzError>,
    {
        let mut scratch = Vec::new();
        self.visit_leaves_for_parent_with_scratch(node, parent_hash, &mut scratch, visitor)
    }

    fn visit_leaves_for_parent_with_scratch<F>(
        &self,
        node: NodeRef,
        parent_hash: u64,
        scratch: &mut Vec<u8>,
        visitor: &mut F,
    ) -> Result<(), VzError>
    where
        F: FnMut(&LeafNodeView<'_>) -> Result<(), VzError>,
    {
        if node.height == 0 {
            if !node.is_cluster && self.pipe_root.is_none() {
                let off = usize::try_from(node.off).map_err(|_| VzError::ValueOverflow)?;
                let leaf = LeafNodeView::parse_trusted(&self.boot_block[off..])?;
                return visitor(&leaf);
            }
            if node.is_cluster {
                let cached = self.read_cluster_node_cached(node.off, node.cluster_len)?;
                let leaf = LeafNodeView::parse_trusted(&cached.payload)?;
                return visitor(&leaf);
            }
            let _ = scratch;
            let (_, _, bytes) = self.read_node_bytes(node.off, node.is_cluster, node.cluster_len)?;
            let leaf = LeafNodeView::parse(&bytes)?;
            return visitor(&leaf);
        }

        let routes: Vec<RouteEntry> = if !node.is_cluster && self.pipe_root.is_none() {
            let off = usize::try_from(node.off).map_err(|_| VzError::ValueOverflow)?;
            let table = RouteTableView::new(&self.boot_block[off..], node.entry_count)?;
            let start = match table.lower_bound(parent_hash, 0)? {
                Some((i, _)) => i,
                None => return Ok(()),
            };
            let mut v = Vec::new();
            for i in start..table.len() {
                let r = table.get(i)?;
                if r.min_parent_hash > parent_hash {
                    break;
                }
                v.push(r);
            }
            v
        } else {
            let (_, cnt, bytes) = self.read_node_bytes(node.off, node.is_cluster, node.cluster_len)?;
            let table = RouteTableView::new(&bytes, cnt as usize)?;
            let start = match table.lower_bound(parent_hash, 0)? {
                Some((i, _)) => i,
                None => return Ok(()),
            };
            let mut v = Vec::new();
            for i in start..table.len() {
                let r = table.get(i)?;
                if r.min_parent_hash > parent_hash {
                    break;
                }
                v.push(r);
            }
            v
        };

        for r in routes {
            self.visit_leaves_for_parent_with_scratch(
                NodeRef {
                    off: r.child_cluster_off,
                    is_cluster: true,
                    cluster_len: Some(r.child_cluster_len),
                    height: node.height - 1,
                    entry_count: r.subtree_count_lo as usize,
                },
                parent_hash,
                scratch,
                visitor,
            )?;
        }
        Ok(())
    }

    fn collect_all_in_run_raw(&self, run: &LsmRunDesc) -> Result<Vec<ResolvedEntry>, VzError> {
        let mut out = Vec::new();
        self.visit_all_leaves(
            NodeRef {
                off: run.root_offset,
                is_cluster: run.root_is_cluster,
                cluster_len: None,
                height: run.tree_height,
                entry_count: run.root_entry_count as usize,
            },
            &mut |leaf| {
                for i in 0..leaf.entry_count() {
                    let de = leaf.entry(i)?;
                    let explicit_parent = de
                        .entry_parent_path(leaf.ext_meta_pool())?
                        .and_then(|b| core::str::from_utf8(b).ok())
                        .unwrap_or("");
                    out.push(self.decode_resolved_entry(
                        &de,
                        leaf.name_pool(),
                        leaf.ext_meta_pool(),
                        explicit_parent,
                        run.run_generation,
                    )?);
                }
                Ok(())
            },
        )?;
        Ok(out)
    }

    fn visit_all_leaves<F>(&self, node: NodeRef, visitor: &mut F) -> Result<(), VzError>
    where
        F: FnMut(&LeafNodeView<'_>) -> Result<(), VzError>,
    {
        if node.height == 0 {
            if !node.is_cluster && self.pipe_root.is_none() {
                let off = usize::try_from(node.off).map_err(|_| VzError::ValueOverflow)?;
                let leaf = LeafNodeView::parse(&self.boot_block[off..])?;
                return visitor(&leaf);
            }
            let (_, _, bytes) = self.read_node_bytes(node.off, node.is_cluster, node.cluster_len)?;
            let leaf = LeafNodeView::parse(&bytes)?;
            return visitor(&leaf);
        }

        let routes: Vec<RouteEntry> = if !node.is_cluster && self.pipe_root.is_none() {
            let off = usize::try_from(node.off).map_err(|_| VzError::ValueOverflow)?;
            let table = RouteTableView::new(&self.boot_block[off..], node.entry_count)?;
            (0..table.len())
                .map(|i| table.get(i))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            let (_, cnt, bytes) = self.read_node_bytes(node.off, node.is_cluster, node.cluster_len)?;
            let table = RouteTableView::new(&bytes, cnt as usize)?;
            (0..table.len())
                .map(|i| table.get(i))
                .collect::<Result<Vec<_>, _>>()?
        };

        for r in routes {
            self.visit_all_leaves(
                NodeRef {
                    off: r.child_cluster_off,
                    is_cluster: true,
                    cluster_len: Some(r.child_cluster_len),
                    height: node.height - 1,
                    entry_count: r.subtree_count_lo as usize,
                },
                visitor,
            )?;
        }
        Ok(())
    }

    fn decode_resolved_entry(
        &self,
        de: &DirEntry,
        name_pool: &[u8],
        ext_meta_pool: &[u8],
        parent_path: &str,
        run_generation: u64,
    ) -> Result<ResolvedEntry, VzError> {
        let name_b = de.entry_name(name_pool)?;
        let name = core::str::from_utf8(name_b)
            .map_err(|_| VzError::BadFormat)?
            .to_string();

        let mut entry_id = de.entry_id_lo as u64;
        let mut ext_time = None;
        let mut ext_owner = None;
        let mut xattrs = Vec::new();
        let mut ext_codec = None;
        let mut schema_link = None;
        let mut sparse_extents = None;
        let mut resolved_parent = parent_path.to_string();

        if de.has_ext_meta() {
            let chain = de.entry_ext_meta(ext_meta_pool)?;
            for elem in TlvIter::new(chain) {
                let elem = elem?;
                if elem.tag == TAG_NOP {
                    break;
                }
                match elem.tag {
                    TAG_PARENT_PATH => {
                        if resolved_parent.is_empty() {
                            resolved_parent = core::str::from_utf8(elem.value)
                                .map_err(|_| VzError::BadFormat)?
                                .to_string();
                        }
                    }
                    crate::wire::TAG_INODE_HI => {
                        if elem.value.len() < 4 {
                            return Err(VzError::BadFormat);
                        }
                        let hi = read_le_u32(elem.value, 0) as u64;
                        entry_id = (hi << 32) | (de.entry_id_lo as u64);
                    }
                    TAG_EXT_TIME => ext_time = Some(ExtTime::from_bytes(elem.value)?),
                    TAG_EXT_OWNER => ext_owner = Some(decode_ext_owner(elem.value)?),
                    TAG_XATTR_LIST => xattrs = decode_xattr_list(elem.value)?,
                    TAG_EXT_CODEC => ext_codec = Some(decode_ext_codec(elem.value)?),
                    TAG_SCHEMA_LINK => schema_link = Some(decode_schema_link(elem.value)?),
                    TAG_SPARSE_EXTENTS => sparse_extents = Some(decode_sparse_extents(elem.value)?),
                    _ => {}
                }
            }
        }
        if (de.flags_and_codec & FLAG_INODE_64) != 0 && entry_id == de.entry_id_lo as u64 {
            // FLAG_INODE_64 set without TAG_INODE_HI is malformed only if hi wasn't 0;
            // full_entry_id already checks TAG_INODE_HI presence.
            entry_id = de.full_entry_id(ext_meta_pool)?;
        }

        let owner = if de.owner_idx < 255 {
            self.owners.get(de.owner_idx as usize).cloned()
        } else {
            ext_owner
        };

        let (size, stored_size) = match de.payload {
            DirPayload::Inline { len, .. } => (len as u64, len as u64),
            DirPayload::Ref {
                raw_size,
                stored_size,
                ..
            } => (raw_size, stored_size),
        };

        let (schema_id, schema_extra) = match schema_link {
            Some(l) => (Some(l.schema_id), l.extra),
            None => (None, Vec::new()),
        };

        Ok(ResolvedEntry {
            stat: VzStat {
                name,
                parent_path: resolved_parent,
                kind: de.kind(),
                mode: de.permissions(),
                size,
                stored_size,
                entry_id,
                mtime_ns: de.mtime_ns,
                ext_time,
                owner,
                codec: de.codec(),
                is_inline: de.is_inline(),
                is_sparse: de.is_sparse(),
                is_multi_cluster: de.is_multi_cluster(),
                has_hash_collision: de.has_hash_collision(),
                xattrs,
                schema_id,
            },
            dir_entry: *de,
            run_generation,
            ext_codec,
            sparse_extents,
            schema_extra,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn read_non_inline_bytes(
        &self,
        is_multi_cluster: bool,
        data_offset: u64,
        in_cluster_offset: u32,
        stored_size: u64,
        raw_size: u64,
        codec: u8,
        ext_codec: Option<&ExtCodecMeta>,
        generation: u64,
        entry_id: u64,
    ) -> Result<Vec<u8>, VzError> {
        if !is_multi_cluster {
            return self.read_single_cluster_payload(
                data_offset,
                in_cluster_offset,
                stored_size,
                raw_size,
                codec,
                ext_codec,
                generation,
                entry_id,
            );
        }
        let extents = self.read_chunk_table_at(data_offset, in_cluster_offset)?;
        let mut out = Vec::with_capacity(usize::try_from(raw_size).unwrap_or(0));
        for ext in extents {
            let chunk = self.read_single_cluster_payload(
                ext.cluster_offset,
                ext.in_cluster_offset,
                ext.stored_size,
                ext.raw_size,
                codec,
                ext_codec,
                generation,
                entry_id,
            )?;
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn read_single_cluster_payload(
        &self,
        cluster_offset: u64,
        in_cluster_offset: u32,
        stored_size: u64,
        raw_size: u64,
        codec: u8,
        ext_codec: Option<&ExtCodecMeta>,
        generation: u64,
        entry_id: u64,
    ) -> Result<Vec<u8>, VzError> {
        let mut out = Vec::new();
        self.read_single_cluster_payload_into(
            cluster_offset,
            in_cluster_offset,
            stored_size,
            raw_size,
            codec,
            ext_codec,
            generation,
            entry_id,
            &mut out,
        )?;
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn read_single_cluster_payload_into(
        &self,
        cluster_offset: u64,
        in_cluster_offset: u32,
        stored_size: u64,
        raw_size: u64,
        codec: u8,
        ext_codec: Option<&ExtCodecMeta>,
        generation: u64,
        entry_id: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), VzError> {
        let slen = usize::try_from(stored_size).map_err(|_| VzError::ValueOverflow)?;
        let rlen = usize::try_from(raw_size).map_err(|_| VzError::ValueOverflow)?;
        let payload_off = cluster_offset
            .checked_add(in_cluster_offset as u64)
            .ok_or(VzError::ValueOverflow)?;

        if self.crypto.is_none()
            && let Some(all) = self.reader.contiguous_bytes()
        {
            let p_off = usize::try_from(payload_off).map_err(|_| VzError::ValueOverflow)?;
            let p_end = p_off.checked_add(slen).ok_or(VzError::ValueOverflow)?;
            let stored = all.get(p_off..p_end).ok_or(VzError::BufferTooSmall)?;
            return decompress_payload_into(
                stored,
                out,
                rlen,
                codec,
                ext_codec,
                &self.dicts,
                Some(&self.dict_cache),
            );
        }

        if let Some(ref ctx) = self.crypto {
            let span = (in_cluster_offset as usize)
                .checked_add(slen)
                .ok_or(VzError::ValueOverflow)?;
            let mut buf = vec![0u8; span];
            self.reader.read_at(cluster_offset, &mut buf)?;
            let chdr = ClusterHeader::from_bytes(&buf)?;
            if chdr.sync_magic != MAGIC_CLUSTER {
                return Err(VzError::BadMagic);
            }
            let compressed = ctx.decrypt_payload(
                generation,
                chdr.cluster_seq,
                entry_id,
                &buf[in_cluster_offset as usize..],
            )?;
            return decompress_payload_into(
                &compressed,
                out,
                rlen,
                codec,
                ext_codec,
                &self.dicts,
                Some(&self.dict_cache),
            );
        }

        if codec == crate::wire::CODEC_NONE && ext_codec.is_none() {
            out.resize(slen, 0);
            return self.reader.read_at(payload_off, out);
        }

        let mut stored = vec![0u8; slen];
        self.reader.read_at(payload_off, &mut stored)?;
        decompress_payload_into(
            &stored,
            out,
            rlen,
            codec,
            ext_codec,
            &self.dicts,
            Some(&self.dict_cache),
        )
    }

    pub(crate) fn read_raw_stored_bytes(&self, offset: u64, len: usize) -> Result<Vec<u8>, VzError> {
        let mut out = vec![0u8; len];
        self.reader.read_at(offset, &mut out)?;
        Ok(out)
    }

    pub(crate) fn read_encrypted_cluster_chunk(
        &self,
        cluster_offset: u64,
        in_cluster_offset: u32,
        slen: usize,
        generation: u64,
        entry_id: u64,
    ) -> Result<Vec<u8>, VzError> {
        let ctx = self.crypto.as_ref().ok_or(VzError::CryptoError)?;
        let span = (in_cluster_offset as usize)
            .checked_add(slen)
            .ok_or(VzError::ValueOverflow)?;
        let mut buf = vec![0u8; span];
        self.reader.read_at(cluster_offset, &mut buf)?;
        let chdr = ClusterHeader::from_bytes(&buf)?;
        if chdr.sync_magic != MAGIC_CLUSTER {
            return Err(VzError::BadMagic);
        }
        ctx.decrypt_payload(
            generation,
            chdr.cluster_seq,
            entry_id,
            &buf[in_cluster_offset as usize..],
        )
    }

    pub(crate) fn read_chunk_table_at(
        &self,
        cluster_offset: u64,
        in_cluster_offset: u32,
    ) -> Result<Vec<ChunkExtent>, VzError> {
        let cluster_buf = read_cluster_at(&self.reader, cluster_offset)?;
        let (_, _, _) = validate_cluster(&cluster_buf)?;
        let rel = in_cluster_offset as usize;
        if rel >= cluster_buf.len() {
            return Err(VzError::BufferTooSmall);
        }
        let (elem, _) = crate::wire::tlv_next(&cluster_buf[rel..])?;
        if elem.tag != TAG_CHUNK_TABLE {
            return Err(VzError::BadFormat);
        }
        decode_chunk_table(elem.value)
    }
}

// ============================================================================
// CLUSTER SCANNING, RECOVERY, VERIFICATION & REPAIR
// ============================================================================

fn read_cluster_at<R: RangeReader>(reader: &R, offset: u64) -> Result<Vec<u8>, VzError> {
    let mut hdr_buf = [0u8; ClusterHeader::SIZE];
    reader.read_at(offset, &mut hdr_buf)?;
    let hdr = ClusterHeader::from_bytes(&hdr_buf)?;
    if hdr.sync_magic != MAGIC_CLUSTER {
        return Err(VzError::BadMagic);
    }
    let clen = usize::try_from(hdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
    if clen < ClusterHeader::SIZE + ClusterFooter::SIZE {
        return Err(VzError::BadFormat);
    }
    let mut full = vec![0u8; clen];
    full[..ClusterHeader::SIZE].copy_from_slice(&hdr_buf);
    reader.read_at(offset + ClusterHeader::SIZE as u64, &mut full[ClusterHeader::SIZE..])?;
    Ok(full)
}

fn read_tail_cluster<R: RangeReader>(reader: &R, total_len: u64) -> Result<Vec<u8>, VzError> {
    if total_len < ClusterHeader::SIZE as u64 + ClusterFooter::SIZE as u64 {
        return Err(VzError::BufferTooSmall);
    }
    let mut ftr_buf = [0u8; ClusterFooter::SIZE];
    reader.read_at(total_len - ClusterFooter::SIZE as u64, &mut ftr_buf)?;
    let ftr = ClusterFooter::from_bytes(&ftr_buf)?;
    if ftr.footer_magic != MAGIC_FOOTER {
        return Err(VzError::BadMagic);
    }
    let start = total_len
        .checked_sub(ftr.cluster_len)
        .ok_or(VzError::BadFormat)?;
    let clen = usize::try_from(ftr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
    let mut buf = vec![0u8; clen];
    reader.read_at(start, &mut buf)?;
    Ok(buf)
}

pub(crate) fn parse_dir_node_body(body: &[u8]) -> Result<(u8, u32, &[u8]), VzError> {
    for elem in TlvIter::new(body) {
        let elem = elem?;
        if elem.tag == TAG_DIR_NODE {
            if elem.value.len() < 8 {
                return Err(VzError::BufferTooSmall);
            }
            let level = elem.value[0];
            let count = read_le_u32(elem.value, 4);
            let payload = &elem.value[8..];
            if level >= 1 {
                let expected = (count as usize)
                    .checked_mul(RouteEntry::SIZE)
                    .ok_or(VzError::ValueOverflow)?;
                if payload.len() < expected + 4 {
                    return Err(VzError::BufferTooSmall);
                }
                let stored_crc = read_le_u32(payload, expected);
                let calc = crc32c(&elem.value[..8 + expected]);
                if calc != stored_crc {
                    return Err(VzError::CrcMismatch);
                }
                return Ok((level, count, &payload[..expected]));
            }
            return Ok((level, count, payload));
        }
    }
    Err(VzError::NotFound)
}

/// Walks all clusters backward from EOF via `ClusterFooter::cluster_len`.
pub fn walk_clusters_reverse<R: RangeReader>(reader: &R) -> Result<Vec<(u64, ClusterHeader)>, VzError> {
    let mut boot = [0u8; BootHeader::SIZE];
    reader.read_at(0, &mut boot)?;
    let hdr = BootHeader::from_bytes(&boot)?;
    let (active, _) = hdr.select_active(SUPPORTED_INCOMPAT)?;
    let boot_end = active.boot_block_size as u64;
    let mut pos = reader.total_len()?;
    let mut out = Vec::new();

    while pos > boot_end {
        if pos < boot_end + (ClusterHeader::SIZE + ClusterFooter::SIZE) as u64 {
            return Err(VzError::BadFormat);
        }
        let mut ftr_buf = [0u8; ClusterFooter::SIZE];
        reader.read_at(pos - ClusterFooter::SIZE as u64, &mut ftr_buf)?;
        let ftr = ClusterFooter::from_bytes(&ftr_buf)?;
        if ftr.footer_magic != MAGIC_FOOTER {
            return Err(VzError::BadMagic);
        }
        let start = pos
            .checked_sub(ftr.cluster_len)
            .ok_or(VzError::BadFormat)?;
        if start < boot_end {
            return Err(VzError::BadFormat);
        }
        let clen = usize::try_from(ftr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
        let mut cbuf = vec![0u8; clen];
        reader.read_at(start, &mut cbuf)?;
        let (chdr, _, _) = validate_cluster(&cbuf)?;
        out.push((start, chdr));
        pos = start;
    }
    out.reverse();
    Ok(out)
}

/// Scans forward from `start_offset` for valid `MAGIC_CLUSTER` clusters, recovering sync after gaps.
pub fn scan_clusters_forward<R: RangeReader>(
    reader: &R,
    start_offset: u64,
) -> Result<Vec<(u64, ClusterHeader)>, VzError> {
    let total = reader.total_len()?;
    let magic_bytes = MAGIC_CLUSTER.to_le_bytes();
    let mut out = Vec::new();
    let mut pos = start_offset;
    let mut hdr_buf = [0u8; ClusterHeader::SIZE];

    while pos + (ClusterHeader::SIZE + ClusterFooter::SIZE) as u64 <= total {
        reader.read_at(pos, &mut hdr_buf)?;
        if hdr_buf[..8] == magic_bytes
            && let Ok(chdr) = ClusterHeader::from_bytes(&hdr_buf)
            && chdr.cluster_len >= (ClusterHeader::SIZE + ClusterFooter::SIZE) as u64
            && pos + chdr.cluster_len <= total
            && let Ok(clen) = usize::try_from(chdr.cluster_len)
        {
            let mut cbuf = vec![0u8; clen];
            if reader.read_at(pos, &mut cbuf).is_ok() && validate_cluster(&cbuf).is_ok() {
                out.push((pos, chdr));
                pos += chdr.cluster_len;
                continue;
            }
        }
        pos += 8;
    }
    Ok(out)
}

/// Performs full verification of Boot Block, Boot ECC, cluster links/CRCs, data manifests,
/// `DirNode` CRCs, and RS parity stripes.
pub fn verify_archive<R: RangeReader>(
    reader: &R,
    encryption: Option<EncryptionKey>,
) -> Result<VerifyReport, VzError> {
    let mut report = VerifyReport::default();
    let mut boot = vec![0u8; DEFAULT_BOOT_SIZE];
    reader.read_at(0, &mut boot)?;

    let boot_hdr_raw = BootHeader::from_bytes(&boot);
    let ecc_enabled = boot_hdr_raw
        .as_ref()
        .ok()
        .and_then(|h| h.select_active(0xFFFF).ok())
        .is_none_or(|(s, _)| (s.compat_flags & COMPAT_BOOT_ECC) != 0);

    if ecc_enabled {
        let mut test_boot = boot.clone();
        match boot_ecc_verify_and_repair(&mut test_boot) {
            Ok(None) => report.boot_ecc_ok = true,
            Ok(Some(p)) => {
                report.boot_ecc_ok = true;
                report.boot_ecc_repaired_page = Some(p);
            }
            Err(e) => {
                report.boot_ecc_ok = false;
                report
                    .errors
                    .push(format!("boot ECC verification failed: {e}"));
            }
        }
    } else {
        report.boot_ecc_ok = true;
    }

    let vz = match VzReader::open_with_options(
        reader,
        VzReaderOptions {
            encryption,
            repair_boot_ecc: true,
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            report.errors.push(format!("open failed: {e}"));
            return Ok(report);
        }
    };

    let boot_end = vz.active_slot().boot_block_size as u64;
    let total_len = reader.total_len()?;
    let mut pos = boot_end;
    let mut expected_prev = 0u64;
    let mut expected_seq = 0u64;
    let mut parity_stripes_seen: HashSet<u64> = HashSet::new();

    while pos < total_len {
        let cbuf = match read_cluster_at(reader, pos) {
            Ok(b) => b,
            Err(e) => {
                report
                    .errors
                    .push(format!("cluster at offset {pos:#x} unreadable: {e}"));
                break;
            }
        };
        let (chdr, body, _) = match validate_cluster(&cbuf) {
            Ok(v) => v,
            Err(e) => {
                report
                    .errors
                    .push(format!("cluster at offset {pos:#x} corrupt: {e}"));
                break;
            }
        };
        if chdr.prev_cluster_len != expected_prev || chdr.cluster_seq != expected_seq {
            report.errors.push(format!(
                "cluster chain mismatch at {pos:#x}: seq={} (exp {}), prev_len={} (exp {})",
                chdr.cluster_seq, expected_seq, chdr.prev_cluster_len, expected_prev
            ));
        }

        for elem in TlvIter::new(body) {
            let elem = match elem {
                Ok(e) => e,
                Err(e) => {
                    report
                        .errors
                        .push(format!("cluster TLV error at {pos:#x}: {e}"));
                    break;
                }
            };
            match elem.tag {
                TAG_DATA_MANIFEST => {
                    let dm = DataManifestHeader::from_bytes(elem.value)?;
                    let rel = dm.payload_rel_off as usize;
                    let slen = usize::try_from(dm.stored_size)
                        .map_err(|_| VzError::ValueOverflow)?;
                    if rel + slen > elem.value.len() {
                        report
                            .errors
                            .push(format!("manifest bounds overflow at {pos:#x}"));
                    } else if crc32c(&elem.value[rel..rel + slen]) != dm.payload_crc32c {
                        report
                            .errors
                            .push(format!("payload CRC mismatch in cluster {pos:#x}"));
                    }
                }
                TAG_DIR_NODE => {
                    if let Err(e) = parse_dir_node_body(body) {
                        report
                            .errors
                            .push(format!("DirNode CRC error at {pos:#x}: {e}"));
                    } else if elem.value.first().copied() == Some(0)
                        && let Err(e) = LeafNodeView::parse(&elem.value[8..])
                    {
                        report
                            .errors
                            .push(format!("LeafNode CRC error at {pos:#x}: {e}"));
                    }
                }
                TAG_PARITY_CLUSTER => {
                    if let Ok(Some((manifest, _, _))) = parse_parity_cluster_body(body)
                        && parity_stripes_seen.insert(manifest.first_cluster_seq)
                    {
                        report.parity_stripes_checked += 1;
                    }
                }
                _ => {}
            }
        }

        report.clusters_checked += 1;
        expected_prev = chdr.cluster_len;
        expected_seq += 1;
        pos += chdr.cluster_len;
    }

    Ok(report)
}

/// Repairs a `.vz` archive stored in a mutable byte slice (`Boot ECC` + `RS_GF256` clusters).
pub fn repair_slice(buf: &mut [u8]) -> Result<RepairReport, VzError> {
    let mut cursor = std::io::Cursor::new(buf);
    repair_read_write_seek(&mut cursor)
}

/// Repairs a `.vz` archive file in-place (`Boot ECC` + `RS_GF256` clusters).
pub fn repair_file(file: &mut std::fs::File) -> Result<RepairReport, VzError> {
    repair_read_write_seek(file)
}

/// Generic in-place repair over any `Read + Write + Seek` backing store.
pub fn repair_read_write_seek<S: Read + Write + Seek>(io: &mut S) -> Result<RepairReport, VzError> {
    let mut report = RepairReport::default();
    let total_len = io.seek(SeekFrom::End(0)).map_err(|_| VzError::IoError)?;
    if total_len < DEFAULT_BOOT_SIZE as u64 {
        return Err(VzError::BufferTooSmall);
    }

    let mut boot = vec![0u8; DEFAULT_BOOT_SIZE];
    io.seek(SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
    io.read_exact(&mut boot).map_err(|_| VzError::IoError)?;

    let pre_ecc = BootHeader::from_bytes(&boot)
        .ok()
        .and_then(|h| h.select_active(0xFFFF).ok().map(|(s, _)| s.compat_flags))
        .is_none_or(|f| (f & COMPAT_BOOT_ECC) != 0);

    if pre_ecc
        && let Some(page) = boot_ecc_verify_and_repair(&mut boot)?
    {
        io.seek(SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
        io.write_all(&boot).map_err(|_| VzError::IoError)?;
        report.boot_page_repaired = Some(page);
    }

    let boot_hdr = BootHeader::from_bytes(&boot)?;
    let (active, _) = boot_hdr.select_active(0xFFFF)?;
    let boot_size = active.boot_block_size as u64;

    // Read entire stream area into an indexed scanner via seek+read so we can repair RS stripes
    // even when ClusterHeaders are zeroed!
    // Scan forward for valid MAGIC_CLUSTER headers across the archive.
    let mut found_parity_stripes: HashMap<u64, (u64, u32)> = HashMap::new(); // first_seq -> (p0_off, p_clen)
    let magic_bytes = MAGIC_CLUSTER.to_le_bytes();
    let mut pos = boot_size;
    let mut hdr_buf = [0u8; ClusterHeader::SIZE];

    while pos + (ClusterHeader::SIZE + ClusterFooter::SIZE) as u64 <= total_len {
        io.seek(SeekFrom::Start(pos)).map_err(|_| VzError::IoError)?;
        io.read_exact(&mut hdr_buf).map_err(|_| VzError::IoError)?;
        if hdr_buf[..8] == magic_bytes
            && let Ok(chdr) = ClusterHeader::from_bytes(&hdr_buf)
            && chdr.cluster_len >= (ClusterHeader::SIZE + ClusterFooter::SIZE) as u64
            && pos + chdr.cluster_len <= total_len
            && let Ok(clen) = usize::try_from(chdr.cluster_len)
        {
            let mut cbuf = vec![0u8; clen];
            io.seek(SeekFrom::Start(pos)).map_err(|_| VzError::IoError)?;
            io.read_exact(&mut cbuf).map_err(|_| VzError::IoError)?;
            if let Ok((_, body, _)) = validate_cluster(&cbuf) {
                if let Some((manifest, _, _)) = parse_parity_cluster_body(body)? {
                    let p0_off = pos
                        .checked_sub(manifest.parity_index as u64 * chdr.cluster_len)
                        .ok_or(VzError::BadFormat)?;
                    found_parity_stripes
                        .entry(manifest.first_cluster_seq)
                        .or_insert((p0_off, clen as u32));
                }
                pos += chdr.cluster_len;
                continue;
            }
        }
        pos += 8;
    }

    // Reconstruct each RS stripe that has any damaged data or parity clusters.
    let mut stripe_keys: Vec<u64> = found_parity_stripes.keys().copied().collect();
    stripe_keys.sort_unstable();

    for first_seq in stripe_keys {
        let (p0_off, p_clen) = found_parity_stripes[&first_seq];
        // Read first intact parity cluster to get Manifest + data offsets.
        let mut first_manifest = None;
        let mut first_offsets = Vec::new();
        let mut parity_raw_bufs: Vec<Option<(u16, Vec<u8>)>> = Vec::new();

        // Discover M from the first surviving parity cluster.
        let mut probe_idx = 0u16;
        loop {
            let p_off = p0_off + probe_idx as u64 * p_clen as u64;
            if p_off + p_clen as u64 > total_len {
                break;
            }
            let mut pbuf = vec![0u8; p_clen as usize];
            io.seek(SeekFrom::Start(p_off)).map_err(|_| VzError::IoError)?;
            io.read_exact(&mut pbuf).map_err(|_| VzError::IoError)?;
            if let Ok((_, body, _)) = validate_cluster(&pbuf)
                && let Some((manifest, offs, payload)) = parse_parity_cluster_body(body)?
                && manifest.first_cluster_seq == first_seq
            {
                let m = manifest.parity_clusters_m as usize;
                if parity_raw_bufs.is_empty() {
                    parity_raw_bufs = vec![None; m];
                }
                parity_raw_bufs[manifest.parity_index as usize] =
                    Some((manifest.parity_index, payload.to_vec()));
                if first_manifest.is_none() {
                    first_manifest = Some(manifest);
                    first_offsets = offs;
                }
            }
            probe_idx += 1;
            if let Some(ref fm) = first_manifest {
                if probe_idx >= fm.parity_clusters_m {
                    break;
                }
            } else if probe_idx >= 256 {
                break;
            }
        }

        let Some(manifest) = first_manifest else {
            continue;
        };
        let k = manifest.data_clusters_k as usize;
        let m = manifest.parity_clusters_m as usize;
        let max_len = usize::try_from(manifest.max_cluster_len)
            .map_err(|_| VzError::ValueOverflow)?;

        let mut data_slots: Vec<Option<Vec<u8>>> = Vec::with_capacity(k);
        for j in 0..k {
            let d_off = first_offsets[j];
            let next_off = if j + 1 < k {
                first_offsets[j + 1]
            } else {
                p0_off
            };
            let span = next_off.saturating_sub(d_off).min(max_len as u64) as usize;
            if span < ClusterHeader::SIZE + ClusterFooter::SIZE {
                data_slots.push(None);
                continue;
            }
            let mut dbuf = vec![0u8; span];
            io.seek(SeekFrom::Start(d_off)).map_err(|_| VzError::IoError)?;
            io.read_exact(&mut dbuf).map_err(|_| VzError::IoError)?;
            if let Ok((dhdr, _, _)) = validate_cluster(&dbuf) {
                let dlen = dhdr.cluster_len as usize;
                data_slots.push(Some(dbuf[..dlen].to_vec()));
            } else {
                data_slots.push(None);
            }
        }

        let had_missing_data: Vec<bool> = data_slots.iter().map(Option::is_none).collect();
        let repaired_data =
            recover_rs_gf256_stripe(&mut data_slots, &parity_raw_bufs, k, m, max_len)?;
        report.data_clusters_repaired += repaired_data;

        for (j, was_missing) in had_missing_data.iter().enumerate() {
            if *was_missing
                && let Some(ref rec_bytes) = data_slots[j]
            {
                io.seek(SeekFrom::Start(first_offsets[j]))
                    .map_err(|_| VzError::IoError)?;
                io.write_all(rec_bytes).map_err(|_| VzError::IoError)?;
            }
        }

        // Re-encode and repair any damaged parity clusters in this stripe.
        let any_bad_parity = parity_raw_bufs.iter().any(Option::is_none);
        if any_bad_parity {
            let data_refs: Vec<&[u8]> = data_slots
                .iter()
                .map(|o| o.as_deref().ok_or(VzError::CorruptUnrecoverable))
                .collect::<Result<Vec<_>, _>>()?;
            let last_data = data_refs[k - 1];
            let last_hdr = ClusterHeader::from_bytes(last_data)?;
            let prev_len_for_p = last_hdr.cluster_len;
            let start_p_seq = last_hdr.cluster_seq + 1;
            let (rebuilt_parities, _) = encode_rs_gf256_stripe(
                &data_refs,
                &first_offsets,
                first_seq,
                m as u16,
                start_p_seq,
                prev_len_for_p,
            )?;
            for (p_idx, p_slot) in parity_raw_bufs.iter().enumerate() {
                if p_slot.is_none() {
                    let p_off = p0_off + p_idx as u64 * p_clen as u64;
                    io.seek(SeekFrom::Start(p_off))
                        .map_err(|_| VzError::IoError)?;
                    io.write_all(&rebuilt_parities[p_idx])
                        .map_err(|_| VzError::IoError)?;
                    report.parity_clusters_repaired += 1;
                }
            }
        }
    }

    io.flush().map_err(|_| VzError::IoError)?;
    Ok(report)
}
