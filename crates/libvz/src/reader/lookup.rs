use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{
    CachedNode, DirEntryRef, FastHasher, LookupTarget, NodeCache, NodeRef, ResolvedEntry,
    VerifiedSlice, VzReader, VzStat, parse_dir_node_body, read_cluster_at,
};

const MMAP_L1_SETS: usize = 64;
const BUF_L1_SETS: usize = 64;
const BUF_L1_MAX_PAYLOAD: usize = 256 * 1024;

type MmapL1Entry = (u64, u64, VerifiedSlice);
type BufL1Entry = Option<(u64, u64, Arc<CachedNode>)>;

const EMPTY_MMAP_L1_ENTRY: MmapL1Entry = (
    0,
    0,
    VerifiedSlice {
        start: 0,
        len: 0,
        entry_count: 0,
    },
);

struct MmapL1Cache {
    entries: [[MmapL1Entry; 2]; MMAP_L1_SETS],
    rr_bits: u64,
}

impl MmapL1Cache {
    const fn new() -> Self {
        Self {
            entries: [[EMPTY_MMAP_L1_ENTRY; 2]; MMAP_L1_SETS],
            rr_bits: 0,
        }
    }

    #[inline]
    fn get(&self, set_idx: usize, tag: u64, offset: u64) -> Option<VerifiedSlice> {
        for &(e_tag, e_off, vs) in &self.entries[set_idx] {
            if e_tag == tag && e_off == offset {
                return Some(vs);
            }
        }
        None
    }

    #[inline]
    fn insert(&mut self, set_idx: usize, tag: u64, offset: u64, vs: VerifiedSlice) {
        for (w, slot) in self.entries[set_idx].iter().enumerate() {
            if slot.0 == 0 || slot.0 != tag || slot.1 == offset {
                self.entries[set_idx][w] = (tag, offset, vs);
                return;
            }
        }
        let way = ((self.rr_bits >> set_idx) & 1) as usize;
        self.rr_bits ^= 1u64 << set_idx;
        self.entries[set_idx][way] = (tag, offset, vs);
    }
}

struct BufL1Cache {
    entries: [[BufL1Entry; 2]; BUF_L1_SETS],
    rr_bits: u64,
}

impl BufL1Cache {
    const fn new() -> Self {
        Self {
            entries: [const { [None, None] }; BUF_L1_SETS],
            rr_bits: 0,
        }
    }

    #[inline]
    fn insert(&mut self, set_idx: usize, tag: u64, offset: u64, node: Arc<CachedNode>) {
        for (w, slot) in self.entries[set_idx].iter().enumerate() {
            match slot {
                None => {
                    self.entries[set_idx][w] = Some((tag, offset, node));
                    return;
                }
                Some((e_tag, e_off, _)) if *e_tag != tag || *e_off == offset => {
                    self.entries[set_idx][w] = Some((tag, offset, node));
                    return;
                }
                _ => {}
            }
        }
        let way = ((self.rr_bits >> set_idx) & 1) as usize;
        self.rr_bits ^= 1u64 << set_idx;
        self.entries[set_idx][way] = Some((tag, offset, node));
    }
}

std::thread_local! {
    static MMAP_NODE_L1: RefCell<MmapL1Cache> = const { RefCell::new(MmapL1Cache::new()) };
    static BUF_NODE_L1: RefCell<BufL1Cache> = const { RefCell::new(BufL1Cache::new()) };
}

#[inline]
fn node_l1_slot(offset: u64, sets: usize) -> usize {
    ((offset >> 6).wrapping_mul(0x9E37_79B9_7F4A_7C15) as usize) & (sets - 1)
}
use crate::btree::{LeafNodeView, RouteTableView, validate_cluster};
use crate::error::VzError;
use crate::ext_meta::{
    ColumnMeta, LsmRunDesc, RawTlv, SchemaEntry, TensorMeta, Xattr, decode_ext_codec,
    decode_ext_owner, decode_schema_link, decode_sparse_extents, decode_xattr_list,
    normalize_dir_path, split_archive_path, split_archive_path_borrowed,
};
use crate::io::RangeReader;
use crate::wire::{
    ClusterHeader, DirEntry, DirPayload, ExtTime, FLAG_INODE_64, KIND_MASK, RouteEntry,
    TAG_EXT_CODEC, TAG_EXT_OWNER, TAG_EXT_TIME, TAG_NOP, TAG_PARENT_PATH, TAG_SCHEMA_LINK,
    TAG_SPARSE_EXTENTS, TAG_XATTR_LIST, TlvIter, read_le_u32,
};

impl<R: RangeReader> VzReader<R> {
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

    /// Returns all live entries across the archive (used by compaction, bulk extraction, and FUSE).
    pub fn list_all_live(&self) -> Result<Vec<ResolvedEntry>, VzError> {
        if self.lsm_runs.len() == 1 {
            let mut items = self.collect_all_in_run_raw(&self.lsm_runs[0])?;
            Self::resolve_missing_dir_parents(&self.hasher, std::slice::from_mut(&mut items))?;
            items.retain(|e| !e.dir_entry.is_tombstone());
            return Ok(items);
        }

        // Collect newest-to-oldest so global directory BFS resolves parent paths for overlay
        // tombstones and updates emitted without redundant KIND_DIR headers in delta runs.
        let mut runs_rev: Vec<Vec<ResolvedEntry>> = Vec::with_capacity(self.lsm_runs.len());
        let mut total_est = 0usize;
        for run in self.lsm_runs.iter().rev() {
            let r = self.collect_all_in_run_raw(run)?;
            total_est += r.len();
            runs_rev.push(r);
        }

        Self::resolve_missing_dir_parents(&self.hasher, &mut runs_rev)?;

        let mut seen: HashSet<(u64, String, String)> = HashSet::with_capacity(total_est);
        let mut out = Vec::with_capacity(total_est);
        for run_items in runs_rev {
            for entry in run_items {
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

    fn resolve_missing_dir_parents(
        hasher: &FastHasher,
        runs: &mut [Vec<ResolvedEntry>],
    ) -> Result<(), VzError> {
        if !runs
            .iter()
            .any(|run_items| run_items.iter().any(|e| e.stat.parent_path.is_empty()))
        {
            return Ok(());
        }
        let mut dir_paths_by_hash: HashMap<u64, String> = HashMap::new();
        let root_h = hasher.hash(b"/")?;
        dir_paths_by_hash.insert(root_h, "/".to_string());
        loop {
            let mut progressed = false;
            for run_items in runs.iter() {
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
                        let h = hasher.hash(full.as_bytes())?;
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
        for run_items in runs.iter_mut() {
            for entry in run_items {
                if entry.stat.parent_path.is_empty()
                    && let Some(p) = dir_paths_by_hash.get(&entry.dir_entry.parent_hash)
                {
                    entry.stat.parent_path = p.clone();
                }
            }
        }
        Ok(())
    }

    pub(crate) fn max_entry_id(&self) -> Result<u64, VzError> {
        let mut max_id = 0u64;
        for run in &self.lsm_runs {
            self.visit_all_leaves(
                NodeRef {
                    off: run.root_offset,
                    is_cluster: run.root_is_cluster,
                    cluster_len: None,
                    height: run.tree_height,
                    entry_count: run.root_entry_count as usize,
                },
                &mut |leaf| {
                    let ext_pool = leaf.ext_meta_pool();
                    for i in 0..leaf.entry_count() {
                        let de = leaf.entry(i)?;
                        let eid = if (de.flags_and_codec & FLAG_INODE_64) != 0 {
                            de.full_entry_id(ext_pool)?
                        } else {
                            de.entry_id_lo as u64
                        };
                        max_id = max_id.max(eid);
                    }
                    Ok(())
                },
            )?;
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

    fn with_cluster_node<T>(
        &self,
        offset: u64,
        expected_len: Option<u32>,
        f: impl FnOnce(&[u8], u32) -> Result<T, VzError>,
    ) -> Result<T, VzError> {
        let tag = self.cache_tag.load(Ordering::Acquire);
        match &self.node_cache {
            NodeCache::Contiguous { shards, mask } => {
                let all = self.reader.contiguous_bytes().ok_or(VzError::BadFormat)?;
                let l1_idx = node_l1_slot(offset, MMAP_L1_SETS);
                let l1_hit = MMAP_NODE_L1
                    .try_with(|cell| {
                        let Ok(cache) = cell.try_borrow() else {
                            return None;
                        };
                        cache.get(l1_idx, tag, offset)
                    })
                    .ok()
                    .flatten();
                if let Some(vs) = l1_hit {
                    let slice = all
                        .get(vs.start..vs.start + vs.len)
                        .ok_or(VzError::BufferTooSmall)?;
                    return f(slice, vs.entry_count);
                }

                let s_idx = NodeCache::shard_idx(offset, *mask);
                let mut vs_opt = None;
                if let Ok(guard) = shards[s_idx].0.read()
                    && let Some(&vs) = guard.get(&offset)
                {
                    vs_opt = Some(vs);
                }

                let vs = match vs_opt {
                    Some(hit) => hit,
                    None => {
                        let off_u = usize::try_from(offset).map_err(|_| VzError::ValueOverflow)?;
                        let cluster_slice = match expected_len {
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
                                let clen = usize::try_from(hdr.cluster_len)
                                    .map_err(|_| VzError::ValueOverflow)?;
                                let end =
                                    off_u.checked_add(clen).ok_or(VzError::ValueOverflow)?;
                                all.get(off_u..end).ok_or(VzError::BufferTooSmall)?
                            }
                        };
                        let (_, body, _) = validate_cluster(cluster_slice)?;
                        let (_level, count, payload) = parse_dir_node_body(body)?;
                        let start = (payload.as_ptr() as usize)
                            .checked_sub(all.as_ptr() as usize)
                            .ok_or(VzError::BadFormat)?;
                        let cand = VerifiedSlice {
                            start,
                            len: payload.len(),
                            entry_count: count,
                        };
                        if let Ok(mut guard) = shards[s_idx].0.write() {
                            *guard.entry(offset).or_insert(cand)
                        } else {
                            cand
                        }
                    }
                };

                if self.cache_tag.load(Ordering::Acquire) == tag {
                    let _ = MMAP_NODE_L1.try_with(|cell| {
                        if let Ok(mut cache) = cell.try_borrow_mut() {
                            cache.insert(l1_idx, tag, offset, vs);
                        }
                    });
                }
                let slice = all
                    .get(vs.start..vs.start + vs.len)
                    .ok_or(VzError::BufferTooSmall)?;
                f(slice, vs.entry_count)
            }
            NodeCache::Buffered { shards, mask } => {
                let l1_idx = node_l1_slot(offset, BUF_L1_SETS);
                let mut f_opt = Some(f);
                let l1_res = BUF_NODE_L1
                    .try_with(|cell| -> Option<Result<T, VzError>> {
                        let cache = cell.try_borrow().ok()?;
                        for slot in &cache.entries[l1_idx] {
                            if let Some((e_tag, e_off, arc_node)) = slot
                                && *e_tag == tag
                                && *e_off == offset
                            {
                                let func = f_opt.take()?;
                                return Some(func(&arc_node.payload, arc_node.entry_count));
                            }
                        }
                        None
                    })
                    .ok()
                    .flatten();
                if let Some(res) = l1_res {
                    return res;
                }
                let Some(func) = f_opt.take() else {
                    return Err(VzError::IoError);
                };

                let s_idx = NodeCache::shard_idx(offset, *mask);
                let mut arc_opt = None;
                if let Ok(guard) = shards[s_idx].0.read()
                    && let Some(hit) = guard.get(&offset)
                {
                    arc_opt = Some(Arc::clone(hit));
                }

                let node = match arc_opt {
                    Some(hit) => hit,
                    None => {
                        let cluster_buf = match expected_len {
                            Some(clen) => {
                                let mut buf = vec![0u8; clen as usize];
                                self.reader.read_at(offset, &mut buf)?;
                                buf
                            }
                            None => read_cluster_at(&self.reader, offset)?,
                        };
                        let (_, body, _) = validate_cluster(&cluster_buf)?;
                        let (_level, count, payload) = parse_dir_node_body(body)?;
                        let cand = Arc::new(CachedNode {
                            entry_count: count,
                            payload: Box::from(payload),
                        });
                        if let Ok(mut guard) = shards[s_idx].0.write() {
                            Arc::clone(guard.entry(offset).or_insert_with(|| Arc::clone(&cand)))
                        } else {
                            cand
                        }
                    }
                };

                if node.payload.len() <= BUF_L1_MAX_PAYLOAD
                    && self.cache_tag.load(Ordering::Acquire) == tag
                {
                    let _ = BUF_NODE_L1.try_with(|cell| {
                        if let Ok(mut cache) = cell.try_borrow_mut() {
                            cache.insert(l1_idx, tag, offset, Arc::clone(&node));
                        }
                    });
                }
                func(&node.payload, node.entry_count)
            }
        }
    }

    #[inline]
    fn parse_boot_leaf(&self, off: usize) -> Result<LeafNodeView<'_>, VzError> {
        if off >= self.boot_block.len() {
            return Err(VzError::BufferTooSmall);
        }
        let slice = &self.boot_block[off..];
        if off != 0 && self.boot_root_verified.load(Ordering::Acquire) == off as u64 {
            LeafNodeView::parse_trusted(slice)
        } else {
            let leaf = LeafNodeView::parse(slice)?;
            if off != 0 {
                self.boot_root_verified.store(off as u64, Ordering::Release);
            }
            Ok(leaf)
        }
    }

    pub(super) fn resolve_target(&self, path: &str) -> Result<LookupTarget, VzError> {
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
                    // Cluster CRC32C was already validated when populating `node_cache`.
                    return self.with_cluster_node(cur_off, cur_cluster_len, |payload, _cnt| {
                        let leaf = LeafNodeView::parse_trusted(payload)?;
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
                        Ok(None)
                    });
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
                    let leaf = self.parse_boot_leaf(off)?;
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
                self.with_cluster_node(cur_off, cur_cluster_len, |payload, cnt| {
                    let table = RouteTableView::new(payload, cnt as usize)?;
                    table.lookup(parent_hash, name_hash)
                })?
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
                if cur_is_cluster {
                    return self.with_cluster_node(cur_off, cur_cluster_len, |payload, _cnt| {
                        let leaf = LeafNodeView::parse_trusted(payload)?;
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
                        Ok(None)
                    });
                }
                let leaf = if let Some((_, _, ref pipe_bytes)) = self.pipe_root {
                    LeafNodeView::parse(pipe_bytes.as_slice())?
                } else {
                    let off = usize::try_from(cur_off).map_err(|_| VzError::ValueOverflow)?;
                    self.parse_boot_leaf(off)?
                };
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
                self.with_cluster_node(cur_off, cur_cluster_len, |payload, cnt| {
                    let table = RouteTableView::new(payload, cnt as usize)?;
                    table.lookup(parent_hash, name_hash)
                })?
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
                let leaf = self.parse_boot_leaf(off)?;
                return visitor(&leaf);
            }
            if node.is_cluster {
                return self.with_cluster_node(node.off, node.cluster_len, |payload, _cnt| {
                    let leaf = LeafNodeView::parse_trusted(payload)?;
                    visitor(&leaf)
                });
            }
            if let Some((_, _, ref pipe_bytes)) = self.pipe_root {
                let leaf = LeafNodeView::parse(pipe_bytes)?;
                return visitor(&leaf);
            }
            let _ = scratch;
            return Err(VzError::BadFormat);
        }

        let mut routes: Vec<RouteEntry> = Vec::new();
        let collect_routes = |table: RouteTableView<'_>, out: &mut Vec<RouteEntry>| -> Result<(), VzError> {
            let Some((start, _)) = table.lower_bound(parent_hash, 0)? else {
                return Ok(());
            };
            for i in start..table.len() {
                let r = table.get(i)?;
                if r.min_parent_hash > parent_hash {
                    break;
                }
                out.push(r);
            }
            Ok(())
        };
        if !node.is_cluster && self.pipe_root.is_none() {
            let off = usize::try_from(node.off).map_err(|_| VzError::ValueOverflow)?;
            let table = RouteTableView::new(&self.boot_block[off..], node.entry_count)?;
            collect_routes(table, &mut routes)?;
        } else if node.is_cluster {
            self.with_cluster_node(node.off, node.cluster_len, |payload, cnt| {
                let table = RouteTableView::new(payload, cnt as usize)?;
                collect_routes(table, &mut routes)
            })?;
        } else if let Some((_, cnt, ref pipe_bytes)) = self.pipe_root {
            let table = RouteTableView::new(pipe_bytes, cnt as usize)?;
            collect_routes(table, &mut routes)?;
        } else {
            return Err(VzError::BadFormat);
        }
        if routes.is_empty() {
            return Ok(());
        }

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
                let leaf = self.parse_boot_leaf(off)?;
                return visitor(&leaf);
            }
            if node.is_cluster {
                return self.with_cluster_node(node.off, node.cluster_len, |payload, _cnt| {
                    let leaf = LeafNodeView::parse_trusted(payload)?;
                    visitor(&leaf)
                });
            }
            if let Some((_, _, ref pipe_bytes)) = self.pipe_root {
                let leaf = LeafNodeView::parse(pipe_bytes)?;
                return visitor(&leaf);
            }
            return Err(VzError::BadFormat);
        }

        let routes: Vec<RouteEntry> = if !node.is_cluster && self.pipe_root.is_none() {
            let off = usize::try_from(node.off).map_err(|_| VzError::ValueOverflow)?;
            let table = RouteTableView::new(&self.boot_block[off..], node.entry_count)?;
            (0..table.len())
                .map(|i| table.get(i))
                .collect::<Result<Vec<_>, _>>()?
        } else if node.is_cluster {
            self.with_cluster_node(node.off, node.cluster_len, |payload, cnt| {
                let table = RouteTableView::new(payload, cnt as usize)?;
                (0..table.len())
                    .map(|i| table.get(i))
                    .collect::<Result<Vec<_>, _>>()
            })?
        } else if let Some((_, cnt, ref pipe_bytes)) = self.pipe_root {
            let table = RouteTableView::new(pipe_bytes, cnt as usize)?;
            (0..table.len())
                .map(|i| table.get(i))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            return Err(VzError::BadFormat);
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
        let mut extra_ext_tlvs = Vec::new();
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
                    crate::wire::TAG_VOID => {}
                    other => extra_ext_tlvs.push(RawTlv {
                        tag: other,
                        value: elem.value.to_vec(),
                    }),
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
            extra_ext_tlvs,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::io::CountingRangeReader;
    use crate::writer::{VzWriter, VzWriterConfig};

    #[test]
    fn test_buffered_large_leaf_l1_cache_invalidate_and_reentrant_readdir_visit() {
        let cfg = VzWriterConfig {
            max_leaf_entries: 256,
            max_route_entries: 64,
            ..Default::default()
        };
        let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
        let n_files = 600usize;
        let mut paths = Vec::with_capacity(n_files);
        for i in 0..n_files {
            let p = format!(
                "/dir_{:02}/very_long_entry_filename_padding_to_exceed_8k_leaf_{i:04}_payload_tag.bin",
                i % 4
            );
            let data = format!("content-{i:04}").into_bytes();
            w.add_file(&p, &data).unwrap();
            paths.push((p, data));
        }
        let arc = w.finish().unwrap().into_inner();

        let counting = CountingRangeReader::new(arc.as_slice());
        let reader = VzReader::open(counting).unwrap();
        assert!(
            reader.active_slot().tree_height >= 1,
            "expected multi-level tree with clustered leaves"
        );

        let target = &paths[250];
        reader.reader().reset();
        let st1 = reader.stat(&target.0).unwrap();
        assert_eq!(st1.size, target.1.len() as u64);
        assert!(reader.reader().reads() >= 1);

        // Second lookup must hit thread-local 2-way Arc L1 with zero backing reads
        // even though each leaf node payload exceeds 8 KiB.
        reader.reader().reset();
        let st2 = reader.stat(&target.0).unwrap();
        assert_eq!(st2, st1);
        assert_eq!(reader.reader().reads(), 0);

        // clear_index_cache bumps cache_tag and invalidates L1 and L2 cleanly.
        reader.clear_index_cache();
        reader.reader().reset();
        let st3 = reader.stat(&target.0).unwrap();
        assert_eq!(st3, st1);
        assert!(reader.reader().reads() >= 1);

        // Re-entrant `readdir_visit` calling `read_file` inside visitor on Buffered cache.
        let mut visited = 0usize;
        reader
            .readdir_visit("/dir_02", |entry| {
                let full = format!("/dir_02/{}", entry.name);
                let got = reader.read_file(&full)?;
                assert!(got.starts_with(b"content-"));
                visited += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(visited, n_files / 4);

        // Also test re-entrant `readdir_visit` + `read_file` on Contiguous reader.
        let contig_reader = VzReader::open(arc).unwrap();
        let mut contig_visited = 0usize;
        contig_reader
            .readdir_visit("/dir_02", |entry| {
                let full = format!("/dir_02/{}", entry.name);
                let got = contig_reader.read_file(&full)?;
                assert!(got.starts_with(b"content-"));
                contig_visited += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(contig_visited, n_files / 4);
    }
}
