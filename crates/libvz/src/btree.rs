use core::cmp::Ordering;

use crate::crc::{crc32c, crc32c_update};
use crate::error::VzError;
use crate::wire::{
    ClusterFooter, ClusterHeader, DirEntry, LeafNodeHeader, MAGIC_CLUSTER, MAGIC_FOOTER,
    RouteEntry, read_le_u64,
};

/// Compares two 128-bit composite B+Tree keys `(parent_hash, name_hash)`.
#[inline]
pub fn key128_cmp(a_parent: u64, a_name: u64, b_parent: u64, b_name: u64) -> Ordering {
    match a_parent.cmp(&b_parent) {
        Ordering::Equal => a_name.cmp(&b_name),
        ord => ord,
    }
}

/// Validates a Cluster slice's header magic, alignment, footer mirror, and CRC32C.
///
/// On success, returns `(header, body_tlv_slice, footer)`.
pub fn validate_cluster(buf: &[u8]) -> Result<(ClusterHeader, &[u8], ClusterFooter), VzError> {
    let min_len = ClusterHeader::SIZE + ClusterFooter::SIZE;
    if buf.len() < min_len {
        return Err(VzError::BufferTooSmall);
    }
    let hdr = ClusterHeader::from_bytes(buf)?;
    if hdr.sync_magic != MAGIC_CLUSTER {
        return Err(VzError::BadMagic);
    }
    if hdr.cluster_len < min_len as u64 || (hdr.cluster_len & 7) != 0 {
        return Err(VzError::BadFormat);
    }
    let clen = usize::try_from(hdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
    if buf.len() < clen {
        return Err(VzError::BufferTooSmall);
    }
    let ftr = ClusterFooter::from_bytes(&buf[clen - ClusterFooter::SIZE..clen])?;
    if ftr.footer_magic != MAGIC_FOOTER {
        return Err(VzError::BadMagic);
    }
    if ftr.cluster_len != hdr.cluster_len {
        return Err(VzError::BadFormat);
    }
    let calc_crc = crc32c(&buf[..clen - 8]);
    if calc_crc != ftr.cluster_crc32c {
        return Err(VzError::CrcMismatch);
    }
    let body = &buf[ClusterHeader::SIZE..clen - ClusterFooter::SIZE];
    Ok((hdr, body, ftr))
}

/// Zero-copy view over a contiguous slice of packed 48-byte [`RouteEntry`] items.
#[derive(Debug, Clone, Copy)]
pub struct RouteTableView<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> RouteTableView<'a> {
    /// Wraps `buf` containing `route_count` packed 48-byte [`RouteEntry`] elements.
    pub fn new(buf: &'a [u8], route_count: usize) -> Result<Self, VzError> {
        let needed = route_count
            .checked_mul(RouteEntry::SIZE)
            .ok_or(VzError::ValueOverflow)?;
        if buf.len() < needed {
            return Err(VzError::BufferTooSmall);
        }
        Ok(Self {
            bytes: &buf[..needed],
            count: route_count,
        })
    }

    /// Returns the number of routing entries in this table.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the table has zero routing entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Decodes the [`RouteEntry`] at `index`.
    pub fn get(&self, index: usize) -> Result<RouteEntry, VzError> {
        if index >= self.count {
            return Err(VzError::NotFound);
        }
        let off = index * RouteEntry::SIZE;
        RouteEntry::from_bytes(&self.bytes[off..off + RouteEntry::SIZE])
    }

    /// Binary searches for the first route whose `max >= (parent_hash, name_hash)`.
    ///
    /// Pass `(parent_hash, 0)` to find the first child cluster for `readdir`.
    #[inline]
    pub fn lower_bound(
        &self,
        parent_hash: u64,
        name_hash: u64,
    ) -> Result<Option<(usize, RouteEntry)>, VzError> {
        if self.count == 0 {
            return Ok(None);
        }
        let mut base = 0usize;
        let mut size = self.count;
        while size > 1 {
            let half = size >> 1;
            let mid = base + half;
            let off = mid * RouteEntry::SIZE;
            let mp = read_le_u64(self.bytes, off + 16);
            let mn = read_le_u64(self.bytes, off + 24);
            let less = (mp < parent_hash) | ((mp == parent_hash) & (mn < name_hash));
            base = if less { mid } else { base };
            size -= half;
        }
        let off = base * RouteEntry::SIZE;
        let mp = read_le_u64(self.bytes, off + 16);
        let mn = read_le_u64(self.bytes, off + 24);
        let less = (mp < parent_hash) | ((mp == parent_hash) & (mn < name_hash));
        let idx = base + usize::from(less);
        if idx < self.count {
            Ok(Some((idx, self.get(idx)?)))
        } else {
            Ok(None)
        }
    }

    /// Binary searches for the first route whose `[min, max]` range covers `(parent_hash, name_hash)`.
    pub fn lookup(
        &self,
        parent_hash: u64,
        name_hash: u64,
    ) -> Result<Option<(usize, RouteEntry)>, VzError> {
        let Some((idx, r)) = self.lower_bound(parent_hash, name_hash)? else {
            return Ok(None);
        };
        if key128_cmp(parent_hash, name_hash, r.min_parent_hash, r.min_name_hash)
            == Ordering::Less
        {
            return Ok(None);
        }
        Ok(Some((idx, r)))
    }
}

/// Zero-copy, CRC32C-validated view over a Leaf DirNode (`Header + DirEntry[] + NamePool + ExtMetaPool`).
#[derive(Debug, Clone, Copy)]
pub struct LeafNodeView<'a> {
    header: LeafNodeHeader,
    entries_bytes: &'a [u8],
    name_pool: &'a [u8],
    ext_meta_pool: &'a [u8],
}

impl<'a> LeafNodeView<'a> {
    /// Parses and validates a complete Leaf DirNode buffer including `node_crc32c`.
    pub fn parse(buf: &'a [u8]) -> Result<Self, VzError> {
        Self::parse_inner(buf, true)
    }

    /// Parses a Leaf DirNode buffer whose outer container CRC32C (or cache entry) was already verified.
    pub fn parse_trusted(buf: &'a [u8]) -> Result<Self, VzError> {
        Self::parse_inner(buf, false)
    }

    fn parse_inner(buf: &'a [u8], verify_crc: bool) -> Result<Self, VzError> {
        let header = LeafNodeHeader::from_bytes(buf)?;
        let total = header.total_size()?;
        if buf.len() < total {
            return Err(VzError::BufferTooSmall);
        }
        if verify_crc {
            let mut crc = crc32c_update(0xFFFF_FFFF, &buf[..12]);
            crc = crc32c_update(crc, &buf[LeafNodeHeader::SIZE..total]);
            if !crc != header.node_crc32c {
                return Err(VzError::CrcMismatch);
            }
        }

        let entries_bytes_len = (header.entry_count as usize)
            .checked_mul(DirEntry::SIZE)
            .ok_or(VzError::ValueOverflow)?;
        let entries_end = LeafNodeHeader::SIZE
            .checked_add(entries_bytes_len)
            .ok_or(VzError::ValueOverflow)?;
        let names_end = entries_end
            .checked_add(header.name_pool_len as usize)
            .ok_or(VzError::ValueOverflow)?;

        Ok(Self {
            header,
            entries_bytes: &buf[LeafNodeHeader::SIZE..entries_end],
            name_pool: &buf[entries_end..names_end],
            ext_meta_pool: &buf[names_end..total],
        })
    }

    /// Returns the parsed [`LeafNodeHeader`].
    pub fn header(&self) -> &LeafNodeHeader {
        &self.header
    }

    /// Returns the number of [`DirEntry`] items in this leaf.
    pub fn entry_count(&self) -> usize {
        self.header.entry_count as usize
    }

    /// Returns the raw `NamePool` byte slice.
    pub fn name_pool(&self) -> &'a [u8] {
        self.name_pool
    }

    /// Returns the raw `ExtMetaPool` byte slice.
    pub fn ext_meta_pool(&self) -> &'a [u8] {
        self.ext_meta_pool
    }

    /// Decodes the [`DirEntry`] at `index`.
    pub fn entry(&self, index: usize) -> Result<DirEntry, VzError> {
        if index >= self.entry_count() {
            return Err(VzError::NotFound);
        }
        let off = index * DirEntry::SIZE;
        DirEntry::from_bytes(&self.entries_bytes[off..off + DirEntry::SIZE])
    }

    /// Returns the first entry index in `0..=entry_count()` with key `>= (parent_hash, name_hash)`.
    ///
    /// Pass `(parent_hash, 0)` to locate the start of a directory for `readdir`.
    #[inline]
    pub fn lower_bound(&self, parent_hash: u64, name_hash: u64) -> Result<usize, VzError> {
        let count = self.entry_count();
        if count == 0 {
            return Ok(0);
        }
        let mut base = 0usize;
        let mut size = count;
        while size > 1 {
            let half = size >> 1;
            let mid = base + half;
            let off = mid * DirEntry::SIZE;
            let p_hash = read_le_u64(self.entries_bytes, off);
            let n_hash = read_le_u64(self.entries_bytes, off + 8);
            let less = (p_hash < parent_hash) | ((p_hash == parent_hash) & (n_hash < name_hash));
            base = if less { mid } else { base };
            size -= half;
        }
        let off = base * DirEntry::SIZE;
        let p_hash = read_le_u64(self.entries_bytes, off);
        let n_hash = read_le_u64(self.entries_bytes, off + 8);
        let less = (p_hash < parent_hash) | ((p_hash == parent_hash) & (n_hash < name_hash));
        Ok(base + usize::from(less))
    }

    /// Binary searches this leaf for `(parent_hash, name_hash)`, verifying both `exact_basename`
    /// (when provided) and `TAG_PARENT_PATH` against `exact_parent_path` (when provided).
    ///
    /// Returns matching entries even if `FLAG_TOMBSTONE` is set (for multi-run LSM lookups).
    pub fn lookup_raw_exact(
        &self,
        parent_hash: u64,
        name_hash: u64,
        exact_basename: Option<&[u8]>,
        exact_parent_path: Option<&[u8]>,
    ) -> Result<Option<DirEntry>, VzError> {
        let count = self.entry_count();
        let mut idx = self.lower_bound(parent_hash, name_hash)?;
        while idx < count {
            let off = idx * DirEntry::SIZE;
            let p_hash = read_le_u64(self.entries_bytes, off);
            let n_hash = read_le_u64(self.entries_bytes, off + 8);
            if p_hash != parent_hash || n_hash != name_hash {
                break;
            }
            let e = DirEntry::from_bytes(&self.entries_bytes[off..off + DirEntry::SIZE])?;
            if let Some(target_name) = exact_basename {
                match e.entry_name(self.name_pool) {
                    Ok(stored) if stored == target_name => {}
                    Ok(_) => {
                        idx += 1;
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            }
            if let Some(target_parent) = exact_parent_path
                && e.has_hash_collision()
                && let Some(stored_parent) = e.entry_parent_path(self.ext_meta_pool)?
                && stored_parent != target_parent
            {
                idx += 1;
                continue;
            }
            return Ok(Some(e));
        }
        Ok(None)
    }

    /// Binary searches this leaf for `(parent_hash, name_hash)`, verifying `exact_basename`
    /// against `NamePool` when provided, and returning matching entries even if `FLAG_TOMBSTONE` is set.
    pub fn lookup_raw(
        &self,
        parent_hash: u64,
        name_hash: u64,
        exact_basename: Option<&[u8]>,
    ) -> Result<Option<DirEntry>, VzError> {
        self.lookup_raw_exact(parent_hash, name_hash, exact_basename, None)
    }

    /// Standard single-run Leaf lookup verifying both `exact_basename` and `exact_parent_path`.
    /// Returns `Ok(None)` for entries marked `FLAG_TOMBSTONE`.
    pub fn lookup_exact(
        &self,
        parent_hash: u64,
        name_hash: u64,
        exact_basename: Option<&[u8]>,
        exact_parent_path: Option<&[u8]>,
    ) -> Result<Option<DirEntry>, VzError> {
        match self.lookup_raw_exact(parent_hash, name_hash, exact_basename, exact_parent_path)? {
            Some(e) if !e.is_tombstone() => Ok(Some(e)),
            _ => Ok(None),
        }
    }

    /// Standard single-run Leaf lookup; returns `Ok(None)` for entries marked `FLAG_TOMBSTONE`.
    pub fn lookup(
        &self,
        parent_hash: u64,
        name_hash: u64,
        exact_basename: Option<&[u8]>,
    ) -> Result<Option<DirEntry>, VzError> {
        match self.lookup_raw(parent_hash, name_hash, exact_basename)? {
            Some(e) if !e.is_tombstone() => Ok(Some(e)),
            _ => Ok(None),
        }
    }

    /// Returns an iterator over all entries in this leaf matching `parent_hash` (`readdir`).
    pub fn iter_dir(&self, parent_hash: u64) -> Result<LeafDirIter<'a, '_>, VzError> {
        let start = self.lower_bound(parent_hash, 0)?;
        Ok(LeafDirIter {
            view: self,
            parent_hash,
            idx: start,
        })
    }
}

/// Iterator yielding contiguous directory entries sharing `parent_hash` inside a [`LeafNodeView`].
#[derive(Debug, Clone, Copy)]
pub struct LeafDirIter<'a, 'v> {
    view: &'v LeafNodeView<'a>,
    parent_hash: u64,
    idx: usize,
}

impl<'a, 'v> Iterator for LeafDirIter<'a, 'v> {
    type Item = Result<DirEntry, VzError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.view.entry_count() {
            return None;
        }
        match self.view.entry(self.idx) {
            Ok(e) if e.parent_hash == self.parent_hash => {
                self.idx += 1;
                Some(Ok(e))
            }
            Ok(_) => {
                self.idx = self.view.entry_count();
                None
            }
            Err(err) => {
                self.idx = self.view.entry_count();
                Some(Err(err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{CODEC_NONE, DirPayload, FLAG_INLINE_DATA, KIND_REG, LeafNodeHeader, write_le_u64};

    #[test]
    fn test_branchless_lower_bound_exhaustive_with_duplicates() {
        let mut route_buf = [0u8; 65 * RouteEntry::SIZE];
        let mut leaf_buf = [0u8; LeafNodeHeader::SIZE + 65 * DirEntry::SIZE];

        for n in 0usize..=65 {
            let mut keys = Vec::with_capacity(n);
            for i in 0..n {
                // Inject duplicates every ~3 entries and span multiple parent_hash groups.
                let p = (i / 7) as u64 * 10 + 10;
                let k = ((i % 7) / 2) as u64 * 10 + 5;
                keys.push((p, k));

                let r = RouteEntry {
                    min_parent_hash: p,
                    min_name_hash: k,
                    max_parent_hash: p,
                    max_name_hash: k,
                    child_cluster_off: 0x10000 + (i as u64) * 64,
                    child_cluster_len: 4096,
                    subtree_count_lo: 1,
                };
                r.write_bytes(&mut route_buf[i * RouteEntry::SIZE..(i + 1) * RouteEntry::SIZE])
                    .unwrap();

                let off = LeafNodeHeader::SIZE + i * DirEntry::SIZE;
                let de = DirEntry {
                    parent_hash: p,
                    name_hash: k,
                    payload: DirPayload::Inline {
                        bytes: [0u8; 27],
                        len: 0,
                    },
                    entry_id_lo: i as u32,
                    mtime_ns: 0,
                    name_pool_off: 0,
                    ext_meta_off: 0,
                    posix_mode: KIND_REG | 0o644,
                    owner_idx: 0,
                    flags_and_codec: CODEC_NONE | FLAG_INLINE_DATA,
                };
                de.write_bytes(&mut leaf_buf[off..off + DirEntry::SIZE]).unwrap();
                write_le_u64(&mut leaf_buf, off, p);
                write_le_u64(&mut leaf_buf, off + 8, k);
            }

            let hdr = LeafNodeHeader {
                entry_count: n as u32,
                name_pool_len: 0,
                ext_meta_len: 0,
                node_crc32c: 0,
            };
            hdr.write_bytes(&mut leaf_buf[..LeafNodeHeader::SIZE]).unwrap();

            let rtable = RouteTableView::new(&route_buf[..n * RouteEntry::SIZE], n).unwrap();
            let leaf = LeafNodeView::parse_trusted(&leaf_buf).unwrap();

            for qp in [0u64, 5, 10, 15, 20, 30, 100, 1000] {
                for qn in [0u64, 5, 10, 15, 25, 35, 100] {
                    let expected = keys
                        .iter()
                        .position(|&(p, k)| (p, k) >= (qp, qn))
                        .unwrap_or(n);
                    let got_leaf = leaf.lower_bound(qp, qn).unwrap();
                    assert_eq!(got_leaf, expected, "leaf n={n} q=({qp},{qn})");

                    let got_route = rtable.lower_bound(qp, qn).unwrap().map(|(i, _)| i);
                    let exp_route = if expected < n { Some(expected) } else { None };
                    assert_eq!(got_route, exp_route, "route n={n} q=({qp},{qn})");
                }
            }
        }
    }
}
