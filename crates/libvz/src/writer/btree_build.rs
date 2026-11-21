use std::io::Write;

use super::emitter::{ClusterEmitter, StagedEntry};
use crate::btree::key128_cmp;
use crate::crc::crc32c;
use crate::ecc::boot_ecc_encode;
use crate::error::VzError;
use crate::ext_meta::{
    DictEntry, LsmRunDesc, OwnerEntry, RawTlv, SchemaEntry, encode_dict_table, encode_ext_codec,
    encode_ext_owner, encode_lsm_runs, encode_owner_table, encode_schema_link,
    encode_schema_table, encode_sparse_extents, encode_xattr_list, push_lp_bytes, push_tlv,
};
use crate::wire::{
    BootHeader, DEFAULT_BOOT_SIZE, DirEntry, FLAG_HASH_COLLISION, FLAG_INODE_64, HeaderSlot,
    LeafNodeHeader, MAGIC_HEADER, RouteEntry, TAG_CIPHER_HEADER, TAG_DICT_TABLE, TAG_DIR_NODE,
    TAG_EXT_CODEC, TAG_EXT_OWNER, TAG_EXT_TIME, TAG_INODE_HI, TAG_LSM_RUNS, TAG_NOP,
    TAG_OWNER_TABLE, TAG_PARENT_PATH, TAG_SCHEMA_LINK, TAG_SCHEMA_TABLE, TAG_SPARSE_EXTENTS,
    TAG_XATTR_LIST, pool_shift,
};

// ============================================================================
// B+TREE BUILDER HELPERS
// ============================================================================

pub(super) struct BuiltTree {
    pub(super) tree_height: u8,
    pub(super) root_entry_count: u32,
    pub(super) root_bytes: Vec<u8>,
}

pub(super) fn align_up_64(v: usize) -> usize {
    (v + 63) & !63
}

/// Canonicalizes entry ordering by 128-bit `(parent_hash, name_hash, parent_path, basename)` and
/// flags any hash-colliding runs with `FLAG_HASH_COLLISION` in a single allocation-free pass.
pub(super) fn sort_and_mark_hash_collisions(entries: &mut [StagedEntry]) {
    entries.sort_by(|a, b| {
        key128_cmp(a.parent_hash, a.name_hash, b.parent_hash, b.name_hash)
            .then_with(|| a.parent_path.cmp(&b.parent_path))
            .then_with(|| a.basename.cmp(&b.basename))
    });
    let n = entries.len();
    let mut i = 0usize;
    while i < n {
        let p_hash = entries[i].parent_hash;
        let mut j = i + 1;
        let mut p_coll = false;
        while j < n && entries[j].parent_hash == p_hash {
            if entries[j].parent_path != entries[i].parent_path {
                p_coll = true;
            }
            j += 1;
        }
        if p_coll {
            for e in &mut entries[i..j] {
                e.flags_and_codec |= FLAG_HASH_COLLISION;
            }
        } else {
            let mut a = i;
            while a < j {
                let n_hash = entries[a].name_hash;
                let mut b = a + 1;
                while b < j && entries[b].name_hash == n_hash {
                    b += 1;
                }
                if b - a > 1 {
                    for e in &mut entries[a..b] {
                        e.flags_and_codec |= FLAG_HASH_COLLISION;
                    }
                }
                a = b;
            }
        }
        i = j;
    }
}

pub(super) fn build_registry_bytes(
    owners: &[OwnerEntry],
    dicts: &[DictEntry],
    schemas: &[SchemaEntry],
    cipher_hdr: Option<&crate::ext_meta::CipherHeader>,
    lsm_runs: Option<&[LsmRunDesc]>,
    extra_tlvs: &[RawTlv],
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
    for raw in extra_tlvs {
        push_tlv(&mut reg, raw.tag, &raw.value)?;
    }
    Ok(reg)
}

fn append_entry_ext_chain(e: &StagedEntry, chain: &mut Vec<u8>) -> Result<(), VzError> {
    let start = chain.len();
    if (e.flags_and_codec & FLAG_HASH_COLLISION) != 0 {
        push_tlv(chain, TAG_PARENT_PATH, e.parent_path.as_bytes())?;
    }
    if (e.flags_and_codec & FLAG_INODE_64) != 0 {
        let hi = (e.entry_id >> 32) as u32;
        push_tlv(chain, TAG_INODE_HI, &hi.to_le_bytes())?;
    }
    if let Some(ref time) = e.ext_time {
        push_tlv(chain, TAG_EXT_TIME, &time.to_bytes())?;
    }
    if let Some(ref owner) = e.ext_owner {
        let val = encode_ext_owner(owner)?;
        push_tlv(chain, TAG_EXT_OWNER, &val)?;
    }
    if !e.xattrs.is_empty() {
        let val = encode_xattr_list(&e.xattrs)?;
        push_tlv(chain, TAG_XATTR_LIST, &val)?;
    }
    if let Some(ref ext_codec) = e.ext_codec {
        let val = encode_ext_codec(ext_codec)?;
        push_tlv(chain, TAG_EXT_CODEC, &val)?;
    }
    if let Some(ref link) = e.schema_link {
        let val = encode_schema_link(link)?;
        push_tlv(chain, TAG_SCHEMA_LINK, &val)?;
    }
    if let Some(ref extents) = e.sparse_extents {
        let val = encode_sparse_extents(extents)?;
        push_tlv(chain, TAG_SPARSE_EXTENTS, &val)?;
    }
    for raw in &e.extra_ext_tlvs {
        if raw.tag != TAG_NOP {
            push_tlv(chain, raw.tag, &raw.value)?;
        }
    }
    if chain.len() > start {
        chain.push(TAG_NOP as u8);
    }
    Ok(())
}

fn serialize_leaf_node(entries: &[StagedEntry]) -> Result<Vec<u8>, VzError> {
    // Fast flat path: append directly to `name_pool` and `ext_meta_pool` assuming `pool_shift == 0`
    // (`len <= 65_536`), falling back to `pack_pool` only when a huge entry forces shifting.
    let mut name_pool = Vec::with_capacity(entries.len().saturating_mul(16));
    let mut name_offs = Vec::with_capacity(entries.len());
    let mut name_overflow = false;
    for e in entries {
        let off = name_pool.len();
        if off > u16::MAX as usize {
            name_overflow = true;
        }
        name_offs.push(off as u16);
        push_lp_bytes(&mut name_pool, e.basename.as_bytes())?;
    }
    if name_overflow || name_pool.len() > 65_536 {
        let mut name_raws = Vec::with_capacity(entries.len());
        let mut total_name_bytes = 0usize;
        for e in entries {
            let mut nb = Vec::with_capacity(8 + e.basename.len());
            push_lp_bytes(&mut nb, e.basename.as_bytes())?;
            total_name_bytes += nb.len();
            name_raws.push(nb);
        }
        (name_pool, name_offs) = pack_pool(&name_raws, total_name_bytes, false)?;
    }

    let mut ext_meta_pool = Vec::new();
    let mut ext_offs = Vec::with_capacity(entries.len());
    let mut ext_overflow = false;
    for e in entries {
        if ext_meta_pool.is_empty() {
            ext_meta_pool.push(0x00); // byte 0 reserved EXT_META_NONE
        }
        let before = ext_meta_pool.len();
        append_entry_ext_chain(e, &mut ext_meta_pool)?;
        if ext_meta_pool.len() == before {
            ext_offs.push(0);
        } else {
            if before > u16::MAX as usize {
                ext_overflow = true;
            }
            ext_offs.push(before as u16);
        }
    }
    if ext_meta_pool.len() == 1 && ext_offs.iter().all(|&o| o == 0) {
        ext_meta_pool.clear();
    } else if ext_overflow || ext_meta_pool.len() > 65_536 {
        let mut ext_raws = Vec::with_capacity(entries.len());
        let mut total_ext_bytes = 1usize;
        for e in entries {
            let mut eb = Vec::new();
            append_entry_ext_chain(e, &mut eb)?;
            total_ext_bytes += eb.len();
            ext_raws.push(eb);
        }
        (ext_meta_pool, ext_offs) = pack_pool(&ext_raws, total_ext_bytes, true)?;
    }

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
                || !e.extra_ext_tlvs.is_empty()
                || (e.flags_and_codec & FLAG_INODE_64) != 0
            {
                64 + e.extra_ext_tlvs.iter().map(|t| 8 + t.value.len()).sum::<usize>()
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

pub(super) fn serialize_dir_node_tlv(node_level: u8, entry_count: u32, payload: &[u8]) -> Result<Vec<u8>, VzError> {
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

pub(super) fn build_btree_index<W: Write>(
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



pub(super) struct BootCommitSpec<'a> {
    pub compat_flags: u16,
    pub ro_compat_flags: u16,
    pub incompat_flags: u16,
    pub tree_height: u8,
    pub hash_algo: u8,
    pub lsm_run_count: u16,
    pub registry_offset: usize,
    pub registry_bytes: &'a [u8],
    pub root_node_offset: usize,
    pub root_bytes: &'a [u8],
    pub root_entry_count: u32,
    pub total_entries: u64,
    pub root_fallback_off: u64,
}

/// Serializes `slot`, commits it into `boot_hdr`, writes registry + root node, encodes optional
/// Boot ECC (`DEFAULT_BOOT_SIZE`), seeks to offset `0`, writes `boot_block`, and flushes `writer`.
pub(super) fn commit_boot_block<W: std::io::Write + std::io::Seek>(
    writer: &mut W,
    boot_hdr: &mut BootHeader,
    boot_size: usize,
    ecc_active: bool,
    spec: BootCommitSpec<'_>,
) -> Result<(), VzError> {
    let slot = HeaderSlot {
        magic: MAGIC_HEADER,
        generation: 0,
        boot_block_size: u32::try_from(boot_size).map_err(|_| VzError::ValueOverflow)?,
        compat_flags: spec.compat_flags,
        ro_compat_flags: spec.ro_compat_flags,
        incompat_flags: spec.incompat_flags,
        tree_height: spec.tree_height,
        hash_algo: spec.hash_algo,
        lsm_run_count: spec.lsm_run_count,
        registry_offset: u16::try_from(spec.registry_offset).map_err(|_| VzError::ValueOverflow)?,
        registry_size: u32::try_from(spec.registry_bytes.len()).map_err(|_| VzError::ValueOverflow)?,
        root_node_offset: u32::try_from(spec.root_node_offset).map_err(|_| VzError::ValueOverflow)?,
        total_entries: spec.total_entries,
        root_fallback_off: spec.root_fallback_off,
        root_entry_count: spec.root_entry_count,
        header_crc32c: 0,
    };
    let mut boot_block = vec![0u8; boot_size];
    boot_hdr.commit(&slot);
    boot_hdr.write_bytes(&mut boot_block[..BootHeader::SIZE])?;
    boot_block[spec.registry_offset..spec.registry_offset + spec.registry_bytes.len()]
        .copy_from_slice(spec.registry_bytes);
    boot_block[spec.root_node_offset..spec.root_node_offset + spec.root_bytes.len()]
        .copy_from_slice(spec.root_bytes);
    if ecc_active && boot_size == DEFAULT_BOOT_SIZE {
        boot_ecc_encode(&mut boot_block)?;
    }
    writer.seek(std::io::SeekFrom::Start(0)).map_err(|_| VzError::IoError)?;
    writer.write_all(&boot_block).map_err(|_| VzError::IoError)?;
    writer.flush().map_err(|_| VzError::IoError)?;
    Ok(())
}
