mod lookup;
mod payload;
mod verify_repair;

pub use verify_repair::{
    repair_file, repair_read_write_seek, repair_slice, scan_clusters_forward, verify_archive,
    walk_clusters_reverse,
};
pub(super) use verify_repair::{parse_dir_node_body, read_cluster_at, read_tail_cluster};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::btree::validate_cluster;
use crate::codec::{CryptoContext, EncryptionKey, ZstdDictCache};
use crate::ecc::boot_ecc_verify_and_repair;
use crate::error::VzError;
use crate::ext_meta::{
    CipherHeader, DictEntry, ExtCodecMeta, LsmRunDesc, OwnerEntry, RawTlv, SchemaEntry,
    SparseExtent, Xattr, decode_dict_table, decode_lsm_runs, decode_owner_table,
    decode_root_fallback, decode_schema_table,
};
use crate::hash::{AlgoHasher, PathHasher};
use crate::io::RangeReader;
use crate::wire::{
    BootHeader, COMPAT_BOOT_ECC, ClusterFooter, DEFAULT_BOOT_SIZE, DirEntry, ExtTime, HeaderSlot,
    INCOMPAT_BIG_BOOT, INCOMPAT_ENCRYPTED, RO_COMPAT_LSM_RUNS, TAG_CIPHER_HEADER,
    TAG_DICT_TABLE, TAG_LSM_RUNS, TAG_NOP, TAG_OWNER_TABLE, TAG_ROOT_FALLBACK, TAG_SCHEMA_TABLE,
    TREE_HEIGHT_PIPE, TlvIter,
};

pub(super) const SUPPORTED_INCOMPAT: u16 = INCOMPAT_ENCRYPTED | INCOMPAT_BIG_BOOT;

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
    /// Unrecognized / downstream extension TLVs (e.g. `TAG_VENDOR_EXT`) preserved across compaction.
    pub extra_ext_tlvs: Vec<RawTlv>,
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
pub(super) struct NodeRef {
    pub(super) off: u64,
    pub(super) is_cluster: bool,
    pub(super) cluster_len: Option<u32>,
    pub(super) height: u8,
    pub(super) entry_count: usize,
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

pub(super) struct CachedNode {
    pub(super) entry_count: u32,
    pub(super) payload: Arc<[u8]>,
}

pub(super) struct LookupTarget {
    pub(super) dir_entry: DirEntry,
    pub(super) entry_id: u64,
    pub(super) run_generation: u64,
    pub(super) ext_codec: Option<ExtCodecMeta>,
    pub(super) sparse_extents: Option<Vec<SparseExtent>>,
}

/// Random-access, HTTP-Range-friendly `.vz` reader.
pub struct VzReader<R: RangeReader> {
    pub(super) reader: R,
    pub(super) boot_block: Vec<u8>,
    pub(super) active_slot: HeaderSlot,
    pub(super) hasher: Box<dyn PathHasher>,
    pub(super) owners: Vec<OwnerEntry>,
    pub(super) dicts: Vec<DictEntry>,
    pub(super) dict_cache: ZstdDictCache,
    pub(super) schemas: Vec<SchemaEntry>,
    pub(super) cipher_hdr: Option<CipherHeader>,
    pub(super) crypto: Option<CryptoContext>,
    pub(super) lsm_runs: Vec<LsmRunDesc>,
    /// Preserved downstream/unknown Global Registry TLVs.
    pub(super) extra_registry_tlvs: Vec<RawTlv>,
    /// Embedded root bytes when opened from an unfinalized pipe via `TAG_ROOT_FALLBACK`.
    pub(super) pipe_root: Option<(u8, u32, Vec<u8>)>,
    /// Verified B+Tree internal/leaf node cache populated lazily on first cluster validation.
    pub(super) node_cache: RwLock<HashMap<u64, Arc<CachedNode>>>,
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
        let mut extra_registry_tlvs = Vec::new();

        for elem in TlvIter::new(reg_slice) {
            let elem = elem?;
            match elem.tag {
                TAG_NOP | crate::wire::TAG_VOID => {}
                TAG_OWNER_TABLE => owners = decode_owner_table(elem.value)?,
                TAG_DICT_TABLE => dicts = decode_dict_table(elem.value)?,
                TAG_SCHEMA_TABLE => schemas = decode_schema_table(elem.value)?,
                TAG_CIPHER_HEADER => cipher_hdr = Some(CipherHeader::from_bytes(elem.value)?),
                TAG_LSM_RUNS => lsm_runs = decode_lsm_runs(elem.value)?,
                other => extra_registry_tlvs.push(RawTlv {
                    tag: other,
                    value: elem.value.to_vec(),
                }),
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
            extra_registry_tlvs,
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

    pub fn extra_registry_tlvs(&self) -> &[RawTlv] {
        &self.extra_registry_tlvs
    }

    pub fn reader(&self) -> &R {
        &self.reader
    }
}
