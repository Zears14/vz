use std::collections::HashMap;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

use super::btree_build::{align_up_64, build_btree_index, build_registry_bytes, mark_hash_collisions};
use super::emitter::{ClusterEmitter, StagedEntry};
use crate::btree::{key128_cmp, validate_cluster};
use crate::codec::{CryptoContext, EncryptionKey};
use crate::crc::crc32c;
use crate::ecc::{boot_ecc_encode, boot_ecc_verify_and_repair};
use crate::error::VzError;
use crate::ext_meta::{
    ChunkExtent, CipherHeader, DataManifestHeader, DictEntry, ExtCodecMeta, OwnerEntry, RawTlv,
    SchemaEntry, SchemaLinkMeta, SparseExtent, Xattr, decode_dict_table, decode_owner_table,
    decode_schema_table,
};
use crate::hash::{AlgoHasher, PathHasher};
use crate::reader::{VzReader, VzReaderOptions};
use crate::rs::{build_cluster_from_body, encode_rs_gf256_stripe};
use crate::wire::{
    BOOT_ECC_DESC_OFF, BootHeader, COMPAT_BOOT_ECC, ClusterHeader, DEFAULT_BOOT_SIZE, DirPayload,
    ExtTime, FLAG_HASH_COLLISION, FLAG_TOMBSTONE, HeaderSlot, INCOMPAT_BIG_BOOT,
    INCOMPAT_COMPACTING, INCOMPAT_ENCRYPTED, KIND_MASK, MAGIC_CLUSTER, MAGIC_HEADER,
    RO_COMPAT_STREAM_ECC, TAG_CIPHER_HEADER, TAG_DICT_TABLE, TAG_OWNER_TABLE, TAG_SCHEMA_TABLE,
    TlvIter, read_le_u16, read_le_u32, read_le_u64,
};

const JOURNAL_MAGIC: [u8; 8] = *b"VZCMPJ01";
const EVAC_MAGIC: [u8; 8] = *b"VZEVAC01";
const PLAN_MAGIC: [u8; 8] = *b"VZPLAN01";
const CKPT_SIZE: usize = 256;
const OUT_SLOT_SIZE: usize = 32;
const DEFAULT_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MIN_BATCH_BYTES: usize = 64 * 1024;

const PHASE_ACTIVE: u8 = 0;
const PHASE_APPLY_BOUNCE: u8 = 1;
const PHASE_BUILD_BTREE: u8 = 2;
const PHASE_WRITE_FINAL_BOOT: u8 = 3;

const CKPT_FLAG_ENCRYPTED: u8 = 1 << 0;
const CKPT_FLAG_RS_PARITY: u8 = 1 << 1;
const CKPT_FLAG_BOOT_ECC: u8 = 1 << 2;
const CKPT_FLAG_BIG_BOOT: u8 = 1 << 3;

/// Controls [`compact_file_in_place`] and [`resume_in_place_compaction`] behavior.
#[derive(Debug, Clone)]
pub struct InPlaceCompactOptions {
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
    /// Decryption/encryption key (`Some(...)` required when the source archive is encrypted).
    pub encryption: Option<EncryptionKey>,
    /// Bounded RAM and bounce window batch target in bytes (default `4 MiB`, clamped `>= 64 KiB`).
    pub batch_bytes: usize,
}

impl Default for InPlaceCompactOptions {
    fn default() -> Self {
        Self {
            enable_boot_ecc: None,
            target_cluster_size: None,
            max_leaf_entries: None,
            max_route_entries: None,
            rs_parity: None,
            encryption: None,
            batch_bytes: DEFAULT_BATCH_BYTES,
        }
    }
}

/// Summary statistics returned by [`compact_file_in_place`] and [`resume_in_place_compaction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPlaceCompactReport {
    /// `true` if compaction resumed from an interrupted `INCOMPAT_COMPACTING` journal.
    pub resumed: bool,
    /// Original `lsm_run_count` before compaction (`0` if recovered directly from an uninspected crash).
    pub prev_lsm_runs: u16,
    /// Original archive byte length before compaction.
    pub original_bytes: u64,
    /// Final compacted archive byte length after truncation.
    pub compacted_bytes: u64,
    /// Number of payload bounce batches applied.
    pub batches_written: u64,
    /// Total source bytes evacuated into the EOF safety log to avoid overwrite collisions.
    pub evacuated_bytes: u64,
    /// Peak temporary file extension reached during compaction.
    pub peak_file_bytes: u64,
}

/// Deterministic fault-injection trigger points for verifying crash-safe recovery.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InPlaceCrashPoint {
    BeforeJournalActivation,
    AfterJournalActivation,
    MidBounceWrite,
    AfterBounceCommitBeforeOverwrite,
    MidInPlaceOverwrite,
    AfterBatchCommit(u64),
    AfterBtreeWrite,
    MidFinalBootWrite,
    BeforeFinalTruncate,
}

#[derive(Debug, Clone, Copy)]
struct CompactionCheckpoint {
    ckpt_seq: u64,
    phase: u8,
    flags: u8,
    hash_algo: u8,
    orig_compat_flags: u16,
    rs_k: u16,
    rs_m: u16,
    orig_file_len: u64,
    orig_boot_size: u32,
    new_boot_size: u32,
    max_leaf_entries: u32,
    max_route_entries: u32,
    target_cluster_size: u32,
    orig_gen: u64,
    target_generation: u64,
    journal_base: u64,
    plan_offset: u64,
    plan_len: u64,
    out_log_offset: u64,
    total_work_items: u64,
    bounce_offset: u64,
    bounce_max_len: u64,
    evac_log_offset: u64,
    evac_cursor: u64,
    completed_items: u64,
    write_cursor: u64,
    cluster_seq: u64,
    prev_cluster_len: u64,
    stripe_start_offset: u64,
    bounce_target_off: u64,
    bounce_len: u64,
    bounce_crc32c: u32,
    next_completed_items: u64,
    next_write_cursor: u64,
    next_cluster_seq: u64,
    next_prev_cluster_len: u64,
    data_end_cursor: u64,
    data_end_seq: u64,
    data_end_prev_len: u64,
    data_end_stripe_start: u64,
    final_len: u64,
    batches_written: u64,
    evacuated_bytes: u64,
}

impl CompactionCheckpoint {
    fn to_bytes(self) -> [u8; CKPT_SIZE] {
        let mut b = [0u8; CKPT_SIZE];
        b[0..8].copy_from_slice(&JOURNAL_MAGIC);
        b[8..16].copy_from_slice(&self.ckpt_seq.to_le_bytes());
        b[16] = self.phase;
        b[17] = self.flags;
        b[18] = self.hash_algo;
        b[20..22].copy_from_slice(&self.orig_compat_flags.to_le_bytes());
        b[22..24].copy_from_slice(&self.rs_k.to_le_bytes());
        b[24..26].copy_from_slice(&self.rs_m.to_le_bytes());
        b[28..32].copy_from_slice(&self.orig_boot_size.to_le_bytes());
        b[32..36].copy_from_slice(&self.new_boot_size.to_le_bytes());
        b[36..40].copy_from_slice(&self.max_leaf_entries.to_le_bytes());
        b[40..44].copy_from_slice(&self.max_route_entries.to_le_bytes());
        b[44..48].copy_from_slice(&self.target_cluster_size.to_le_bytes());
        b[48..56].copy_from_slice(&self.orig_file_len.to_le_bytes());
        b[56..64].copy_from_slice(&self.orig_gen.to_le_bytes());
        b[64..72].copy_from_slice(&self.target_generation.to_le_bytes());
        b[72..80].copy_from_slice(&self.journal_base.to_le_bytes());
        b[80..88].copy_from_slice(&self.plan_offset.to_le_bytes());
        b[88..96].copy_from_slice(&self.plan_len.to_le_bytes());
        b[96..104].copy_from_slice(&self.out_log_offset.to_le_bytes());
        b[104..112].copy_from_slice(&self.total_work_items.to_le_bytes());
        b[112..120].copy_from_slice(&self.bounce_offset.to_le_bytes());
        b[120..128].copy_from_slice(&self.bounce_max_len.to_le_bytes());
        b[128..136].copy_from_slice(&self.evac_log_offset.to_le_bytes());
        b[136..144].copy_from_slice(&self.evac_cursor.to_le_bytes());
        b[144..152].copy_from_slice(&self.completed_items.to_le_bytes());
        b[152..160].copy_from_slice(&self.write_cursor.to_le_bytes());
        b[160..168].copy_from_slice(&self.cluster_seq.to_le_bytes());
        b[168..176].copy_from_slice(&self.prev_cluster_len.to_le_bytes());
        b[176..184].copy_from_slice(&self.stripe_start_offset.to_le_bytes());
        b[184..192].copy_from_slice(&self.bounce_target_off.to_le_bytes());
        b[192..200].copy_from_slice(&self.bounce_len.to_le_bytes());
        b[200..204].copy_from_slice(&self.bounce_crc32c.to_le_bytes());
        b[204..212].copy_from_slice(&self.next_completed_items.to_le_bytes());
        b[212..220].copy_from_slice(&self.next_write_cursor.to_le_bytes());
        b[220..228].copy_from_slice(&self.next_cluster_seq.to_le_bytes());
        b[228..236].copy_from_slice(&self.next_prev_cluster_len.to_le_bytes());
        b[236..244].copy_from_slice(&self.data_end_cursor.to_le_bytes());
        b[244..252].copy_from_slice(&self.data_end_seq.to_le_bytes());
        let c = crc32c(&b[0..252]);
        b[252..256].copy_from_slice(&c.to_le_bytes());
        b
    }

    fn from_bytes(b: &[u8]) -> Result<Self, VzError> {
        if b.len() < CKPT_SIZE {
            return Err(VzError::BufferTooSmall);
        }
        if b[0..8] != JOURNAL_MAGIC {
            return Err(VzError::BadMagic);
        }
        let stored_crc = read_le_u32(b, 252);
        if crc32c(&b[0..252]) != stored_crc {
            return Err(VzError::CrcMismatch);
        }
        Ok(Self {
            ckpt_seq: read_le_u64(b, 8),
            phase: b[16],
            flags: b[17],
            hash_algo: b[18],
            orig_compat_flags: read_le_u16(b, 20),
            rs_k: read_le_u16(b, 22),
            rs_m: read_le_u16(b, 24),
            orig_boot_size: read_le_u32(b, 28),
            new_boot_size: read_le_u32(b, 32),
            max_leaf_entries: read_le_u32(b, 36),
            max_route_entries: read_le_u32(b, 40),
            target_cluster_size: read_le_u32(b, 44),
            orig_file_len: read_le_u64(b, 48),
            orig_gen: read_le_u64(b, 56),
            target_generation: read_le_u64(b, 64),
            journal_base: read_le_u64(b, 72),
            plan_offset: read_le_u64(b, 80),
            plan_len: read_le_u64(b, 88),
            out_log_offset: read_le_u64(b, 96),
            total_work_items: read_le_u64(b, 104),
            bounce_offset: read_le_u64(b, 112),
            bounce_max_len: read_le_u64(b, 120),
            evac_log_offset: read_le_u64(b, 128),
            evac_cursor: read_le_u64(b, 136),
            completed_items: read_le_u64(b, 144),
            write_cursor: read_le_u64(b, 152),
            cluster_seq: read_le_u64(b, 160),
            prev_cluster_len: read_le_u64(b, 168),
            stripe_start_offset: read_le_u64(b, 176),
            bounce_target_off: read_le_u64(b, 184),
            bounce_len: read_le_u64(b, 192),
            bounce_crc32c: read_le_u32(b, 200),
            next_completed_items: read_le_u64(b, 204),
            next_write_cursor: read_le_u64(b, 212),
            next_cluster_seq: read_le_u64(b, 220),
            next_prev_cluster_len: read_le_u64(b, 228),
            data_end_cursor: read_le_u64(b, 236),
            data_end_seq: read_le_u64(b, 244),
            data_end_prev_len: 0,
            data_end_stripe_start: 0,
            final_len: 0,
            batches_written: 0,
            evacuated_bytes: 0,
        })
    }
}

/// Companion trailer struct stored immediately inside the extended 512-byte slot tail (`CKPT_SLOT_STRIDE = 320`)
/// so every checkpoint carries full `data_end_*`, `final_len`, and counters atomically under one CRC!
const CKPT_WIRE_LEN: usize = 320;

fn encode_ckpt_wire(c: &CompactionCheckpoint) -> [u8; CKPT_WIRE_LEN] {
    let mut b = [0u8; CKPT_WIRE_LEN];
    let head = c.to_bytes();
    b[0..252].copy_from_slice(&head[0..252]);
    b[256..264].copy_from_slice(&c.data_end_prev_len.to_le_bytes());
    b[264..272].copy_from_slice(&c.data_end_stripe_start.to_le_bytes());
    b[272..280].copy_from_slice(&c.final_len.to_le_bytes());
    b[280..288].copy_from_slice(&c.batches_written.to_le_bytes());
    b[288..296].copy_from_slice(&c.evacuated_bytes.to_le_bytes());
    let head_crc = crc32c(&b[0..252]);
    b[252..256].copy_from_slice(&head_crc.to_le_bytes());
    let full_crc = crc32c(&b[0..316]);
    b[316..320].copy_from_slice(&full_crc.to_le_bytes());
    b
}

fn decode_ckpt_wire(b: &[u8; CKPT_WIRE_LEN]) -> Result<CompactionCheckpoint, VzError> {
    if read_le_u32(b, 316) != crc32c(&b[0..316]) {
        return Err(VzError::CrcMismatch);
    }
    let mut c = CompactionCheckpoint::from_bytes(&b[0..CKPT_SIZE])?;
    c.data_end_prev_len = read_le_u64(b, 256);
    c.data_end_stripe_start = read_le_u64(b, 264);
    c.final_len = read_le_u64(b, 272);
    c.batches_written = read_le_u64(b, 280);
    c.evacuated_bytes = read_le_u64(b, 288);
    Ok(c)
}

#[derive(Debug, Clone)]
enum PlanPayloadKind {
    Inline {
        bytes: [u8; 27],
        len: u8,
    },
    ZeroSparse {
        raw_size: u64,
    },
    SingleCluster {
        work_idx: u64,
        raw_size: u64,
        logical_or_packed_raw: u64,
    },
    MultiCluster {
        first_work_idx: u64,
        chunk_count: u32,
        raw_size: u64,
    },
    HardlinkDup {
        primary_entry_idx: u32,
    },
}

#[derive(Debug, Clone)]
struct PlanEntry {
    parent_path: String,
    basename: String,
    parent_hash: u64,
    name_hash: u64,
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
    extra_ext_tlvs: Vec<RawTlv>,
    kind: PlanPayloadKind,
}

#[derive(Debug, Clone)]
struct PlanWorkItem {
    entry_id: u64,
    run_generation: u64,
    src_cluster_off: u64,
    src_cluster_len: u32,
    src_in_cluster_off: u32,
    src_stored_size: u64,
    chunk_raw_size: u64,
    is_dedicated: bool,
}

#[derive(Debug, Clone, Copy)]
struct OutSlot {
    cluster_off: u64,
    stored_size: u64,
    raw_size: u64,
    in_cluster_offset: u32,
}

impl OutSlot {
    fn to_bytes(self) -> [u8; OUT_SLOT_SIZE] {
        let mut b = [0u8; OUT_SLOT_SIZE];
        b[0..8].copy_from_slice(&self.cluster_off.to_le_bytes());
        b[8..16].copy_from_slice(&self.stored_size.to_le_bytes());
        b[16..24].copy_from_slice(&self.raw_size.to_le_bytes());
        b[24..28].copy_from_slice(&self.in_cluster_offset.to_le_bytes());
        let c = crc32c(&b[0..28]);
        b[28..32].copy_from_slice(&c.to_le_bytes());
        b
    }

    fn from_bytes(b: &[u8]) -> Result<Self, VzError> {
        if b.len() < OUT_SLOT_SIZE {
            return Err(VzError::BufferTooSmall);
        }
        if read_le_u32(b, 28) != crc32c(&b[0..28]) {
            return Err(VzError::CrcMismatch);
        }
        Ok(Self {
            cluster_off: read_le_u64(b, 0),
            stored_size: read_le_u64(b, 8),
            raw_size: read_le_u64(b, 16),
            in_cluster_offset: read_le_u32(b, 24),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct EvacSpan {
    orig_off: u64,
    len: u64,
    evac_payload_off: u64,
}

fn align_up_8(v: u64) -> u64 {
    (v + 7) & !7
}

fn file_read_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
    #[cfg(unix)]
    {
        file.read_exact_at(buf, offset).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => VzError::BufferTooSmall,
            _ => VzError::IoError,
        })
    }
    #[cfg(not(unix))]
    {
        let mut f = file;
        f.seek(SeekFrom::Start(offset)).map_err(|_| VzError::IoError)?;
        f.read_exact(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => VzError::BufferTooSmall,
            _ => VzError::IoError,
        })
    }
}

fn file_write_at(file: &mut File, offset: u64, buf: &[u8]) -> Result<(), VzError> {
    #[cfg(unix)]
    {
        file.write_all_at(buf, offset).map_err(|_| VzError::IoError)
    }
    #[cfg(not(unix))]
    {
        file.seek(SeekFrom::Start(offset)).map_err(|_| VzError::IoError)?;
        file.write_all(buf).map_err(|_| VzError::IoError)
    }
}

/// Reads `[offset .. offset + buf.len())`, transparently routing any byte range overlapping an
/// evacuated span in `evac_spans` to its preserved copy inside the EOF evacuation log.
fn read_source_range(
    file: &File,
    evac_spans: &[EvacSpan],
    offset: u64,
    buf: &mut [u8],
) -> Result<(), VzError> {
    let total = buf.len() as u64;
    let end = offset.checked_add(total).ok_or(VzError::ValueOverflow)?;
    let mut cur = offset;
    while cur < end {
        let pos = (cur - offset) as usize;
        // Find an evacuated span covering `cur`, or the nearest evacuated span starting after `cur`.
        let covering = evac_spans
            .iter()
            .find(|s| cur >= s.orig_off && cur < s.orig_off.saturating_add(s.len));
        if let Some(span) = covering {
            let span_end = span.orig_off.saturating_add(span.len);
            let take = (end.min(span_end) - cur) as usize;
            let evac_off = span.evac_payload_off + (cur - span.orig_off);
            file_read_at(file, evac_off, &mut buf[pos..pos + take])?;
            cur += take as u64;
        } else {
            let next_start = evac_spans
                .iter()
                .filter(|s| s.orig_off > cur && s.orig_off < end)
                .map(|s| s.orig_off)
                .min()
                .unwrap_or(end);
            let take = (next_start - cur) as usize;
            file_read_at(file, cur, &mut buf[pos..pos + take])?;
            cur += take as u64;
        }
    }
    Ok(())
}

fn push_u16_le(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn push_u32_le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn push_u64_le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn push_lp_vec(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), VzError> {
    let len = u32::try_from(bytes.len()).map_err(|_| VzError::ValueOverflow)?;
    push_u32_le(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn take_slice<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], VzError> {
    if buf.len() < n {
        return Err(VzError::BufferTooSmall);
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Ok(head)
}
fn take_u8(buf: &mut &[u8]) -> Result<u8, VzError> {
    Ok(take_slice(buf, 1)?[0])
}
fn take_u16(buf: &mut &[u8]) -> Result<u16, VzError> {
    Ok(read_le_u16(take_slice(buf, 2)?, 0))
}
fn take_u32(buf: &mut &[u8]) -> Result<u32, VzError> {
    Ok(read_le_u32(take_slice(buf, 4)?, 0))
}
fn take_u64(buf: &mut &[u8]) -> Result<u64, VzError> {
    Ok(read_le_u64(take_slice(buf, 8)?, 0))
}
fn take_lp_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], VzError> {
    let len = take_u32(buf)? as usize;
    take_slice(buf, len)
}
fn take_lp_string(buf: &mut &[u8]) -> Result<String, VzError> {
    let b = take_lp_bytes(buf)?;
    core::str::from_utf8(b)
        .map(str::to_string)
        .map_err(|_| VzError::BadFormat)
}

fn serialize_plan(
    entries: &[PlanEntry],
    work: &[PlanWorkItem],
    extra_reg_tlvs: &[RawTlv],
) -> Result<Vec<u8>, VzError> {
    let mut out = Vec::with_capacity(entries.len() * 64 + work.len() * 44 + 64);
    out.extend_from_slice(&PLAN_MAGIC);
    push_u32_le(
        &mut out,
        u32::try_from(entries.len()).map_err(|_| VzError::ValueOverflow)?,
    );
    push_u32_le(
        &mut out,
        u32::try_from(work.len()).map_err(|_| VzError::ValueOverflow)?,
    );
    push_u32_le(
        &mut out,
        u32::try_from(extra_reg_tlvs.len()).map_err(|_| VzError::ValueOverflow)?,
    );
    for t in extra_reg_tlvs {
        push_u64_le(&mut out, t.tag);
        push_lp_vec(&mut out, &t.value)?;
    }

    for e in entries {
        push_lp_vec(&mut out, e.parent_path.as_bytes())?;
        push_lp_vec(&mut out, e.basename.as_bytes())?;
        push_u64_le(&mut out, e.parent_hash);
        push_u64_le(&mut out, e.name_hash);
        push_u64_le(&mut out, e.entry_id);
        push_u64_le(&mut out, e.mtime_ns as u64);
        push_u16_le(&mut out, e.posix_mode);
        out.push(e.owner_idx);
        out.push(e.flags_and_codec);

        match &e.ext_time {
            Some(t) => {
                out.push(1);
                out.extend_from_slice(&t.to_bytes());
            }
            None => out.push(0),
        }
        match &e.ext_owner {
            Some(o) => {
                out.push(1);
                push_u32_le(&mut out, o.uid);
                push_u32_le(&mut out, o.gid);
                push_lp_vec(&mut out, o.uname.as_bytes())?;
                push_lp_vec(&mut out, o.gname.as_bytes())?;
            }
            None => out.push(0),
        }
        push_u16_le(
            &mut out,
            u16::try_from(e.xattrs.len()).map_err(|_| VzError::ValueOverflow)?,
        );
        for x in &e.xattrs {
            push_lp_vec(&mut out, x.key.as_bytes())?;
            push_lp_vec(&mut out, &x.value)?;
        }
        match &e.ext_codec {
            Some(c) => {
                out.push(1);
                push_u16_le(&mut out, c.ext_codec_id);
                push_u32_le(&mut out, c.dict_id);
                push_lp_vec(&mut out, &c.params)?;
            }
            None => out.push(0),
        }
        match &e.schema_link {
            Some(s) => {
                out.push(1);
                push_u32_le(&mut out, s.schema_id);
                push_lp_vec(&mut out, &s.extra)?;
            }
            None => out.push(0),
        }
        match &e.sparse_extents {
            Some(exs) => {
                out.push(1);
                push_u32_le(
                    &mut out,
                    u32::try_from(exs.len()).map_err(|_| VzError::ValueOverflow)?,
                );
                for x in exs {
                    push_u64_le(&mut out, x.logical_offset);
                    push_u64_le(&mut out, x.length);
                }
            }
            None => out.push(0),
        }
        push_u16_le(
            &mut out,
            u16::try_from(e.extra_ext_tlvs.len()).map_err(|_| VzError::ValueOverflow)?,
        );
        for t in &e.extra_ext_tlvs {
            push_u64_le(&mut out, t.tag);
            push_lp_vec(&mut out, &t.value)?;
        }

        match e.kind {
            PlanPayloadKind::Inline { bytes, len } => {
                out.push(0);
                out.push(len);
                out.extend_from_slice(&bytes);
            }
            PlanPayloadKind::ZeroSparse { raw_size } => {
                out.push(1);
                push_u64_le(&mut out, raw_size);
            }
            PlanPayloadKind::SingleCluster {
                work_idx,
                raw_size,
                logical_or_packed_raw,
            } => {
                out.push(2);
                push_u64_le(&mut out, work_idx);
                push_u64_le(&mut out, raw_size);
                push_u64_le(&mut out, logical_or_packed_raw);
            }
            PlanPayloadKind::MultiCluster {
                first_work_idx,
                chunk_count,
                raw_size,
            } => {
                out.push(3);
                push_u64_le(&mut out, first_work_idx);
                push_u32_le(&mut out, chunk_count);
                push_u64_le(&mut out, raw_size);
            }
            PlanPayloadKind::HardlinkDup { primary_entry_idx } => {
                out.push(4);
                push_u32_le(&mut out, primary_entry_idx);
            }
        }
    }

    for w in work {
        push_u64_le(&mut out, w.entry_id);
        push_u64_le(&mut out, w.run_generation);
        push_u64_le(&mut out, w.src_cluster_off);
        push_u32_le(&mut out, w.src_cluster_len);
        push_u32_le(&mut out, w.src_in_cluster_off);
        push_u64_le(&mut out, w.src_stored_size);
        push_u64_le(&mut out, w.chunk_raw_size);
        out.push(u8::from(w.is_dedicated));
    }

    let c = crc32c(&out);
    push_u32_le(&mut out, c);
    Ok(out)
}

struct DecodedRegistry {
    owners: Vec<OwnerEntry>,
    dicts: Vec<DictEntry>,
    schemas: Vec<SchemaEntry>,
    crypto: Option<(CipherHeader, CryptoContext)>,
}

struct ParsedPlan {
    entries: Vec<PlanEntry>,
    work: Vec<PlanWorkItem>,
    extra_reg_tlvs: Vec<RawTlv>,
}

fn deserialize_plan(mut buf: &[u8]) -> Result<ParsedPlan, VzError> {
    if buf.len() < 24 {
        return Err(VzError::BufferTooSmall);
    }
    let payload_len = buf.len() - 4;
    let stored_crc = read_le_u32(buf, payload_len);
    if crc32c(&buf[..payload_len]) != stored_crc {
        return Err(VzError::CrcMismatch);
    }
    buf = &buf[..payload_len];
    if take_slice(&mut buf, 8)? != PLAN_MAGIC {
        return Err(VzError::BadMagic);
    }
    let n_entries = take_u32(&mut buf)? as usize;
    let n_work = take_u32(&mut buf)? as usize;
    let n_reg_tlv = take_u32(&mut buf)? as usize;

    let mut extra_reg_tlvs = Vec::with_capacity(n_reg_tlv);
    for _ in 0..n_reg_tlv {
        let tag = take_u64(&mut buf)?;
        let value = take_lp_bytes(&mut buf)?.to_vec();
        extra_reg_tlvs.push(RawTlv { tag, value });
    }

    let mut entries = Vec::with_capacity(n_entries);
    for _ in 0..n_entries {
        let parent_path = take_lp_string(&mut buf)?;
        let basename = take_lp_string(&mut buf)?;
        let parent_hash = take_u64(&mut buf)?;
        let name_hash = take_u64(&mut buf)?;
        let entry_id = take_u64(&mut buf)?;
        let mtime_ns = take_u64(&mut buf)? as i64;
        let posix_mode = take_u16(&mut buf)?;
        let owner_idx = take_u8(&mut buf)?;
        let flags_and_codec = take_u8(&mut buf)?;

        let ext_time = if take_u8(&mut buf)? != 0 {
            Some(ExtTime::from_bytes(take_slice(&mut buf, ExtTime::SIZE)?)?)
        } else {
            None
        };
        let ext_owner = if take_u8(&mut buf)? != 0 {
            let uid = take_u32(&mut buf)?;
            let gid = take_u32(&mut buf)?;
            let uname = take_lp_string(&mut buf)?;
            let gname = take_lp_string(&mut buf)?;
            Some(OwnerEntry {
                uid,
                gid,
                uname,
                gname,
            })
        } else {
            None
        };
        let n_x = take_u16(&mut buf)? as usize;
        let mut xattrs = Vec::with_capacity(n_x);
        for _ in 0..n_x {
            let key = take_lp_string(&mut buf)?;
            let value = take_lp_bytes(&mut buf)?.to_vec();
            xattrs.push(Xattr { key, value });
        }
        let ext_codec = if take_u8(&mut buf)? != 0 {
            let ext_codec_id = take_u16(&mut buf)?;
            let dict_id = take_u32(&mut buf)?;
            let params = take_lp_bytes(&mut buf)?.to_vec();
            Some(ExtCodecMeta {
                ext_codec_id,
                dict_id,
                params,
            })
        } else {
            None
        };
        let schema_link = if take_u8(&mut buf)? != 0 {
            let schema_id = take_u32(&mut buf)?;
            let extra = take_lp_bytes(&mut buf)?.to_vec();
            Some(SchemaLinkMeta { schema_id, extra })
        } else {
            None
        };
        let sparse_extents = if take_u8(&mut buf)? != 0 {
            let n_s = take_u32(&mut buf)? as usize;
            let mut exs = Vec::with_capacity(n_s);
            for _ in 0..n_s {
                let logical_offset = take_u64(&mut buf)?;
                let length = take_u64(&mut buf)?;
                exs.push(SparseExtent {
                    logical_offset,
                    length,
                });
            }
            Some(exs)
        } else {
            None
        };
        let n_ext = take_u16(&mut buf)? as usize;
        let mut extra_ext_tlvs = Vec::with_capacity(n_ext);
        for _ in 0..n_ext {
            let tag = take_u64(&mut buf)?;
            let value = take_lp_bytes(&mut buf)?.to_vec();
            extra_ext_tlvs.push(RawTlv { tag, value });
        }

        let kind = match take_u8(&mut buf)? {
            0 => {
                let len = take_u8(&mut buf)?;
                let raw = take_slice(&mut buf, 27)?;
                let mut bytes = [0u8; 27];
                bytes.copy_from_slice(raw);
                PlanPayloadKind::Inline { bytes, len }
            }
            1 => PlanPayloadKind::ZeroSparse {
                raw_size: take_u64(&mut buf)?,
            },
            2 => PlanPayloadKind::SingleCluster {
                work_idx: take_u64(&mut buf)?,
                raw_size: take_u64(&mut buf)?,
                logical_or_packed_raw: take_u64(&mut buf)?,
            },
            3 => PlanPayloadKind::MultiCluster {
                first_work_idx: take_u64(&mut buf)?,
                chunk_count: take_u32(&mut buf)?,
                raw_size: take_u64(&mut buf)?,
            },
            4 => PlanPayloadKind::HardlinkDup {
                primary_entry_idx: take_u32(&mut buf)?,
            },
            _ => return Err(VzError::BadFormat),
        };

        entries.push(PlanEntry {
            parent_path,
            basename,
            parent_hash,
            name_hash,
            entry_id,
            mtime_ns,
            posix_mode,
            owner_idx,
            flags_and_codec,
            ext_time,
            ext_owner,
            xattrs,
            ext_codec,
            schema_link,
            sparse_extents,
            extra_ext_tlvs,
            kind,
        });
    }

    let mut work = Vec::with_capacity(n_work);
    for _ in 0..n_work {
        work.push(PlanWorkItem {
            entry_id: take_u64(&mut buf)?,
            run_generation: take_u64(&mut buf)?,
            src_cluster_off: take_u64(&mut buf)?,
            src_cluster_len: take_u32(&mut buf)?,
            src_in_cluster_off: take_u32(&mut buf)?,
            src_stored_size: take_u64(&mut buf)?,
            chunk_raw_size: take_u64(&mut buf)?,
            is_dedicated: take_u8(&mut buf)? != 0,
        });
    }
    if !buf.is_empty() {
        return Err(VzError::BadFormat);
    }
    Ok(ParsedPlan {
        entries,
        work,
        extra_reg_tlvs,
    })
}

fn write_ckpt(file: &mut File, ckpt_base: u64, ckpt: &CompactionCheckpoint) -> Result<(), VzError> {
    let slot_idx = ckpt.ckpt_seq & 1;
    let off = ckpt_base + slot_idx * (CKPT_WIRE_LEN as u64);
    let wire = encode_ckpt_wire(ckpt);
    file_write_at(file, off, &wire)?;
    file.sync_data().map_err(|_| VzError::IoError)
}

fn read_best_ckpt(file: &File, ckpt_base: u64) -> Result<CompactionCheckpoint, VzError> {
    let mut best: Option<CompactionCheckpoint> = None;
    for slot_idx in 0u64..2 {
        let mut raw = [0u8; CKPT_WIRE_LEN];
        if file_read_at(file, ckpt_base + slot_idx * (CKPT_WIRE_LEN as u64), &mut raw).is_ok()
            && let Ok(c) = decode_ckpt_wire(&raw)
            && best.as_ref().is_none_or(|b| c.ckpt_seq > b.ckpt_seq)
        {
            best = Some(c);
        }
    }
    best.ok_or(VzError::CrcMismatch)
}

fn reconstruct_evac_spans(file: &File, start: u64, end: u64) -> Result<Vec<EvacSpan>, VzError> {
    let mut spans = Vec::new();
    let mut pos = start;
    let mut hdr = [0u8; 28];
    while pos + 28 <= end {
        file_read_at(file, pos, &mut hdr)?;
        if hdr[0..8] != EVAC_MAGIC {
            return Err(VzError::BadMagic);
        }
        let orig_off = read_le_u64(&hdr, 8);
        let len = read_le_u64(&hdr, 16);
        let h_crc = read_le_u32(&hdr, 24);
        if crc32c(&hdr[0..24]) != h_crc {
            return Err(VzError::CrcMismatch);
        }
        let payload_off = pos + 28;
        let payload_end = payload_off.checked_add(len).ok_or(VzError::ValueOverflow)?;
        if payload_end + 4 > end {
            break;
        }
        spans.push(EvacSpan {
            orig_off,
            len,
            evac_payload_off: payload_off,
        });
        pos = payload_end + 4;
    }
    Ok(spans)
}

fn decode_registry_from_boot(
    boot_block: &[u8],
    slot: &HeaderSlot,
    encryption: Option<&EncryptionKey>,
) -> Result<DecodedRegistry, VzError> {
    let reg_s = slot.registry_offset as usize;
    let reg_e = reg_s
        .checked_add(slot.registry_size as usize)
        .ok_or(VzError::ValueOverflow)?;
    let reg_slice = boot_block.get(reg_s..reg_e).ok_or(VzError::BufferTooSmall)?;

    let mut owners = Vec::new();
    let mut dicts = Vec::new();
    let mut schemas = Vec::new();
    let mut cipher_hdr = None;
    for tlv in TlvIter::new(reg_slice) {
        let tlv = tlv?;
        match tlv.tag {
            TAG_OWNER_TABLE => owners = decode_owner_table(tlv.value)?,
            TAG_DICT_TABLE => dicts = decode_dict_table(tlv.value)?,
            TAG_SCHEMA_TABLE => schemas = decode_schema_table(tlv.value)?,
            TAG_CIPHER_HEADER => cipher_hdr = Some(CipherHeader::from_bytes(tlv.value)?),
            _ => {}
        }
    }
    let crypto = match cipher_hdr {
        Some(hdr) => {
            let key = encryption.ok_or(VzError::CryptoError)?;
            let ctx = CryptoContext::unlock(&hdr, key)?;
            Some((hdr, ctx))
        }
        None => None,
    };
    Ok(DecodedRegistry {
        owners,
        dicts,
        schemas,
        crypto,
    })
}

fn read_cluster_len(file: &File, evac_spans: &[EvacSpan], off: u64) -> Result<(u64, u32), VzError> {
    let mut hdr = [0u8; ClusterHeader::SIZE];
    read_source_range(file, evac_spans, off, &mut hdr)?;
    let chdr = ClusterHeader::from_bytes(&hdr)?;
    if chdr.sync_magic != MAGIC_CLUSTER {
        return Err(VzError::BadMagic);
    }
    let clen = u32::try_from(chdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
    Ok((chdr.cluster_seq, clen))
}

/// Evacuates every untouched source cluster span in `remaining_work` intersecting `[target_start .. target_end)`
/// into the EOF evacuation log before any in-place overwrite touches `[target_start .. target_end)`.
fn evacuate_overlaps(
    file: &mut File,
    ckpt: &mut CompactionCheckpoint,
    evac_spans: &mut Vec<EvacSpan>,
    remaining_work: &[PlanWorkItem],
    target_start: u64,
    target_end: u64,
    scratch: &mut Vec<u8>,
) -> Result<(), VzError> {
    let mut did_write = false;
    for w in remaining_work {
        let s = w.src_cluster_off;
        let l = w.src_cluster_len as u64;
        let e = s.checked_add(l).ok_or(VzError::ValueOverflow)?;
        if e <= target_start || s >= target_end {
            continue;
        }
        if evac_spans.iter().any(|sp| s >= sp.orig_off && e <= sp.orig_off + sp.len) {
            continue;
        }
        let len_u = usize::try_from(l).map_err(|_| VzError::ValueOverflow)?;
        scratch.resize(len_u, 0);
        // Cluster `[s..e)` cannot have been overwritten yet because we always evacuate before overwriting.
        file_read_at(file, s, scratch)?;

        let mut hdr = [0u8; 28];
        hdr[0..8].copy_from_slice(&EVAC_MAGIC);
        hdr[8..16].copy_from_slice(&s.to_le_bytes());
        hdr[16..24].copy_from_slice(&l.to_le_bytes());
        let h_crc = crc32c(&hdr[0..24]);
        hdr[24..28].copy_from_slice(&h_crc.to_le_bytes());
        let p_crc = crc32c(scratch);

        let rec_off = ckpt.evac_cursor;
        let payload_off = rec_off + 28;
        file_write_at(file, rec_off, &hdr)?;
        file_write_at(file, payload_off, scratch)?;
        file_write_at(file, payload_off + l, &p_crc.to_le_bytes())?;

        evac_spans.push(EvacSpan {
            orig_off: s,
            len: l,
            evac_payload_off: payload_off,
        });
        ckpt.evac_cursor = payload_off + l + 4;
        ckpt.evacuated_bytes = ckpt.evacuated_bytes.saturating_add(l);
        did_write = true;
    }
    if did_write {
        file.sync_data().map_err(|_| VzError::IoError)?;
    }
    Ok(())
}

struct BatchEmission {
    cluster_buf: Vec<u8>,
    out_slots: Vec<OutSlot>,
    next_completed_items: u64,
    next_write_cursor: u64,
    next_cluster_seq: u64,
    next_prev_cluster_len: u64,
}

#[allow(clippy::too_many_arguments)]
fn commit_and_apply_bounce(
    file: &mut File,
    ckpt: &mut CompactionCheckpoint,
    ckpt_base: u64,
    target_off: u64,
    payload: &[u8],
    out_range: Option<(u64, &[OutSlot])>,
    next_state: (u64, u64, u64, u64),
    is_first_data_batch: bool,
    hook: &mut dyn FnMut(InPlaceCrashPoint) -> Result<(), VzError>,
) -> Result<(), VzError> {
    let target_end = target_off
        .checked_add(payload.len() as u64)
        .ok_or(VzError::ValueOverflow)?;
    if target_end > ckpt.journal_base || (payload.len() as u64) > ckpt.bounce_max_len {
        return Err(VzError::BufferTooSmall);
    }

    // 1. Write compacted bytes to BounceSlot.
    if is_first_data_batch && payload.len() >= 16 {
        let half = payload.len() / 2;
        file_write_at(file, ckpt.bounce_offset, &payload[..half])?;
        file.sync_data().map_err(|_| VzError::IoError)?;
        hook(InPlaceCrashPoint::MidBounceWrite)?;
        file_write_at(file, ckpt.bounce_offset + half as u64, &payload[half..])?;
    } else {
        file_write_at(file, ckpt.bounce_offset, payload)?;
    }

    // 2. Write OutLog updates for items >= ckpt.completed_items (safe before completed_items advances!).
    if let Some((start_idx, slots)) = out_range {
        let mut slot_bytes = Vec::with_capacity(slots.len() * OUT_SLOT_SIZE);
        for s in slots {
            slot_bytes.extend_from_slice(&s.to_bytes());
        }
        let log_off = ckpt.out_log_offset + start_idx * (OUT_SLOT_SIZE as u64);
        file_write_at(file, log_off, &slot_bytes)?;
    }
    file.sync_data().map_err(|_| VzError::IoError)?;

    // 3. Commit PHASE_APPLY_BOUNCE checkpoint cleanly.
    ckpt.ckpt_seq += 1;
    ckpt.phase = PHASE_APPLY_BOUNCE;
    ckpt.bounce_target_off = target_off;
    ckpt.bounce_len = payload.len() as u64;
    ckpt.bounce_crc32c = crc32c(payload);
    ckpt.next_completed_items = next_state.0;
    ckpt.next_write_cursor = next_state.1;
    ckpt.next_cluster_seq = next_state.2;
    ckpt.next_prev_cluster_len = next_state.3;
    write_ckpt(file, ckpt_base, ckpt)?;

    if is_first_data_batch {
        hook(InPlaceCrashPoint::AfterBounceCommitBeforeOverwrite)?;
    }

    // 4. Write compacted payload into final in-place target location (split-write tested once!).
    if is_first_data_batch && payload.len() >= 16 {
        let half = payload.len() / 2;
        file_write_at(file, target_off, &payload[..half])?;
        file.sync_data().map_err(|_| VzError::IoError)?;
        hook(InPlaceCrashPoint::MidInPlaceOverwrite)?;
        file_write_at(file, target_off + half as u64, &payload[half..])?;
    } else {
        file_write_at(file, target_off, payload)?;
    }
    file.sync_data().map_err(|_| VzError::IoError)?;

    // 5. Commit completion checkpoint advancing write_cursor and completed_items.
    ckpt.ckpt_seq += 1;
    ckpt.phase = PHASE_ACTIVE;
    ckpt.completed_items = next_state.0;
    ckpt.write_cursor = next_state.1;
    ckpt.cluster_seq = next_state.2;
    ckpt.prev_cluster_len = next_state.3;
    ckpt.batches_written += 1;
    write_ckpt(file, ckpt_base, ckpt)?;
    Ok(())
}

fn finish_pending_bounce_if_any(
    file: &mut File,
    ckpt: &mut CompactionCheckpoint,
    ckpt_base: u64,
    scratch: &mut Vec<u8>,
) -> Result<(), VzError> {
    if ckpt.phase != PHASE_APPLY_BOUNCE {
        return Ok(());
    }
    let blen = usize::try_from(ckpt.bounce_len).map_err(|_| VzError::ValueOverflow)?;
    scratch.resize(blen, 0);
    file_read_at(file, ckpt.bounce_offset, scratch)?;
    if crc32c(scratch) != ckpt.bounce_crc32c {
        return Err(VzError::CrcMismatch);
    }
    if ckpt.bounce_target_off + ckpt.bounce_len > ckpt.journal_base {
        return Err(VzError::BufferTooSmall);
    }
    file_write_at(file, ckpt.bounce_target_off, scratch)?;
    file.sync_data().map_err(|_| VzError::IoError)?;

    ckpt.ckpt_seq += 1;
    ckpt.phase = PHASE_ACTIVE;
    ckpt.completed_items = ckpt.next_completed_items;
    ckpt.write_cursor = ckpt.next_write_cursor;
    ckpt.cluster_seq = ckpt.next_cluster_seq;
    ckpt.prev_cluster_len = ckpt.next_prev_cluster_len;
    ckpt.batches_written += 1;
    write_ckpt(file, ckpt_base, ckpt)?;
    Ok(())
}

fn collect_stripe_clusters(file: &File, start_off: u64, end_off: u64) -> Result<Vec<(u64, u32)>, VzError> {
    let mut out = Vec::new();
    let mut off = start_off;
    let mut hdr = [0u8; ClusterHeader::SIZE];
    while off < end_off {
        file_read_at(file, off, &mut hdr)?;
        let chdr = ClusterHeader::from_bytes(&hdr)?;
        if chdr.sync_magic != MAGIC_CLUSTER {
            return Err(VzError::BadMagic);
        }
        let clen = u32::try_from(chdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
        out.push((off, clen));
        off = off
            .checked_add(chdr.cluster_len)
            .ok_or(VzError::ValueOverflow)?;
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn maybe_flush_rs_stripes(
    file: &mut File,
    ckpt: &mut CompactionCheckpoint,
    ckpt_base: u64,
    evac_spans: &mut Vec<EvacSpan>,
    remaining_work: &[PlanWorkItem],
    flush_partial: bool,
    scratch: &mut Vec<u8>,
    hook: &mut dyn FnMut(InPlaceCrashPoint) -> Result<(), VzError>,
) -> Result<(), VzError> {
    if (ckpt.flags & CKPT_FLAG_RS_PARITY) == 0 || ckpt.rs_k == 0 || ckpt.rs_m == 0 {
        return Ok(());
    }
    let k = ckpt.rs_k as usize;
    let m = ckpt.rs_m;
    let locs = collect_stripe_clusters(file, ckpt.stripe_start_offset, ckpt.write_cursor)?;
    if locs.is_empty() || (!flush_partial && locs.len() < k) {
        return Ok(());
    }
    let mut idx = 0usize;
    while idx < locs.len() {
        let take = k.min(locs.len() - idx);
        if !flush_partial && take < k {
            break;
        }
        let stripe_locs = &locs[idx..idx + take];
        let mut raw_bufs = Vec::with_capacity(take);
        let mut offsets = Vec::with_capacity(take);
        let mut first_seq = 0u64;
        for (si, &(off, clen)) in stripe_locs.iter().enumerate() {
            let mut buf = vec![0u8; clen as usize];
            file_read_at(file, off, &mut buf)?;
            if si == 0 {
                first_seq = ClusterHeader::from_bytes(&buf)?.cluster_seq;
            }
            raw_bufs.push(buf);
            offsets.push(off);
        }
        let refs: Vec<&[u8]> = raw_bufs.iter().map(Vec::as_slice).collect();
        let (parities, new_prev_len) = encode_rs_gf256_stripe(
            &refs,
            &offsets,
            first_seq,
            m,
            ckpt.cluster_seq,
            ckpt.prev_cluster_len,
        )?;
        let mut p_buf = Vec::new();
        for p in &parities {
            p_buf.extend_from_slice(p);
        }
        let target_start = ckpt.write_cursor;
        let target_end = target_start + p_buf.len() as u64;
        evacuate_overlaps(
            file,
            ckpt,
            evac_spans,
            remaining_work,
            target_start,
            target_end,
            scratch,
        )?;
        let next_seq = ckpt.cluster_seq + parities.len() as u64;
        commit_and_apply_bounce(
            file,
            ckpt,
            ckpt_base,
            target_start,
            &p_buf,
            None,
            (ckpt.completed_items, target_end, next_seq, new_prev_len),
            false,
            hook,
        )?;
        let last_off = stripe_locs[stripe_locs.len() - 1];
        ckpt.stripe_start_offset = target_end;
        let _ = last_off;
        ckpt.ckpt_seq += 1;
        write_ckpt(file, ckpt_base, ckpt)?;
        idx += take;
    }
    Ok(())
}

/// Builds compacted clusters for the next batch in `<= batch_bytes` bounded RAM, reads each source
/// cluster once via `read_source_range`, re-tags encryption AAD if enabled, and commits via bounce.
#[allow(clippy::too_many_arguments)]
fn run_next_batch(
    file: &mut File,
    ckpt: &mut CompactionCheckpoint,
    ckpt_base: u64,
    work: &[PlanWorkItem],
    crypto: Option<&CryptoContext>,
    batch_bytes: usize,
    evac_spans: &mut Vec<EvacSpan>,
    cluster_cache_buf: &mut Vec<u8>,
    decrypt_buf: &mut Vec<u8>,
    encrypt_buf: &mut Vec<u8>,
    evac_scratch: &mut Vec<u8>,
    hook: &mut dyn FnMut(InPlaceCrashPoint) -> Result<(), VzError>,
) -> Result<bool, VzError> {
    let start_idx = ckpt.completed_items as usize;
    if start_idx >= work.len() {
        return Ok(false);
    }

    let max_in_stripe = if (ckpt.flags & CKPT_FLAG_RS_PARITY) != 0 && ckpt.rs_k > 0 {
        let already = collect_stripe_clusters(file, ckpt.stripe_start_offset, ckpt.write_cursor)?.len();
        (ckpt.rs_k as usize).saturating_sub(already).max(1)
    } else {
        usize::MAX
    };

    let target_cluster_size = (ckpt.target_cluster_size as usize).max(4096);
    let max_batch_bytes = batch_bytes.max(MIN_BATCH_BYTES);
    let mut batch = BatchEmission {
        cluster_buf: Vec::new(),
        out_slots: Vec::new(),
        next_completed_items: ckpt.completed_items,
        next_write_cursor: ckpt.write_cursor,
        next_cluster_seq: ckpt.cluster_seq,
        next_prev_cluster_len: ckpt.prev_cluster_len,
    };

    let mut cur_pending_body: Vec<u8> = Vec::new();
    let mut cur_cluster_off = batch.next_write_cursor;
    let mut clusters_emitted_in_batch = 0usize;
    let mut cached_src_off: Option<u64> = None;
    let mut cached_src_seq = 0u64;

    let flush_pending = |batch: &mut BatchEmission,
                         pending: &mut Vec<u8>,
                         cur_off: &mut u64,
                         emitted: &mut usize|
     -> Result<(), VzError> {
        if pending.is_empty() {
            return Ok(());
        }
        let raw_c = build_cluster_from_body(
            pending,
            batch.next_prev_cluster_len,
            batch.next_cluster_seq,
        )?;
        let clen = raw_c.len() as u64;
        batch.cluster_buf.extend_from_slice(&raw_c);
        batch.next_write_cursor = batch
            .next_write_cursor
            .checked_add(clen)
            .ok_or(VzError::ValueOverflow)?;
        batch.next_prev_cluster_len = clen;
        batch.next_cluster_seq += 1;
        *cur_off = batch.next_write_cursor;
        pending.clear();
        *emitted += 1;
        Ok(())
    };

    let mut idx = start_idx;
    while idx < work.len() {
        let w = &work[idx];
        if cached_src_off != Some(w.src_cluster_off) {
            let slen_c = usize::try_from(w.src_cluster_len).map_err(|_| VzError::ValueOverflow)?;
            cluster_cache_buf.resize(slen_c, 0);
            read_source_range(file, evac_spans, w.src_cluster_off, cluster_cache_buf)?;
            let (chdr, _, _) = validate_cluster(cluster_cache_buf)?;
            cached_src_seq = chdr.cluster_seq;
            cached_src_off = Some(w.src_cluster_off);
        }

        let slen = usize::try_from(w.src_stored_size).map_err(|_| VzError::ValueOverflow)?;
        let ioff = w.src_in_cluster_off as usize;
        let end = ioff.checked_add(slen).ok_or(VzError::ValueOverflow)?;
        let stored_slice = cluster_cache_buf
            .get(ioff..end)
            .ok_or(VzError::BufferTooSmall)?;

        let plain_slice: &[u8] = if let Some(ctx) = crypto {
            ctx.decrypt_payload_into(
                w.run_generation,
                cached_src_seq,
                w.entry_id,
                stored_slice,
                decrypt_buf,
            )?;
            decrypt_buf
        } else {
            stored_slice
        };

        if w.is_dedicated {
            flush_pending(
                &mut batch,
                &mut cur_pending_body,
                &mut cur_cluster_off,
                &mut clusters_emitted_in_batch,
            )?;
            if clusters_emitted_in_batch >= max_in_stripe && idx > start_idx {
                break;
            }
            let seq = batch.next_cluster_seq;
            let out_slice: &[u8] = if let Some(ctx) = crypto {
                ctx.encrypt_payload_into(
                    ckpt.target_generation,
                    seq,
                    w.entry_id,
                    plain_slice,
                    encrypt_buf,
                )?;
                encrypt_buf
            } else {
                plain_slice
            };
            let out_slen = out_slice.len() as u64;
            let cluster_off = batch.next_write_cursor;
            let mut body = Vec::new();
            let new_ioff = ClusterEmitter::<std::io::Sink>::append_manifest_tlv_to_body(
                &mut body,
                cluster_off,
                w.entry_id,
                w.chunk_raw_size,
                out_slice,
                &[],
                0x0002,
            )?;
            let raw_c = build_cluster_from_body(
                &body,
                batch.next_prev_cluster_len,
                batch.next_cluster_seq,
            )?;
            let clen = raw_c.len() as u64;
            batch.cluster_buf.extend_from_slice(&raw_c);
            batch.next_write_cursor = batch
                .next_write_cursor
                .checked_add(clen)
                .ok_or(VzError::ValueOverflow)?;
            batch.next_prev_cluster_len = clen;
            batch.next_cluster_seq += 1;
            cur_cluster_off = batch.next_write_cursor;
            clusters_emitted_in_batch += 1;
            batch.out_slots.push(OutSlot {
                cluster_off,
                stored_size: out_slen,
                raw_size: w.chunk_raw_size,
                in_cluster_offset: new_ioff,
            });
            idx += 1;
        } else {
            let est_add =
                16 + DataManifestHeader::SIZE + 64 + plain_slice.len() + if crypto.is_some() { 80 } else { 40 };
            if !cur_pending_body.is_empty()
                && cur_pending_body.len() + est_add > target_cluster_size
            {
                flush_pending(
                    &mut batch,
                    &mut cur_pending_body,
                    &mut cur_cluster_off,
                    &mut clusters_emitted_in_batch,
                )?;
                if clusters_emitted_in_batch >= max_in_stripe || batch.cluster_buf.len() >= max_batch_bytes {
                    break;
                }
            }
            let seq = batch.next_cluster_seq;
            let cluster_off = cur_cluster_off;
            let out_slice: &[u8] = if let Some(ctx) = crypto {
                ctx.encrypt_payload_into(
                    ckpt.target_generation,
                    seq,
                    w.entry_id,
                    plain_slice,
                    encrypt_buf,
                )?;
                encrypt_buf
            } else {
                plain_slice
            };
            let out_slen = out_slice.len() as u64;
            let new_ioff = ClusterEmitter::<std::io::Sink>::append_manifest_tlv_to_body(
                &mut cur_pending_body,
                cluster_off,
                w.entry_id,
                w.chunk_raw_size,
                out_slice,
                &[],
                0x0002,
            )?;
            batch.out_slots.push(OutSlot {
                cluster_off,
                stored_size: out_slen,
                raw_size: w.chunk_raw_size,
                in_cluster_offset: new_ioff,
            });
            idx += 1;
            if cur_pending_body.len() >= target_cluster_size {
                flush_pending(
                    &mut batch,
                    &mut cur_pending_body,
                    &mut cur_cluster_off,
                    &mut clusters_emitted_in_batch,
                )?;
                if clusters_emitted_in_batch >= max_in_stripe || batch.cluster_buf.len() >= max_batch_bytes {
                    break;
                }
            }
        }

        if idx < work.len() && batch.cluster_buf.len() + cur_pending_body.len() >= max_batch_bytes {
            break;
        }
    }

    flush_pending(
        &mut batch,
        &mut cur_pending_body,
        &mut cur_cluster_off,
        &mut clusters_emitted_in_batch,
    )?;
    batch.next_completed_items = idx as u64;

    if !batch.cluster_buf.is_empty() {
        let target_start = ckpt.write_cursor;
        let target_end = batch.next_write_cursor;
        let is_first = ckpt.batches_written == 0;
        evacuate_overlaps(
            file,
            ckpt,
            evac_spans,
            &work[idx..],
            target_start,
            target_end,
            evac_scratch,
        )?;
        commit_and_apply_bounce(
            file,
            ckpt,
            ckpt_base,
            target_start,
            &batch.cluster_buf,
            Some((ckpt.completed_items, &batch.out_slots)),
            (
                batch.next_completed_items,
                target_end,
                batch.next_cluster_seq,
                batch.next_prev_cluster_len,
            ),
            is_first,
            hook,
        )?;
    }

    maybe_flush_rs_stripes(
        file,
        ckpt,
        ckpt_base,
        evac_spans,
        &work[idx..],
        false,
        evac_scratch,
        hook,
    )?;

    let batch_num = ckpt.batches_written;
    hook(InPlaceCrashPoint::AfterBatchCommit(batch_num))?;
    Ok(true)
}

/// Sink writing clusters issued by `build_btree_index` directly to `[write_cursor..]` under bounds guard.
struct InPlaceBtreeSink<'a> {
    file: &'a mut File,
    write_cursor: &'a mut u64,
    journal_base: u64,
    pending: Vec<u8>,
}

impl<'a> Write for InPlaceBtreeSink<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while self.pending.len() >= ClusterHeader::SIZE {
            let Ok(chdr) = ClusterHeader::from_bytes(&self.pending) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid cluster header",
                ));
            };
            let clen = chdr.cluster_len as usize;
            if self.pending.len() < clen {
                break;
            }
            let end = self
                .write_cursor
                .checked_add(clen as u64)
                .ok_or_else(|| std::io::Error::other("offset overflow"))?;
            if end > self.journal_base {
                return Err(std::io::Error::other("compacted btree exceeds journal_base"));
            }
            file_write_at(self.file, *self.write_cursor, &self.pending[..clen])
                .map_err(|_| std::io::Error::other("write failed"))?;
            *self.write_cursor = end;
            self.pending.drain(..clen);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.sync_data()
    }
}

fn prepare_journal(
    file: &mut File,
    options: &InPlaceCompactOptions,
    hook: &mut dyn FnMut(InPlaceCrashPoint) -> Result<(), VzError>,
) -> Result<(), VzError> {
    let orig_file_len = file.seek(SeekFrom::End(0)).map_err(|_| VzError::IoError)?;

    let (
        orig_boot_size,
        orig_boot_block,
        orig_slot,
        extra_reg_tlvs,
        entries,
        work,
    ) = {
        let reader = VzReader::open_with_options(
            &*file,
            VzReaderOptions {
                encryption: options.encryption.clone(),
                repair_boot_ecc: true,
            },
        )?;
        let active = *reader.active_slot();
        let orig_boot_size = active.boot_block_size as usize;
        let mut orig_boot = vec![0u8; orig_boot_size];
        file_read_at(file, 0, &mut orig_boot)?;

        let owners = reader.owners().to_vec();
        let extra_reg_tlvs = reader.extra_registry_tlvs().to_vec();
        let hasher = AlgoHasher::new(active.hash_algo)?;

        let mut live = reader.list_all_live()?;
        live.sort_by(|a, b| {
            let key = |e: &crate::reader::ResolvedEntry| match e.dir_entry.payload {
                DirPayload::Inline { .. } => (0u8, 0u64, 0u32),
                DirPayload::Ref {
                    data_offset,
                    in_cluster_offset,
                    ..
                } => {
                    if e.dir_entry.is_multi_cluster() {
                        (2u8, data_offset, in_cluster_offset)
                    } else {
                        (1u8, data_offset, in_cluster_offset)
                    }
                }
            };
            key(a)
                .cmp(&key(b))
                .then_with(|| a.stat.parent_path.cmp(&b.stat.parent_path))
                .then_with(|| a.stat.name.cmp(&b.stat.name))
        });

        let mut plan_entries: Vec<PlanEntry> = Vec::with_capacity(live.len());
        let mut work_items: Vec<PlanWorkItem> = Vec::new();
        let mut hardlink_first: HashMap<(u64, u64, u32), u32> = HashMap::new();
        let mut cluster_len_cache: HashMap<u64, u32> = HashMap::new();
        let mut cached_len_of = |off: u64| -> Result<u32, VzError> {
            if let Some(&l) = cluster_len_cache.get(&off) {
                return Ok(l);
            }
            let (_, l) = read_cluster_len(file, &[], off)?;
            cluster_len_cache.insert(off, l);
            Ok(l)
        };

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
            let (owner_idx, ext_owner) =
                if de.owner_idx < 255 && (de.owner_idx as usize) < owners.len() {
                    (de.owner_idx, None)
                } else {
                    (255, entry.stat.owner.clone())
                };
            let schema_link = entry.stat.schema_id.map(|schema_id| SchemaLinkMeta {
                schema_id,
                extra: entry.schema_extra,
            });

            let p_idx = u32::try_from(plan_entries.len()).map_err(|_| VzError::ValueOverflow)?;
            let kind = match de.payload {
                DirPayload::Inline { bytes, len } => PlanPayloadKind::Inline { bytes, len },
                DirPayload::Ref {
                    data_offset,
                    stored_size,
                    raw_size,
                    in_cluster_offset,
                } => {
                    if de.is_sparse() && stored_size == 0 {
                        PlanPayloadKind::ZeroSparse { raw_size }
                    } else {
                        let dedup_key = (entry.stat.entry_id, data_offset, in_cluster_offset);
                        if let Some(&primary) = hardlink_first.get(&dedup_key) {
                            PlanPayloadKind::HardlinkDup {
                                primary_entry_idx: primary,
                            }
                        } else if de.is_multi_cluster() {
                            hardlink_first.insert(dedup_key, p_idx);
                            let extents =
                                reader.read_chunk_table_at(data_offset, in_cluster_offset)?;
                            let first_work_idx = work_items.len() as u64;
                            let chunk_count = u32::try_from(extents.len())
                                .map_err(|_| VzError::ValueOverflow)?;
                            for ext in extents {
                                let clen = cached_len_of(ext.cluster_offset)?;
                                work_items.push(PlanWorkItem {
                                    entry_id: entry.stat.entry_id,
                                    run_generation: entry.run_generation,
                                    src_cluster_off: ext.cluster_offset,
                                    src_cluster_len: clen,
                                    src_in_cluster_off: ext.in_cluster_offset,
                                    src_stored_size: ext.stored_size,
                                    chunk_raw_size: ext.raw_size,
                                    is_dedicated: true,
                                });
                            }
                            PlanPayloadKind::MultiCluster {
                                first_work_idx,
                                chunk_count,
                                raw_size,
                            }
                        } else {
                            hardlink_first.insert(dedup_key, p_idx);
                            let logical_or_packed = if de.is_sparse() {
                                entry
                                    .sparse_extents
                                    .as_deref()
                                    .map(|exs| exs.iter().map(|x| x.length).sum())
                                    .unwrap_or(raw_size)
                            } else {
                                raw_size
                            };
                            let work_idx = work_items.len() as u64;
                            let clen = cached_len_of(data_offset)?;
                            work_items.push(PlanWorkItem {
                                entry_id: entry.stat.entry_id,
                                run_generation: entry.run_generation,
                                src_cluster_off: data_offset,
                                src_cluster_len: clen,
                                src_in_cluster_off: in_cluster_offset,
                                src_stored_size: stored_size,
                                chunk_raw_size: logical_or_packed,
                                is_dedicated: false,
                            });
                            PlanPayloadKind::SingleCluster {
                                work_idx,
                                raw_size,
                                logical_or_packed_raw: logical_or_packed,
                            }
                        }
                    }
                }
            };

            plan_entries.push(PlanEntry {
                parent_path: entry.stat.parent_path,
                basename: entry.stat.name,
                parent_hash,
                name_hash,
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
                extra_ext_tlvs: entry.extra_ext_tlvs,
                kind,
            });
        }

        (
            orig_boot_size,
            orig_boot,
            active,
            extra_reg_tlvs,
            plan_entries,
            work_items,
        )
    };

    let new_boot_size = orig_boot_size;
    let ecc_active = options
        .enable_boot_ecc
        .unwrap_or((orig_slot.compat_flags & COMPAT_BOOT_ECC) != 0)
        && new_boot_size == DEFAULT_BOOT_SIZE;
    let batch_bytes = options.batch_bytes.max(MIN_BATCH_BYTES);
    let target_cluster_size = options
        .target_cluster_size
        .unwrap_or_else(|| batch_bytes.min(1024 * 1024))
        .max(4096);
    let max_leaf_entries = options.max_leaf_entries.unwrap_or(512).clamp(1, 2048);
    let max_route_entries = options.max_route_entries.unwrap_or(128).clamp(2, 1024);

    if let Some((k, m)) = options.rs_parity
        && (k == 0 || m == 0 || (k as usize + m as usize) > 256)
    {
        return Err(VzError::InvalidInput);
    }

    let plan_bytes = serialize_plan(&entries, &work, &extra_reg_tlvs)?;
    let sum_work_stored: u64 = work
        .iter()
        .map(|w| w.src_stored_size + 192)
        .sum();
    let base_output_est = (new_boot_size as u64)
        .saturating_add(sum_work_stored)
        .saturating_add((entries.len() as u64) * 192)
        .saturating_add(256 * 1024);
    let expanded_est = if let Some((k, m)) = options.rs_parity {
        base_output_est
            .saturating_mul((k as u64) + (m as u64))
            .div_ceil(k as u64)
            .saturating_add(((m as u64) + 2) * (target_cluster_size as u64 + 65_536))
    } else {
        base_output_est
    };
    let journal_base = align_up_8(orig_file_len.max(expanded_est));

    let ckpt_base = journal_base + orig_boot_size as u64;
    let plan_offset = ckpt_base + 2 * (CKPT_WIRE_LEN as u64);
    let plan_len = plan_bytes.len() as u64;
    let out_log_offset = align_up_8(plan_offset + plan_len);
    let out_log_bytes = (work.len() as u64) * (OUT_SLOT_SIZE as u64);
    let bounce_offset = align_up_8(out_log_offset + out_log_bytes);

    let max_item_cluster = work
        .iter()
        .map(|w| w.src_stored_size + 256)
        .max()
        .unwrap_or(0) as usize;
    let rs_m_max = options.rs_parity.map_or(0, |(_, m)| m as usize);
    let bounce_max_len = (batch_bytes.saturating_mul(2))
        .max(target_cluster_size.saturating_mul(2))
        .max(rs_m_max.saturating_mul(target_cluster_size + 65_536))
        .max(max_item_cluster.saturating_add(4096))
        .max(new_boot_size) as u64;
    let evac_log_offset = bounce_offset + bounce_max_len;

    let mut ckpt_flags = 0u8;
    if (orig_slot.incompat_flags & INCOMPAT_ENCRYPTED) != 0 {
        ckpt_flags |= CKPT_FLAG_ENCRYPTED;
    }
    if options.rs_parity.is_some() {
        ckpt_flags |= CKPT_FLAG_RS_PARITY;
    }
    if ecc_active {
        ckpt_flags |= CKPT_FLAG_BOOT_ECC;
    }
    if new_boot_size > DEFAULT_BOOT_SIZE {
        ckpt_flags |= CKPT_FLAG_BIG_BOOT;
    }
    let (rs_k, rs_m) = options.rs_parity.unwrap_or((0, 0));

    let ckpt = CompactionCheckpoint {
        ckpt_seq: 1,
        phase: PHASE_ACTIVE,
        flags: ckpt_flags,
        hash_algo: orig_slot.hash_algo,
        orig_compat_flags: orig_slot.compat_flags,
        rs_k,
        rs_m,
        orig_file_len,
        orig_boot_size: orig_boot_size as u32,
        new_boot_size: new_boot_size as u32,
        max_leaf_entries: max_leaf_entries as u32,
        max_route_entries: max_route_entries as u32,
        target_cluster_size: target_cluster_size as u32,
        orig_gen: orig_slot.generation,
        target_generation: orig_slot.generation.saturating_add(2),
        journal_base,
        plan_offset,
        plan_len,
        out_log_offset,
        total_work_items: work.len() as u64,
        bounce_offset,
        bounce_max_len,
        evac_log_offset,
        evac_cursor: evac_log_offset,
        completed_items: 0,
        write_cursor: new_boot_size as u64,
        cluster_seq: 0,
        prev_cluster_len: 0,
        stripe_start_offset: new_boot_size as u64,
        bounce_target_off: 0,
        bounce_len: 0,
        bounce_crc32c: 0,
        next_completed_items: 0,
        next_write_cursor: new_boot_size as u64,
        next_cluster_seq: 0,
        next_prev_cluster_len: 0,
        data_end_cursor: 0,
        data_end_seq: 0,
        data_end_prev_len: 0,
        data_end_stripe_start: 0,
        final_len: 0,
        batches_written: 0,
        evacuated_bytes: 0,
    };

    // Persist orig_boot_block, Ckpt, PlanBlob, and zero OutLog/BounceSlot BEFORE mutating byte 0.
    file_write_at(file, journal_base, &orig_boot_block)?;
    file_write_at(file, plan_offset, &plan_bytes)?;
    if out_log_bytes > 0 {
        file_write_at(file, out_log_offset, &vec![0u8; out_log_bytes as usize])?;
    }
    file.set_len(bounce_offset).map_err(|_| VzError::IoError)?;
    write_ckpt(file, ckpt_base, &ckpt)?;
    file.sync_data().map_err(|_| VzError::IoError)?;

    hook(InPlaceCrashPoint::BeforeJournalActivation)?;

    // Activate INCOMPAT_COMPACTING sentinel in BootHeader (`root_fallback_off = journal_base`).
    let mut sentinel_boot = orig_boot_block;
    let mut boot_hdr = BootHeader::from_bytes(&sentinel_boot)?;
    let mut s_slot = orig_slot;
    s_slot.generation = orig_slot.generation.saturating_add(1);
    s_slot.incompat_flags |= INCOMPAT_COMPACTING;
    s_slot.root_fallback_off = journal_base;
    boot_hdr.commit(&s_slot);
    // Commit sentinel into both slots so torn sector writes during final boot transition stay recoverable.
    let mut s_slot_b = s_slot;
    s_slot_b.generation = orig_slot.generation.saturating_add(1);
    boot_hdr.slot_a = s_slot;
    boot_hdr.slot_a.header_crc32c = crc32c(&s_slot.to_bytes()[..60]);
    boot_hdr.slot_b = s_slot_b;
    boot_hdr.slot_b.header_crc32c = crc32c(&s_slot_b.to_bytes()[..60]);
    boot_hdr.write_bytes(&mut sentinel_boot[..BootHeader::SIZE])?;
    if orig_boot_size == DEFAULT_BOOT_SIZE && (orig_slot.compat_flags & COMPAT_BOOT_ECC) != 0 {
        boot_ecc_encode(&mut sentinel_boot)?;
    }
    file_write_at(file, 0, &sentinel_boot)?;
    file.sync_data().map_err(|_| VzError::IoError)?;

    hook(InPlaceCrashPoint::AfterJournalActivation)?;
    Ok(())
}

fn read_out_slots(file: &File, out_log_offset: u64, count: usize) -> Result<Vec<OutSlot>, VzError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut raw = vec![0u8; count * OUT_SLOT_SIZE];
    file_read_at(file, out_log_offset, &mut raw)?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        out.push(OutSlot::from_bytes(&raw[i * OUT_SLOT_SIZE..(i + 1) * OUT_SLOT_SIZE])?);
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn finish_btree_and_boot_block(
    file: &mut File,
    ckpt: &mut CompactionCheckpoint,
    ckpt_base: u64,
    owners: &[OwnerEntry],
    dicts: &[DictEntry],
    schemas: &[SchemaEntry],
    cipher_hdr: Option<&CipherHeader>,
    extra_reg_tlvs: &[RawTlv],
    plan_entries: &[PlanEntry],
    hook: &mut dyn FnMut(InPlaceCrashPoint) -> Result<(), VzError>,
) -> Result<u64, VzError> {
    let out_slots = read_out_slots(file, ckpt.out_log_offset, ckpt.total_work_items as usize)?;

    // Reset write cursor cleanly back to end of compacted data clusters if resuming a crash in PHASE_BUILD_BTREE.
    let mut btree_write_cursor = ckpt.data_end_cursor;
    let rs_parity = if (ckpt.flags & CKPT_FLAG_RS_PARITY) != 0 && ckpt.rs_k > 0 && ckpt.rs_m > 0 {
        Some((ckpt.rs_k, ckpt.rs_m))
    } else {
        None
    };

    let mut emitter = ClusterEmitter::new(
        InPlaceBtreeSink {
            file,
            write_cursor: &mut btree_write_cursor,
            journal_base: ckpt.journal_base,
            pending: Vec::new(),
        },
        ckpt.data_end_cursor,
        ckpt.data_end_seq,
        ckpt.data_end_prev_len,
        ckpt.target_cluster_size as usize,
        rs_parity,
    )?;

    // Restore unfinished RS stripe cluster slices before emitting ChunkTables and B+Tree clusters.
    if let Some((_k, _m)) = rs_parity {
        let locs = collect_stripe_clusters(emitter.writer.file, ckpt.data_end_stripe_start, ckpt.data_end_cursor)?;
        for (i, &(off, clen)) in locs.iter().enumerate() {
            let mut cbuf = vec![0u8; clen as usize];
            file_read_at(emitter.writer.file, off, &mut cbuf)?;
            if i == 0 {
                emitter.stripe_first_seq = ClusterHeader::from_bytes(&cbuf)?.cluster_seq;
            }
            emitter.stripe_offsets.push(off);
            emitter.stripe_clusters.push(cbuf);
        }
    }

    let mut staged: Vec<StagedEntry> = Vec::with_capacity(plan_entries.len());
    for p in plan_entries {
        let payload = match p.kind {
            PlanPayloadKind::Inline { bytes, len } => DirPayload::Inline { bytes, len },
            PlanPayloadKind::ZeroSparse { raw_size } => DirPayload::Ref {
                data_offset: 0,
                stored_size: 0,
                raw_size,
                in_cluster_offset: 0,
            },
            PlanPayloadKind::SingleCluster {
                work_idx, raw_size, ..
            } => {
                let s = out_slots
                    .get(work_idx as usize)
                    .ok_or(VzError::BadFormat)?;
                DirPayload::Ref {
                    data_offset: s.cluster_off,
                    stored_size: s.stored_size,
                    raw_size,
                    in_cluster_offset: s.in_cluster_offset,
                }
            }
            PlanPayloadKind::MultiCluster {
                first_work_idx,
                chunk_count,
                raw_size,
            } => {
                let first = first_work_idx as usize;
                let end = first
                    .checked_add(chunk_count as usize)
                    .ok_or(VzError::ValueOverflow)?;
                let slice = out_slots.get(first..end).ok_or(VzError::BadFormat)?;
                let mut extents = Vec::with_capacity(slice.len());
                let mut total_stored = 0u64;
                for s in slice {
                    total_stored = total_stored
                        .checked_add(s.stored_size)
                        .ok_or(VzError::ValueOverflow)?;
                    extents.push(ChunkExtent {
                        cluster_offset: s.cluster_off,
                        in_cluster_offset: s.in_cluster_offset,
                        stored_size: s.stored_size,
                        raw_size: s.raw_size,
                    });
                }
                let (t_off, t_ioff) = emitter.emit_chunk_table_cluster(&extents)?;
                DirPayload::Ref {
                    data_offset: t_off,
                    stored_size: total_stored,
                    raw_size,
                    in_cluster_offset: t_ioff,
                }
            }
            PlanPayloadKind::HardlinkDup { primary_entry_idx } => staged
                .get(primary_entry_idx as usize)
                .ok_or(VzError::BadFormat)?
                .payload,
        };

        staged.push(StagedEntry {
            parent_path: p.parent_path.clone(),
            basename: p.basename.clone(),
            parent_hash: p.parent_hash,
            name_hash: p.name_hash,
            payload,
            entry_id: p.entry_id,
            mtime_ns: p.mtime_ns,
            posix_mode: p.posix_mode,
            owner_idx: p.owner_idx,
            flags_and_codec: p.flags_and_codec,
            ext_time: p.ext_time,
            ext_owner: p.ext_owner.clone(),
            xattrs: p.xattrs.clone(),
            ext_codec: p.ext_codec.clone(),
            schema_link: p.schema_link.clone(),
            sparse_extents: p.sparse_extents.clone(),
            extra_ext_tlvs: p.extra_ext_tlvs.clone(),
        });
    }

    mark_hash_collisions(&mut staged);
    staged.sort_by(|a, b| {
        key128_cmp(a.parent_hash, a.name_hash, b.parent_hash, b.name_hash)
            .then_with(|| a.parent_path.cmp(&b.parent_path))
            .then_with(|| a.basename.cmp(&b.basename))
    });

    let total_entries = staged.len() as u64;
    let registry_bytes = build_registry_bytes(
        owners,
        dicts,
        schemas,
        cipher_hdr,
        None,
        extra_reg_tlvs,
    )?;
    let new_boot_size = ckpt.new_boot_size as usize;
    let ecc_active = (ckpt.flags & CKPT_FLAG_BOOT_ECC) != 0 && new_boot_size == DEFAULT_BOOT_SIZE;
    let boot_limit = if ecc_active {
        BOOT_ECC_DESC_OFF
    } else {
        new_boot_size
    };
    let registry_offset = 0x0080usize;
    let root_node_offset = align_up_64(registry_offset + registry_bytes.len());
    if root_node_offset > boot_limit {
        return Err(VzError::BufferTooSmall);
    }
    let available_boot = boot_limit - root_node_offset;

    let tree_built = build_btree_index(
        &staged,
        ckpt.max_leaf_entries as usize,
        ckpt.max_route_entries as usize,
        available_boot,
        &mut emitter,
    )?;
    emitter.flush_parity_stripe()?;
    let final_len = *emitter.writer.write_cursor;
    drop(emitter);

    file.sync_data().map_err(|_| VzError::IoError)?;
    hook(InPlaceCrashPoint::AfterBtreeWrite)?;

    // Build final Boot Block image cleanly in BounceSlot BEFORE overwriting offset 0..boot_size.
    let mut compat_flags = ckpt.orig_compat_flags & !COMPAT_BOOT_ECC;
    if ecc_active {
        compat_flags |= COMPAT_BOOT_ECC;
    }
    let mut ro_compat_flags = 0u16;
    if rs_parity.is_some() {
        ro_compat_flags |= RO_COMPAT_STREAM_ECC;
    }
    let mut incompat_flags = 0u16;
    if (ckpt.flags & CKPT_FLAG_ENCRYPTED) != 0 {
        incompat_flags |= INCOMPAT_ENCRYPTED;
    }
    if (ckpt.flags & CKPT_FLAG_BIG_BOOT) != 0 {
        incompat_flags |= INCOMPAT_BIG_BOOT;
    }

    let final_slot = HeaderSlot {
        magic: MAGIC_HEADER,
        generation: ckpt.target_generation,
        boot_block_size: u32::try_from(new_boot_size).map_err(|_| VzError::ValueOverflow)?,
        compat_flags,
        ro_compat_flags,
        incompat_flags,
        tree_height: tree_built.tree_height,
        hash_algo: ckpt.hash_algo,
        lsm_run_count: 1,
        registry_offset: u16::try_from(registry_offset).map_err(|_| VzError::ValueOverflow)?,
        registry_size: u32::try_from(registry_bytes.len()).map_err(|_| VzError::ValueOverflow)?,
        root_node_offset: u32::try_from(root_node_offset).map_err(|_| VzError::ValueOverflow)?,
        total_entries,
        root_fallback_off: 0,
        root_entry_count: tree_built.root_entry_count,
        header_crc32c: 0,
    };

    let mut final_boot = vec![0u8; new_boot_size];
    let mut boot_hdr = BootHeader {
        slot_a: final_slot,
        slot_b: final_slot,
    };
    boot_hdr.slot_a.header_crc32c = crc32c(&final_slot.to_bytes()[..60]);
    let mut slot_b_zero = final_slot;
    slot_b_zero.generation = ckpt.target_generation.saturating_sub(1);
    slot_b_zero.header_crc32c = crc32c(&slot_b_zero.to_bytes()[..60]);
    boot_hdr.slot_b = slot_b_zero;
    boot_hdr.write_bytes(&mut final_boot[..BootHeader::SIZE])?;
    final_boot[registry_offset..registry_offset + registry_bytes.len()]
        .copy_from_slice(&registry_bytes);
    final_boot[root_node_offset..root_node_offset + tree_built.root_bytes.len()]
        .copy_from_slice(&tree_built.root_bytes);
    if ecc_active && new_boot_size == DEFAULT_BOOT_SIZE {
        boot_ecc_encode(&mut final_boot)?;
    }

    file_write_at(file, ckpt.bounce_offset, &final_boot)?;
    file.sync_data().map_err(|_| VzError::IoError)?;

    ckpt.ckpt_seq += 1;
    ckpt.phase = PHASE_WRITE_FINAL_BOOT;
    ckpt.final_len = final_len;
    ckpt.bounce_crc32c = crc32c(&final_boot);
    write_ckpt(file, ckpt_base, ckpt)?;
    Ok(final_len)
}

fn commit_final_boot_and_truncate(
    file: &mut File,
    ckpt: &CompactionCheckpoint,
    hook: &mut dyn FnMut(InPlaceCrashPoint) -> Result<(), VzError>,
) -> Result<(), VzError> {
    let bsize = ckpt.new_boot_size as usize;
    let mut final_boot = vec![0u8; bsize];
    file_read_at(file, ckpt.bounce_offset, &mut final_boot)?;
    if crc32c(&final_boot) != ckpt.bounce_crc32c {
        return Err(VzError::CrcMismatch);
    }

    // Write upper Boot Block pages first so offset 0..4096 still holds `INCOMPAT_COMPACTING` if a
    // crash happens before page 0 commits.
    if bsize > 4096 {
        let split_end = if bsize == DEFAULT_BOOT_SIZE { 0xEFB0 } else { bsize };
        file_write_at(file, 4096, &final_boot[4096..split_end])?;
        file.sync_data().map_err(|_| VzError::IoError)?;
        hook(InPlaceCrashPoint::MidFinalBootWrite)?;
        if split_end < bsize {
            file_write_at(file, split_end as u64, &final_boot[split_end..])?;
        }
    } else {
        hook(InPlaceCrashPoint::MidFinalBootWrite)?;
    }
    file_write_at(file, 0, &final_boot[..4096.min(bsize)])?;
    file.sync_data().map_err(|_| VzError::IoError)?;

    hook(InPlaceCrashPoint::BeforeFinalTruncate)?;
    file.set_len(ckpt.final_len).map_err(|_| VzError::IoError)?;
    file.sync_data().map_err(|_| VzError::IoError)?;
    Ok(())
}

fn execute_from_journal(
    file: &mut File,
    resumed: bool,
    prev_lsm_runs: u16,
    encryption: Option<&EncryptionKey>,
    batch_bytes: usize,
    hook: &mut dyn FnMut(InPlaceCrashPoint) -> Result<(), VzError>,
) -> Result<InPlaceCompactReport, VzError> {
    let mut boot_probe = vec![0u8; DEFAULT_BOOT_SIZE];
    file_read_at(file, 0, &mut boot_probe)?;
    if boot_ecc_verify_and_repair(&mut boot_probe).is_ok() {
        // Use ECC-repaired copy if applicable.
    }
    let bh = BootHeader::from_bytes(&boot_probe)?;
    let (slot, _) = bh.select_active(
        INCOMPAT_ENCRYPTED | INCOMPAT_BIG_BOOT | INCOMPAT_COMPACTING,
    )?;

    if (slot.incompat_flags & INCOMPAT_COMPACTING) == 0 {
        // Final boot was already written before an interrupted `truncate`. Trim trailing dead journal if needed.
        return Err(VzError::InvalidInput);
    }

    let journal_base = slot.root_fallback_off;
    let peek_file_len = file.seek(SeekFrom::End(0)).map_err(|_| VzError::IoError)?;
    if journal_base == 0 || journal_base >= peek_file_len {
        return Err(VzError::BadFormat);
    }

    // Read ckpt_base safely via orig_boot_size inferred from journal or BootHeader.
    // Try standard DEFAULT_BOOT_SIZE first, then slot.boot_block_size if bigger.
    let mut ckpt_base = journal_base + slot.boot_block_size as u64;
    let mut ckpt = match read_best_ckpt(file, ckpt_base) {
        Ok(c) => c,
        Err(_) => {
            ckpt_base = journal_base + DEFAULT_BOOT_SIZE as u64;
            read_best_ckpt(file, ckpt_base)?
        }
    };

    let mut orig_boot_block = vec![0u8; ckpt.orig_boot_size as usize];
    file_read_at(file, journal_base, &mut orig_boot_block)?;
    let orig_bh = BootHeader::from_bytes(&orig_boot_block)?;
    let (orig_slot, _) = orig_bh.select_active(INCOMPAT_ENCRYPTED | INCOMPAT_BIG_BOOT)?;
    let DecodedRegistry {
        owners,
        dicts,
        schemas,
        crypto: crypto_pair,
    } = decode_registry_from_boot(&orig_boot_block, orig_slot, encryption)?;
    let cipher_hdr = crypto_pair.as_ref().map(|(h, _)| h);
    let crypto_ctx = crypto_pair.as_ref().map(|(_, c)| c);

    if ckpt.phase == PHASE_WRITE_FINAL_BOOT {
        let peak = file.seek(SeekFrom::End(0)).map_err(|_| VzError::IoError)?;
        commit_final_boot_and_truncate(file, &ckpt, hook)?;
        return Ok(InPlaceCompactReport {
            resumed,
            prev_lsm_runs,
            original_bytes: ckpt.orig_file_len,
            compacted_bytes: ckpt.final_len,
            batches_written: ckpt.batches_written,
            evacuated_bytes: ckpt.evacuated_bytes,
            peak_file_bytes: peak,
        });
    }

    let mut plan_buf = vec![0u8; ckpt.plan_len as usize];
    file_read_at(file, ckpt.plan_offset, &mut plan_buf)?;
    let ParsedPlan {
        entries: plan_entries,
        work,
        extra_reg_tlvs,
    } = deserialize_plan(&plan_buf)?;
    drop(plan_buf);

    let mut evac_spans = reconstruct_evac_spans(file, ckpt.evac_log_offset, ckpt.evac_cursor)?;
    let mut evac_scratch = Vec::new();
    finish_pending_bounce_if_any(file, &mut ckpt, ckpt_base, &mut evac_scratch)?;

    if ckpt.phase == PHASE_ACTIVE {
        let mut cluster_cache_buf = Vec::new();
        let mut decrypt_buf = Vec::new();
        let mut encrypt_buf = Vec::new();
        while (ckpt.completed_items as usize) < work.len() {
            let progressed = run_next_batch(
                file,
                &mut ckpt,
                ckpt_base,
                &work,
                crypto_ctx,
                batch_bytes,
                &mut evac_spans,
                &mut cluster_cache_buf,
                &mut decrypt_buf,
                &mut encrypt_buf,
                &mut evac_scratch,
                hook,
            )?;
            if !progressed {
                break;
            }
        }
        maybe_flush_rs_stripes(
            file,
            &mut ckpt,
            ckpt_base,
            &mut evac_spans,
            &[],
            false,
            &mut evac_scratch,
            hook,
        )?;

        ckpt.ckpt_seq += 1;
        ckpt.phase = PHASE_BUILD_BTREE;
        ckpt.data_end_cursor = ckpt.write_cursor;
        ckpt.data_end_seq = ckpt.cluster_seq;
        ckpt.data_end_prev_len = ckpt.prev_cluster_len;
        ckpt.data_end_stripe_start = ckpt.stripe_start_offset;
        write_ckpt(file, ckpt_base, &ckpt)?;
    }

    if ckpt.phase == PHASE_BUILD_BTREE {
        let _final_len = finish_btree_and_boot_block(
            file,
            &mut ckpt,
            ckpt_base,
            &owners,
            &dicts,
            &schemas,
            cipher_hdr,
            &extra_reg_tlvs,
            &plan_entries,
            hook,
        )?;
    }

    let peak = file.seek(SeekFrom::End(0)).map_err(|_| VzError::IoError)?;
    if ckpt.phase == PHASE_WRITE_FINAL_BOOT {
        commit_final_boot_and_truncate(file, &ckpt, hook)?;
    }

    Ok(InPlaceCompactReport {
        resumed,
        prev_lsm_runs,
        original_bytes: ckpt.orig_file_len,
        compacted_bytes: ckpt.final_len,
        batches_written: ckpt.batches_written,
        evacuated_bytes: ckpt.evacuated_bytes,
        peak_file_bytes: peak,
    })
}

fn check_compacting_state(file: &File) -> Result<(bool, u16), VzError> {
    let mut boot_probe = vec![0u8; DEFAULT_BOOT_SIZE];
    file_read_at(file, 0, &mut boot_probe)?;
    let _ = boot_ecc_verify_and_repair(&mut boot_probe);
    let bh = BootHeader::from_bytes(&boot_probe)?;
    let (slot, _) = bh.select_active(
        INCOMPAT_ENCRYPTED | INCOMPAT_BIG_BOOT | INCOMPAT_COMPACTING,
    )?;
    Ok((
        (slot.incompat_flags & INCOMPAT_COMPACTING) != 0,
        slot.lsm_run_count,
    ))
}

/// Compacts a `.vz` archive file in place using bounded RAM (`options.batch_bytes`) and zero `2x`
/// disk duplication.
///
/// Automatically detects and resumes any previously interrupted in-place compaction (`INCOMPAT_COMPACTING`).
pub fn compact_file_in_place(
    file: &mut File,
    options: InPlaceCompactOptions,
) -> Result<InPlaceCompactReport, VzError> {
    compact_file_in_place_with_hook(file, options, &mut |_| Ok(()))
}

/// Resumes an interrupted in-place compaction on `file` whose `BootHeader` has [`INCOMPAT_COMPACTING`] set.
///
/// Returns [`VzError::InvalidInput`] if `file` is not currently mid-compaction.
pub fn resume_in_place_compaction(
    file: &mut File,
    options: InPlaceCompactOptions,
) -> Result<InPlaceCompactReport, VzError> {
    let (is_compacting, prev_runs) = check_compacting_state(file)?;
    if !is_compacting {
        return Err(VzError::InvalidInput);
    }
    execute_from_journal(
        file,
        true,
        prev_runs,
        options.encryption.as_ref(),
        options.batch_bytes.max(MIN_BATCH_BYTES),
        &mut |_| Ok(()),
    )
}

#[doc(hidden)]
pub fn compact_file_in_place_with_hook(
    file: &mut File,
    options: InPlaceCompactOptions,
    hook: &mut dyn FnMut(InPlaceCrashPoint) -> Result<(), VzError>,
) -> Result<InPlaceCompactReport, VzError> {
    let (is_compacting, prev_runs) = check_compacting_state(file)?;
    if !is_compacting {
        prepare_journal(file, &options, hook)?;
    }
    execute_from_journal(
        file,
        is_compacting,
        prev_runs,
        options.encryption.as_ref(),
        options.batch_bytes.max(MIN_BATCH_BYTES),
        hook,
    )
}
