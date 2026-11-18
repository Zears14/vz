use std::io::Write;

use crate::crc::crc32c;
use crate::error::VzError;
use crate::ext_meta::{
    ChunkExtent, ColChunkStats, DataManifestHeader, ExtCodecMeta, OwnerEntry, RawTlv,
    SchemaLinkMeta, SparseExtent, Xattr, encode_chunk_table, push_levint, push_lp_bytes, push_tlv,
};
use crate::rs::{build_cluster_from_body, encode_rs_gf256_stripe};
use crate::wire::{ClusterHeader, DirPayload, ExtTime, TAG_CHUNK_TABLE, TAG_DATA_MANIFEST, levint_len};

#[derive(Debug, Clone)]
pub(super) struct StagedEntry {
    pub(super) parent_path: String,
    pub(super) basename: String,
    pub(super) parent_hash: u64,
    pub(super) name_hash: u64,
    pub(super) payload: DirPayload,
    pub(super) entry_id: u64,
    pub(super) mtime_ns: i64,
    pub(super) posix_mode: u16,
    pub(super) owner_idx: u8,
    pub(super) flags_and_codec: u8,
    pub(super) ext_time: Option<ExtTime>,
    pub(super) ext_owner: Option<OwnerEntry>,
    pub(super) xattrs: Vec<Xattr>,
    pub(super) ext_codec: Option<ExtCodecMeta>,
    pub(super) schema_link: Option<SchemaLinkMeta>,
    pub(super) sparse_extents: Option<Vec<SparseExtent>>,
    pub(super) extra_ext_tlvs: Vec<RawTlv>,
}

pub(super) struct ClusterEmitter<W: Write> {
    pub(super) writer: W,
    pub(super) current_offset: u64,
    pub(super) cluster_seq: u64,
    pub(super) prev_cluster_len: u64,
    pub(super) rs_parity: Option<(u16, u16)>,
    pub(super) pending_body: Vec<u8>,
    pub(super) target_cluster_size: usize,
    pub(super) stripe_clusters: Vec<Vec<u8>>,
    pub(super) stripe_offsets: Vec<u64>,
    pub(super) stripe_first_seq: u64,
}

impl<W: Write> ClusterEmitter<W> {
    pub(super)fn new(
        writer: W,
        start_offset: u64,
        start_seq: u64,
        prev_cluster_len: u64,
        target_cluster_size: usize,
        rs_parity: Option<(u16, u16)>,
    ) -> Result<Self, VzError> {
        if let Some((k, m)) = rs_parity
            && (k == 0 || m == 0 || (k as usize + m as usize) > 256)
        {
            return Err(VzError::InvalidInput);
        }
        Ok(Self {
            writer,
            current_offset: start_offset,
            cluster_seq: start_seq,
            prev_cluster_len,
            rs_parity,
            pending_body: Vec::new(),
            target_cluster_size: target_cluster_size.max(4096),
            stripe_clusters: Vec::new(),
            stripe_offsets: Vec::new(),
            stripe_first_seq: start_seq,
        })
    }

    pub(super)fn emit_raw_cluster_bytes(&mut self, cluster: Vec<u8>) -> Result<(u64, u32), VzError> {
        let off = self.current_offset;
        let len = u32::try_from(cluster.len()).map_err(|_| VzError::ValueOverflow)?;
        self.writer.write_all(&cluster).map_err(|_| VzError::IoError)?;
        self.current_offset = self
            .current_offset
            .checked_add(len as u64)
            .ok_or(VzError::ValueOverflow)?;
        self.prev_cluster_len = len as u64;
        self.cluster_seq += 1;

        if let Some((k, _m)) = self.rs_parity {
            if self.stripe_clusters.is_empty() {
                self.stripe_first_seq = self.cluster_seq - 1;
            }
            self.stripe_offsets.push(off);
            self.stripe_clusters.push(cluster);
            if self.stripe_clusters.len() == k as usize {
                self.flush_parity_stripe()?;
            }
        }
        Ok((off, len))
    }

    pub(super)fn emit_cluster_body(&mut self, body_tlv: &[u8]) -> Result<(u64, u32), VzError> {
        let cluster = build_cluster_from_body(body_tlv, self.prev_cluster_len, self.cluster_seq)?;
        self.emit_raw_cluster_bytes(cluster)
    }

    pub(super) fn flush_parity_stripe(&mut self) -> Result<(), VzError> {
        let Some((_k, m)) = self.rs_parity else {
            return Ok(());
        };
        if self.stripe_clusters.is_empty() {
            return Ok(());
        }
        let refs: Vec<&[u8]> = self.stripe_clusters.iter().map(Vec::as_slice).collect();
        let (parities, new_prev_len) = encode_rs_gf256_stripe(
            &refs,
            &self.stripe_offsets,
            self.stripe_first_seq,
            m,
            self.cluster_seq,
            self.prev_cluster_len,
        )?;
        for p in parities {
            let len = p.len() as u64;
            self.writer.write_all(&p).map_err(|_| VzError::IoError)?;
            self.current_offset = self
                .current_offset
                .checked_add(len)
                .ok_or(VzError::ValueOverflow)?;
            self.cluster_seq += 1;
        }
        self.prev_cluster_len = new_prev_len;
        self.stripe_clusters.clear();
        self.stripe_offsets.clear();
        Ok(())
    }

    pub(super) fn next_data_cluster_seq(&self, chunk_index: usize) -> u64 {
        let parities_before = match self.rs_parity {
            Some((k, m)) => {
                ((self.stripe_clusters.len() + chunk_index) / k as usize) as u64 * m as u64
            }
            None => 0,
        };
        self.cluster_seq + chunk_index as u64 + parities_before
    }

    pub(super) fn flush_pending_data_cluster(&mut self) -> Result<(), VzError> {
        if self.pending_body.is_empty() {
            return Ok(());
        }
        let body = core::mem::take(&mut self.pending_body);
        self.emit_cluster_body(&body)?;
        Ok(())
    }

    /// Appends a 64-byte-aligned `TAG_DATA_MANIFEST` TLV to `body`, returning `in_cluster_offset`.
    pub(super) fn append_manifest_tlv_to_body(
        body: &mut Vec<u8>,
        cluster_off: u64,
        entry_id: u64,
        raw_size: u64,
        stored_payload: &[u8],
        stats_bytes: &[u8],
        manifest_flags: u16,
    ) -> Result<u32, VzError> {
        let body_pos = body.len();
        let prefix_len = DataManifestHeader::SIZE + stats_bytes.len();
        let stored_len = stored_payload.len();
        let file_pos_before_tlv = cluster_off + ClusterHeader::SIZE as u64 + body_pos as u64;

        let (vint_w, pad) = solve_manifest_align64(file_pos_before_tlv, prefix_len, stored_len)?;
        let val_len = prefix_len + pad + stored_len;
        if levint_len(val_len as u64)? != vint_w {
            return Err(VzError::BadFormat);
        }
        let payload_rel_off = u16::try_from(prefix_len + pad).map_err(|_| VzError::ValueOverflow)?;
        let in_cluster_offset =
            u32::try_from(ClusterHeader::SIZE + body_pos + 1 + vint_w + prefix_len + pad)
                .map_err(|_| VzError::ValueOverflow)?;
        debug_assert_eq!((cluster_off + in_cluster_offset as u64) & 63, 0);

        let hdr = DataManifestHeader {
            entry_id,
            raw_size,
            stored_size: stored_len as u64,
            payload_crc32c: crc32c(stored_payload),
            manifest_flags,
            payload_rel_off,
        };
        body.reserve(1 + vint_w + val_len);
        push_levint(body, TAG_DATA_MANIFEST)?;
        push_levint(body, val_len as u64)?;
        body.extend_from_slice(&hdr.to_bytes());
        body.extend_from_slice(stats_bytes);
        write_padding_bytes(body, pad)?;
        body.extend_from_slice(stored_payload);
        Ok(in_cluster_offset)
    }

    /// Appends a `TAG_DATA_MANIFEST` + 64-byte-aligned payload to the current shared data cluster,
    /// returning `(cluster_offset, in_cluster_offset, cluster_seq)`.
    pub(super) fn append_data_payload(
        &mut self,
        entry_id: u64,
        raw_size: u64,
        stored_payload: &[u8],
        col_stats: Option<&ColChunkStats>,
    ) -> Result<(u64, u32, u64), VzError> {
        let stats_bytes = encode_col_chunk_stats(col_stats)?;
        let manifest_flags: u16 = 0x0002 | u16::from(col_stats.is_some());
        let prefix_len = DataManifestHeader::SIZE + stats_bytes.len();
        let est_add = 16 + prefix_len + 64 + stored_payload.len();
        if !self.pending_body.is_empty() && self.pending_body.len() + est_add > self.target_cluster_size {
            self.flush_pending_data_cluster()?;
        }

        let cluster_off = self.current_offset;
        let seq = self.cluster_seq;
        let in_cluster_offset = Self::append_manifest_tlv_to_body(
            &mut self.pending_body,
            cluster_off,
            entry_id,
            raw_size,
            stored_payload,
            &stats_bytes,
            manifest_flags,
        )?;

        if self.pending_body.len() >= self.target_cluster_size {
            self.flush_pending_data_cluster()?;
        }
        Ok((cluster_off, in_cluster_offset, seq))
    }

    /// Writes a dedicated standalone cluster containing a single `TAG_DATA_MANIFEST` (for multi-cluster chunks).
    pub(super) fn emit_dedicated_data_cluster(
        &mut self,
        entry_id: u64,
        raw_size: u64,
        stored_payload: &[u8],
        col_stats: Option<&ColChunkStats>,
    ) -> Result<(u64, u32, u64), VzError> {
        self.flush_pending_data_cluster()?;
        let stats_bytes = encode_col_chunk_stats(col_stats)?;
        let manifest_flags: u16 = 0x0002 | u16::from(col_stats.is_some());
        let cluster_off = self.current_offset;
        let seq = self.cluster_seq;
        let mut body = Vec::new();
        let in_cluster_offset = Self::append_manifest_tlv_to_body(
            &mut body,
            cluster_off,
            entry_id,
            raw_size,
            stored_payload,
            &stats_bytes,
            manifest_flags,
        )?;
        self.emit_cluster_body(&body)?;
        Ok((cluster_off, in_cluster_offset, seq))
    }

    /// Writes a standalone cluster containing a 64-byte-aligned `TAG_CHUNK_TABLE` TLV.
    pub(super) fn emit_chunk_table_cluster(&mut self, extents: &[ChunkExtent]) -> Result<(u64, u32), VzError> {
        self.flush_pending_data_cluster()?;
        let table = encode_chunk_table(extents)?;
        let cluster_off = self.current_offset;
        let mut body = Vec::with_capacity(64 + table.len());
        // Pad inside cluster body to 64-byte align the TAG_CHUNK_TABLE TLV header itself.
        let file_pos = cluster_off + ClusterHeader::SIZE as u64;
        let rem = (file_pos & 63) as usize;
        let pad = if rem == 0 { 0 } else { 64 - rem };
        write_padding_bytes(&mut body, pad)?;
        let in_cluster_offset =
            u32::try_from(ClusterHeader::SIZE + body.len()).map_err(|_| VzError::ValueOverflow)?;
        push_tlv(&mut body, TAG_CHUNK_TABLE, &table)?;
        self.emit_cluster_body(&body)?;
        Ok((cluster_off, in_cluster_offset))
    }
}

fn solve_manifest_align64(
    file_pos_before_tlv: u64,
    prefix_len: usize,
    stored_len: usize,
) -> Result<(usize, usize), VzError> {
    for &vint_w in &[1usize, 2, 4, 8] {
        let base_pos = file_pos_before_tlv + 1 + vint_w as u64 + prefix_len as u64;
        let rem = (base_pos & 63) as usize;
        let mut pad = if rem == 0 { 0 } else { 64 - rem };
        let val_len = prefix_len + pad + stored_len;
        let needed_w = levint_len(val_len as u64)?;
        if needed_w == vint_w {
            return Ok((vint_w, pad));
        }
        if needed_w < vint_w {
            pad += 64;
            let val_len2 = prefix_len + pad + stored_len;
            if levint_len(val_len2 as u64)? == vint_w {
                return Ok((vint_w, pad));
            }
        }
    }
    Err(VzError::ValueOverflow)
}

fn write_padding_bytes(out: &mut Vec<u8>, pad: usize) -> Result<(), VzError> {
    if pad == 0 {
        return Ok(());
    }
    if pad == 1 {
        out.push(0x00);
        return Ok(());
    }
    out.push(0xEC);
    let inner = (pad - 2) as u64;
    let w = levint_len(inner)?;
    if pad < 1 + w {
        return Err(VzError::BadFormat);
    }
    let payload_len = (pad - 1 - w) as u64;
    // Re-check width if subtracting w changed threshold
    if levint_len(payload_len)? == w {
        push_levint(out, payload_len)?;
        out.resize(out.len() + payload_len as usize, 0);
    } else {
        // Fall back to leading 0x00 NOP + Void
        out.pop();
        out.push(0x00);
        write_padding_bytes(out, pad - 1)?;
    }
    Ok(())
}

pub(super) fn encode_col_chunk_stats(stats: Option<&ColChunkStats>) -> Result<Vec<u8>, VzError> {
    let Some(s) = stats else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&s.col_schema_id.to_le_bytes());
    out.extend_from_slice(&s.row_count.to_le_bytes());
    out.extend_from_slice(&s.null_count.to_le_bytes());
    push_lp_bytes(&mut out, &s.min_bytes)?;
    push_lp_bytes(&mut out, &s.max_bytes)?;
    Ok(out)
}

