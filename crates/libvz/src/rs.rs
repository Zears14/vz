use crate::btree::validate_cluster;
use crate::crc::crc32c;
use crate::ecc::{
    gf256_invert_matrix_in_place, rs_gf256_cauchy_coeff, rs_gf256_madd_multi,
};
use crate::error::VzError;
use crate::ext_meta::push_levint;
use crate::parallel::{adaptive_workers, par_try_map};
use crate::wire::{
    ClusterFooter, ClusterHeader, ECC_RAPTORQ, ECC_RS_GF256, ECC_RS_GF65536, MAGIC_CLUSTER,
    MAGIC_FOOTER, ParityManifest, TAG_PARITY_CLUSTER, TlvIter, read_le_u64, write_void_align64,
};

const RS_TILE_BYTES: usize = 32 * 1024;

#[inline]
fn accumulate_tile(
    tile_dsts: &mut [&mut [u8]],
    srcs: &[&[u8]],
    coeffs_row_major: &[u8],
    n_dst: usize,
    global_off: usize,
    global_end: usize,
) -> Result<(), VzError> {
    for (s_idx, src) in srcs.iter().enumerate() {
        if global_off >= src.len() {
            continue;
        }
        let src_tile = &src[global_off..global_end.min(src.len())];
        let row_coeffs = &coeffs_row_major[s_idx * n_dst..(s_idx + 1) * n_dst];
        rs_gf256_madd_multi(tile_dsts, src_tile, row_coeffs)?;
    }
    Ok(())
}

fn accumulate_band(
    band_dsts: &mut [&mut [u8]],
    band_start: usize,
    band_len: usize,
    srcs: &[&[u8]],
    coeffs_row_major: &[u8],
    n_dst: usize,
) -> Result<(), VzError> {
    let mut tile_off = 0usize;
    while tile_off < band_len {
        let tile_len = RS_TILE_BYTES.min(band_len - tile_off);
        let global_off = band_start + tile_off;
        let global_end = global_off + tile_len;
        if n_dst <= 16 {
            let mut tile_dsts: [&mut [u8]; 16] = Default::default();
            for (slot, d) in tile_dsts[..n_dst].iter_mut().zip(band_dsts.iter_mut()) {
                *slot = &mut d[tile_off..tile_off + tile_len];
            }
            accumulate_tile(
                &mut tile_dsts[..n_dst],
                srcs,
                coeffs_row_major,
                n_dst,
                global_off,
                global_end,
            )?;
        } else {
            let mut tile_dsts: Vec<&mut [u8]> = band_dsts
                .iter_mut()
                .map(|d| &mut d[tile_off..tile_off + tile_len])
                .collect();
            accumulate_tile(
                &mut tile_dsts,
                srcs,
                coeffs_row_major,
                n_dst,
                global_off,
                global_end,
            )?;
        }
        tile_off += tile_len;
    }
    Ok(())
}

fn accumulate_tiled_gf256(
    dst_payloads: &mut [&mut [u8]],
    srcs: &[&[u8]],
    coeffs_row_major: &[u8],
    len: usize,
) -> Result<(), VzError> {
    let n_dst = dst_payloads.len();
    let n_src = srcs.len();
    if len == 0 || n_dst == 0 || n_src == 0 {
        return Ok(());
    }
    let num_tiles = len.div_ceil(RS_TILE_BYTES);
    let ops_bytes = n_src.saturating_mul(n_dst).saturating_mul(len);
    let workers = adaptive_workers(num_tiles, ops_bytes, 1024 * 1024);
    if workers <= 1 {
        return accumulate_band(dst_payloads, 0, len, srcs, coeffs_row_major, n_dst);
    }

    let tiles_per_worker = num_tiles.div_ceil(workers);
    let band_bytes = tiles_per_worker.saturating_mul(RS_TILE_BYTES);
    let mut bands: Vec<(usize, usize, Vec<&mut [u8]>)> = Vec::with_capacity(workers);
    let mut rem: Vec<&mut [u8]> = dst_payloads.iter_mut().map(|s| &mut **s).collect();
    let mut cur_off = 0usize;
    while cur_off < len {
        let band_len = band_bytes.min(len - cur_off);
        let mut band_slices = Vec::with_capacity(n_dst);
        let mut next_rem = Vec::with_capacity(n_dst);
        for slice in rem {
            let (head, tail) = slice.split_at_mut(band_len);
            band_slices.push(head);
            next_rem.push(tail);
        }
        bands.push((cur_off, band_len, band_slices));
        rem = next_rem;
        cur_off += band_len;
    }

    if bands.len() <= 1 {
        if let Some((start, blen, mut slices)) = bands.pop() {
            return accumulate_band(&mut slices, start, blen, srcs, coeffs_row_major, n_dst);
        }
        return Ok(());
    }

    par_try_map(bands, workers, |(start, blen, mut slices)| {
        accumulate_band(&mut slices, start, blen, srcs, coeffs_row_major, n_dst)
    })?;
    Ok(())
}

/// Encodes a single `TAG_PARITY_CLUSTER` cluster buffer (header + TLV + align64 + footer).
pub fn build_cluster_from_body(
    body_tlv: &[u8],
    prev_cluster_len: u64,
    cluster_seq: u64,
) -> Result<Vec<u8>, VzError> {
    let min_unaligned = ClusterHeader::SIZE
        .checked_add(body_tlv.len())
        .and_then(|v| v.checked_add(ClusterFooter::SIZE))
        .ok_or(VzError::ValueOverflow)?;
    let rem = min_unaligned & 63;
    let pad = if rem == 0 { 0 } else { 64 - rem };
    let total_len = min_unaligned
        .checked_add(pad)
        .ok_or(VzError::ValueOverflow)?;

    let mut out = vec![0u8; total_len];
    let hdr = ClusterHeader {
        sync_magic: MAGIC_CLUSTER,
        cluster_len: total_len as u64,
        prev_cluster_len,
        cluster_seq,
    };
    hdr.write_bytes(&mut out[..ClusterHeader::SIZE])?;
    let body_end = ClusterHeader::SIZE + body_tlv.len();
    out[ClusterHeader::SIZE..body_end].copy_from_slice(body_tlv);
    if pad > 0 {
        let written = write_void_align64(
            &mut out[body_end..total_len - ClusterFooter::SIZE],
            (body_end + ClusterFooter::SIZE) as u64,
        )?;
        if written != pad {
            return Err(VzError::BadFormat);
        }
    }

    let ftr_start = total_len - ClusterFooter::SIZE;
    let mut ftr = ClusterFooter {
        cluster_len: total_len as u64,
        cluster_crc32c: 0,
        footer_magic: MAGIC_FOOTER,
    };
    ftr.write_bytes(&mut out[ftr_start..total_len])?;
    ftr.cluster_crc32c = crc32c(&out[..total_len - 8]);
    ftr.write_bytes(&mut out[ftr_start..total_len])?;
    Ok(out)
}

/// Encodes `M` Reed-Solomon `GF(2^8)` Cauchy parity clusters for `K` data clusters.
///
/// Returns `(parity_cluster_buffers, last_cluster_len)`.
pub fn encode_rs_gf256_stripe(
    data_clusters: &[&[u8]],
    data_offsets: &[u64],
    first_cluster_seq: u64,
    parity_clusters_m: u16,
    start_parity_seq: u64,
    prev_cluster_len: u64,
) -> Result<(Vec<Vec<u8>>, u64), VzError> {
    let k = data_clusters.len();
    let m = parity_clusters_m as usize;
    if k == 0 || m == 0 || k != data_offsets.len() {
        return Err(VzError::InvalidInput);
    }
    if k + m > 256 {
        return Err(VzError::InvalidInput);
    }

    let max_cluster_len = data_clusters.iter().map(|c| c.len()).max().unwrap_or(0);
    let header_plus_offsets = ParityManifest::FIXED_SIZE
        .checked_add(k.checked_mul(8).ok_or(VzError::ValueOverflow)?)
        .ok_or(VzError::ValueOverflow)?;
    let tlv_val_len = header_plus_offsets
        .checked_add(max_cluster_len)
        .ok_or(VzError::ValueOverflow)?;

    let mut tlv_hdr = Vec::with_capacity(16);
    push_levint(&mut tlv_hdr, TAG_PARITY_CLUSTER)?;
    push_levint(&mut tlv_hdr, tlv_val_len as u64)?;
    let body_len = tlv_hdr
        .len()
        .checked_add(tlv_val_len)
        .ok_or(VzError::ValueOverflow)?;
    let min_unaligned = ClusterHeader::SIZE
        .checked_add(body_len)
        .and_then(|v| v.checked_add(ClusterFooter::SIZE))
        .ok_or(VzError::ValueOverflow)?;
    let rem = min_unaligned & 63;
    let pad = if rem == 0 { 0 } else { 64 - rem };
    let total_len = min_unaligned
        .checked_add(pad)
        .ok_or(VzError::ValueOverflow)?;
    let body_end = ClusterHeader::SIZE + body_len;
    let payload_start = ClusterHeader::SIZE + tlv_hdr.len() + header_plus_offsets;
    let payload_end = payload_start + max_cluster_len;
    let ftr_start = total_len - ClusterFooter::SIZE;

    let mut parity_clusters: Vec<Vec<u8>> = Vec::with_capacity(m);
    for p_idx in 0..m {
        let mut out = vec![0u8; total_len];
        let hdr = ClusterHeader {
            sync_magic: MAGIC_CLUSTER,
            cluster_len: total_len as u64,
            prev_cluster_len: if p_idx == 0 {
                prev_cluster_len
            } else {
                total_len as u64
            },
            cluster_seq: start_parity_seq + p_idx as u64,
        };
        hdr.write_bytes(&mut out[..ClusterHeader::SIZE])?;

        let mut cursor = ClusterHeader::SIZE;
        out[cursor..cursor + tlv_hdr.len()].copy_from_slice(&tlv_hdr);
        cursor += tlv_hdr.len();

        let manifest = ParityManifest {
            ecc_codec: ECC_RS_GF256,
            interleave_stride: 1,
            data_clusters_k: k as u16,
            parity_clusters_m,
            parity_index: p_idx as u16,
            first_cluster_seq,
            max_cluster_len: max_cluster_len as u64,
        };
        out[cursor..cursor + ParityManifest::FIXED_SIZE].copy_from_slice(&manifest.to_bytes());
        cursor += ParityManifest::FIXED_SIZE;

        for &off in data_offsets {
            out[cursor..cursor + 8].copy_from_slice(&off.to_le_bytes());
            cursor += 8;
        }

        if pad > 0 {
            let written = write_void_align64(
                &mut out[body_end..ftr_start],
                (body_end + ClusterFooter::SIZE) as u64,
            )?;
            if written != pad {
                return Err(VzError::BadFormat);
            }
        }

        parity_clusters.push(out);
    }

    if max_cluster_len > 0 {
        let mut coeffs = Vec::with_capacity(k * m);
        for d_idx in 0..k {
            for p_idx in 0..m {
                coeffs.push(rs_gf256_cauchy_coeff(
                    p_idx as u16,
                    d_idx as u16,
                    parity_clusters_m,
                )?);
            }
        }
        let mut payload_slices: Vec<&mut [u8]> = parity_clusters
            .iter_mut()
            .map(|c| &mut c[payload_start..payload_end])
            .collect();
        accumulate_tiled_gf256(&mut payload_slices, data_clusters, &coeffs, max_cluster_len)?;
    }

    let crc_workers = adaptive_workers(m, m.saturating_mul(total_len), 512 * 1024);
    let finalize_one = |cluster: &mut Vec<u8>| -> Result<(), VzError> {
        let ftr_zero = ClusterFooter {
            cluster_len: total_len as u64,
            cluster_crc32c: 0,
            footer_magic: MAGIC_FOOTER,
        };
        ftr_zero.write_bytes(&mut cluster[ftr_start..total_len])?;
        let crc = crc32c(&cluster[..total_len - 8]);
        let ftr = ClusterFooter {
            cluster_len: total_len as u64,
            cluster_crc32c: crc,
            footer_magic: MAGIC_FOOTER,
        };
        ftr.write_bytes(&mut cluster[ftr_start..total_len])
    };
    if crc_workers <= 1 {
        for cluster in &mut parity_clusters {
            finalize_one(cluster)?;
        }
    } else {
        let chunk_sz = m.div_ceil(crc_workers);
        let groups: Vec<&mut [Vec<u8>]> = parity_clusters.chunks_mut(chunk_sz).collect();
        par_try_map(groups, crc_workers, |grp| {
            for cluster in grp {
                finalize_one(cluster)?;
            }
            Ok(())
        })?;
    }

    Ok((parity_clusters, total_len as u64))
}

/// Recovers any missing/corrupted data clusters in an `RS_GF256` stripe using full `GF(2^8)`
/// Gauss-Jordan matrix inversion.
///
/// On success, missing `None` entries in `data_slots` are populated with validated cluster bytes,
/// and the count of recovered data clusters is returned.
pub fn recover_rs_gf256_stripe(
    data_slots: &mut [Option<Vec<u8>>],
    parity_slots: &[Option<(u16, Vec<u8>)>],
    k: usize,
    m: usize,
    max_cluster_len: usize,
) -> Result<usize, VzError> {
    if k == 0 || m == 0 || data_slots.len() != k || k + m > 256 {
        return Err(VzError::InvalidInput);
    }
    let missing_indices: Vec<usize> = data_slots
        .iter()
        .enumerate()
        .filter_map(|(i, s)| if s.is_none() { Some(i) } else { None })
        .collect();

    if missing_indices.is_empty() {
        return Ok(0);
    }

    enum Source<'a> {
        Data(usize, &'a [u8]),
        Parity(u16, &'a [u8]),
    }

    let mut sources: Vec<Source<'_>> = Vec::with_capacity(k);
    for (idx, slot) in data_slots.iter().enumerate() {
        if let Some(bytes) = slot {
            sources.push(Source::Data(idx, bytes.as_slice()));
            if sources.len() == k {
                break;
            }
        }
    }
    if sources.len() < k {
        for (p_idx, p_bytes) in parity_slots.iter().flatten() {
            if p_bytes.len() < max_cluster_len {
                return Err(VzError::BadFormat);
            }
            sources.push(Source::Parity(*p_idx, &p_bytes[..max_cluster_len]));
            if sources.len() == k {
                break;
            }
        }
    }
    if sources.len() < k {
        return Err(VzError::CorruptUnrecoverable);
    }

    let mut mat = vec![0u8; k * k];
    let mut inv = vec![0u8; k * k];
    for (row, src) in sources.iter().enumerate() {
        match *src {
            Source::Data(col, _) => {
                mat[row * k + col] = 1;
            }
            Source::Parity(p_idx, _) => {
                for col in 0..k {
                    mat[row * k + col] = rs_gf256_cauchy_coeff(p_idx, col as u16, m as u16)?;
                }
            }
        }
    }

    gf256_invert_matrix_in_place(&mut mat, &mut inv, k)?;

    let missing_count = missing_indices.len();
    let mut recovered_bufs: Vec<Vec<u8>> = (0..missing_count)
        .map(|_| vec![0u8; max_cluster_len])
        .collect();
    if max_cluster_len > 0 {
        let src_slices: Vec<&[u8]> = sources
            .iter()
            .map(|src| match *src {
                Source::Data(_, b) | Source::Parity(_, b) => b,
            })
            .collect();
        let mut rec_coeffs = Vec::with_capacity(k * missing_count);
        for row in 0..k {
            for &u in &missing_indices {
                rec_coeffs.push(inv[u * k + row]);
            }
        }
        let mut dst_slices: Vec<&mut [u8]> =
            recovered_bufs.iter_mut().map(|b| b.as_mut_slice()).collect();
        accumulate_tiled_gf256(&mut dst_slices, &src_slices, &rec_coeffs, max_cluster_len)?;
    }

    let validate_one = |buf: &mut Vec<u8>| -> Result<(), VzError> {
        let hdr = ClusterHeader::from_bytes(buf)?;
        if hdr.sync_magic != MAGIC_CLUSTER {
            return Err(VzError::CorruptUnrecoverable);
        }
        let clen = usize::try_from(hdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
        if clen > max_cluster_len || clen < ClusterHeader::SIZE + ClusterFooter::SIZE {
            return Err(VzError::CorruptUnrecoverable);
        }
        if buf[clen..max_cluster_len].iter().any(|&b| b != 0) {
            return Err(VzError::CorruptUnrecoverable);
        }
        validate_cluster(&buf[..clen]).map_err(|_| VzError::CorruptUnrecoverable)?;
        buf.truncate(clen);
        Ok(())
    };

    let val_workers = adaptive_workers(
        missing_count,
        missing_count.saturating_mul(max_cluster_len),
        512 * 1024,
    );
    if val_workers <= 1 {
        for buf in &mut recovered_bufs {
            validate_one(buf)?;
        }
    } else {
        let chunk_sz = missing_count.div_ceil(val_workers);
        let groups: Vec<&mut [Vec<u8>]> = recovered_bufs.chunks_mut(chunk_sz).collect();
        par_try_map(groups, val_workers, |grp| {
            for buf in grp {
                validate_one(buf)?;
            }
            Ok(())
        })?;
    }

    for (idx, bytes) in missing_indices.into_iter().zip(recovered_bufs) {
        data_slots[idx] = Some(bytes);
    }
    Ok(missing_count)
}

/// Decoded contents of a `TAG_PARITY_CLUSTER` body: `(manifest, data_offsets, parity_payload)`.
pub type ParsedParityCluster<'a> = (ParityManifest, Vec<u64>, &'a [u8]);

/// Checks whether a validated cluster body contains a `TAG_PARITY_CLUSTER` element, returning
/// `(ParityManifest, data_offsets, parity_payload_slice)`.
pub fn parse_parity_cluster_body(body: &[u8]) -> Result<Option<ParsedParityCluster<'_>>, VzError> {
    for elem in TlvIter::new(body) {
        let elem = elem?;
        if elem.tag == TAG_PARITY_CLUSTER {
            let (manifest, offsets_raw) = ParityManifest::parse_with_offsets(elem.value)?;
            match manifest.ecc_codec {
                ECC_RS_GF256 => {}
                ECC_RS_GF65536 | ECC_RAPTORQ => return Err(VzError::Unsupported),
                _ => return Err(VzError::BadFormat),
            }
            let k = manifest.data_clusters_k as usize;
            let header_plus_offsets = ParityManifest::FIXED_SIZE + k * 8;
            let max_len = usize::try_from(manifest.max_cluster_len)
                .map_err(|_| VzError::ValueOverflow)?;
            let expected_end = header_plus_offsets
                .checked_add(max_len)
                .ok_or(VzError::ValueOverflow)?;
            if elem.value.len() < expected_end {
                return Err(VzError::BufferTooSmall);
            }
            let mut offsets = Vec::with_capacity(k);
            for i in 0..k {
                offsets.push(read_le_u64(offsets_raw, i * 8));
            }
            return Ok(Some((
                manifest,
                offsets,
                &elem.value[header_plus_offsets..expected_end],
            )));
        }
    }
    Ok(None)
}
