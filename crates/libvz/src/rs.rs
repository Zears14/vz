use crate::btree::validate_cluster;
use crate::crc::crc32c;
use crate::ecc::{
    gf256_invert_matrix_in_place, rs_gf256_cauchy_coeff, rs_gf256_madd_slice,
};
use crate::error::VzError;
use crate::ext_meta::push_tlv;
use crate::wire::{
    ClusterFooter, ClusterHeader, ECC_RAPTORQ, ECC_RS_GF256, ECC_RS_GF65536, MAGIC_CLUSTER,
    MAGIC_FOOTER, ParityManifest, TAG_PARITY_CLUSTER, TlvIter, read_le_u64, write_void_align64,
};

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
    mut prev_cluster_len: u64,
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
    let mut parity_clusters = Vec::with_capacity(m);

    for p_idx in 0..m {
        let mut parity_payload = vec![0u8; max_cluster_len];
        for (d_idx, d_bytes) in data_clusters.iter().enumerate() {
            let coeff = rs_gf256_cauchy_coeff(p_idx as u16, d_idx as u16, parity_clusters_m)?;
            rs_gf256_madd_slice(&mut parity_payload, d_bytes, coeff)?;
        }

        let manifest = ParityManifest {
            ecc_codec: ECC_RS_GF256,
            interleave_stride: 1,
            data_clusters_k: k as u16,
            parity_clusters_m,
            parity_index: p_idx as u16,
            first_cluster_seq,
            max_cluster_len: max_cluster_len as u64,
        };

        let mut tlv_val =
            Vec::with_capacity(ParityManifest::FIXED_SIZE + k * 8 + max_cluster_len);
        tlv_val.extend_from_slice(&manifest.to_bytes());
        for &off in data_offsets {
            tlv_val.extend_from_slice(&off.to_le_bytes());
        }
        tlv_val.extend_from_slice(&parity_payload);

        let mut body = Vec::new();
        push_tlv(&mut body, TAG_PARITY_CLUSTER, &tlv_val)?;
        let cluster = build_cluster_from_body(
            &body,
            prev_cluster_len,
            start_parity_seq + p_idx as u64,
        )?;
        prev_cluster_len = cluster.len() as u64;
        parity_clusters.push(cluster);
    }

    Ok((parity_clusters, prev_cluster_len))
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

    let mut recovered: Vec<(usize, Vec<u8>)> = Vec::with_capacity(missing_indices.len());
    for &u in &missing_indices {
        let mut buf = vec![0u8; max_cluster_len];
        for (row, src) in sources.iter().enumerate() {
            let coeff = inv[u * k + row];
            if coeff == 0 {
                continue;
            }
            let src_bytes = match *src {
                Source::Data(_, b) | Source::Parity(_, b) => b,
            };
            rs_gf256_madd_slice(&mut buf, src_bytes, coeff)?;
        }

        let hdr = ClusterHeader::from_bytes(&buf)?;
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
        recovered.push((u, buf[..clen].to_vec()));
    }

    let count = recovered.len();
    for (idx, bytes) in recovered {
        data_slots[idx] = Some(bytes);
    }
    Ok(count)
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
