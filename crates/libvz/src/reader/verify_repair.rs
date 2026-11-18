use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};

use super::{RepairReport, SUPPORTED_INCOMPAT, VerifyReport, VzReader, VzReaderOptions};
use crate::btree::{LeafNodeView, validate_cluster};
use crate::codec::EncryptionKey;
use crate::crc::crc32c;
use crate::ecc::boot_ecc_verify_and_repair;
use crate::error::VzError;
use crate::ext_meta::DataManifestHeader;
use crate::io::RangeReader;
use crate::rs::{encode_rs_gf256_stripe, parse_parity_cluster_body, recover_rs_gf256_stripe};
use crate::wire::{
    BootHeader, COMPAT_BOOT_ECC, ClusterFooter, ClusterHeader, DEFAULT_BOOT_SIZE, MAGIC_CLUSTER,
    MAGIC_FOOTER, RouteEntry, TAG_DATA_MANIFEST, TAG_DIR_NODE, TAG_PARITY_CLUSTER, TlvIter,
    read_le_u32,
};

// ============================================================================
// CLUSTER SCANNING, RECOVERY, VERIFICATION & REPAIR
// ============================================================================

pub(crate) fn read_cluster_at<R: RangeReader>(reader: &R, offset: u64) -> Result<Vec<u8>, VzError> {
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

pub(crate) fn read_tail_cluster<R: RangeReader>(reader: &R, total_len: u64) -> Result<Vec<u8>, VzError> {
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

fn resync_next_cluster<R: RangeReader>(
    reader: &R,
    start_pos: u64,
    total_len: u64,
) -> Option<u64> {
    let magic = MAGIC_CLUSTER.to_le_bytes();
    let min_cluster = (ClusterHeader::SIZE + ClusterFooter::SIZE) as u64;
    let chunk_size = 64 * 1024u64;
    let mut pos = (start_pos + 7) & !7;
    let mut buf = vec![0u8; chunk_size as usize + ClusterHeader::SIZE];

    while pos + min_cluster <= total_len {
        let read_len = ((total_len - pos).min(buf.len() as u64)) as usize;
        if read_len < ClusterHeader::SIZE || reader.read_at(pos, &mut buf[..read_len]).is_err() {
            return None;
        }
        let scan_end = read_len - ClusterHeader::SIZE;
        let mut rel = 0usize;
        while rel <= scan_end {
            if buf[rel..rel + 8] == magic
                && let Ok(chdr) = ClusterHeader::from_bytes(&buf[rel..rel + ClusterHeader::SIZE])
                && chdr.cluster_len >= min_cluster
                && (chdr.cluster_len & 7) == 0
            {
                let candidate = pos + rel as u64;
                if candidate + chdr.cluster_len <= total_len
                    && let Ok(cbuf) = read_cluster_at(reader, candidate)
                    && validate_cluster(&cbuf).is_ok()
                {
                    return Some(candidate);
                }
            }
            rel += 8;
        }
        let advance = (scan_end + 8).min(read_len) as u64;
        if advance == 0 {
            break;
        }
        pos += advance;
    }
    None
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
        .is_none_or(|(s, _)| {
            (s.compat_flags & COMPAT_BOOT_ECC) != 0 && s.boot_block_size as usize == DEFAULT_BOOT_SIZE
        });

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
    let mut just_resynced = false;
    let mut parity_stripes_seen: HashSet<u64> = HashSet::new();

    while pos < total_len {
        let cbuf = match read_cluster_at(reader, pos) {
            Ok(b) => b,
            Err(e) => {
                report
                    .errors
                    .push(format!("cluster at offset {pos:#x} unreadable: {e}"));
                match resync_next_cluster(reader, pos + 8, total_len) {
                    Some(next_pos) => {
                        pos = next_pos;
                        just_resynced = true;
                        continue;
                    }
                    None => break,
                }
            }
        };
        let (chdr, body, _) = match validate_cluster(&cbuf) {
            Ok(v) => v,
            Err(e) => {
                report
                    .errors
                    .push(format!("cluster at offset {pos:#x} corrupt: {e}"));
                match resync_next_cluster(reader, pos + 8, total_len) {
                    Some(next_pos) => {
                        pos = next_pos;
                        just_resynced = true;
                        continue;
                    }
                    None => break,
                }
            }
        };
        if !just_resynced
            && (chdr.prev_cluster_len != expected_prev || chdr.cluster_seq != expected_seq)
        {
            report.errors.push(format!(
                "cluster chain mismatch at {pos:#x}: seq={} (exp {}), prev_len={} (exp {})",
                chdr.cluster_seq, expected_seq, chdr.prev_cluster_len, expected_prev
            ));
        }
        just_resynced = false;

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
        .is_none_or(|h| {
            h.select_active(0xFFFF).ok().is_none_or(|(s, _)| {
                (s.compat_flags & COMPAT_BOOT_ECC) != 0
                    && s.boot_block_size as usize == DEFAULT_BOOT_SIZE
            })
        });

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
    let mut any_unrecoverable = false;

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
                let k = manifest.data_clusters_k as usize;
                let m = manifest.parity_clusters_m as usize;
                let pidx = manifest.parity_index as usize;
                if k == 0 || m == 0 || k + m > 256 || pidx >= m || offs.len() < k {
                    any_unrecoverable = true;
                    break;
                }
                if parity_raw_bufs.is_empty() {
                    parity_raw_bufs = vec![None; m];
                }
                if pidx < parity_raw_bufs.len() {
                    parity_raw_bufs[pidx] = Some((manifest.parity_index, payload.to_vec()));
                }
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
        if first_offsets.len() < k {
            any_unrecoverable = true;
            continue;
        }
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
            if span < ClusterHeader::SIZE + ClusterFooter::SIZE || d_off + span as u64 > total_len {
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
            match recover_rs_gf256_stripe(&mut data_slots, &parity_raw_bufs, k, m, max_len) {
                Ok(n) => n,
                Err(VzError::CorruptUnrecoverable) => {
                    any_unrecoverable = true;
                    continue;
                }
                Err(e) => return Err(e),
            };
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
            let mut data_refs: Vec<&[u8]> = Vec::with_capacity(k);
            let mut missing_after = false;
            for slot in &data_slots {
                match slot.as_deref() {
                    Some(b) => data_refs.push(b),
                    None => {
                        missing_after = true;
                        break;
                    }
                }
            }
            if missing_after {
                any_unrecoverable = true;
                continue;
            }
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
                if p_slot.is_none() && p_idx < rebuilt_parities.len() {
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
    if any_unrecoverable {
        return Err(VzError::CorruptUnrecoverable);
    }
    Ok(report)
}
