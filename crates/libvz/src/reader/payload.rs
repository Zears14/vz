use std::collections::BTreeMap;
use std::io::Write;

use super::{LookupTarget, ResolvedEntry, VzReader, read_cluster_at};
use crate::btree::validate_cluster;
use crate::codec::{CryptoContext, ZstdDictCache, decompress_payload_into, decompress_payload_into_slice};
use crate::error::VzError;
use crate::ext_meta::{ChunkExtent, DictEntry, ExtCodecMeta, decode_chunk_table};
use crate::io::RangeReader;
use crate::wire::{ClusterFooter, ClusterHeader, DirPayload, MAGIC_CLUSTER, TAG_CHUNK_TABLE};

std::thread_local! {
    static DEC_SCRATCH_TLS: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[allow(clippy::too_many_arguments)]
fn decrypt_then_decompress_into(
    ctx: &CryptoContext,
    generation: u64,
    cluster_seq: u64,
    entry_id: u64,
    stored: &[u8],
    out: &mut Vec<u8>,
    raw_size: usize,
    codec: u8,
    ext_codec: Option<&ExtCodecMeta>,
    dicts: &[DictEntry],
    dict_cache: &ZstdDictCache,
) -> Result<(), VzError> {
    if codec == crate::wire::CODEC_NONE && ext_codec.is_none() {
        return ctx.decrypt_payload_into(generation, cluster_seq, entry_id, stored, out);
    }
    let res = DEC_SCRATCH_TLS.try_with(|cell| -> Result<(), VzError> {
        let Ok(mut scratch) = cell.try_borrow_mut() else {
            let compressed = ctx.decrypt_payload(generation, cluster_seq, entry_id, stored)?;
            return decompress_payload_into(
                &compressed,
                out,
                raw_size,
                codec,
                ext_codec,
                dicts,
                Some(dict_cache),
            );
        };
        ctx.decrypt_payload_into(generation, cluster_seq, entry_id, stored, &mut scratch)?;
        let r = decompress_payload_into(
            &scratch,
            out,
            raw_size,
            codec,
            ext_codec,
            dicts,
            Some(dict_cache),
        );
        if scratch.capacity() > 4 * 1024 * 1024 {
            *scratch = Vec::new();
        }
        r
    });
    match res {
        Ok(r) => r,
        Err(_) => {
            let compressed = ctx.decrypt_payload(generation, cluster_seq, entry_id, stored)?;
            decompress_payload_into(
                &compressed,
                out,
                raw_size,
                codec,
                ext_codec,
                dicts,
                Some(dict_cache),
            )
        }
    }
}

impl<R: RangeReader> VzReader<R> {
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

        // Parallel multi-cluster decode when contiguous memory view (`Mmap`/`Vec`) is available.
        if !de.is_sparse()
            && de.is_multi_cluster()
            && raw_size >= 2 * 1024 * 1024
            && let Some(all) = self.reader.contiguous_bytes()
        {
            let extents = self.read_chunk_table_at(data_offset, in_cluster_offset)?;
            let total_raw = usize::try_from(raw_size).map_err(|_| VzError::ValueOverflow)?;
            let mut sum_raw = 0usize;
            for ext in &extents {
                let cr = usize::try_from(ext.raw_size).map_err(|_| VzError::ValueOverflow)?;
                sum_raw = sum_raw.checked_add(cr).ok_or(VzError::ValueOverflow)?;
            }
            if sum_raw != total_raw {
                return Err(VzError::BadFormat);
            }
            let n_workers = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .min(extents.len())
                .max(1);
            if n_workers >= 2 {
                out.resize(total_raw, 0);
                let mut dest_slices: Vec<&mut [u8]> = Vec::with_capacity(extents.len());
                let mut rest = out.as_mut_slice();
                for ext in &extents {
                    let cr = ext.raw_size as usize;
                    let (head, tail) = rest.split_at_mut(cr);
                    dest_slices.push(head);
                    rest = tail;
                }
                let dicts = &self.dicts;
                let dict_cache = &self.dict_cache;
                let crypto = &self.crypto;
                let run_gen = target.run_generation;
                let entry_id = target.entry_id;
                let next_idx = std::sync::atomic::AtomicUsize::new(0);
                let first_err: std::sync::Mutex<Option<VzError>> = std::sync::Mutex::new(None);
                // Pack mutable subslice pointers safely by wrapping each slice in Mutex-free per-index work.
                let slice_cells: Vec<std::sync::Mutex<&mut [u8]>> =
                    dest_slices.into_iter().map(std::sync::Mutex::new).collect();

                std::thread::scope(|s| {
                    for _ in 0..n_workers {
                        s.spawn(|| {
                            let mut dec_scratch = Vec::new();
                            let mut plain_scratch = Vec::new();
                            loop {
                                let i = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if i >= extents.len() {
                                    break;
                                }
                                let ext = &extents[i];
                                let res = (|| -> Result<(), VzError> {
                                    let slen = usize::try_from(ext.stored_size)
                                        .map_err(|_| VzError::ValueOverflow)?;
                                    let rlen = usize::try_from(ext.raw_size)
                                        .map_err(|_| VzError::ValueOverflow)?;
                                    let p_off = ext
                                        .cluster_offset
                                        .checked_add(ext.in_cluster_offset as u64)
                                        .and_then(|v| usize::try_from(v).ok())
                                        .ok_or(VzError::ValueOverflow)?;
                                    let p_end =
                                        p_off.checked_add(slen).ok_or(VzError::ValueOverflow)?;
                                    let stored =
                                        all.get(p_off..p_end).ok_or(VzError::BufferTooSmall)?;

                                    let mut guard = slice_cells[i]
                                        .lock()
                                        .map_err(|_| VzError::IoError)?;
                                    let dst = &mut **guard;

                                    if let Some(ctx) = crypto {
                                        let c_off = usize::try_from(ext.cluster_offset)
                                            .map_err(|_| VzError::ValueOverflow)?;
                                        let chdr = ClusterHeader::from_bytes(
                                            all.get(c_off..).ok_or(VzError::BufferTooSmall)?,
                                        )?;
                                        if chdr.sync_magic != MAGIC_CLUSTER {
                                            return Err(VzError::BadMagic);
                                        }
                                        ctx.decrypt_payload_into(
                                            run_gen,
                                            chdr.cluster_seq,
                                            entry_id,
                                            stored,
                                            &mut dec_scratch,
                                        )?;
                                        if codec == crate::wire::CODEC_NONE && ext_codec.is_none() {
                                            if dec_scratch.len() != dst.len() {
                                                return Err(VzError::BadFormat);
                                            }
                                            dst.copy_from_slice(&dec_scratch);
                                        } else {
                                            decompress_payload_into(
                                                &dec_scratch,
                                                &mut plain_scratch,
                                                rlen,
                                                codec,
                                                ext_codec,
                                                dicts,
                                                Some(dict_cache),
                                            )?;
                                            if plain_scratch.len() != dst.len() {
                                                return Err(VzError::BadFormat);
                                            }
                                            dst.copy_from_slice(&plain_scratch);
                                        }
                                    } else if codec == crate::wire::CODEC_NONE
                                        && ext_codec.is_none()
                                    {
                                        if stored.len() != dst.len() {
                                            return Err(VzError::BadFormat);
                                        }
                                        dst.copy_from_slice(stored);
                                    } else {
                                        decompress_payload_into(
                                            stored,
                                            &mut plain_scratch,
                                            rlen,
                                            codec,
                                            ext_codec,
                                            dicts,
                                            Some(dict_cache),
                                        )?;
                                        if plain_scratch.len() != dst.len() {
                                            return Err(VzError::BadFormat);
                                        }
                                        dst.copy_from_slice(&plain_scratch);
                                    }
                                    Ok(())
                                })();
                                if let Err(e) = res
                                    && let Ok(mut eg) = first_err.lock()
                                    && eg.is_none()
                                {
                                    *eg = Some(e);
                                }
                            }
                        });
                    }
                });
                if let Ok(mut eg) = first_err.lock()
                    && let Some(e) = eg.take()
                {
                    return Err(e);
                }
                return Ok(());
            }
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
    pub(crate) fn load_validated_cluster<'a>(
        reader: &R,
        contig: Option<&'a [u8]>,
        cluster_off: u64,
        cluster_buf: &'a mut Vec<u8>,
    ) -> Result<(ClusterHeader, &'a [u8]), VzError> {
        let cluster_slice: &[u8] = if let Some(all) = contig {
            let off_u = usize::try_from(cluster_off).map_err(|_| VzError::ValueOverflow)?;
            let chdr = ClusterHeader::from_bytes(all.get(off_u..).ok_or(VzError::BufferTooSmall)?)?;
            let clen = usize::try_from(chdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
            let end = off_u.checked_add(clen).ok_or(VzError::ValueOverflow)?;
            all.get(off_u..end).ok_or(VzError::BufferTooSmall)?
        } else {
            let mut hdr_buf = [0u8; ClusterHeader::SIZE];
            reader.read_at(cluster_off, &mut hdr_buf)?;
            let chdr = ClusterHeader::from_bytes(&hdr_buf)?;
            let clen = usize::try_from(chdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
            if clen < ClusterHeader::SIZE + ClusterFooter::SIZE {
                return Err(VzError::BadFormat);
            }
            cluster_buf.resize(clen, 0);
            cluster_buf[..ClusterHeader::SIZE].copy_from_slice(&hdr_buf);
            reader.read_at(
                cluster_off + ClusterHeader::SIZE as u64,
                &mut cluster_buf[ClusterHeader::SIZE..],
            )?;
            cluster_buf.as_slice()
        };
        let (chdr, _, _) = validate_cluster(cluster_slice)?;
        Ok((chdr, cluster_slice))
    }

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
        let mut decrypt_buf = Vec::new();
        let mut out_buf = Vec::new();

        for (cluster_off, idxs) in by_cluster {
            let (chdr, cluster_slice) =
                Self::load_validated_cluster(&self.reader, contig, cluster_off, &mut cluster_buf)?;
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

                if out_buf.len() < rlen {
                    out_buf.resize(rlen, 0);
                }
                let codec = entry.dir_entry.codec();
                let ext_codec = entry.ext_codec.as_ref();
                if let Some(ref ctx) = self.crypto {
                    ctx.decrypt_payload_into(
                        entry.run_generation,
                        chdr.cluster_seq,
                        entry.stat.entry_id,
                        stored_slice,
                        &mut decrypt_buf,
                    )?;
                    decompress_payload_into_slice(
                        &decrypt_buf,
                        &mut out_buf[..rlen],
                        codec,
                        ext_codec,
                        &self.dicts,
                        Some(&self.dict_cache),
                    )?;
                } else {
                    decompress_payload_into_slice(
                        stored_slice,
                        &mut out_buf[..rlen],
                        codec,
                        ext_codec,
                        &self.dicts,
                        Some(&self.dict_cache),
                    )?;
                }
                visitor(entry, &out_buf[..rlen])?;
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
            if let Some(all) = self.reader.contiguous_bytes() {
                let c_off = usize::try_from(cluster_offset).map_err(|_| VzError::ValueOverflow)?;
                let chdr = ClusterHeader::from_bytes(
                    all.get(c_off..).ok_or(VzError::BufferTooSmall)?,
                )?;
                if chdr.sync_magic != MAGIC_CLUSTER {
                    return Err(VzError::BadMagic);
                }
                let p_off = usize::try_from(payload_off).map_err(|_| VzError::ValueOverflow)?;
                let p_end = p_off.checked_add(slen).ok_or(VzError::ValueOverflow)?;
                let stored = all.get(p_off..p_end).ok_or(VzError::BufferTooSmall)?;
                return decrypt_then_decompress_into(
                    ctx,
                    generation,
                    chdr.cluster_seq,
                    entry_id,
                    stored,
                    out,
                    rlen,
                    codec,
                    ext_codec,
                    &self.dicts,
                    &self.dict_cache,
                );
            }

            let ioff = in_cluster_offset as usize;
            let (chdr, stored) = if (ClusterHeader::SIZE..=256).contains(&ioff) {
                let total = ioff.checked_add(slen).ok_or(VzError::ValueOverflow)?;
                let mut combined = vec![0u8; total];
                self.reader.read_at(cluster_offset, &mut combined)?;
                let chdr = ClusterHeader::from_bytes(&combined)?;
                if chdr.sync_magic != MAGIC_CLUSTER {
                    return Err(VzError::BadMagic);
                }
                (chdr, combined.split_off(ioff))
            } else {
                let mut hdr_buf = [0u8; ClusterHeader::SIZE];
                self.reader.read_at(cluster_offset, &mut hdr_buf)?;
                let chdr = ClusterHeader::from_bytes(&hdr_buf)?;
                if chdr.sync_magic != MAGIC_CLUSTER {
                    return Err(VzError::BadMagic);
                }
                let mut stored = vec![0u8; slen];
                self.reader.read_at(payload_off, &mut stored)?;
                (chdr, stored)
            };
            return decrypt_then_decompress_into(
                ctx,
                generation,
                chdr.cluster_seq,
                entry_id,
                &stored,
                out,
                rlen,
                codec,
                ext_codec,
                &self.dicts,
                &self.dict_cache,
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
        let payload_off = cluster_offset
            .checked_add(in_cluster_offset as u64)
            .ok_or(VzError::ValueOverflow)?;
        if let Some(all) = self.reader.contiguous_bytes() {
            let c_off = usize::try_from(cluster_offset).map_err(|_| VzError::ValueOverflow)?;
            let chdr = ClusterHeader::from_bytes(all.get(c_off..).ok_or(VzError::BufferTooSmall)?)?;
            if chdr.sync_magic != MAGIC_CLUSTER {
                return Err(VzError::BadMagic);
            }
            let p_off = usize::try_from(payload_off).map_err(|_| VzError::ValueOverflow)?;
            let p_end = p_off.checked_add(slen).ok_or(VzError::ValueOverflow)?;
            let stored = all.get(p_off..p_end).ok_or(VzError::BufferTooSmall)?;
            return ctx.decrypt_payload(generation, chdr.cluster_seq, entry_id, stored);
        }
        let mut hdr_buf = [0u8; ClusterHeader::SIZE];
        self.reader.read_at(cluster_offset, &mut hdr_buf)?;
        let chdr = ClusterHeader::from_bytes(&hdr_buf)?;
        if chdr.sync_magic != MAGIC_CLUSTER {
            return Err(VzError::BadMagic);
        }
        let mut stored = vec![0u8; slen];
        self.reader.read_at(payload_off, &mut stored)?;
        ctx.decrypt_payload(generation, chdr.cluster_seq, entry_id, &stored)
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
