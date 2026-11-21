use std::collections::BTreeMap;
use std::io::Write;

use super::{LookupTarget, ResolvedEntry, VzReader, read_cluster_at};
use crate::btree::validate_cluster;
use crate::codec::{
    CryptoContext, ZstdDictCache, decompress_payload_into, decompress_payload_into_slice,
    resize_for_overwrite,
};
use crate::error::VzError;
use crate::ext_meta::{ChunkExtent, DictEntry, ExtCodecMeta, decode_chunk_table};
use crate::io::RangeReader;
use crate::parallel::{adaptive_workers, par_try_map};
use crate::wire::{ClusterFooter, ClusterHeader, DirPayload, MAGIC_CLUSTER, TAG_CHUNK_TABLE};

const READ_TLS_CAP: usize = 1_048_576;

std::thread_local! {
    static DEC_SCRATCH_TLS: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    static READ_SCRATCH_TLS: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn read_with_tls_scratch<T>(
    len: usize,
    fill: impl FnOnce(&mut [u8]) -> Result<(), VzError>,
    consume: impl FnOnce(&[u8]) -> Result<T, VzError>,
) -> Result<T, VzError> {
    if len > READ_TLS_CAP {
        let mut buf = vec![0u8; len];
        fill(&mut buf)?;
        return consume(&buf);
    }
    let mut ops = Some((fill, consume));
    if let Ok(res) = READ_SCRATCH_TLS.try_with(|cell| -> Result<T, VzError> {
        let Some((f, c)) = ops.take() else {
            return Err(VzError::IoError);
        };
        let Ok(mut buf) = cell.try_borrow_mut() else {
            let mut fallback = vec![0u8; len];
            f(&mut fallback)?;
            return c(&fallback);
        };
        if buf.len() < len {
            buf.resize(len, 0);
        }
        f(&mut buf[..len])?;
        c(&buf[..len])
    }) {
        return res;
    }
    let Some((f, c)) = ops.take() else {
        return Err(VzError::IoError);
    };
    let mut buf = vec![0u8; len];
    f(&mut buf)?;
    c(&buf)
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

    /// Reads and decodes the entire payload of `path` directly into `out` (reusing existing capacity).
    pub fn read_file_into(&self, path: &str, out: &mut Vec<u8>) -> Result<(), VzError> {
        let target = match self.resolve_target(path) {
            Ok(t) => t,
            Err(e) => {
                out.clear();
                return Err(e);
            }
        };
        let de = &target.dir_entry;

        if let Some(inline) = de.inline_slice() {
            out.clear();
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
            out.clear();
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

        // Contiguous multi-cluster decode: zero-copy + adaptive parallel across disjoint slices.
        if !de.is_sparse()
            && de.is_multi_cluster()
            && let Some(all) = self.reader.contiguous_bytes()
        {
            return self.read_multi_cluster_into(
                all,
                data_offset,
                in_cluster_offset,
                raw_size,
                codec,
                ext_codec,
                target.run_generation,
                target.entry_id,
                out,
            );
        }

        // Sparse or non-contiguous multi-cluster path delegates cleanly to streaming writer.
        out.clear();
        if let Err(e) = self.decode_ref_to_writer(&target, out) {
            out.clear();
            return Err(e);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn read_multi_cluster_into(
        &self,
        all: &[u8],
        data_offset: u64,
        in_cluster_offset: u32,
        raw_size: u64,
        codec: u8,
        ext_codec: Option<&ExtCodecMeta>,
        generation: u64,
        entry_id: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), VzError> {
        let res = self.read_multi_cluster_into_inner(
            all,
            data_offset,
            in_cluster_offset,
            raw_size,
            codec,
            ext_codec,
            generation,
            entry_id,
            out,
        );
        if res.is_err() {
            out.clear();
        }
        res
    }

    #[allow(clippy::too_many_arguments)]
    fn read_multi_cluster_into_inner(
        &self,
        all: &[u8],
        data_offset: u64,
        in_cluster_offset: u32,
        raw_size: u64,
        codec: u8,
        ext_codec: Option<&ExtCodecMeta>,
        generation: u64,
        entry_id: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), VzError> {
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

        if self.crypto.is_none() && codec == crate::wire::CODEC_NONE && ext_codec.is_none() {
            out.clear();
            out.reserve(total_raw);
            for ext in &extents {
                let slen = usize::try_from(ext.stored_size).map_err(|_| VzError::ValueOverflow)?;
                let rlen = usize::try_from(ext.raw_size).map_err(|_| VzError::ValueOverflow)?;
                if slen != rlen {
                    return Err(VzError::BadFormat);
                }
                let p_off = ext
                    .cluster_offset
                    .checked_add(ext.in_cluster_offset as u64)
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or(VzError::ValueOverflow)?;
                let p_end = p_off.checked_add(slen).ok_or(VzError::ValueOverflow)?;
                let stored = all.get(p_off..p_end).ok_or(VzError::BufferTooSmall)?;
                out.extend_from_slice(stored);
            }
            return Ok(());
        }

        if out.is_empty() && out.capacity() < total_raw {
            *out = vec![0u8; total_raw];
        } else {
            resize_for_overwrite(out, total_raw);
        }

        let dicts = &self.dicts;
        let dict_cache = &self.dict_cache;
        let crypto = self.crypto.as_ref();
        let decode_chunk = |ext: &ChunkExtent, dst: &mut [u8]| -> Result<(), VzError> {
            let slen = usize::try_from(ext.stored_size).map_err(|_| VzError::ValueOverflow)?;
            let p_off = ext
                .cluster_offset
                .checked_add(ext.in_cluster_offset as u64)
                .and_then(|v| usize::try_from(v).ok())
                .ok_or(VzError::ValueOverflow)?;
            let p_end = p_off.checked_add(slen).ok_or(VzError::ValueOverflow)?;
            let stored = all.get(p_off..p_end).ok_or(VzError::BufferTooSmall)?;

            if let Some(ctx) = crypto {
                let c_off =
                    usize::try_from(ext.cluster_offset).map_err(|_| VzError::ValueOverflow)?;
                let chdr =
                    ClusterHeader::from_bytes(all.get(c_off..).ok_or(VzError::BufferTooSmall)?)?;
                if chdr.sync_magic != MAGIC_CLUSTER {
                    return Err(VzError::BadMagic);
                }
                if codec == crate::wire::CODEC_NONE && ext_codec.is_none() {
                    ctx.decrypt_payload_into_slice(
                        generation,
                        chdr.cluster_seq,
                        entry_id,
                        stored,
                        dst,
                    )?;
                } else {
                    let tls_res = DEC_SCRATCH_TLS.try_with(|cell| -> Result<(), VzError> {
                        let Ok(mut dec_scratch) = cell.try_borrow_mut() else {
                            let decrypted = ctx.decrypt_payload(
                                generation,
                                chdr.cluster_seq,
                                entry_id,
                                stored,
                            )?;
                            return decompress_payload_into_slice(
                                &decrypted,
                                dst,
                                codec,
                                ext_codec,
                                dicts,
                                Some(dict_cache),
                            );
                        };
                        ctx.decrypt_payload_into(
                            generation,
                            chdr.cluster_seq,
                            entry_id,
                            stored,
                            &mut dec_scratch,
                        )?;
                        let dec_r = decompress_payload_into_slice(
                            &dec_scratch,
                            dst,
                            codec,
                            ext_codec,
                            dicts,
                            Some(dict_cache),
                        );
                        if dec_scratch.capacity() > 4 * 1024 * 1024 {
                            *dec_scratch = Vec::new();
                        }
                        dec_r
                    });
                    match tls_res {
                        Ok(r) => r?,
                        Err(_) => {
                            let decrypted = ctx.decrypt_payload(
                                generation,
                                chdr.cluster_seq,
                                entry_id,
                                stored,
                            )?;
                            decompress_payload_into_slice(
                                &decrypted,
                                dst,
                                codec,
                                ext_codec,
                                dicts,
                                Some(dict_cache),
                            )?;
                        }
                    }
                }
            } else {
                decompress_payload_into_slice(
                    stored,
                    dst,
                    codec,
                    ext_codec,
                    dicts,
                    Some(dict_cache),
                )?;
            }
            Ok(())
        };

        let min_bytes = if crypto.is_some()
            || (codec != crate::wire::CODEC_NONE && codec != crate::wire::CODEC_LZ4)
            || ext_codec.is_some()
        {
            512 * 1024
        } else {
            2 * 1024 * 1024
        };
        let n_workers = adaptive_workers(extents.len(), total_raw, min_bytes);
        if n_workers <= 1 {
            let mut off = 0usize;
            for ext in &extents {
                let rlen = ext.raw_size as usize;
                decode_chunk(ext, &mut out[off..off + rlen])?;
                off += rlen;
            }
            return Ok(());
        }

        let target_bands = if extents.len() <= 64 {
            extents.len()
        } else {
            n_workers.saturating_mul(2).min(extents.len())
        }
        .max(1);
        let group_sz = extents.len().div_ceil(target_bands);
        let mut tasks: Vec<(&[ChunkExtent], &mut [u8])> = Vec::with_capacity(target_bands);
        let mut rest_out = out.as_mut_slice();
        for ext_band in extents.chunks(group_sz) {
            let band_bytes: usize = ext_band.iter().map(|e| e.raw_size as usize).sum();
            let (head, tail) = rest_out.split_at_mut(band_bytes);
            tasks.push((ext_band, head));
            rest_out = tail;
        }

        par_try_map(tasks, n_workers, |(ext_band, band_out)| {
            let mut off = 0usize;
            for ext in ext_band {
                let rlen = ext.raw_size as usize;
                decode_chunk(ext, &mut band_out[off..off + rlen])?;
                off += rlen;
            }
            Ok(())
        })?;
        Ok(())
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
        let clusters_vec: Vec<(u64, Vec<usize>)> = by_cluster.into_iter().collect();
        let mut comp_clusters = 0usize;
        let mut comp_bytes = 0usize;
        for (_, idxs) in &clusters_vec {
            let mut cluster_has_work = false;
            for &idx in idxs {
                let entry = &live[idx];
                if self.crypto.is_some()
                    || entry.dir_entry.codec() != crate::wire::CODEC_NONE
                    || entry.ext_codec.is_some()
                {
                    cluster_has_work = true;
                    if let DirPayload::Ref { raw_size, .. } = entry.dir_entry.payload {
                        comp_bytes = comp_bytes.saturating_add(raw_size as usize);
                    }
                }
            }
            if cluster_has_work {
                comp_clusters += 1;
            }
        }
        let n_workers = adaptive_workers(comp_clusters, comp_bytes, 512 * 1024);

        let mut cluster_buf = Vec::new();
        let mut decrypt_buf = Vec::new();
        let mut out_buf = Vec::new();

        if n_workers > 1
            && let Some(all) = contig
        {
            struct DecodedClusterBatch {
                arena: Vec<u8>,
                ranges: Vec<(usize, usize)>,
            }
            let live_ref = &live;
            let crypto = self.crypto.as_ref();
            let dicts = &self.dicts;
            let dict_cache = &self.dict_cache;
            let decoded_batches = crate::parallel::par_try_map(
                clusters_vec.iter().collect(),
                n_workers,
                |&(cluster_off, ref idxs): &(u64, Vec<usize>)| -> Result<DecodedClusterBatch, VzError> {
                    let mut d_buf = Vec::new();
                    let off_u =
                        usize::try_from(cluster_off).map_err(|_| VzError::ValueOverflow)?;
                    let hdr = ClusterHeader::from_bytes(
                        all.get(off_u..).ok_or(VzError::BufferTooSmall)?,
                    )?;
                    let clen =
                        usize::try_from(hdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
                    let c_end = off_u.checked_add(clen).ok_or(VzError::ValueOverflow)?;
                    let cluster_slice = all.get(off_u..c_end).ok_or(VzError::BufferTooSmall)?;
                    let (chdr, _, _) = validate_cluster(cluster_slice)?;
                    let total_raw: usize = idxs
                        .iter()
                        .map(|&i| match live_ref[i].dir_entry.payload {
                            DirPayload::Ref { raw_size, .. } => raw_size as usize,
                            _ => 0,
                        })
                        .sum();
                    let mut arena = vec![0u8; total_raw];
                    let mut ranges = Vec::with_capacity(idxs.len());
                    let mut pos = 0usize;
                    for &idx in idxs {
                        let entry = &live_ref[idx];
                        let DirPayload::Ref {
                            stored_size,
                            raw_size,
                            in_cluster_offset,
                            ..
                        } = entry.dir_entry.payload
                        else {
                            return Err(VzError::BadFormat);
                        };
                        let slen =
                            usize::try_from(stored_size).map_err(|_| VzError::ValueOverflow)?;
                        let rlen =
                            usize::try_from(raw_size).map_err(|_| VzError::ValueOverflow)?;
                        let ioff = in_cluster_offset as usize;
                        let end = ioff.checked_add(slen).ok_or(VzError::ValueOverflow)?;
                        let stored_slice =
                            cluster_slice.get(ioff..end).ok_or(VzError::BufferTooSmall)?;
                        let dst = &mut arena[pos..pos + rlen];
                        let codec = entry.dir_entry.codec();
                        let ext_codec = entry.ext_codec.as_ref();
                        if let Some(ctx) = crypto {
                            ctx.decrypt_payload_into(
                                entry.run_generation,
                                chdr.cluster_seq,
                                entry.stat.entry_id,
                                stored_slice,
                                &mut d_buf,
                            )?;
                            decompress_payload_into_slice(
                                &d_buf,
                                dst,
                                codec,
                                ext_codec,
                                dicts,
                                Some(dict_cache),
                            )?;
                        } else {
                            decompress_payload_into_slice(
                                stored_slice,
                                dst,
                                codec,
                                ext_codec,
                                dicts,
                                Some(dict_cache),
                            )?;
                        }
                        ranges.push((pos, pos + rlen));
                        pos += rlen;
                    }
                    Ok(DecodedClusterBatch { arena, ranges })
                },
            )?;

            for ((_, idxs), batch) in clusters_vec.iter().zip(decoded_batches.iter()) {
                for (&idx, &(s, e)) in idxs.iter().zip(batch.ranges.iter()) {
                    visitor(&live[idx], &batch.arena[s..e])?;
                }
            }
        } else {
            for (cluster_off, idxs) in clusters_vec {
                let (chdr, cluster_slice) = Self::load_validated_cluster(
                    &self.reader,
                    contig,
                    cluster_off,
                    &mut cluster_buf,
                )?;
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
                    let stored_slice =
                        cluster_slice.get(ioff..end).ok_or(VzError::BufferTooSmall)?;

                    let codec = entry.dir_entry.codec();
                    let ext_codec = entry.ext_codec.as_ref();
                    if self.crypto.is_none()
                        && codec == crate::wire::CODEC_NONE
                        && ext_codec.is_none()
                    {
                        if slen != rlen {
                            return Err(VzError::BadFormat);
                        }
                        visitor(entry, stored_slice)?;
                        continue;
                    }

                    if out_buf.len() < rlen {
                        out_buf.resize(rlen, 0);
                    }
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
        }

        for idx in complex_idxs {
            let entry = &live[idx];
            out_buf.clear();
            if !entry.dir_entry.is_sparse()
                && entry.dir_entry.is_multi_cluster()
                && let Some(all) = contig
                && let DirPayload::Ref {
                    data_offset,
                    raw_size,
                    in_cluster_offset,
                    ..
                } = entry.dir_entry.payload
            {
                self.read_multi_cluster_into(
                    all,
                    data_offset,
                    in_cluster_offset,
                    raw_size,
                    entry.dir_entry.codec(),
                    entry.ext_codec.as_ref(),
                    entry.run_generation,
                    entry.stat.entry_id,
                    &mut out_buf,
                )?;
                visitor(entry, &out_buf)?;
                continue;
            }
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
        if !resolved.dir_entry.is_sparse()
            && let DirPayload::Ref {
                data_offset,
                stored_size,
                raw_size,
                in_cluster_offset,
            } = resolved.dir_entry.payload
        {
            if !resolved.dir_entry.is_multi_cluster() {
                self.read_single_cluster_payload_into(
                    data_offset,
                    in_cluster_offset,
                    stored_size,
                    raw_size,
                    resolved.dir_entry.codec(),
                    resolved.ext_codec.as_ref(),
                    resolved.run_generation,
                    resolved.stat.entry_id,
                    &mut out,
                )?;
                return Ok(out);
            }
            if let Some(all) = self.reader.contiguous_bytes() {
                self.read_multi_cluster_into(
                    all,
                    data_offset,
                    in_cluster_offset,
                    raw_size,
                    resolved.dir_entry.codec(),
                    resolved.ext_codec.as_ref(),
                    resolved.run_generation,
                    resolved.stat.entry_id,
                    &mut out,
                )?;
                return Ok(out);
            }
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
        let res = self.read_single_cluster_payload_into_inner(
            cluster_offset,
            in_cluster_offset,
            stored_size,
            raw_size,
            codec,
            ext_codec,
            generation,
            entry_id,
            out,
        );
        if res.is_err() {
            out.clear();
        }
        res
    }

    #[allow(clippy::too_many_arguments)]
    fn read_single_cluster_payload_into_inner(
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
            if (ClusterHeader::SIZE..=256).contains(&ioff) {
                let total = ioff.checked_add(slen).ok_or(VzError::ValueOverflow)?;
                return read_with_tls_scratch(
                    total,
                    |buf| self.reader.read_at(cluster_offset, buf),
                    |buf| {
                        let chdr = ClusterHeader::from_bytes(buf)?;
                        if chdr.sync_magic != MAGIC_CLUSTER {
                            return Err(VzError::BadMagic);
                        }
                        decrypt_then_decompress_into(
                            ctx,
                            generation,
                            chdr.cluster_seq,
                            entry_id,
                            &buf[ioff..],
                            out,
                            rlen,
                            codec,
                            ext_codec,
                            &self.dicts,
                            &self.dict_cache,
                        )
                    },
                );
            }
            let mut hdr_buf = [0u8; ClusterHeader::SIZE];
            self.reader.read_at(cluster_offset, &mut hdr_buf)?;
            let chdr = ClusterHeader::from_bytes(&hdr_buf)?;
            if chdr.sync_magic != MAGIC_CLUSTER {
                return Err(VzError::BadMagic);
            }
            return read_with_tls_scratch(
                slen,
                |buf| self.reader.read_at(payload_off, buf),
                |stored| {
                    decrypt_then_decompress_into(
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
                    )
                },
            );
        }

        if codec == crate::wire::CODEC_NONE && ext_codec.is_none() {
            resize_for_overwrite(out, slen);
            return self.reader.read_at(payload_off, out);
        }

        read_with_tls_scratch(
            slen,
            |buf| self.reader.read_at(payload_off, buf),
            |stored| {
                decompress_payload_into(
                    stored,
                    out,
                    rlen,
                    codec,
                    ext_codec,
                    &self.dicts,
                    Some(&self.dict_cache),
                )
            },
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
        if let Some(all) = self.reader.contiguous_bytes() {
            let off_u = usize::try_from(cluster_offset).map_err(|_| VzError::ValueOverflow)?;
            let chdr = ClusterHeader::from_bytes(all.get(off_u..).ok_or(VzError::BufferTooSmall)?)?;
            let clen = usize::try_from(chdr.cluster_len).map_err(|_| VzError::ValueOverflow)?;
            let end = off_u.checked_add(clen).ok_or(VzError::ValueOverflow)?;
            let slice = all.get(off_u..end).ok_or(VzError::BufferTooSmall)?;
            let (_, _, _) = validate_cluster(slice)?;
            let rel = in_cluster_offset as usize;
            if rel >= slice.len() {
                return Err(VzError::BufferTooSmall);
            }
            let (elem, _) = crate::wire::tlv_next(&slice[rel..])?;
            if elem.tag != TAG_CHUNK_TABLE {
                return Err(VzError::BadFormat);
            }
            return decode_chunk_table(elem.value);
        }
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::wire::{CODEC_LZ4, CODEC_NONE, CODEC_ZSTD};
    use crate::writer::{EntryOptions, VzWriter, VzWriterConfig};

    #[cfg(feature = "compression")]
    #[test]
    fn test_read_file_into_dirty_scratch_and_error_clearing() {
        let small = vec![0x11u8; 512];
        let equal = vec![0x22u8; 2048];
        let larger = vec![0x33u8; 8192];
        let multi: Vec<u8> = (0..(150 * 1024)).map(|i| ((i * 7 + 3) & 0xFF) as u8).collect();

        for &codec in &[CODEC_NONE, CODEC_LZ4, CODEC_ZSTD] {
            let cfg = VzWriterConfig {
                default_codec: codec,
                target_cluster_size: 32 * 1024,
                multi_cluster_threshold: 32 * 1024,
                ..Default::default()
            };
            let mut w = VzWriter::new(Cursor::new(Vec::new()), cfg).unwrap();
            w.add_file_with_options("/small.bin", &small, EntryOptions::default())
                .unwrap();
            w.add_file_with_options("/equal.bin", &equal, EntryOptions::default())
                .unwrap();
            w.add_file_with_options("/larger.bin", &larger, EntryOptions::default())
                .unwrap();
            w.add_file_with_options("/multi.bin", &multi, EntryOptions::default())
                .unwrap();
            let arc = w.finish().unwrap().into_inner();

            let tf = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(tf.path(), &arc).unwrap();
            let f_reader = VzReader::open(tf.reopen().unwrap()).unwrap();
            let m_reader = VzReader::open(arc).unwrap();

            for r_kind in [0u8, 1u8] {
                let mut scratch = vec![0xFFu8; 2048];
                if r_kind == 0 {
                    f_reader.read_file_into("/smaller_missing", &mut scratch).unwrap_err();
                    assert!(scratch.is_empty(), "error must leave dirty out empty");

                    scratch = vec![0xEEu8; 4096];
                    f_reader.read_file_into("/small.bin", &mut scratch).unwrap();
                    assert_eq!(scratch, small);

                    scratch = vec![0xDDu8; 2048];
                    f_reader.read_file_into("/equal.bin", &mut scratch).unwrap();
                    assert_eq!(scratch, equal);

                    f_reader.read_file_into("/larger.bin", &mut scratch).unwrap();
                    assert_eq!(scratch, larger);

                    f_reader.read_file_into("/multi.bin", &mut scratch).unwrap();
                    assert_eq!(scratch, multi);

                    f_reader.read_file_into("/missing.bin", &mut scratch).unwrap_err();
                    assert!(scratch.is_empty());
                } else {
                    scratch = vec![0xEEu8; 4096];
                    m_reader.read_file_into("/small.bin", &mut scratch).unwrap();
                    assert_eq!(scratch, small);

                    scratch = vec![0xDDu8; 2048];
                    m_reader.read_file_into("/equal.bin", &mut scratch).unwrap();
                    assert_eq!(scratch, equal);

                    m_reader.read_file_into("/larger.bin", &mut scratch).unwrap();
                    assert_eq!(scratch, larger);

                    m_reader.read_file_into("/multi.bin", &mut scratch).unwrap();
                    assert_eq!(scratch, multi);

                    m_reader.read_file_into("/missing.bin", &mut scratch).unwrap_err();
                    assert!(scratch.is_empty());
                }
            }
        }
    }
}
