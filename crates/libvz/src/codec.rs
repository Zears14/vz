use std::collections::HashMap;

use crate::error::VzError;
use crate::ext_meta::{DictEntry, ExtCodecMeta};
use crate::wire::{
    CODEC_EXT, CODEC_LZ4, CODEC_NONE, CODEC_ZSTD, EXT_CODEC_LZ4, EXT_CODEC_NONE, EXT_CODEC_ZSTD,
    EXT_CODEC_ZSTD_DICT,
};
#[cfg(feature = "crypto")]
use crate::ext_meta::CipherHeader;
#[cfg(feature = "crypto")]
use crate::wire::{CIPHER_XCHACHA20_POLY1305, KDF_MODE_ARGON2ID, KDF_MODE_RAW_KEY};

/// Pre-digested Zstd dictionary cache (`CDict` / `DDict`) eliminating per-file dictionary setup.
#[derive(Default)]
pub struct ZstdDictCache {
    #[cfg(feature = "compression")]
    cdicts: HashMap<u32, zstd::dict::EncoderDictionary<'static>>,
    #[cfg(feature = "compression")]
    ddicts: HashMap<u32, zstd::dict::DecoderDictionary<'static>>,
    #[cfg(not(feature = "compression"))]
    _phantom: HashMap<u32, ()>,
}

impl ZstdDictCache {
    /// Builds pre-digested encoder and decoder dictionaries from `dicts` at `zstd_level`.
    pub fn new(dicts: &[DictEntry], zstd_level: i32) -> Self {
        #[cfg(feature = "compression")]
        {
            let mut cdicts = HashMap::with_capacity(dicts.len());
            let mut ddicts = HashMap::with_capacity(dicts.len());
            for d in dicts {
                if d.codec == CODEC_ZSTD {
                    cdicts.insert(
                        d.dict_id,
                        zstd::dict::EncoderDictionary::copy(&d.bytes, zstd_level),
                    );
                    ddicts.insert(d.dict_id, zstd::dict::DecoderDictionary::copy(&d.bytes));
                }
            }
            Self { cdicts, ddicts }
        }
        #[cfg(not(feature = "compression"))]
        {
            let _ = (dicts, zstd_level);
            Self {
                _phantom: HashMap::new(),
            }
        }
    }
}

/// Compresses `raw` using `codec`, reusing pre-digested dictionaries from `cache`.
pub fn compress_payload_with_cache(
    raw: &[u8],
    codec: u8,
    ext_codec: Option<&ExtCodecMeta>,
    dicts: &[DictEntry],
    cache: Option<&ZstdDictCache>,
    zstd_level: i32,
) -> Result<Vec<u8>, VzError> {
    let mut out = Vec::new();
    compress_payload_into_with_cache(raw, &mut out, codec, ext_codec, dicts, cache, zstd_level)?;
    Ok(out)
}

/// Compresses `raw` directly into caller-owned `out` (clearing `out` first), eliminating
/// per-entry buffer allocations in sequential writer loops.
pub fn compress_payload_into_with_cache(
    raw: &[u8],
    out: &mut Vec<u8>,
    codec: u8,
    ext_codec: Option<&ExtCodecMeta>,
    dicts: &[DictEntry],
    cache: Option<&ZstdDictCache>,
    zstd_level: i32,
) -> Result<(), VzError> {
    out.clear();
    match codec {
        CODEC_NONE => {
            out.extend_from_slice(raw);
            Ok(())
        }
        CODEC_LZ4 => compress_lz4_into(raw, out),
        CODEC_ZSTD => {
            if let Some(ext) = ext_codec
                && ext.dict_id != 0
            {
                return compress_zstd_dict_into(raw, out, ext.dict_id, dicts, cache, zstd_level);
            }
            compress_zstd_into(raw, out, zstd_level)
        }
        CODEC_EXT => {
            let ext = ext_codec.ok_or(VzError::BadFormat)?;
            match ext.ext_codec_id {
                EXT_CODEC_NONE => {
                    out.extend_from_slice(raw);
                    Ok(())
                }
                EXT_CODEC_LZ4 => compress_lz4_into(raw, out),
                EXT_CODEC_ZSTD => compress_zstd_into(raw, out, zstd_level),
                EXT_CODEC_ZSTD_DICT => {
                    compress_zstd_dict_into(raw, out, ext.dict_id, dicts, cache, zstd_level)
                }
                _ => Err(VzError::Unsupported),
            }
        }
        _ => Err(VzError::BadFormat),
    }
}

/// Decompresses `stored` using `codec`, reusing pre-digested dictionaries from `cache`.
pub fn decompress_payload_with_cache(
    stored: &[u8],
    raw_size: usize,
    codec: u8,
    ext_codec: Option<&ExtCodecMeta>,
    dicts: &[DictEntry],
    cache: Option<&ZstdDictCache>,
) -> Result<Vec<u8>, VzError> {
    let mut out = Vec::new();
    decompress_payload_into(stored, &mut out, raw_size, codec, ext_codec, dicts, cache)?;
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedCodec {
    None,
    Lz4,
    Zstd,
    ZstdDict(u32),
}

#[inline]
fn resolve_decompress_codec(
    codec: u8,
    ext_codec: Option<&ExtCodecMeta>,
) -> Result<ResolvedCodec, VzError> {
    let eff = match codec {
        CODEC_EXT => {
            let ext = ext_codec.ok_or(VzError::BadFormat)?;
            match ext.ext_codec_id {
                EXT_CODEC_NONE => return Ok(ResolvedCodec::None),
                EXT_CODEC_LZ4 => CODEC_LZ4,
                EXT_CODEC_ZSTD => CODEC_ZSTD,
                EXT_CODEC_ZSTD_DICT => return Ok(ResolvedCodec::ZstdDict(ext.dict_id)),
                _ => return Err(VzError::Unsupported),
            }
        }
        other => other,
    };
    match eff {
        CODEC_NONE => Ok(ResolvedCodec::None),
        CODEC_LZ4 => Ok(ResolvedCodec::Lz4),
        CODEC_ZSTD => {
            if let Some(ext) = ext_codec
                && ext.dict_id != 0
            {
                return Ok(ResolvedCodec::ZstdDict(ext.dict_id));
            }
            Ok(ResolvedCodec::Zstd)
        }
        _ => Err(VzError::BadFormat),
    }
}

/// Decompresses `stored` directly into caller-owned `out` buffer (clearing `out` first),
/// avoiding repeated buffer allocations during bulk sequential extraction.
pub fn decompress_payload_into(
    stored: &[u8],
    out: &mut Vec<u8>,
    raw_size: usize,
    codec: u8,
    ext_codec: Option<&ExtCodecMeta>,
    dicts: &[DictEntry],
    cache: Option<&ZstdDictCache>,
) -> Result<(), VzError> {
    out.clear();
    match resolve_decompress_codec(codec, ext_codec)? {
        ResolvedCodec::None => {
            out.extend_from_slice(stored);
            Ok(())
        }
        ResolvedCodec::Lz4 => decompress_lz4_into(stored, out, raw_size),
        ResolvedCodec::Zstd => decompress_zstd_into(stored, out, raw_size),
        ResolvedCodec::ZstdDict(dict_id) => {
            decompress_zstd_dict_into(stored, out, raw_size, dict_id, dicts, cache)
        }
    }
}

/// Decompresses `stored` directly into an exact caller-owned mutable destination slice `dst`
/// (`dst.len() == raw_size`), eliminating per-entry allocation, pre-zeroing, and intermediate copies.
pub fn decompress_payload_into_slice(
    stored: &[u8],
    dst: &mut [u8],
    codec: u8,
    ext_codec: Option<&ExtCodecMeta>,
    dicts: &[DictEntry],
    cache: Option<&ZstdDictCache>,
) -> Result<(), VzError> {
    match resolve_decompress_codec(codec, ext_codec)? {
        ResolvedCodec::None => {
            if stored.len() != dst.len() {
                return Err(VzError::BadFormat);
            }
            dst.copy_from_slice(stored);
            Ok(())
        }
        ResolvedCodec::Lz4 => decompress_lz4_into_slice(stored, dst),
        ResolvedCodec::Zstd => decompress_zstd_into_slice(stored, dst),
        ResolvedCodec::ZstdDict(dict_id) => {
            decompress_zstd_dict_into_slice(stored, dst, dict_id, dicts, cache)
        }
    }
}

/// Compresses `raw` using `codec` (and optional `ext_codec` / dictionary table).
pub fn compress_payload(
    raw: &[u8],
    codec: u8,
    ext_codec: Option<&ExtCodecMeta>,
    dicts: &[DictEntry],
    zstd_level: i32,
) -> Result<Vec<u8>, VzError> {
    compress_payload_with_cache(raw, codec, ext_codec, dicts, None, zstd_level)
}

/// Decompresses `stored` using `codec` (and optional `ext_codec` / dictionary table).
pub fn decompress_payload(
    stored: &[u8],
    raw_size: usize,
    codec: u8,
    ext_codec: Option<&ExtCodecMeta>,
    dicts: &[DictEntry],
) -> Result<Vec<u8>, VzError> {
    decompress_payload_with_cache(stored, raw_size, codec, ext_codec, dicts, None)
}

#[cfg(feature = "compression")]
fn lz4_headers_7b() -> &'static [[u8; 7]; 4] {
    static HDRS: std::sync::OnceLock<[[u8; 7]; 4]> = std::sync::OnceLock::new();
    HDRS.get_or_init(|| {
        use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
        let sizes = [
            BlockSize::Max64KB,
            BlockSize::Max256KB,
            BlockSize::Max1MB,
            BlockSize::Max4MB,
        ];
        let mut out = [[0u8; 7]; 4];
        for (i, &bs) in sizes.iter().enumerate() {
            let info = FrameInfo::new()
                .block_size(bs)
                .block_mode(BlockMode::Independent);
            let enc = FrameEncoder::with_frame_info(info, Vec::with_capacity(16));
            if let Ok(done) = enc.finish()
                && done.len() >= 7
            {
                out[i].copy_from_slice(&done[..7]);
            }
        }
        out
    })
}

#[cfg(feature = "compression")]
std::thread_local! {
    static ZSTD_COMP_TLS: std::cell::RefCell<Option<(i32, zstd::bulk::Compressor<'static>)>> =
        const { std::cell::RefCell::new(None) };
    static ZSTD_RAW_CCTX_TLS: std::cell::RefCell<Option<zstd::zstd_safe::CCtx<'static>>> =
        const { std::cell::RefCell::new(None) };
    static ZSTD_DCTX_TLS: std::cell::RefCell<Option<zstd::zstd_safe::DCtx<'static>>> =
        const { std::cell::RefCell::new(None) };
    static LZ4_COMP_SCRATCH: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(feature = "compression")]
fn compress_lz4_single_block_into_buf(raw: &[u8], out: &mut Vec<u8>) -> Result<(), VzError> {
    let hdr_idx = if raw.len() <= 64 * 1024 {
        0
    } else if raw.len() <= 256 * 1024 {
        1
    } else if raw.len() <= 1024 * 1024 {
        2
    } else {
        3
    };
    let hdr = lz4_headers_7b()[hdr_idx];
    if raw.is_empty() {
        out.clear();
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&[0u8; 4]);
        return Ok(());
    }
    let max_blk = lz4_flex::block::get_maximum_output_size(raw.len());
    let needed = 11 + max_blk + 4;
    let write_frame = |buf: &mut Vec<u8>| -> Result<usize, VzError> {
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        buf[..7].copy_from_slice(&hdr);
        let clen = lz4_flex::block::compress_into(raw, &mut buf[11..11 + max_blk])
            .map_err(|_| VzError::CompressionError)?;
        let total = if clen < raw.len() {
            buf[7..11].copy_from_slice(&(clen as u32).to_le_bytes());
            buf[11 + clen..15 + clen].fill(0);
            15 + clen
        } else {
            // Incompressible block: store raw with LZ4 frame uncompressed bit (bit 31).
            buf[7..11].copy_from_slice(&(0x8000_0000u32 | (raw.len() as u32)).to_le_bytes());
            buf[11..11 + raw.len()].copy_from_slice(raw);
            buf[11 + raw.len()..15 + raw.len()].fill(0);
            15 + raw.len()
        };
        Ok(total)
    };

    out.clear();
    let res = LZ4_COMP_SCRATCH.try_with(|cell| -> Result<(), VzError> {
        let Ok(mut scratch) = cell.try_borrow_mut() else {
            let total = write_frame(out)?;
            out.truncate(total);
            return Ok(());
        };
        let total = write_frame(&mut scratch)?;
        out.extend_from_slice(&scratch[..total]);
        if scratch.capacity() > 8 * 1024 * 1024 {
            *scratch = Vec::new();
        }
        Ok(())
    });
    match res {
        Ok(r) => r,
        Err(_) => {
            let total = write_frame(out)?;
            out.truncate(total);
            Ok(())
        }
    }
}

#[cfg(feature = "compression")]
fn compress_lz4_into(raw: &[u8], out: &mut Vec<u8>) -> Result<(), VzError> {
    use std::io::Write;
    if raw.len() <= 4 * 1024 * 1024 {
        return compress_lz4_single_block_into_buf(raw, out);
    }
    out.clear();
    let buf = core::mem::take(out);
    let info = lz4_flex::frame::FrameInfo::new().block_size(lz4_flex::frame::BlockSize::Max4MB);
    let mut enc = lz4_flex::frame::FrameEncoder::with_frame_info(info, buf);
    enc.write_all(raw).map_err(|_| VzError::CompressionError)?;
    *out = enc.finish().map_err(|_| VzError::CompressionError)?;
    Ok(())
}

#[cfg(not(feature = "compression"))]
fn compress_lz4_into(_raw: &[u8], _out: &mut Vec<u8>) -> Result<(), VzError> {
    Err(VzError::Unsupported)
}

#[cfg(feature = "compression")]
enum Lz4FastBlock<'a> {
    EmptyFrame,
    Uncompressed(&'a [u8]),
    Compressed(&'a [u8]),
}

#[cfg(feature = "compression")]
#[inline]
fn match_lz4_single_block_fast(stored: &[u8]) -> Option<Lz4FastBlock<'_>> {
    if stored.len() < 11 {
        return None;
    }
    let hdrs = lz4_headers_7b();
    let hdr7 = &stored[..7];
    if hdr7 != hdrs[0] && hdr7 != hdrs[1] && hdr7 != hdrs[2] && hdr7 != hdrs[3] {
        // Also allow single-block independent/linked headers from earlier single-block builds.
        if !(stored[..4] == [0x04, 0x22, 0x4D, 0x18]
            && (stored[4] & 0b1101_1111) == 0x40
            && stored[5] == 0x40
            && stored[6] == hdrs[0][6])
        {
            return None;
        }
    }
    if stored.len() == 11 && stored[7..11] == [0, 0, 0, 0] {
        return Some(Lz4FastBlock::EmptyFrame);
    }
    if stored.len() < 15 {
        return None;
    }
    let blk_hdr = u32::from_le_bytes([stored[7], stored[8], stored[9], stored[10]]);
    let blk_len = (blk_hdr & 0x7FFF_FFFF) as usize;
    if 11usize.checked_add(blk_len).and_then(|v| v.checked_add(4)) == Some(stored.len())
        && stored[11 + blk_len..] == [0, 0, 0, 0]
    {
        let blk = &stored[11..11 + blk_len];
        if blk_len == 0 && (blk_hdr & 0x8000_0000) == 0 {
            return Some(Lz4FastBlock::EmptyFrame);
        }
        if (blk_hdr & 0x8000_0000) != 0 {
            return Some(Lz4FastBlock::Uncompressed(blk));
        }
        return Some(Lz4FastBlock::Compressed(blk));
    }
    None
}

#[cfg(feature = "compression")]
fn decompress_lz4_into(stored: &[u8], out: &mut Vec<u8>, raw_size: usize) -> Result<(), VzError> {
    use std::io::Read;
    if let Some(fast) = match_lz4_single_block_fast(stored) {
        out.clear();
        match fast {
            Lz4FastBlock::EmptyFrame => {
                return if raw_size == 0 {
                    Ok(())
                } else {
                    Err(VzError::CompressionError)
                };
            }
            Lz4FastBlock::Uncompressed(blk) => {
                if blk.len() != raw_size {
                    return Err(VzError::CompressionError);
                }
                out.extend_from_slice(blk);
                return Ok(());
            }
            Lz4FastBlock::Compressed(blk) => {
                out.resize(raw_size, 0);
                let n = lz4_flex::block::decompress_into(blk, out)
                    .map_err(|_| VzError::CompressionError)?;
                if n != raw_size {
                    return Err(VzError::CompressionError);
                }
                return Ok(());
            }
        }
    }

    out.clear();
    out.reserve(raw_size.min(4 * 1024 * 1024));
    let mut dec = lz4_flex::frame::FrameDecoder::new(stored);
    dec.read_to_end(out)
        .map_err(|_| VzError::CompressionError)?;
    if out.len() != raw_size {
        return Err(VzError::CompressionError);
    }
    Ok(())
}

#[cfg(not(feature = "compression"))]
fn decompress_lz4_into(_stored: &[u8], _out: &mut Vec<u8>, _raw_size: usize) -> Result<(), VzError> {
    Err(VzError::Unsupported)
}

#[cfg(feature = "compression")]
fn decompress_lz4_into_slice(stored: &[u8], dst: &mut [u8]) -> Result<(), VzError> {
    use std::io::Read;
    if let Some(fast) = match_lz4_single_block_fast(stored) {
        match fast {
            Lz4FastBlock::EmptyFrame => {
                return if dst.is_empty() {
                    Ok(())
                } else {
                    Err(VzError::CompressionError)
                };
            }
            Lz4FastBlock::Uncompressed(blk) => {
                if blk.len() != dst.len() {
                    return Err(VzError::CompressionError);
                }
                dst.copy_from_slice(blk);
                return Ok(());
            }
            Lz4FastBlock::Compressed(blk) => {
                let n = lz4_flex::block::decompress_into(blk, dst)
                    .map_err(|_| VzError::CompressionError)?;
                if n != dst.len() {
                    return Err(VzError::CompressionError);
                }
                return Ok(());
            }
        }
    }

    let mut dec = lz4_flex::frame::FrameDecoder::new(stored);
    dec.read_exact(dst)
        .map_err(|_| VzError::CompressionError)?;
    let mut extra = [0u8; 1];
    let rem = dec
        .read(&mut extra)
        .map_err(|_| VzError::CompressionError)?;
    if rem != 0 {
        return Err(VzError::CompressionError);
    }
    Ok(())
}

#[cfg(not(feature = "compression"))]
fn decompress_lz4_into_slice(_stored: &[u8], _dst: &mut [u8]) -> Result<(), VzError> {
    Err(VzError::Unsupported)
}

#[cfg(feature = "compression")]
#[inline]
fn with_zstd_cctx_raw<R>(
    f: impl FnOnce(&mut zstd::zstd_safe::CCtx<'static>) -> Result<R, VzError>,
) -> Result<R, VzError> {
    let mut f_opt = Some(f);
    if let Ok(res) = ZSTD_RAW_CCTX_TLS.try_with(|cell| -> Option<Result<R, VzError>> {
        let mut slot = cell.try_borrow_mut().ok()?;
        if slot.is_none() {
            *slot = zstd::zstd_safe::CCtx::try_create();
        }
        let cctx = slot.as_mut()?;
        f_opt.take().map(|func| func(cctx))
    }) && let Some(done) = res
    {
        return done;
    }
    let Some(func) = f_opt.take() else {
        return Err(VzError::CompressionError);
    };
    let mut cctx = zstd::zstd_safe::CCtx::try_create().ok_or(VzError::CompressionError)?;
    func(&mut cctx)
}

#[cfg(feature = "compression")]
#[inline]
fn with_zstd_dctx_raw<R>(
    f: impl FnOnce(&mut zstd::zstd_safe::DCtx<'static>) -> Result<R, VzError>,
) -> Result<R, VzError> {
    let mut f_opt = Some(f);
    if let Ok(res) = ZSTD_DCTX_TLS.try_with(|cell| -> Option<Result<R, VzError>> {
        let mut slot = cell.try_borrow_mut().ok()?;
        if slot.is_none() {
            *slot = zstd::zstd_safe::DCtx::try_create();
        }
        let dctx = slot.as_mut()?;
        f_opt.take().map(|func| func(dctx))
    }) && let Some(done) = res
    {
        return done;
    }
    let Some(func) = f_opt.take() else {
        return Err(VzError::CompressionError);
    };
    let mut dctx = zstd::zstd_safe::DCtx::try_create().ok_or(VzError::CompressionError)?;
    func(&mut dctx)
}

#[cfg(feature = "compression")]
fn compress_zstd_into(raw: &[u8], out: &mut Vec<u8>, level: i32) -> Result<(), VzError> {
    let bound = zstd::zstd_safe::compress_bound(raw.len());
    out.clear();
    out.reserve(bound);
    let res = ZSTD_COMP_TLS.try_with(|cell| -> Result<(), VzError> {
        let Ok(mut slot) = cell.try_borrow_mut() else {
            let mut comp =
                zstd::bulk::Compressor::new(level).map_err(|_| VzError::CompressionError)?;
            comp.compress_to_buffer(raw, out)
                .map_err(|_| VzError::CompressionError)?;
            return Ok(());
        };
        match slot.as_mut() {
            Some((cur_lvl, comp)) => {
                if *cur_lvl != level {
                    comp.set_compression_level(level)
                        .map_err(|_| VzError::CompressionError)?;
                    *cur_lvl = level;
                }
                comp.compress_to_buffer(raw, out)
                    .map_err(|_| VzError::CompressionError)?;
            }
            None => {
                let mut comp =
                    zstd::bulk::Compressor::new(level).map_err(|_| VzError::CompressionError)?;
                comp.compress_to_buffer(raw, out)
                    .map_err(|_| VzError::CompressionError)?;
                *slot = Some((level, comp));
            }
        }
        Ok(())
    });
    match res {
        Ok(r) => r,
        Err(_) => {
            let mut comp =
                zstd::bulk::Compressor::new(level).map_err(|_| VzError::CompressionError)?;
            comp.compress_to_buffer(raw, out)
                .map_err(|_| VzError::CompressionError)?;
            Ok(())
        }
    }
}

#[cfg(not(feature = "compression"))]
fn compress_zstd_into(_raw: &[u8], _out: &mut Vec<u8>, _level: i32) -> Result<(), VzError> {
    Err(VzError::Unsupported)
}

#[cfg(feature = "compression")]
fn decompress_zstd_into(stored: &[u8], out: &mut Vec<u8>, raw_size: usize) -> Result<(), VzError> {
    out.reserve(raw_size);
    let n = with_zstd_dctx_raw(|dctx| {
        dctx.decompress(out, stored)
            .map_err(|_| VzError::CompressionError)
    })?;
    if n != raw_size || out.len() != raw_size {
        return Err(VzError::CompressionError);
    }
    Ok(())
}

#[cfg(not(feature = "compression"))]
fn decompress_zstd_into(_stored: &[u8], _out: &mut Vec<u8>, _raw_size: usize) -> Result<(), VzError> {
    Err(VzError::Unsupported)
}

#[cfg(feature = "compression")]
fn decompress_zstd_into_slice(stored: &[u8], dst: &mut [u8]) -> Result<(), VzError> {
    let n = with_zstd_dctx_raw(|dctx| {
        dctx.decompress(dst, stored)
            .map_err(|_| VzError::CompressionError)
    })?;
    if n != dst.len() {
        return Err(VzError::CompressionError);
    }
    Ok(())
}

#[cfg(not(feature = "compression"))]
fn decompress_zstd_into_slice(_stored: &[u8], _dst: &mut [u8]) -> Result<(), VzError> {
    Err(VzError::Unsupported)
}

#[cfg(feature = "compression")]
fn compress_zstd_dict_into(
    raw: &[u8],
    out: &mut Vec<u8>,
    dict_id: u32,
    dicts: &[DictEntry],
    cache: Option<&ZstdDictCache>,
    level: i32,
) -> Result<(), VzError> {
    let bound = zstd::zstd_safe::compress_bound(raw.len());
    out.clear();
    out.reserve(bound);
    if let Some(c) = cache
        && let Some(cdict) = c.cdicts.get(&dict_id)
    {
        with_zstd_cctx_raw(|cctx| {
            cctx.compress_using_cdict(out, raw, cdict.as_cdict())
                .map_err(|_| VzError::CompressionError)
        })?;
        return Ok(());
    }
    let dict = dicts
        .iter()
        .find(|d| d.dict_id == dict_id && d.codec == CODEC_ZSTD)
        .ok_or(VzError::NotFound)?;
    with_zstd_cctx_raw(|cctx| {
        cctx.compress_using_dict(out, raw, &dict.bytes, level)
            .map_err(|_| VzError::CompressionError)
    })?;
    Ok(())
}

#[cfg(not(feature = "compression"))]
fn compress_zstd_dict_into(
    _raw: &[u8],
    _out: &mut Vec<u8>,
    _dict_id: u32,
    _dicts: &[DictEntry],
    _cache: Option<&ZstdDictCache>,
    _level: i32,
) -> Result<(), VzError> {
    Err(VzError::Unsupported)
}

#[cfg(feature = "compression")]
fn decompress_zstd_dict_into(
    stored: &[u8],
    out: &mut Vec<u8>,
    raw_size: usize,
    dict_id: u32,
    dicts: &[DictEntry],
    cache: Option<&ZstdDictCache>,
) -> Result<(), VzError> {
    out.reserve(raw_size);
    let n = if let Some(c) = cache
        && let Some(ddict) = c.ddicts.get(&dict_id)
    {
        with_zstd_dctx_raw(|dctx| {
            dctx.decompress_using_ddict(out, stored, ddict.as_ddict())
                .map_err(|_| VzError::CompressionError)
        })?
    } else {
        let dict = dicts
            .iter()
            .find(|d| d.dict_id == dict_id && d.codec == CODEC_ZSTD)
            .ok_or(VzError::NotFound)?;
        with_zstd_dctx_raw(|dctx| {
            dctx.decompress_using_dict(out, stored, &dict.bytes)
                .map_err(|_| VzError::CompressionError)
        })?
    };
    if n != raw_size || out.len() != raw_size {
        return Err(VzError::CompressionError);
    }
    Ok(())
}

#[cfg(not(feature = "compression"))]
fn decompress_zstd_dict_into(
    _stored: &[u8],
    _out: &mut Vec<u8>,
    _raw_size: usize,
    _dict_id: u32,
    _dicts: &[DictEntry],
    _cache: Option<&ZstdDictCache>,
) -> Result<(), VzError> {
    Err(VzError::Unsupported)
}

#[cfg(feature = "compression")]
fn decompress_zstd_dict_into_slice(
    stored: &[u8],
    dst: &mut [u8],
    dict_id: u32,
    dicts: &[DictEntry],
    cache: Option<&ZstdDictCache>,
) -> Result<(), VzError> {
    let n = if let Some(c) = cache
        && let Some(ddict) = c.ddicts.get(&dict_id)
    {
        with_zstd_dctx_raw(|dctx| {
            dctx.decompress_using_ddict(dst, stored, ddict.as_ddict())
                .map_err(|_| VzError::CompressionError)
        })?
    } else {
        let dict = dicts
            .iter()
            .find(|d| d.dict_id == dict_id && d.codec == CODEC_ZSTD)
            .ok_or(VzError::NotFound)?;
        with_zstd_dctx_raw(|dctx| {
            dctx.decompress_using_dict(dst, stored, &dict.bytes)
                .map_err(|_| VzError::CompressionError)
        })?
    };
    if n != dst.len() {
        return Err(VzError::CompressionError);
    }
    Ok(())
}

#[cfg(not(feature = "compression"))]
fn decompress_zstd_dict_into_slice(
    _stored: &[u8],
    _dst: &mut [u8],
    _dict_id: u32,
    _dicts: &[DictEntry],
    _cache: Option<&ZstdDictCache>,
) -> Result<(), VzError> {
    Err(VzError::Unsupported)
}

// ============================================================================
// AUTHENTICATED ENCRYPTION (Argon2id / Raw256 + HKDF-SHA256 + XChaCha20-Poly1305)
// ============================================================================

/// Encryption credential supplied when creating or opening an encrypted VZ archive.
#[derive(Debug, Clone)]
pub enum EncryptionKey {
    /// Password-based key derivation via Argon2id.
    Password {
        password: Vec<u8>,
        /// Memory cost in KiB (default `65536` = 64 MiB).
        m_cost_kib: u32,
        /// Iteration count (default `3`).
        t_cost: u32,
        /// Parallelism lanes (default `1`).
        p_cost: u32,
    },
    /// Raw 256-bit symmetric key (for fast programmatic/CI usage).
    Raw256([u8; 32]),
}

impl EncryptionKey {
    /// Constructs a password key with standard Argon2id parameters (`64 MiB`, `t=3`, `p=1`).
    pub fn from_password(password: impl AsRef<[u8]>) -> Self {
        Self::Password {
            password: password.as_ref().to_vec(),
            m_cost_kib: 65_536,
            t_cost: 3,
            p_cost: 1,
        }
    }

    /// Constructs a password key with custom Argon2id cost parameters.
    pub fn from_password_with_params(
        password: impl AsRef<[u8]>,
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Self {
        Self::Password {
            password: password.as_ref().to_vec(),
            m_cost_kib,
            t_cost,
            p_cost,
        }
    }
}

/// Active encryption/decryption context holding the unwrapped Content Encryption Key (CEK).
#[derive(Clone)]
pub struct CryptoContext {
    #[cfg(not(feature = "crypto"))]
    #[allow(dead_code)]
    payload_key: [u8; 32],
    #[cfg(feature = "crypto")]
    cipher: chacha20poly1305::XChaCha20Poly1305,
}

impl CryptoContext {
    #[cfg(feature = "crypto")]
    fn from_payload_key(payload_key: [u8; 32]) -> Self {
        use chacha20poly1305::{XChaCha20Poly1305, aead::KeyInit};
        let cipher = XChaCha20Poly1305::new((&payload_key).into());
        Self { cipher }
    }

    #[cfg(not(feature = "crypto"))]
    #[allow(dead_code)]
    fn from_payload_key(payload_key: [u8; 32]) -> Self {
        Self { payload_key }
    }
}

impl core::fmt::Debug for CryptoContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptoContext").finish_non_exhaustive()
    }
}

#[cfg(feature = "crypto")]
fn build_wrap_aad(salt: &[u8; 16]) -> [u8; 30] {
    let mut aad = [0u8; 30];
    aad[..14].copy_from_slice(b"VZ-CEK-WRAP-v1");
    aad[14..30].copy_from_slice(salt);
    aad
}

/// Builds the 24-byte AEAD AAD `(generation, cluster_seq, entry_id)`.
pub fn build_payload_aad(generation: u64, cluster_seq: u64, entry_id: u64) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[0..8].copy_from_slice(&generation.to_le_bytes());
    aad[8..16].copy_from_slice(&cluster_seq.to_le_bytes());
    aad[16..24].copy_from_slice(&entry_id.to_le_bytes());
    aad
}

#[cfg(feature = "crypto")]
fn derive_ikm_argon2id(
    password: &[u8],
    salt: &[u8; 16],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], VzError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|_| VzError::CryptoError)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut ikm = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut ikm)
        .map_err(|_| VzError::CryptoError)?;
    Ok(ikm)
}

#[cfg(feature = "crypto")]
fn hkdf_expand(salt: &[u8; 16], ikm: &[u8; 32], info: &[u8]) -> Result<[u8; 32], VzError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).map_err(|_| VzError::CryptoError)?;
    Ok(okm)
}

impl CryptoContext {
    /// Generates a fresh CEK and [`CipherHeader`] for creating an encrypted archive.
    #[cfg(feature = "crypto")]
    pub fn create(key: &EncryptionKey) -> Result<(CipherHeader, Self), VzError> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::XChaCha20Poly1305;
        use rand_core::{OsRng, RngCore};

        let mut salt = [0u8; 16];
        let mut wrap_nonce = [0u8; 24];
        let mut cek = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut wrap_nonce);
        OsRng.fill_bytes(&mut cek);

        let (kdf_mode, m_cost, t_cost, p_cost, ikm) = match key {
            EncryptionKey::Password {
                password,
                m_cost_kib,
                t_cost,
                p_cost,
            } => (
                KDF_MODE_ARGON2ID,
                *m_cost_kib,
                *t_cost,
                *p_cost,
                derive_ikm_argon2id(password, &salt, *m_cost_kib, *t_cost, *p_cost)?,
            ),
            EncryptionKey::Raw256(raw) => (KDF_MODE_RAW_KEY, 0, 0, 0, *raw),
        };

        let kek = hkdf_expand(&salt, &ikm, b"VZ-v1-KEK")?;
        let cipher = XChaCha20Poly1305::new((&kek).into());
        let aad = build_wrap_aad(&salt);
        let wrapped = cipher
            .encrypt((&wrap_nonce).into(), Payload { msg: &cek, aad: &aad })
            .map_err(|_| VzError::CryptoError)?;
        if wrapped.len() != 48 {
            return Err(VzError::CryptoError);
        }
        let mut wrapped_cek = [0u8; 48];
        wrapped_cek.copy_from_slice(&wrapped);

        let payload_key = hkdf_expand(&salt, &cek, b"VZ-v1-PAYLOAD")?;
        let hdr = CipherHeader {
            version: 1,
            kdf_mode,
            cipher_suite: CIPHER_XCHACHA20_POLY1305,
            reserved: 0,
            argon2_m_cost_kib: m_cost,
            argon2_t_cost: t_cost,
            argon2_p_cost: p_cost,
            salt,
            wrap_nonce,
            wrapped_cek,
        };
        Ok((hdr, Self::from_payload_key(payload_key)))
    }

    #[cfg(not(feature = "crypto"))]
    pub fn create(_key: &EncryptionKey) -> Result<(crate::ext_meta::CipherHeader, Self), VzError> {
        Err(VzError::Unsupported)
    }

    /// Unlocks an existing [`CipherHeader`] using `key`.
    #[cfg(feature = "crypto")]
    pub fn unlock(hdr: &CipherHeader, key: &EncryptionKey) -> Result<Self, VzError> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::XChaCha20Poly1305;

        if hdr.version != 1
            || hdr.cipher_suite != CIPHER_XCHACHA20_POLY1305
            || hdr.reserved != 0
        {
            return Err(VzError::IncompatibleFeature);
        }

        let ikm = match (hdr.kdf_mode, key) {
            (
                KDF_MODE_ARGON2ID,
                EncryptionKey::Password {
                    password,
                    ..
                },
            ) => derive_ikm_argon2id(
                password,
                &hdr.salt,
                hdr.argon2_m_cost_kib,
                hdr.argon2_t_cost,
                hdr.argon2_p_cost,
            )?,
            (KDF_MODE_RAW_KEY, EncryptionKey::Raw256(raw)) => *raw,
            _ => return Err(VzError::CryptoError),
        };

        let kek = hkdf_expand(&hdr.salt, &ikm, b"VZ-v1-KEK")?;
        let cipher = XChaCha20Poly1305::new((&kek).into());
        let aad = build_wrap_aad(&hdr.salt);
        let cek_vec = cipher
            .decrypt(
                (&hdr.wrap_nonce).into(),
                Payload {
                    msg: &hdr.wrapped_cek,
                    aad: &aad,
                },
            )
            .map_err(|_| VzError::CryptoError)?;
        if cek_vec.len() != 32 {
            return Err(VzError::CryptoError);
        }
        let mut cek = [0u8; 32];
        cek.copy_from_slice(&cek_vec);
        let payload_key = hkdf_expand(&hdr.salt, &cek, b"VZ-v1-PAYLOAD")?;
        Ok(Self::from_payload_key(payload_key))
    }

    #[cfg(not(feature = "crypto"))]
    pub fn unlock(_hdr: &crate::ext_meta::CipherHeader, _key: &EncryptionKey) -> Result<Self, VzError> {
        Err(VzError::Unsupported)
    }

    /// Encrypts `plaintext` with `XChaCha20-Poly1305` into `out` (clearing `out` first).
    #[cfg(feature = "crypto")]
    pub fn encrypt_payload_into(
        &self,
        generation: u64,
        cluster_seq: u64,
        entry_id: u64,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), VzError> {
        use chacha20poly1305::aead::AeadInPlace;

        let mut nonce = [0u8; 24];
        fill_csprng_nonce(&mut nonce);
        let aad = build_payload_aad(generation, cluster_seq, entry_id);
        out.clear();
        out.reserve(24 + plaintext.len() + 16);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_in_place_detached((&nonce).into(), &aad, &mut out[24..])
            .map_err(|_| VzError::CryptoError)?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    #[cfg(not(feature = "crypto"))]
    pub fn encrypt_payload_into(
        &self,
        _generation: u64,
        _cluster_seq: u64,
        _entry_id: u64,
        _plaintext: &[u8],
        _out: &mut Vec<u8>,
    ) -> Result<(), VzError> {
        Err(VzError::Unsupported)
    }

    /// Encrypts `plaintext` with `XChaCha20-Poly1305` using AAD `(generation, cluster_seq, entry_id)`.
    #[cfg(feature = "crypto")]
    pub fn encrypt_payload(
        &self,
        generation: u64,
        cluster_seq: u64,
        entry_id: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, VzError> {
        let mut out = Vec::new();
        self.encrypt_payload_into(generation, cluster_seq, entry_id, plaintext, &mut out)?;
        Ok(out)
    }

    #[cfg(not(feature = "crypto"))]
    pub fn encrypt_payload(
        &self,
        _generation: u64,
        _cluster_seq: u64,
        _entry_id: u64,
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, VzError> {
        Err(VzError::Unsupported)
    }

    /// Decrypts `[24B nonce][ciphertext][16B tag]` directly into `out` (zero extra intermediate alloc).
    #[cfg(feature = "crypto")]
    pub fn decrypt_payload_into(
        &self,
        generation: u64,
        cluster_seq: u64,
        entry_id: u64,
        stored: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), VzError> {
        use chacha20poly1305::aead::AeadInPlace;

        if stored.len() < 40 {
            return Err(VzError::CryptoError);
        }
        let nonce = &stored[..24];
        let pt_len = stored.len() - 40;
        let ct = &stored[24..24 + pt_len];
        let tag = &stored[24 + pt_len..];
        let aad = build_payload_aad(generation, cluster_seq, entry_id);
        out.clear();
        out.extend_from_slice(ct);
        self.cipher
            .decrypt_in_place_detached(nonce.into(), &aad, out, tag.into())
            .map_err(|_| {
                out.clear();
                VzError::CryptoError
            })
    }

    #[cfg(not(feature = "crypto"))]
    pub fn decrypt_payload_into(
        &self,
        _generation: u64,
        _cluster_seq: u64,
        _entry_id: u64,
        _stored: &[u8],
        _out: &mut Vec<u8>,
    ) -> Result<(), VzError> {
        Err(VzError::Unsupported)
    }

    /// Decrypts `[24B nonce][ciphertext][16B tag]` directly into exact slice `dst`.
    #[cfg(feature = "crypto")]
    pub fn decrypt_payload_into_slice(
        &self,
        generation: u64,
        cluster_seq: u64,
        entry_id: u64,
        stored: &[u8],
        dst: &mut [u8],
    ) -> Result<(), VzError> {
        use chacha20poly1305::aead::AeadInPlace;

        if stored.len() < 40 {
            return Err(VzError::CryptoError);
        }
        let nonce = &stored[..24];
        let pt_len = stored.len() - 40;
        if pt_len != dst.len() {
            return Err(VzError::BadFormat);
        }
        let ct = &stored[24..24 + pt_len];
        let tag = &stored[24 + pt_len..];
        let aad = build_payload_aad(generation, cluster_seq, entry_id);
        dst.copy_from_slice(ct);
        self.cipher
            .decrypt_in_place_detached(nonce.into(), &aad, dst, tag.into())
            .map_err(|_| {
                dst.fill(0);
                VzError::CryptoError
            })
    }

    #[cfg(not(feature = "crypto"))]
    pub fn decrypt_payload_into_slice(
        &self,
        _generation: u64,
        _cluster_seq: u64,
        _entry_id: u64,
        _stored: &[u8],
        _dst: &mut [u8],
    ) -> Result<(), VzError> {
        Err(VzError::Unsupported)
    }

    /// Decrypts `[24B nonce][ciphertext][16B tag]` using AAD `(generation, cluster_seq, entry_id)`.
    #[cfg(feature = "crypto")]
    pub fn decrypt_payload(
        &self,
        generation: u64,
        cluster_seq: u64,
        entry_id: u64,
        stored: &[u8],
    ) -> Result<Vec<u8>, VzError> {
        let mut out = Vec::new();
        self.decrypt_payload_into(generation, cluster_seq, entry_id, stored, &mut out)?;
        Ok(out)
    }

    #[cfg(not(feature = "crypto"))]
    pub fn decrypt_payload(
        &self,
        _generation: u64,
        _cluster_seq: u64,
        _entry_id: u64,
        _stored: &[u8],
    ) -> Result<Vec<u8>, VzError> {
        Err(VzError::Unsupported)
    }
}

#[cfg(feature = "crypto")]
struct FastKeyErasureRng {
    key: [u8; 32],
    buf: [u8; 4096],
    pos: usize,
    counter: u64,
    seeded: bool,
}

#[cfg(feature = "crypto")]
impl FastKeyErasureRng {
    const fn new() -> Self {
        Self {
            key: [0u8; 32],
            buf: [0u8; 4096],
            pos: 4096,
            counter: 0,
            seeded: false,
        }
    }

    fn fill_nonce(&mut self, out: &mut [u8; 24]) {
        use chacha20poly1305::aead::{AeadInPlace, KeyInit};
        use chacha20poly1305::XChaCha20Poly1305;
        use rand_core::{OsRng, RngCore};

        if !self.seeded {
            OsRng.fill_bytes(&mut self.key);
            self.seeded = true;
            self.pos = self.buf.len();
        }
        if self.pos + 24 > self.buf.len() {
            self.buf.fill(0);
            let mut nonce = [0u8; 24];
            nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
            self.counter = self.counter.wrapping_add(1);
            let cipher = XChaCha20Poly1305::new((&self.key).into());
            let _ = cipher.encrypt_in_place_detached((&nonce).into(), &[], &mut self.buf);
            // Forward-secure fast key erasure: immediately overwrite key with new keyblock prefix.
            self.key.copy_from_slice(&self.buf[..32]);
            self.buf[..32].fill(0);
            self.pos = 32;
        }
        out.copy_from_slice(&self.buf[self.pos..self.pos + 24]);
        self.buf[self.pos..self.pos + 24].fill(0);
        self.pos += 24;
    }
}

#[cfg(feature = "crypto")]
impl Drop for FastKeyErasureRng {
    fn drop(&mut self) {
        self.key.fill(0);
        self.buf.fill(0);
    }
}

#[cfg(feature = "crypto")]
std::thread_local! {
    static NONCE_RNG_TLS: std::cell::RefCell<FastKeyErasureRng> =
        const { std::cell::RefCell::new(FastKeyErasureRng::new()) };
}

#[cfg(feature = "crypto")]
#[inline]
fn fill_csprng_nonce(out: &mut [u8; 24]) {
    let ok = NONCE_RNG_TLS
        .try_with(|cell| {
            if let Ok(mut rng) = cell.try_borrow_mut() {
                rng.fill_nonce(out);
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
    if !ok {
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "compression")]
    #[test]
    fn test_lz4_multi_block_size_fast_path_and_frame_interop() {
        use std::io::Read;
        let dict: Vec<DictEntry> = Vec::new();
        for &sz in &[0usize, 17, 64 * 1024, 200 * 1024, 1024 * 1024, 2 * 1024 * 1024 + 37] {
            let mut raw = Vec::with_capacity(sz);
            for i in 0..sz {
                raw.push(((i.wrapping_mul(13) ^ (i >> 7)) & 0x3F) as u8);
            }
            let comp = compress_payload_with_cache(&raw, CODEC_LZ4, None, &dict, None, 3).unwrap();
            // Must decode cleanly via external standard FrameDecoder.
            let mut dec = lz4_flex::frame::FrameDecoder::new(comp.as_slice());
            let mut ext_out = Vec::new();
            dec.read_to_end(&mut ext_out).unwrap();
            assert_eq!(ext_out, raw, "FrameDecoder mismatch at size {sz}");

            // Must decode cleanly via VZ Vec path and zero-copy slice path.
            let mut vz_out = Vec::new();
            decompress_payload_into(&comp, &mut vz_out, sz, CODEC_LZ4, None, &dict, None).unwrap();
            assert_eq!(vz_out, raw, "decompress_payload_into mismatch at size {sz}");

            let mut slice_out = vec![0xAAu8; sz];
            decompress_payload_into_slice(&comp, &mut slice_out, CODEC_LZ4, None, &dict, None)
                .unwrap();
            assert_eq!(slice_out, raw, "decompress_payload_into_slice mismatch at size {sz}");
        }

        // Also verify incompressible data uses uncompressed LZ4 frame block cleanly.
        let mut incomp = vec![0u8; 128 * 1024];
        let mut s = 0x1234_5678_9ABC_DEF0u64;
        for b in &mut incomp {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = (s >> 56) as u8;
        }
        let comp = compress_payload_with_cache(&incomp, CODEC_LZ4, None, &dict, None, 3).unwrap();
        let mut slice_out = vec![0u8; incomp.len()];
        decompress_payload_into_slice(&comp, &mut slice_out, CODEC_LZ4, None, &dict, None).unwrap();
        assert_eq!(slice_out, incomp);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_zstd_dict_vec_and_slice_roundtrip() {
        let dict_data = b"{\"service\":\"vz\",\"status\":\"ok\",\"region\":\"us-east\"}"
            .repeat(64);
        let dicts = vec![DictEntry {
            dict_id: 7,
            codec: CODEC_ZSTD,
            flags: 0,
            bytes: dict_data,
        }];
        let cache = ZstdDictCache::new(&dicts, 3);
        let ext = ExtCodecMeta {
            ext_codec_id: EXT_CODEC_ZSTD_DICT,
            dict_id: 7,
            params: Vec::new(),
        };
        let raw = b"{\"service\":\"vz\",\"status\":\"ok\",\"id\":42}";
        let comp = compress_payload_with_cache(
            raw,
            CODEC_EXT,
            Some(&ext),
            &dicts,
            Some(&cache),
            3,
        )
        .unwrap();
        let mut dst = vec![0u8; raw.len()];
        decompress_payload_into_slice(&comp, &mut dst, CODEC_EXT, Some(&ext), &dicts, Some(&cache))
            .unwrap();
        assert_eq!(dst.as_slice(), raw);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_fast_key_erasure_nonce_uniqueness_across_refills() {
        let mut seen = std::collections::HashSet::with_capacity(600);
        for _ in 0..600 {
            let mut n = [0u8; 24];
            fill_csprng_nonce(&mut n);
            assert!(seen.insert(n), "duplicate CSPRNG nonce generated");
        }
    }
}
