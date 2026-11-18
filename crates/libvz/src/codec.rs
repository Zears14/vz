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
    let eff = match codec {
        CODEC_EXT => {
            let ext = ext_codec.ok_or(VzError::BadFormat)?;
            match ext.ext_codec_id {
                EXT_CODEC_NONE => {
                    out.extend_from_slice(stored);
                    return Ok(());
                }
                EXT_CODEC_LZ4 => CODEC_LZ4,
                EXT_CODEC_ZSTD => CODEC_ZSTD,
                EXT_CODEC_ZSTD_DICT => return decompress_zstd_dict_into(stored, out, raw_size, ext.dict_id, dicts, cache),
                _ => return Err(VzError::Unsupported),
            }
        }
        other => other,
    };
    match eff {
        CODEC_NONE => {
            out.extend_from_slice(stored);
            Ok(())
        }
        CODEC_LZ4 => decompress_lz4_into(stored, out, raw_size),
        CODEC_ZSTD => {
            if let Some(ext) = ext_codec
                && ext.dict_id != 0
            {
                return decompress_zstd_dict_into(stored, out, raw_size, ext.dict_id, dicts, cache);
            }
            decompress_zstd_into(stored, out, raw_size)
        }
        _ => Err(VzError::BadFormat),
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
fn lz4_default_header_7b() -> [u8; 7] {
    static HDR: std::sync::OnceLock<[u8; 7]> = std::sync::OnceLock::new();
    *HDR.get_or_init(|| {
        let mut hdr = [0u8; 7];
        let enc = lz4_flex::frame::FrameEncoder::new(Vec::with_capacity(16));
        if let Ok(done) = enc.finish()
            && done.len() >= 7
        {
            hdr.copy_from_slice(&done[..7]);
        }
        hdr
    })
}

#[cfg(feature = "compression")]
fn compress_lz4_into(raw: &[u8], out: &mut Vec<u8>) -> Result<(), VzError> {
    use std::io::Write;
    if raw.len() <= 64 * 1024 {
        let hdr = lz4_default_header_7b();
        let max_blk = lz4_flex::block::get_maximum_output_size(raw.len());
        out.clear();
        out.resize(11 + max_blk + 4, 0);
        out[..7].copy_from_slice(&hdr);
        let clen = lz4_flex::block::compress_into(raw, &mut out[11..11 + max_blk])
            .map_err(|_| VzError::CompressionError)?;
        if clen < raw.len() || raw.is_empty() {
            out[7..11].copy_from_slice(&(clen as u32).to_le_bytes());
            out[11 + clen..15 + clen].fill(0);
            out.truncate(15 + clen);
        } else {
            // Incompressible block: store raw with LZ4 frame uncompressed bit (bit 31).
            out[7..11].copy_from_slice(&(0x8000_0000u32 | (raw.len() as u32)).to_le_bytes());
            out[11..11 + raw.len()].copy_from_slice(raw);
            out[11 + raw.len()..15 + raw.len()].fill(0);
            out.truncate(15 + raw.len());
        }
        return Ok(());
    }
    out.clear();
    let buf = core::mem::take(out);
    let mut enc = lz4_flex::frame::FrameEncoder::new(buf);
    enc.write_all(raw).map_err(|_| VzError::CompressionError)?;
    *out = enc.finish().map_err(|_| VzError::CompressionError)?;
    Ok(())
}

#[cfg(not(feature = "compression"))]
fn compress_lz4_into(_raw: &[u8], _out: &mut Vec<u8>) -> Result<(), VzError> {
    Err(VzError::Unsupported)
}

#[cfg(feature = "compression")]
fn decompress_lz4_into(stored: &[u8], out: &mut Vec<u8>, raw_size: usize) -> Result<(), VzError> {
    use std::io::Read;
    // Zero-alloc single-block fast path for independent LZ4 frames without extra header/checksum fields.
    if stored.len() >= 15
        && stored[..4] == [0x04, 0x22, 0x4D, 0x18]
        && (stored[4] & 0b1101_1111) == 0x40
        && (stored[5] & 0x8F) == 0
    {
        let blk_hdr = u32::from_le_bytes([stored[7], stored[8], stored[9], stored[10]]);
        let blk_len = (blk_hdr & 0x7FFF_FFFF) as usize;
        if 11 + blk_len + 4 == stored.len() && stored[11 + blk_len..] == [0, 0, 0, 0] {
            let blk = &stored[11..11 + blk_len];
            out.clear();
            if (blk_hdr & 0x8000_0000) != 0 {
                if blk_len != raw_size {
                    return Err(VzError::CompressionError);
                }
                out.extend_from_slice(blk);
                return Ok(());
            }
            out.resize(raw_size, 0);
            let n = lz4_flex::block::decompress_into(blk, out)
                .map_err(|_| VzError::CompressionError)?;
            if n != raw_size {
                return Err(VzError::CompressionError);
            }
            return Ok(());
        }
    }

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
std::thread_local! {
    static ZSTD_COMP_TLS: std::cell::RefCell<Option<(i32, zstd::bulk::Compressor<'static>)>> =
        const { std::cell::RefCell::new(None) };
    static ZSTD_DECOMP_TLS: std::cell::RefCell<Option<zstd::bulk::Decompressor<'static>>> =
        const { std::cell::RefCell::new(None) };
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
    let res = ZSTD_DECOMP_TLS.try_with(|cell| -> Result<usize, VzError> {
        let Ok(mut slot) = cell.try_borrow_mut() else {
            let mut dec =
                zstd::bulk::Decompressor::new().map_err(|_| VzError::CompressionError)?;
            return dec
                .decompress_to_buffer(stored, out)
                .map_err(|_| VzError::CompressionError);
        };
        if slot.is_none() {
            *slot = Some(zstd::bulk::Decompressor::new().map_err(|_| VzError::CompressionError)?);
        }
        let Some(dec) = slot.as_mut() else {
            return Err(VzError::CompressionError);
        };
        dec.decompress_to_buffer(stored, out)
            .map_err(|_| VzError::CompressionError)
    });
    let n = match res {
        Ok(r) => r?,
        Err(_) => {
            let mut dec =
                zstd::bulk::Decompressor::new().map_err(|_| VzError::CompressionError)?;
            dec.decompress_to_buffer(stored, out)
                .map_err(|_| VzError::CompressionError)?
        }
    };
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
        let mut comp = zstd::bulk::Compressor::with_prepared_dictionary(cdict)
            .map_err(|_| VzError::CompressionError)?;
        comp.compress_to_buffer(raw, out)
            .map_err(|_| VzError::CompressionError)?;
        return Ok(());
    }
    let dict = dicts
        .iter()
        .find(|d| d.dict_id == dict_id && d.codec == CODEC_ZSTD)
        .ok_or(VzError::NotFound)?;
    let mut comp = zstd::bulk::Compressor::with_dictionary(level, &dict.bytes)
        .map_err(|_| VzError::CompressionError)?;
    comp.compress_to_buffer(raw, out)
        .map_err(|_| VzError::CompressionError)?;
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
        let mut decomp = zstd::bulk::Decompressor::with_prepared_dictionary(ddict)
            .map_err(|_| VzError::CompressionError)?;
        decomp
            .decompress_to_buffer(stored, out)
            .map_err(|_| VzError::CompressionError)?
    } else {
        let dict = dicts
            .iter()
            .find(|d| d.dict_id == dict_id && d.codec == CODEC_ZSTD)
            .ok_or(VzError::NotFound)?;
        let mut decomp = zstd::bulk::Decompressor::with_dictionary(&dict.bytes)
            .map_err(|_| VzError::CompressionError)?;
        decomp
            .decompress_to_buffer(stored, out)
            .map_err(|_| VzError::CompressionError)?
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
        use rand_core::{OsRng, RngCore};

        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
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
