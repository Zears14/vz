/// Returns `true` if hardware-accelerated CRC32C (`sse4.2` on x86/x86_64 or `crc` on aarch64)
/// is active on this build/CPU.
#[inline]
pub fn crc32c_hw_active() -> bool {
    #[cfg(all(target_arch = "x86_64", target_feature = "sse4.2"))]
    {
        true
    }
    #[cfg(all(
        target_arch = "x86_64",
        not(target_feature = "sse4.2"),
        feature = "std"
    ))]
    {
        std::arch::is_x86_feature_detected!("sse4.2")
    }
    #[cfg(all(target_arch = "x86", target_feature = "sse4.2"))]
    {
        true
    }
    #[cfg(all(target_arch = "x86", not(target_feature = "sse4.2"), feature = "std"))]
    {
        std::arch::is_x86_feature_detected!("sse4.2")
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "crc"))]
    {
        true
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", any(target_feature = "sse4.2", feature = "std")),
        all(target_arch = "x86", any(target_feature = "sse4.2", feature = "std")),
        all(target_arch = "aarch64", target_feature = "crc"),
    )))]
    {
        false
    }
}

#[cfg(all(target_arch = "x86_64", any(target_feature = "sse4.2", feature = "std")))]
#[target_feature(enable = "sse4.2")]
#[inline]
unsafe fn crc32c_update_x86_64(mut crc: u32, data: &[u8]) -> u32 {
    use core::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
    let mut chunks = data.chunks_exact(8);
    for chunk in chunks.by_ref() {
        let v = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        crc = _mm_crc32_u64(crc as u64, v) as u32;
    }
    for &b in chunks.remainder() {
        crc = _mm_crc32_u8(crc, b);
    }
    crc
}

#[cfg(all(target_arch = "x86", any(target_feature = "sse4.2", feature = "std")))]
#[target_feature(enable = "sse4.2")]
#[inline]
unsafe fn crc32c_update_x86(mut crc: u32, data: &[u8]) -> u32 {
    use core::arch::x86::{_mm_crc32_u32, _mm_crc32_u8};
    let mut chunks = data.chunks_exact(4);
    for chunk in chunks.by_ref() {
        let v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        crc = _mm_crc32_u32(crc, v);
    }
    for &b in chunks.remainder() {
        crc = _mm_crc32_u8(crc, b);
    }
    crc
}

const CRC32C_POLY_REFLECTED: u32 = 0x82F6_3B78;

const fn build_crc32c_slice8_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut bit = 0;
        while bit < 8 {
            c = if (c & 1) != 0 {
                (c >> 1) ^ CRC32C_POLY_REFLECTED
            } else {
                c >> 1
            };
            bit += 1;
        }
        tables[0][i] = c;
        i += 1;
    }
    let mut t = 1usize;
    while t < 8 {
        let mut j = 0usize;
        while j < 256 {
            let prev = tables[t - 1][j];
            tables[t][j] = (prev >> 8) ^ tables[0][(prev & 0xFF) as usize];
            j += 1;
        }
        t += 1;
    }
    tables
}

static CRC32C_SLICE8: [[u32; 256]; 8] = build_crc32c_slice8_tables();

/// Portable `#![no_std]`, host-endian-independent Slice-by-8 Castagnoli CRC32C update.
#[inline]
pub fn crc32c_update_sw(mut crc: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(8);
    for c in chunks.by_ref() {
        // Explicit `from_le_bytes` ensures identical bit ordering on both LE and BE host CPUs.
        let lo = crc ^ u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        crc = CRC32C_SLICE8[7][(lo & 0xFF) as usize]
            ^ CRC32C_SLICE8[6][((lo >> 8) & 0xFF) as usize]
            ^ CRC32C_SLICE8[5][((lo >> 16) & 0xFF) as usize]
            ^ CRC32C_SLICE8[4][((lo >> 24) & 0xFF) as usize]
            ^ CRC32C_SLICE8[3][(hi & 0xFF) as usize]
            ^ CRC32C_SLICE8[2][((hi >> 8) & 0xFF) as usize]
            ^ CRC32C_SLICE8[1][((hi >> 16) & 0xFF) as usize]
            ^ CRC32C_SLICE8[0][((hi >> 24) & 0xFF) as usize];
    }
    for &b in chunks.remainder() {
        crc = (crc >> 8) ^ CRC32C_SLICE8[0][((crc ^ b as u32) & 0xFF) as usize];
    }
    crc
}

/// Computes the Castagnoli CRC32C checksum over `data` using the portable Slice-by-8 path.
#[inline]
pub fn crc32c_sw(data: &[u8]) -> u32 {
    !crc32c_update_sw(0xFFFF_FFFF, data)
}

/// Streaming Castagnoli CRC32C update.
///
/// Pass `0xFFFF_FFFF` as initial `crc`, and finalize with `!crc`. Uses SSE4.2 (`x86`/`x86_64`)
/// or ARMv8 CRC (`aarch64`) hardware instructions when available, falling back to a portable
/// 16-entry nibble table otherwise.
#[inline]
pub fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    #[cfg(all(target_arch = "x86_64", target_feature = "sse4.2"))]
    {
        // SAFETY: `target_feature = "sse4.2"` is verified statically via `#[cfg]`.
        return unsafe { crc32c_update_x86_64(crc, data) };
    }

    #[cfg(all(
        target_arch = "x86_64",
        not(target_feature = "sse4.2"),
        feature = "std"
    ))]
    {
        if std::arch::is_x86_feature_detected!("sse4.2") {
            // SAFETY: runtime CPU feature detection confirmed SSE4.2 support.
            return unsafe { crc32c_update_x86_64(crc, data) };
        }
    }

    #[cfg(all(target_arch = "x86", target_feature = "sse4.2"))]
    {
        // SAFETY: `target_feature = "sse4.2"` is verified statically via `#[cfg]`.
        return unsafe { crc32c_update_x86(crc, data) };
    }

    #[cfg(all(target_arch = "x86", not(target_feature = "sse4.2"), feature = "std"))]
    {
        if std::arch::is_x86_feature_detected!("sse4.2") {
            // SAFETY: runtime CPU feature detection confirmed SSE4.2 support.
            return unsafe { crc32c_update_x86(crc, data) };
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "crc"))]
    {
        use core::arch::aarch64::{__crc32cb, __crc32cd};
        let mut c = crc;
        let mut chunks = data.chunks_exact(8);
        for chunk in chunks.by_ref() {
            let v = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
            // SAFETY: `target_feature = "crc"` is verified statically via `#[cfg]`.
            c = unsafe { __crc32cd(c, v) };
        }
        for &b in chunks.remainder() {
            // SAFETY: `target_feature = "crc"` is verified statically via `#[cfg]`.
            c = unsafe { __crc32cb(c, b) };
        }
        return c;
    }

    #[allow(unreachable_code)]
    crc32c_update_sw(crc, data)
}

/// Computes the finalized Castagnoli CRC32C checksum over `data`.
#[inline]
pub fn crc32c(data: &[u8]) -> u32 {
    !crc32c_update(0xFFFF_FFFF, data)
}

/// Built-in 64-bit path/basename hash mixer (`HASH_ALGO_BUILTIN`).
///
/// Non-cryptographic and unseeded; for untrusted adversarial path inputs,
/// prefer `HASH_ALGO_BLAKE3` (64-bit prefix) when building archives.
pub fn hash64(data: &[u8]) -> u64 {
    let mut h = 0x9E37_79B1_85EB_CA87_u64
        ^ (data.len() as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F_u64);
    let mut chunks = data.chunks_exact(8);
    for chunk in chunks.by_ref() {
        let mut k = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        k = k.wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
        k = k.rotate_left(31);
        k = k.wrapping_mul(0x9E37_79B1_85EB_CA87);
        h ^= k;
        h = h.rotate_left(27).wrapping_mul(5).wrapping_add(0x52DC_E729);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut tail_bytes = [0u8; 8];
        tail_bytes[..rem.len()].copy_from_slice(rem);
        let tail = u64::from_le_bytes(tail_bytes);
        h ^= tail.wrapping_mul(0x9E37_79B1_85EB_CA87);
        h = h
            .rotate_left(23)
            .wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
            .wrapping_add(0x1656_67B1_9E37_79F9);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    h ^= h >> 33;
    h = h.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
    h ^= h >> 33;
    h
}
