use crate::crc::crc32c;
use crate::error::VzError;
use crate::wire::{
    BOOT_DATA_PAGES, BOOT_ECC_DESC_OFF, BOOT_PAGES, BOOT_PARITY_OFFSET, BootEccDescriptor,
    DEFAULT_BOOT_SIZE, MAGIC_BOOT_ECC, PAGE_SIZE,
};

// ============================================================================
// 1. BOOT BLOCK 4 KiB SELF-HEALING ECC
// ============================================================================

/// Computes the Castagnoli CRC32C of page `page_idx` (`0..=15`) in a 64 KiB Boot Block.
///
/// For Page `14`, hashes the `4,016` bytes preceding the 80-byte [`BootEccDescriptor`] (`0xE000..=0xEFAF`).
pub fn boot_page_crc32c(boot_block: &[u8], page_idx: usize) -> Result<u32, VzError> {
    if page_idx >= BOOT_PAGES || boot_block.len() < DEFAULT_BOOT_SIZE {
        return Err(VzError::BufferTooSmall);
    }
    let start = page_idx * PAGE_SIZE;
    let len = if page_idx == 14 {
        PAGE_SIZE - BootEccDescriptor::SIZE
    } else {
        PAGE_SIZE
    };
    Ok(crc32c(&boot_block[start..start + len]))
}

fn xor_reconstruct_page(ecc_zone: &mut [u8], target_page: usize) {
    let (before, rest) = ecc_zone.split_at_mut(target_page * PAGE_SIZE);
    let (target, after) = rest.split_at_mut(PAGE_SIZE);
    target.fill(0);
    for src in before.chunks_exact(PAGE_SIZE).chain(after.chunks_exact(PAGE_SIZE)) {
        for (d, &s) in target.iter_mut().zip(src.iter()) {
            *d ^= s;
        }
    }
}

/// Generates [`BootEccDescriptor`] at `0xEFB0` and the 4 KiB XOR Parity Page at `0xF000`.
///
/// Only valid for 64 KiB Boot Blocks (`boot_block.len() >= 65_536`).
pub fn boot_ecc_encode(boot_block: &mut [u8]) -> Result<(), VzError> {
    if boot_block.len() < DEFAULT_BOOT_SIZE {
        return Err(VzError::BufferTooSmall);
    }
    let ecc_zone = &mut boot_block[..DEFAULT_BOOT_SIZE];

    let mut desc = BootEccDescriptor {
        ecc_magic: MAGIC_BOOT_ECC,
        protected_pages: BOOT_DATA_PAGES as u16,
        ecc_scheme: 1,
        page_crc32c: [0u32; 16],
        reserved: 0,
        desc_crc32c: 0,
    };
    for p in 0..BOOT_DATA_PAGES {
        desc.page_crc32c[p] = boot_page_crc32c(ecc_zone, p)?;
    }

    // Stamp descriptor with page_crc32c[15] = 0 and desc_crc32c = 0 prior to XOR pass.
    desc.write_bytes(
        &mut ecc_zone[BOOT_ECC_DESC_OFF..BOOT_ECC_DESC_OFF + BootEccDescriptor::SIZE],
    )?;

    let (data_pages, parity_page) = ecc_zone.split_at_mut(BOOT_PARITY_OFFSET);
    parity_page.fill(0);
    for src in data_pages.chunks_exact(PAGE_SIZE) {
        for (d, &s) in parity_page.iter_mut().zip(src.iter()) {
            *d ^= s;
        }
    }

    desc.page_crc32c[15] = crc32c(parity_page);
    let prefix = desc.to_bytes();
    desc.desc_crc32c = crc32c(&prefix[..76]);
    desc.write_bytes(
        &mut ecc_zone[BOOT_ECC_DESC_OFF..BOOT_ECC_DESC_OFF + BootEccDescriptor::SIZE],
    )?;
    Ok(())
}

/// Verifies a 64 KiB Boot Block and repairs any single corrupted 4 KiB page (`0..=15`) in-place.
///
/// Returns `Ok(None)` if clean, `Ok(Some(page_idx))` if a single page was repaired, or
/// `Err(VzError::CorruptUnrecoverable)` if 2 or more pages are damaged.
pub fn boot_ecc_verify_and_repair(boot_block: &mut [u8]) -> Result<Option<usize>, VzError> {
    if boot_block.len() < DEFAULT_BOOT_SIZE {
        return Err(VzError::BufferTooSmall);
    }
    let ecc_zone = &mut boot_block[..DEFAULT_BOOT_SIZE];

    let desc_slice = &ecc_zone[BOOT_ECC_DESC_OFF..BOOT_ECC_DESC_OFF + BootEccDescriptor::SIZE];
    let desc = BootEccDescriptor::from_bytes(desc_slice)?;
    let desc_valid = desc.ecc_magic == MAGIC_BOOT_ECC
        && desc.protected_pages == BOOT_DATA_PAGES as u16
        && desc.ecc_scheme == 1
        && desc.reserved == 0
        && crc32c(&desc_slice[..76]) == desc.desc_crc32c;

    // Case A: Descriptor itself (in Page 14) was corrupted -> reconstruct Page 14 via XOR.
    if !desc_valid {
        xor_reconstruct_page(ecc_zone, 14);
        let mut recovered = BootEccDescriptor::from_bytes(
            &ecc_zone[BOOT_ECC_DESC_OFF..BOOT_ECC_DESC_OFF + BootEccDescriptor::SIZE],
        )?;
        // Parity was computed while page_crc32c[15] == 0 and desc_crc32c == 0.
        if recovered.ecc_magic != MAGIC_BOOT_ECC
            || recovered.protected_pages != BOOT_DATA_PAGES as u16
            || recovered.ecc_scheme != 1
            || recovered.reserved != 0
            || recovered.page_crc32c[15] != 0
            || recovered.desc_crc32c != 0
        {
            return Err(VzError::CorruptUnrecoverable);
        }
        for p in 0..BOOT_DATA_PAGES {
            if boot_page_crc32c(ecc_zone, p)? != recovered.page_crc32c[p] {
                return Err(VzError::CorruptUnrecoverable);
            }
        }
        recovered.page_crc32c[15] = crc32c(&ecc_zone[BOOT_PARITY_OFFSET..DEFAULT_BOOT_SIZE]);
        let prefix = recovered.to_bytes();
        recovered.desc_crc32c = crc32c(&prefix[..76]);
        recovered.write_bytes(
            &mut ecc_zone[BOOT_ECC_DESC_OFF..BOOT_ECC_DESC_OFF + BootEccDescriptor::SIZE],
        )?;
        return Ok(Some(14));
    }

    // Case B: Descriptor is valid; locate any damaged data or parity page.
    let mut bad_page: Option<usize> = None;
    let mut bad_count = 0usize;
    for p in 0..BOOT_DATA_PAGES {
        if boot_page_crc32c(ecc_zone, p)? != desc.page_crc32c[p] {
            bad_page = Some(p);
            bad_count += 1;
        }
    }
    let parity_ok = crc32c(&ecc_zone[BOOT_PARITY_OFFSET..DEFAULT_BOOT_SIZE]) == desc.page_crc32c[15];

    if bad_count == 0 {
        if !parity_ok {
            boot_ecc_encode(ecc_zone)?;
            return Ok(Some(15));
        }
        return Ok(None);
    }
    if bad_count > 1 || !parity_ok {
        return Err(VzError::CorruptUnrecoverable);
    }

    let bad = bad_page.ok_or(VzError::CorruptUnrecoverable)?;

    // Restore pre-final-stamp zeroes in the last 8B of Page 14 for exact XOR reconstruction.
    let mut temp_desc = desc;
    temp_desc.page_crc32c[15] = 0;
    temp_desc.desc_crc32c = 0;
    temp_desc.write_bytes(
        &mut ecc_zone[BOOT_ECC_DESC_OFF..BOOT_ECC_DESC_OFF + BootEccDescriptor::SIZE],
    )?;

    xor_reconstruct_page(ecc_zone, bad);
    desc.write_bytes(
        &mut ecc_zone[BOOT_ECC_DESC_OFF..BOOT_ECC_DESC_OFF + BootEccDescriptor::SIZE],
    )?;

    if boot_page_crc32c(ecc_zone, bad)? != desc.page_crc32c[bad] {
        return Err(VzError::CorruptUnrecoverable);
    }
    Ok(Some(bad))
}

// ============================================================================
// 2. REED-SOLOMON GF(2^8) ERASURE CODING PRIMITIVES
// ============================================================================

/// Galois Field `GF(2^8)` multiplication modulo `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`).
#[inline]
pub fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    p
}

/// Computes the multiplicative inverse of `a` in `GF(2^8)` modulo `0x11D`.
#[inline]
pub fn gf256_inv(a: u8) -> Result<u8, VzError> {
    if a == 0 {
        return Err(VzError::BadFormat);
    }
    let mut pow = gf256_mul(a, a);
    let mut res = 1u8;
    for _ in 0..7 {
        res = gf256_mul(res, pow);
        pow = gf256_mul(pow, pow);
    }
    Ok(res)
}

/// Computes `a / b` in `GF(2^8)` modulo `0x11D`.
#[inline]
pub fn gf256_div(a: u8, b: u8) -> Result<u8, VzError> {
    Ok(gf256_mul(a, gf256_inv(b)?))
}

/// Computes the systematic Cauchy matrix coefficient `1 / (x_i ^ y_j)` where `x_i = parity_idx`
/// (`0..M`) and `y_j = M + data_idx` (`M..M+K`), requiring `K + M <= 256`.
#[inline]
pub fn rs_gf256_cauchy_coeff(parity_idx: u16, data_idx: u16, parity_m: u16) -> Result<u8, VzError> {
    let total = parity_m
        .checked_add(data_idx)
        .ok_or(VzError::ValueOverflow)?;
    if total >= 256 || parity_idx >= parity_m {
        return Err(VzError::InvalidInput);
    }
    let x_i = parity_idx as u8;
    let y_j = total as u8;
    gf256_inv(x_i ^ y_j)
}

#[cfg(any(
    all(target_arch = "x86_64", any(target_feature = "avx2", target_feature = "ssse3", feature = "std")),
    all(target_arch = "x86", any(target_feature = "avx2", target_feature = "ssse3", feature = "std"))
))]
#[inline]
fn build_gf256_nibble_tables(gf_coeff: u8) -> ([u8; 16], [u8; 16]) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    // Basis powers for lo (1,2,4,8) and hi (16,32,64,128)
    let mut b_lo = gf_coeff;
    for bit in [1usize, 2, 4, 8] {
        for j in 0..bit {
            lo[bit | j] = lo[j] ^ b_lo;
        }
        let carry = (b_lo & 0x80) != 0;
        b_lo <<= 1;
        if carry {
            b_lo ^= 0x1D;
        }
    }
    let mut b_hi = b_lo; // gf_coeff * 16
    for bit in [1usize, 2, 4, 8] {
        for j in 0..bit {
            hi[bit | j] = hi[j] ^ b_hi;
        }
        let carry = (b_hi & 0x80) != 0;
        b_hi <<= 1;
        if carry {
            b_hi ^= 0x1D;
        }
    }
    (lo, hi)
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_feature = "avx2", feature = "std")
))]
#[target_feature(enable = "avx2")]
unsafe fn rs_gf256_madd_avx2(dst: &mut [u8], src: &[u8], gf_coeff: u8) {
    use core::arch::x86_64::{
        __m128i, __m256i, _mm_loadu_si128, _mm256_and_si256, _mm256_broadcastsi128_si256,
        _mm256_loadu_si256, _mm256_set1_epi8, _mm256_shuffle_epi8, _mm256_srli_epi16,
        _mm256_storeu_si256, _mm256_xor_si256,
    };

    let mut dst_chunks = dst.chunks_exact_mut(32);
    let mut src_chunks = src.chunks_exact(32);

    if gf_coeff == 1 {
        for (d, s) in dst_chunks.by_ref().zip(src_chunks.by_ref()) {
            // SAFETY: chunks_exact(32) guarantees 32 readable/writable bytes.
            unsafe {
                let dv = _mm256_loadu_si256(d.as_ptr() as *const __m256i);
                let sv = _mm256_loadu_si256(s.as_ptr() as *const __m256i);
                _mm256_storeu_si256(d.as_mut_ptr() as *mut __m256i, _mm256_xor_si256(dv, sv));
            }
        }
        for (d, &s) in dst_chunks
            .into_remainder()
            .iter_mut()
            .zip(src_chunks.remainder().iter())
        {
            *d ^= s;
        }
        return;
    }

    let (tbl_lo, tbl_hi) = build_gf256_nibble_tables(gf_coeff);
    // SAFETY: tbl_lo/tbl_hi are 16-byte stack arrays; unaligned 128-bit load + broadcast is valid.
    let (v_lo, v_hi, mask_0f) = unsafe {
        let lo_128 = _mm_loadu_si128(tbl_lo.as_ptr() as *const __m128i);
        let hi_128 = _mm_loadu_si128(tbl_hi.as_ptr() as *const __m128i);
        (
            _mm256_broadcastsi128_si256(lo_128),
            _mm256_broadcastsi128_si256(hi_128),
            _mm256_set1_epi8(0x0F),
        )
    };

    for (d, s) in dst_chunks.by_ref().zip(src_chunks.by_ref()) {
        // SAFETY: chunks_exact(32) guarantees 32 readable/writable bytes.
        unsafe {
            let sv = _mm256_loadu_si256(s.as_ptr() as *const __m256i);
            let lo = _mm256_and_si256(sv, mask_0f);
            let hi = _mm256_and_si256(_mm256_srli_epi16(sv, 4), mask_0f);
            let p_lo = _mm256_shuffle_epi8(v_lo, lo);
            let p_hi = _mm256_shuffle_epi8(v_hi, hi);
            let prod = _mm256_xor_si256(p_lo, p_hi);
            let dv = _mm256_loadu_si256(d.as_ptr() as *const __m256i);
            _mm256_storeu_si256(d.as_mut_ptr() as *mut __m256i, _mm256_xor_si256(dv, prod));
        }
    }

    for (d, &s) in dst_chunks
        .into_remainder()
        .iter_mut()
        .zip(src_chunks.remainder().iter())
    {
        *d ^= tbl_lo[(s & 0x0F) as usize] ^ tbl_hi[(s >> 4) as usize];
    }
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    any(target_feature = "ssse3", feature = "std")
))]
#[target_feature(enable = "ssse3")]
unsafe fn rs_gf256_madd_ssse3(dst: &mut [u8], src: &[u8], gf_coeff: u8) {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        __m128i, _mm_and_si128, _mm_loadu_si128, _mm_set1_epi8, _mm_shuffle_epi8, _mm_srli_epi16,
        _mm_storeu_si128, _mm_xor_si128,
    };
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{
        __m128i, _mm_and_si128, _mm_loadu_si128, _mm_set1_epi8, _mm_shuffle_epi8, _mm_srli_epi16,
        _mm_storeu_si128, _mm_xor_si128,
    };

    let mut dst_chunks = dst.chunks_exact_mut(16);
    let mut src_chunks = src.chunks_exact(16);

    if gf_coeff == 1 {
        for (d, s) in dst_chunks.by_ref().zip(src_chunks.by_ref()) {
            // SAFETY: chunks_exact(16) guarantees 16 readable/writable bytes.
            unsafe {
                let dv = _mm_loadu_si128(d.as_ptr() as *const __m128i);
                let sv = _mm_loadu_si128(s.as_ptr() as *const __m128i);
                _mm_storeu_si128(d.as_mut_ptr() as *mut __m128i, _mm_xor_si128(dv, sv));
            }
        }
        for (d, &s) in dst_chunks
            .into_remainder()
            .iter_mut()
            .zip(src_chunks.remainder().iter())
        {
            *d ^= s;
        }
        return;
    }

    let (tbl_lo, tbl_hi) = build_gf256_nibble_tables(gf_coeff);
    // SAFETY: tbl_lo/tbl_hi are 16-byte stack arrays.
    let (v_lo, v_hi, mask_0f) = unsafe {
        (
            _mm_loadu_si128(tbl_lo.as_ptr() as *const __m128i),
            _mm_loadu_si128(tbl_hi.as_ptr() as *const __m128i),
            _mm_set1_epi8(0x0F),
        )
    };

    for (d, s) in dst_chunks.by_ref().zip(src_chunks.by_ref()) {
        // SAFETY: chunks_exact(16) guarantees 16 readable/writable bytes.
        unsafe {
            let sv = _mm_loadu_si128(s.as_ptr() as *const __m128i);
            let lo = _mm_and_si128(sv, mask_0f);
            let hi = _mm_and_si128(_mm_srli_epi16(sv, 4), mask_0f);
            let p_lo = _mm_shuffle_epi8(v_lo, lo);
            let p_hi = _mm_shuffle_epi8(v_hi, hi);
            let prod = _mm_xor_si128(p_lo, p_hi);
            let dv = _mm_loadu_si128(d.as_ptr() as *const __m128i);
            _mm_storeu_si128(d.as_mut_ptr() as *mut __m128i, _mm_xor_si128(dv, prod));
        }
    }

    for (d, &s) in dst_chunks
        .into_remainder()
        .iter_mut()
        .zip(src_chunks.remainder().iter())
    {
        *d ^= tbl_lo[(s & 0x0F) as usize] ^ tbl_hi[(s >> 4) as usize];
    }
}

#[allow(dead_code)]
fn rs_gf256_madd_scalar(dst: &mut [u8], src_cluster: &[u8], gf_coeff: u8) {
    if gf_coeff == 1 {
        for (d, &s) in dst.iter_mut().zip(src_cluster.iter()) {
            *d ^= s;
        }
        return;
    }

    let mut tbl = [0u8; 256];
    let mut basis = gf_coeff;
    let mut bit = 1usize;
    while bit < 256 {
        for j in 0..bit {
            tbl[bit | j] = tbl[j] ^ basis;
        }
        let hi = (basis & 0x80) != 0;
        basis <<= 1;
        if hi {
            basis ^= 0x1D;
        }
        bit <<= 1;
    }

    for (d, &s) in dst.iter_mut().zip(src_cluster.iter()) {
        *d ^= tbl[s as usize];
    }
}

/// Accumulates `src_cluster * gf_coeff` into `parity_dst[..src_cluster.len()]` over `GF(2^8)`.
///
/// Uses AVX2 (`_mm256_shuffle_epi8`, 32 bytes/iter) or SSSE3 (`_mm_shuffle_epi8`, 16 bytes/iter)
/// nibble-lookup vectorization when supported on `x86`/`x86_64`, falling back to a 256-byte
/// scalar lookup table on other targets or `no_std` builds without SIMD target features.
pub fn rs_gf256_madd_slice(
    parity_dst: &mut [u8],
    src_cluster: &[u8],
    gf_coeff: u8,
) -> Result<(), VzError> {
    if parity_dst.len() < src_cluster.len() {
        return Err(VzError::BufferTooSmall);
    }
    if gf_coeff == 0 || src_cluster.is_empty() {
        return Ok(());
    }
    let dst = &mut parity_dst[..src_cluster.len()];

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        // SAFETY: `target_feature = "avx2"` is verified statically via `#[cfg]`.
        unsafe { rs_gf256_madd_avx2(dst, src_cluster, gf_coeff) };
        return Ok(());
    }

    #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2"), feature = "std"))]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: runtime CPU feature detection confirmed AVX2 support.
            unsafe { rs_gf256_madd_avx2(dst, src_cluster, gf_coeff) };
            return Ok(());
        }
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        target_feature = "ssse3",
        not(target_feature = "avx2")
    ))]
    {
        // SAFETY: `target_feature = "ssse3"` is verified statically via `#[cfg]`.
        unsafe { rs_gf256_madd_ssse3(dst, src_cluster, gf_coeff) };
        return Ok(());
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        not(target_feature = "ssse3"),
        feature = "std"
    ))]
    {
        if std::arch::is_x86_feature_detected!("ssse3") {
            // SAFETY: runtime CPU feature detection confirmed SSSE3 support.
            unsafe { rs_gf256_madd_ssse3(dst, src_cluster, gf_coeff) };
            return Ok(());
        }
    }

    #[allow(unreachable_code)]
    {
        rs_gf256_madd_scalar(dst, src_cluster, gf_coeff);
        Ok(())
    }
}

/// Inverts a `k x k` matrix `mat` over `GF(2^8)` in-place via Gauss-Jordan elimination,
/// writing the inverse into `inv`.
pub fn gf256_invert_matrix_in_place(
    mat: &mut [u8],
    inv: &mut [u8],
    k: usize,
) -> Result<(), VzError> {
    let needed = k.checked_mul(k).ok_or(VzError::ValueOverflow)?;
    if mat.len() < needed || inv.len() < needed {
        return Err(VzError::BufferTooSmall);
    }
    inv[..needed].fill(0);
    for i in 0..k {
        inv[i * k + i] = 1;
    }

    for col in 0..k {
        let mut pivot_row = None;
        for row in col..k {
            if mat[row * k + col] != 0 {
                pivot_row = Some(row);
                break;
            }
        }
        let pivot = pivot_row.ok_or(VzError::CorruptUnrecoverable)?;
        if pivot != col {
            for c in 0..k {
                mat.swap(col * k + c, pivot * k + c);
                inv.swap(col * k + c, pivot * k + c);
            }
        }

        let diag = mat[col * k + col];
        let inv_diag = gf256_inv(diag).map_err(|_| VzError::CorruptUnrecoverable)?;
        if inv_diag != 1 {
            for c in 0..k {
                mat[col * k + c] = gf256_mul(mat[col * k + c], inv_diag);
                inv[col * k + c] = gf256_mul(inv[col * k + c], inv_diag);
            }
        }

        for row in 0..k {
            if row == col {
                continue;
            }
            let factor = mat[row * k + col];
            if factor == 0 {
                continue;
            }
            for c in 0..k {
                let m_sub = gf256_mul(factor, mat[col * k + c]);
                mat[row * k + c] ^= m_sub;
                let i_sub = gf256_mul(factor, inv[col * k + c]);
                inv[row * k + c] ^= i_sub;
            }
        }
    }
    Ok(())
}
