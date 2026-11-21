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

#[cfg(all(target_arch = "x86_64", any(target_feature = "avx2", feature = "std")))]
#[target_feature(enable = "avx2")]
unsafe fn xor_15_pages_avx2(dst: &mut [u8], srcs: &[&[u8]; BOOT_DATA_PAGES]) {
    use core::arch::x86_64::{__m256i, _mm256_loadu_si256, _mm256_storeu_si256, _mm256_xor_si256};
    let mut off = 0usize;
    while off + 32 <= dst.len() {
        // SAFETY: `srcs[p].len() >= PAGE_SIZE == dst.len()` and `off + 32 <= PAGE_SIZE`.
        unsafe {
            let d_ptr = dst.as_mut_ptr().add(off) as *mut __m256i;
            let mut acc = _mm256_loadu_si256(srcs[0].as_ptr().add(off) as *const __m256i);
            for s in &srcs[1..] {
                let v = _mm256_loadu_si256(s.as_ptr().add(off) as *const __m256i);
                acc = _mm256_xor_si256(acc, v);
            }
            _mm256_storeu_si256(d_ptr, acc);
        }
        off += 32;
    }
}

#[inline]
fn xor_15_pages_scalar64(dst: &mut [u8], srcs: &[&[u8]; BOOT_DATA_PAGES]) {
    let mut off = 0usize;
    while off + 8 <= dst.len() {
        let mut acc = u64::from_ne_bytes([
            srcs[0][off],
            srcs[0][off + 1],
            srcs[0][off + 2],
            srcs[0][off + 3],
            srcs[0][off + 4],
            srcs[0][off + 5],
            srcs[0][off + 6],
            srcs[0][off + 7],
        ]);
        for s in &srcs[1..] {
            acc ^= u64::from_ne_bytes([
                s[off],
                s[off + 1],
                s[off + 2],
                s[off + 3],
                s[off + 4],
                s[off + 5],
                s[off + 6],
                s[off + 7],
            ]);
        }
        dst[off..off + 8].copy_from_slice(&acc.to_ne_bytes());
        off += 8;
    }
}

#[inline]
fn xor_15_pages(dst: &mut [u8], srcs: &[&[u8]; BOOT_DATA_PAGES]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        // SAFETY: AVX2 verified statically via #[cfg].
        unsafe { xor_15_pages_avx2(dst, srcs) };
        return;
    }
    #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2"), feature = "std"))]
    if std::arch::is_x86_feature_detected!("avx2") {
        // SAFETY: runtime detection confirmed AVX2.
        unsafe { xor_15_pages_avx2(dst, srcs) };
        return;
    }
    #[allow(unreachable_code)]
    xor_15_pages_scalar64(dst, srcs);
}

fn xor_reconstruct_page(ecc_zone: &mut [u8], target_page: usize) {
    let (before, rest) = ecc_zone.split_at_mut(target_page * PAGE_SIZE);
    let (target, after) = rest.split_at_mut(PAGE_SIZE);
    let mut srcs: [&[u8]; BOOT_DATA_PAGES] = [&[]; BOOT_DATA_PAGES];
    for (dst_slot, src) in srcs
        .iter_mut()
        .zip(before.chunks_exact(PAGE_SIZE).chain(after.chunks_exact(PAGE_SIZE)))
    {
        *dst_slot = src;
    }
    xor_15_pages(target, &srcs);
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
    let mut srcs: [&[u8]; BOOT_DATA_PAGES] = [&[]; BOOT_DATA_PAGES];
    for (dst_slot, src) in srcs.iter_mut().zip(data_pages.chunks_exact(PAGE_SIZE)) {
        *dst_slot = src;
    }
    xor_15_pages(parity_page, &srcs);

    desc.page_crc32c[15] = crc32c(parity_page);
    let prefix = desc.to_bytes();
    desc.desc_crc32c = crc32c(&prefix[..76]);
    desc.write_bytes(
        &mut ecc_zone[BOOT_ECC_DESC_OFF..BOOT_ECC_DESC_OFF + BootEccDescriptor::SIZE],
    )?;
    Ok(())
}

/// Verifies whether a 64 KiB Boot Block passes all Boot ECC checks cleanly without mutating or
/// allocating (`true` = zero corruption detected; `false` = missing, corrupt, or needs repair).
pub fn boot_ecc_verify_clean(boot_block: &[u8]) -> bool {
    if boot_block.len() < DEFAULT_BOOT_SIZE {
        return false;
    }
    let ecc_zone = &boot_block[..DEFAULT_BOOT_SIZE];
    let desc_slice = &ecc_zone[BOOT_ECC_DESC_OFF..BOOT_ECC_DESC_OFF + BootEccDescriptor::SIZE];
    let Ok(desc) = BootEccDescriptor::from_bytes(desc_slice) else {
        return false;
    };
    if desc.ecc_magic != MAGIC_BOOT_ECC
        || desc.protected_pages != BOOT_DATA_PAGES as u16
        || desc.ecc_scheme != 1
        || desc.reserved != 0
        || crc32c(&desc_slice[..76]) != desc.desc_crc32c
    {
        return false;
    }
    for p in 0..BOOT_DATA_PAGES {
        if boot_page_crc32c(ecc_zone, p) != Ok(desc.page_crc32c[p]) {
            return false;
        }
    }
    crc32c(&ecc_zone[BOOT_PARITY_OFFSET..DEFAULT_BOOT_SIZE]) == desc.page_crc32c[15]
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
    all(target_arch = "x86_64", any(target_feature = "avx2", target_feature = "avx512bw", target_feature = "ssse3", feature = "std")),
    all(target_arch = "x86", any(target_feature = "ssse3", feature = "std")),
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128"),
    test
))]
#[inline]
fn build_gf256_nibble_tables(gf_coeff: u8) -> ([u8; 16], [u8; 16]) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
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

#[cfg(any(
    all(target_arch = "x86_64", any(all(target_feature = "avx512f", target_feature = "gfni"), all(target_feature = "avx2", target_feature = "gfni"), feature = "std")),
    test
))]
#[inline]
fn build_gf256_affine_matrix(gf_coeff: u8) -> u64 {
    let mut cols = [0u8; 8];
    let mut basis = gf_coeff;
    for col in &mut cols {
        *col = basis;
        let hi = (basis & 0x80) != 0;
        basis <<= 1;
        if hi {
            basis ^= 0x1D;
        }
    }
    let mut mat = [0u8; 8];
    for b in 0..8 {
        let mut row = 0u8;
        for (k, &col) in cols.iter().enumerate() {
            if ((col >> b) & 1) != 0 {
                row |= 1u8 << (7 - k);
            }
        }
        mat[7 - b] = row;
    }
    u64::from_le_bytes(mat)
}

#[cfg(all(
    target_arch = "x86_64",
    any(all(target_feature = "avx512f", target_feature = "gfni"), feature = "std")
))]
#[target_feature(enable = "avx512f,gfni")]
unsafe fn rs_gf256_madd_avx512_gfni<const N: usize>(
    dsts: &mut [&mut [u8]],
    src: &[u8],
    coeffs: &[u8],
) {
    use core::arch::x86_64::{
        __m512i, _mm512_gf2p8affine_epi64_epi8, _mm512_loadu_si512, _mm512_set1_epi64,
        _mm512_storeu_si512, _mm512_xor_si512,
    };
    let len = src.len();
    let mut mats = [const { unsafe { core::mem::zeroed::<__m512i>() } }; N];
    let mut rem_tbls = [([0u8; 16], [0u8; 16]); N];
    for k in 0..N {
        let m64 = build_gf256_affine_matrix(coeffs[k]) as i64;
        mats[k] = _mm512_set1_epi64(m64);
        rem_tbls[k] = build_gf256_nibble_tables(coeffs[k]);
    }

    let mut off = 0usize;
    if N == 1 {
        let c = coeffs[0];
        let d = &mut dsts[0];
        if c == 1 {
            while off + 128 <= len {
                // SAFETY: `off + 128 <= len <= d.len() == src.len()`.
                unsafe {
                    let dp0 = d.as_mut_ptr().add(off) as *mut __m512i;
                    let dp1 = d.as_mut_ptr().add(off + 64) as *mut __m512i;
                    let sv0 = _mm512_loadu_si512(src.as_ptr().add(off) as *const __m512i);
                    let sv1 = _mm512_loadu_si512(src.as_ptr().add(off + 64) as *const __m512i);
                    _mm512_storeu_si512(dp0, _mm512_xor_si512(_mm512_loadu_si512(dp0), sv0));
                    _mm512_storeu_si512(dp1, _mm512_xor_si512(_mm512_loadu_si512(dp1), sv1));
                }
                off += 128;
            }
            while off + 64 <= len {
                // SAFETY: `off + 64 <= len`.
                unsafe {
                    let dp = d.as_mut_ptr().add(off) as *mut __m512i;
                    let sv = _mm512_loadu_si512(src.as_ptr().add(off) as *const __m512i);
                    _mm512_storeu_si512(dp, _mm512_xor_si512(_mm512_loadu_si512(dp), sv));
                }
                off += 64;
            }
        } else {
            let mat = mats[0];
            while off + 128 <= len {
                // SAFETY: `off + 128 <= len`.
                unsafe {
                    let dp0 = d.as_mut_ptr().add(off) as *mut __m512i;
                    let dp1 = d.as_mut_ptr().add(off + 64) as *mut __m512i;
                    let sv0 = _mm512_loadu_si512(src.as_ptr().add(off) as *const __m512i);
                    let sv1 = _mm512_loadu_si512(src.as_ptr().add(off + 64) as *const __m512i);
                    let p0 = _mm512_gf2p8affine_epi64_epi8::<0>(sv0, mat);
                    let p1 = _mm512_gf2p8affine_epi64_epi8::<0>(sv1, mat);
                    _mm512_storeu_si512(dp0, _mm512_xor_si512(_mm512_loadu_si512(dp0), p0));
                    _mm512_storeu_si512(dp1, _mm512_xor_si512(_mm512_loadu_si512(dp1), p1));
                }
                off += 128;
            }
            while off + 64 <= len {
                // SAFETY: `off + 64 <= len`.
                unsafe {
                    let dp = d.as_mut_ptr().add(off) as *mut __m512i;
                    let sv = _mm512_loadu_si512(src.as_ptr().add(off) as *const __m512i);
                    let prod = _mm512_gf2p8affine_epi64_epi8::<0>(sv, mat);
                    _mm512_storeu_si512(dp, _mm512_xor_si512(_mm512_loadu_si512(dp), prod));
                }
                off += 64;
            }
        }
    } else {
        while off + 64 <= len {
            // SAFETY: `off + 64 <= len <= src.len()` and all `dsts[k].len() >= len`.
            unsafe {
                let sv = _mm512_loadu_si512(src.as_ptr().add(off) as *const __m512i);
                for k in 0..N {
                    let dp = dsts[k].as_mut_ptr().add(off) as *mut __m512i;
                    let prod = _mm512_gf2p8affine_epi64_epi8::<0>(sv, mats[k]);
                    _mm512_storeu_si512(dp, _mm512_xor_si512(_mm512_loadu_si512(dp), prod));
                }
            }
            off += 64;
        }
    }

    for (k, d) in dsts.iter_mut().take(N).enumerate() {
        let (ref t_lo, ref t_hi) = rem_tbls[k];
        for i in off..len {
            let s = src[i];
            d[i] ^= t_lo[(s & 0x0F) as usize] ^ t_hi[(s >> 4) as usize];
        }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    not(all(target_feature = "avx512f", target_feature = "gfni")),
    any(all(target_feature = "avx2", target_feature = "gfni"), feature = "std")
))]
#[target_feature(enable = "avx2,gfni")]
unsafe fn rs_gf256_madd_avx2_gfni<const N: usize>(
    dsts: &mut [&mut [u8]],
    src: &[u8],
    coeffs: &[u8],
) {
    use core::arch::x86_64::{
        __m256i, _mm256_gf2p8affine_epi64_epi8, _mm256_loadu_si256, _mm256_set1_epi64x,
        _mm256_storeu_si256, _mm256_xor_si256,
    };
    let len = src.len();
    let mut mats = [const { unsafe { core::mem::zeroed::<__m256i>() } }; N];
    let mut rem_tbls = [([0u8; 16], [0u8; 16]); N];
    for k in 0..N {
        mats[k] = _mm256_set1_epi64x(build_gf256_affine_matrix(coeffs[k]) as i64);
        rem_tbls[k] = build_gf256_nibble_tables(coeffs[k]);
    }

    let mut off = 0usize;
    if N == 1 {
        let d = &mut dsts[0];
        let mat = mats[0];
        while off + 64 <= len {
            // SAFETY: `off + 64 <= len`.
            unsafe {
                let dp0 = d.as_mut_ptr().add(off) as *mut __m256i;
                let dp1 = d.as_mut_ptr().add(off + 32) as *mut __m256i;
                let sv0 = _mm256_loadu_si256(src.as_ptr().add(off) as *const __m256i);
                let sv1 = _mm256_loadu_si256(src.as_ptr().add(off + 32) as *const __m256i);
                let p0 = _mm256_gf2p8affine_epi64_epi8::<0>(sv0, mat);
                let p1 = _mm256_gf2p8affine_epi64_epi8::<0>(sv1, mat);
                _mm256_storeu_si256(dp0, _mm256_xor_si256(_mm256_loadu_si256(dp0), p0));
                _mm256_storeu_si256(dp1, _mm256_xor_si256(_mm256_loadu_si256(dp1), p1));
            }
            off += 64;
        }
        while off + 32 <= len {
            // SAFETY: `off + 32 <= len`.
            unsafe {
                let dp = d.as_mut_ptr().add(off) as *mut __m256i;
                let sv = _mm256_loadu_si256(src.as_ptr().add(off) as *const __m256i);
                let prod = _mm256_gf2p8affine_epi64_epi8::<0>(sv, mat);
                _mm256_storeu_si256(dp, _mm256_xor_si256(_mm256_loadu_si256(dp), prod));
            }
            off += 32;
        }
    } else {
        while off + 32 <= len {
            // SAFETY: `off + 32 <= len`.
            unsafe {
                let sv = _mm256_loadu_si256(src.as_ptr().add(off) as *const __m256i);
                for k in 0..N {
                    let dp = dsts[k].as_mut_ptr().add(off) as *mut __m256i;
                    let prod = _mm256_gf2p8affine_epi64_epi8::<0>(sv, mats[k]);
                    _mm256_storeu_si256(dp, _mm256_xor_si256(_mm256_loadu_si256(dp), prod));
                }
            }
            off += 32;
        }
    }

    for (k, d) in dsts.iter_mut().take(N).enumerate() {
        let (ref t_lo, ref t_hi) = rem_tbls[k];
        for i in off..len {
            let s = src[i];
            d[i] ^= t_lo[(s & 0x0F) as usize] ^ t_hi[(s >> 4) as usize];
        }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    not(all(target_feature = "avx512f", target_feature = "gfni")),
    not(all(target_feature = "avx2", target_feature = "gfni")),
    any(target_feature = "avx512bw", feature = "std")
))]
#[target_feature(enable = "avx512bw")]
unsafe fn rs_gf256_madd_avx512bw<const N: usize>(
    dsts: &mut [&mut [u8]],
    src: &[u8],
    coeffs: &[u8],
) {
    use core::arch::x86_64::{
        __m128i, __m512i, _mm_loadu_si128, _mm512_and_si512, _mm512_broadcast_i32x4,
        _mm512_loadu_si512, _mm512_set1_epi8, _mm512_shuffle_epi8, _mm512_srli_epi16,
        _mm512_storeu_si512, _mm512_xor_si512,
    };
    let len = src.len();
    let mask_0f = _mm512_set1_epi8(0x0F);
    let mut v_lo = [const { unsafe { core::mem::zeroed::<__m512i>() } }; N];
    let mut v_hi = [const { unsafe { core::mem::zeroed::<__m512i>() } }; N];
    let mut rem_tbls = [([0u8; 16], [0u8; 16]); N];
    for k in 0..N {
        let (lo, hi) = build_gf256_nibble_tables(coeffs[k]);
        rem_tbls[k] = (lo, hi);
        // SAFETY: 16-byte stack arrays.
        unsafe {
            v_lo[k] = _mm512_broadcast_i32x4(_mm_loadu_si128(lo.as_ptr() as *const __m128i));
            v_hi[k] = _mm512_broadcast_i32x4(_mm_loadu_si128(hi.as_ptr() as *const __m128i));
        }
    }

    let mut off = 0usize;
    if N == 1 && coeffs[0] == 1 {
        let d = &mut dsts[0];
        while off + 64 <= len {
            // SAFETY: `off + 64 <= len`.
            unsafe {
                let dp = d.as_mut_ptr().add(off) as *mut __m512i;
                let sv = _mm512_loadu_si512(src.as_ptr().add(off) as *const __m512i);
                _mm512_storeu_si512(dp, _mm512_xor_si512(_mm512_loadu_si512(dp), sv));
            }
            off += 64;
        }
    } else {
        while off + 64 <= len {
            // SAFETY: `off + 64 <= len`.
            unsafe {
                let sv = _mm512_loadu_si512(src.as_ptr().add(off) as *const __m512i);
                let lo = _mm512_and_si512(sv, mask_0f);
                let hi = _mm512_and_si512(_mm512_srli_epi16::<4>(sv), mask_0f);
                for k in 0..N {
                    let dp = dsts[k].as_mut_ptr().add(off) as *mut __m512i;
                    let prod = _mm512_xor_si512(
                        _mm512_shuffle_epi8(v_lo[k], lo),
                        _mm512_shuffle_epi8(v_hi[k], hi),
                    );
                    _mm512_storeu_si512(dp, _mm512_xor_si512(_mm512_loadu_si512(dp), prod));
                }
            }
            off += 64;
        }
    }

    for (k, d) in dsts.iter_mut().take(N).enumerate() {
        let (ref t_lo, ref t_hi) = rem_tbls[k];
        for i in off..len {
            let s = src[i];
            d[i] ^= t_lo[(s & 0x0F) as usize] ^ t_hi[(s >> 4) as usize];
        }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    not(all(target_feature = "avx512f", target_feature = "gfni")),
    not(all(target_feature = "avx2", target_feature = "gfni")),
    not(target_feature = "avx512bw"),
    any(target_feature = "avx2", feature = "std")
))]
#[target_feature(enable = "avx2")]
unsafe fn rs_gf256_madd_avx2<const N: usize>(
    dsts: &mut [&mut [u8]],
    src: &[u8],
    coeffs: &[u8],
) {
    use core::arch::x86_64::{
        __m128i, __m256i, _mm_loadu_si128, _mm256_and_si256, _mm256_broadcastsi128_si256,
        _mm256_loadu_si256, _mm256_set1_epi8, _mm256_shuffle_epi8, _mm256_srli_epi16,
        _mm256_storeu_si256, _mm256_xor_si256,
    };
    let len = src.len();
    let mask_0f = _mm256_set1_epi8(0x0F);
    let mut v_lo = [const { unsafe { core::mem::zeroed::<__m256i>() } }; N];
    let mut v_hi = [const { unsafe { core::mem::zeroed::<__m256i>() } }; N];
    let mut rem_tbls = [([0u8; 16], [0u8; 16]); N];
    for k in 0..N {
        let (lo, hi) = build_gf256_nibble_tables(coeffs[k]);
        rem_tbls[k] = (lo, hi);
        // SAFETY: 16-byte stack arrays.
        unsafe {
            v_lo[k] = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo.as_ptr() as *const __m128i));
            v_hi[k] = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi.as_ptr() as *const __m128i));
        }
    }

    let mut off = 0usize;
    if N == 1 && coeffs[0] == 1 {
        let d = &mut dsts[0];
        while off + 64 <= len {
            // SAFETY: `off + 64 <= len`.
            unsafe {
                let dp0 = d.as_mut_ptr().add(off) as *mut __m256i;
                let dp1 = d.as_mut_ptr().add(off + 32) as *mut __m256i;
                let sv0 = _mm256_loadu_si256(src.as_ptr().add(off) as *const __m256i);
                let sv1 = _mm256_loadu_si256(src.as_ptr().add(off + 32) as *const __m256i);
                _mm256_storeu_si256(dp0, _mm256_xor_si256(_mm256_loadu_si256(dp0), sv0));
                _mm256_storeu_si256(dp1, _mm256_xor_si256(_mm256_loadu_si256(dp1), sv1));
            }
            off += 64;
        }
        while off + 32 <= len {
            // SAFETY: `off + 32 <= len`.
            unsafe {
                let dp = d.as_mut_ptr().add(off) as *mut __m256i;
                let sv = _mm256_loadu_si256(src.as_ptr().add(off) as *const __m256i);
                _mm256_storeu_si256(dp, _mm256_xor_si256(_mm256_loadu_si256(dp), sv));
            }
            off += 32;
        }
    } else if N == 1 {
        let d = &mut dsts[0];
        let vlo = v_lo[0];
        let vhi = v_hi[0];
        while off + 64 <= len {
            // SAFETY: `off + 64 <= len`.
            unsafe {
                let sv0 = _mm256_loadu_si256(src.as_ptr().add(off) as *const __m256i);
                let sv1 = _mm256_loadu_si256(src.as_ptr().add(off + 32) as *const __m256i);
                let lo0 = _mm256_and_si256(sv0, mask_0f);
                let hi0 = _mm256_and_si256(_mm256_srli_epi16::<4>(sv0), mask_0f);
                let lo1 = _mm256_and_si256(sv1, mask_0f);
                let hi1 = _mm256_and_si256(_mm256_srli_epi16::<4>(sv1), mask_0f);
                let p0 = _mm256_xor_si256(_mm256_shuffle_epi8(vlo, lo0), _mm256_shuffle_epi8(vhi, hi0));
                let p1 = _mm256_xor_si256(_mm256_shuffle_epi8(vlo, lo1), _mm256_shuffle_epi8(vhi, hi1));
                let dp0 = d.as_mut_ptr().add(off) as *mut __m256i;
                let dp1 = d.as_mut_ptr().add(off + 32) as *mut __m256i;
                _mm256_storeu_si256(dp0, _mm256_xor_si256(_mm256_loadu_si256(dp0), p0));
                _mm256_storeu_si256(dp1, _mm256_xor_si256(_mm256_loadu_si256(dp1), p1));
            }
            off += 64;
        }
        while off + 32 <= len {
            // SAFETY: `off + 32 <= len`.
            unsafe {
                let sv = _mm256_loadu_si256(src.as_ptr().add(off) as *const __m256i);
                let lo = _mm256_and_si256(sv, mask_0f);
                let hi = _mm256_and_si256(_mm256_srli_epi16::<4>(sv), mask_0f);
                let prod = _mm256_xor_si256(_mm256_shuffle_epi8(vlo, lo), _mm256_shuffle_epi8(vhi, hi));
                let dp = d.as_mut_ptr().add(off) as *mut __m256i;
                _mm256_storeu_si256(dp, _mm256_xor_si256(_mm256_loadu_si256(dp), prod));
            }
            off += 32;
        }
    } else {
        while off + 32 <= len {
            // SAFETY: `off + 32 <= len`.
            unsafe {
                let sv = _mm256_loadu_si256(src.as_ptr().add(off) as *const __m256i);
                let lo = _mm256_and_si256(sv, mask_0f);
                let hi = _mm256_and_si256(_mm256_srli_epi16::<4>(sv), mask_0f);
                for k in 0..N {
                    let dp = dsts[k].as_mut_ptr().add(off) as *mut __m256i;
                    let prod = _mm256_xor_si256(
                        _mm256_shuffle_epi8(v_lo[k], lo),
                        _mm256_shuffle_epi8(v_hi[k], hi),
                    );
                    _mm256_storeu_si256(dp, _mm256_xor_si256(_mm256_loadu_si256(dp), prod));
                }
            }
            off += 32;
        }
    }

    for (k, d) in dsts.iter_mut().take(N).enumerate() {
        let (ref t_lo, ref t_hi) = rem_tbls[k];
        for i in off..len {
            let s = src[i];
            d[i] ^= t_lo[(s & 0x0F) as usize] ^ t_hi[(s >> 4) as usize];
        }
    }
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    not(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "gfni")),
    not(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "gfni")),
    not(all(target_arch = "x86_64", target_feature = "avx512bw")),
    not(all(target_arch = "x86_64", target_feature = "avx2")),
    any(target_feature = "ssse3", feature = "std")
))]
#[target_feature(enable = "ssse3")]
unsafe fn rs_gf256_madd_ssse3<const N: usize>(
    dsts: &mut [&mut [u8]],
    src: &[u8],
    coeffs: &[u8],
) {
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

    let len = src.len();
    let mask_0f = _mm_set1_epi8(0x0F);
    let mut v_lo = [const { unsafe { core::mem::zeroed::<__m128i>() } }; N];
    let mut v_hi = [const { unsafe { core::mem::zeroed::<__m128i>() } }; N];
    let mut rem_tbls = [([0u8; 16], [0u8; 16]); N];
    for k in 0..N {
        let (lo, hi) = build_gf256_nibble_tables(coeffs[k]);
        rem_tbls[k] = (lo, hi);
        // SAFETY: 16-byte stack arrays.
        unsafe {
            v_lo[k] = _mm_loadu_si128(lo.as_ptr() as *const __m128i);
            v_hi[k] = _mm_loadu_si128(hi.as_ptr() as *const __m128i);
        }
    }

    let mut off = 0usize;
    while off + 16 <= len {
        // SAFETY: `off + 16 <= len`.
        unsafe {
            let sv = _mm_loadu_si128(src.as_ptr().add(off) as *const __m128i);
            let lo = _mm_and_si128(sv, mask_0f);
            let hi = _mm_and_si128(_mm_srli_epi16::<4>(sv), mask_0f);
            for k in 0..N {
                let dp = dsts[k].as_mut_ptr().add(off) as *mut __m128i;
                let prod = _mm_xor_si128(
                    _mm_shuffle_epi8(v_lo[k], lo),
                    _mm_shuffle_epi8(v_hi[k], hi),
                );
                _mm_storeu_si128(dp, _mm_xor_si128(_mm_loadu_si128(dp), prod));
            }
        }
        off += 16;
    }

    for (k, d) in dsts.iter_mut().take(N).enumerate() {
        let (ref t_lo, ref t_hi) = rem_tbls[k];
        for i in off..len {
            let s = src[i];
            d[i] ^= t_lo[(s & 0x0F) as usize] ^ t_hi[(s >> 4) as usize];
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn rs_gf256_madd_neon<const N: usize>(dsts: &mut [&mut [u8]], src: &[u8], coeffs: &[u8]) {
    use core::arch::aarch64::{
        uint8x16_t, vandq_u8, vdupq_n_u8, veorq_u8, vld1q_u8, vqtbl1q_u8, vshrq_n_u8, vst1q_u8,
    };
    let len = src.len();
    let mask_0f = vdupq_n_u8(0x0F);
    let mut v_lo: [uint8x16_t; N] = [vdupq_n_u8(0); N];
    let mut v_hi: [uint8x16_t; N] = [vdupq_n_u8(0); N];
    let mut rem_tbls = [([0u8; 16], [0u8; 16]); N];
    for k in 0..N {
        let (lo, hi) = build_gf256_nibble_tables(coeffs[k]);
        rem_tbls[k] = (lo, hi);
        // SAFETY: 16-byte stack arrays.
        unsafe {
            v_lo[k] = vld1q_u8(rem_tbls[k].0.as_ptr());
            v_hi[k] = vld1q_u8(rem_tbls[k].1.as_ptr());
        }
    }

    let mut off = 0usize;
    while off + 16 <= len {
        // SAFETY: `off + 16 <= len <= src.len()` and `dsts[k].len() >= len`.
        unsafe {
            let sv = vld1q_u8(src.as_ptr().add(off));
            let lo = vandq_u8(sv, mask_0f);
            let hi = vshrq_n_u8::<4>(sv);
            for k in 0..N {
                let dp = dsts[k].as_mut_ptr().add(off);
                let prod = veorq_u8(vqtbl1q_u8(v_lo[k], lo), vqtbl1q_u8(v_hi[k], hi));
                vst1q_u8(dp, veorq_u8(vld1q_u8(dp), prod));
            }
        }
        off += 16;
    }

    for (k, d) in dsts.iter_mut().take(N).enumerate() {
        let (ref t_lo, ref t_hi) = rem_tbls[k];
        for i in off..len {
            let s = src[i];
            d[i] ^= t_lo[(s & 0x0F) as usize] ^ t_hi[(s >> 4) as usize];
        }
    }
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
fn rs_gf256_madd_wasm_simd128<const N: usize>(dsts: &mut [&mut [u8]], src: &[u8], coeffs: &[u8]) {
    use core::arch::wasm32::{
        u8x16_splat, u8x16_swizzle, u16x8_shr, v128, v128_and, v128_load, v128_store, v128_xor,
    };
    let len = src.len();
    let mask_0f = u8x16_splat(0x0F);
    let mut v_lo = [u8x16_splat(0); N];
    let mut v_hi = [u8x16_splat(0); N];
    let mut rem_tbls = [([0u8; 16], [0u8; 16]); N];
    for k in 0..N {
        let (lo, hi) = build_gf256_nibble_tables(coeffs[k]);
        rem_tbls[k] = (lo, hi);
        // SAFETY: 16-byte stack arrays.
        unsafe {
            v_lo[k] = v128_load(rem_tbls[k].0.as_ptr() as *const v128);
            v_hi[k] = v128_load(rem_tbls[k].1.as_ptr() as *const v128);
        }
    }

    let mut off = 0usize;
    while off + 16 <= len {
        // SAFETY: `off + 16 <= len`.
        unsafe {
            let sv = v128_load(src.as_ptr().add(off) as *const v128);
            let lo = v128_and(sv, mask_0f);
            let hi = v128_and(u16x8_shr(sv, 4), mask_0f);
            for k in 0..N {
                let dp = dsts[k].as_mut_ptr().add(off) as *mut v128;
                let prod = v128_xor(u8x16_swizzle(v_lo[k], lo), u8x16_swizzle(v_hi[k], hi));
                v128_store(dp, v128_xor(v128_load(dp), prod));
            }
        }
        off += 16;
    }

    for (k, d) in dsts.iter_mut().take(N).enumerate() {
        let (ref t_lo, ref t_hi) = rem_tbls[k];
        for i in off..len {
            let s = src[i];
            d[i] ^= t_lo[(s & 0x0F) as usize] ^ t_hi[(s >> 4) as usize];
        }
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

fn rs_gf256_madd_group<const N: usize>(dsts: &mut [&mut [u8]], src: &[u8], coeffs: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(all(target_feature = "avx512f", target_feature = "gfni"))]
        {
            // SAFETY: AVX-512F + GFNI verified statically via #[cfg].
            unsafe { rs_gf256_madd_avx512_gfni::<N>(dsts, src, coeffs) };
            return;
        }

        #[cfg(all(
            not(all(target_feature = "avx512f", target_feature = "gfni")),
            target_feature = "avx2",
            target_feature = "gfni"
        ))]
        {
            #[cfg(feature = "std")]
            if std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("gfni")
            {
                unsafe { rs_gf256_madd_avx512_gfni::<N>(dsts, src, coeffs) };
                return;
            }
            // SAFETY: AVX2 + GFNI verified statically via #[cfg].
            unsafe { rs_gf256_madd_avx2_gfni::<N>(dsts, src, coeffs) };
            return;
        }

        #[cfg(all(
            not(all(target_feature = "avx512f", target_feature = "gfni")),
            not(all(target_feature = "avx2", target_feature = "gfni")),
            target_feature = "avx512bw"
        ))]
        {
            #[cfg(feature = "std")]
            if std::arch::is_x86_feature_detected!("gfni") {
                if std::arch::is_x86_feature_detected!("avx512f") {
                    unsafe { rs_gf256_madd_avx512_gfni::<N>(dsts, src, coeffs) };
                    return;
                }
                if std::arch::is_x86_feature_detected!("avx2") {
                    unsafe { rs_gf256_madd_avx2_gfni::<N>(dsts, src, coeffs) };
                    return;
                }
            }
            // SAFETY: AVX-512BW verified statically via #[cfg].
            unsafe { rs_gf256_madd_avx512bw::<N>(dsts, src, coeffs) };
            return;
        }

        #[cfg(all(
            not(all(target_feature = "avx512f", target_feature = "gfni")),
            not(all(target_feature = "avx2", target_feature = "gfni")),
            not(target_feature = "avx512bw"),
            target_feature = "avx2"
        ))]
        {
            #[cfg(feature = "std")]
            if std::arch::is_x86_feature_detected!("gfni") {
                if std::arch::is_x86_feature_detected!("avx512f") {
                    unsafe { rs_gf256_madd_avx512_gfni::<N>(dsts, src, coeffs) };
                    return;
                }
                unsafe { rs_gf256_madd_avx2_gfni::<N>(dsts, src, coeffs) };
                return;
            }
            #[cfg(feature = "std")]
            if std::arch::is_x86_feature_detected!("avx512bw") {
                unsafe { rs_gf256_madd_avx512bw::<N>(dsts, src, coeffs) };
                return;
            }
            // SAFETY: AVX2 verified statically via #[cfg].
            unsafe { rs_gf256_madd_avx2::<N>(dsts, src, coeffs) };
            return;
        }

        #[cfg(all(
            not(all(target_feature = "avx512f", target_feature = "gfni")),
            not(all(target_feature = "avx2", target_feature = "gfni")),
            not(target_feature = "avx512bw"),
            not(target_feature = "avx2"),
            feature = "std"
        ))]
        {
            if std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("gfni")
            {
                unsafe { rs_gf256_madd_avx512_gfni::<N>(dsts, src, coeffs) };
                return;
            }
            if std::arch::is_x86_feature_detected!("avx2")
                && std::arch::is_x86_feature_detected!("gfni")
            {
                unsafe { rs_gf256_madd_avx2_gfni::<N>(dsts, src, coeffs) };
                return;
            }
            if std::arch::is_x86_feature_detected!("avx512bw") {
                unsafe { rs_gf256_madd_avx512bw::<N>(dsts, src, coeffs) };
                return;
            }
            if std::arch::is_x86_feature_detected!("avx2") {
                unsafe { rs_gf256_madd_avx2::<N>(dsts, src, coeffs) };
                return;
            }
            if std::arch::is_x86_feature_detected!("ssse3") {
                unsafe { rs_gf256_madd_ssse3::<N>(dsts, src, coeffs) };
                return;
            }
        }

        #[cfg(all(
            not(all(target_feature = "avx512f", target_feature = "gfni")),
            not(all(target_feature = "avx2", target_feature = "gfni")),
            not(target_feature = "avx512bw"),
            not(target_feature = "avx2"),
            target_feature = "ssse3",
            not(feature = "std")
        ))]
        {
            unsafe { rs_gf256_madd_ssse3::<N>(dsts, src, coeffs) };
            return;
        }
    }

    #[cfg(target_arch = "x86")]
    {
        #[cfg(target_feature = "ssse3")]
        {
            unsafe { rs_gf256_madd_ssse3::<N>(dsts, src, coeffs) };
            return;
        }
        #[cfg(all(not(target_feature = "ssse3"), feature = "std"))]
        if std::arch::is_x86_feature_detected!("ssse3") {
            unsafe { rs_gf256_madd_ssse3::<N>(dsts, src, coeffs) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        #[cfg(target_feature = "neon")]
        {
            // SAFETY: NEON target feature is enabled at compile time.
            unsafe { rs_gf256_madd_neon::<N>(dsts, src, coeffs) };
            return;
        }
        #[cfg(all(not(target_feature = "neon"), feature = "std"))]
        if std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY: Runtime check confirmed NEON support.
            unsafe { rs_gf256_madd_neon::<N>(dsts, src, coeffs) };
            return;
        }
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        rs_gf256_madd_wasm_simd128::<N>(dsts, src, coeffs);
        return;
    }

    #[allow(unreachable_code)]
    {
        for k in 0..N {
            rs_gf256_madd_scalar(dsts[k], src, coeffs[k]);
        }
    }
}

/// Accumulates `src_cluster * gf_coeff` into `parity_dst[..src_cluster.len()]` over `GF(2^8)`.
///
/// Automatically selects the fastest compiled or runtime-detected ISA backend:
/// `GFNI` (`AVX-512` / `AVX2`), `AVX-512BW`, 2x unrolled `AVX2`, `SSSE3`, `aarch64` `NEON`,
/// `wasm32` `simd128`, or portable `#![no_std]` lookup table fallback.
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
    let dst_len = src_cluster.len();
    let mut dsts: [&mut [u8]; 1] = [&mut parity_dst[..dst_len]];
    let coeffs = [gf_coeff];
    rs_gf256_madd_group::<1>(&mut dsts, src_cluster, &coeffs);
    Ok(())
}

/// Fused multi-output `GF(2^8)` multiply-add: reads `src` once to update up to `dsts.len()`
/// parity slices with distinct `coeffs` (dispatched in fused 4-way and 2-way SIMD groups).
pub fn rs_gf256_madd_multi(
    dsts: &mut [&mut [u8]],
    src: &[u8],
    coeffs: &[u8],
) -> Result<(), VzError> {
    if dsts.len() != coeffs.len() {
        return Err(VzError::InvalidInput);
    }
    for d in dsts.iter() {
        if d.len() < src.len() {
            return Err(VzError::BufferTooSmall);
        }
    }
    if src.is_empty() || dsts.is_empty() {
        return Ok(());
    }
    if coeffs.contains(&0) {
        for (d, &c) in dsts.iter_mut().zip(coeffs.iter()) {
            rs_gf256_madd_slice(d, src, c)?;
        }
        return Ok(());
    }
    let mut idx = 0usize;
    while idx + 4 <= dsts.len() {
        let end = idx + 4;
        rs_gf256_madd_group::<4>(&mut dsts[idx..end], src, &coeffs[idx..end]);
        idx = end;
    }
    if idx + 2 <= dsts.len() {
        let end = idx + 2;
        rs_gf256_madd_group::<2>(&mut dsts[idx..end], src, &coeffs[idx..end]);
        idx = end;
    }
    if idx < dsts.len() {
        rs_gf256_madd_group::<1>(&mut dsts[idx..idx + 1], src, &coeffs[idx..idx + 1]);
    }
    Ok(())
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::wire::{BOOT_DATA_PAGES, BOOT_PAGES, DEFAULT_BOOT_SIZE, PAGE_SIZE};

    fn gf256_reference_madd(dst: &mut [u8], src: &[u8], coeff: u8) {
        if coeff == 0 {
            return;
        }
        for (d, &s) in dst.iter_mut().zip(src.iter()) {
            *d ^= gf256_mul(s, coeff);
        }
    }

    #[test]
    fn test_gf256_madd_all_256x256_pairs_and_lengths() {
        let lengths = [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 129, 323, 4099];
        for &len in &lengths {
            let src: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(17).wrapping_add(i as u8))
                .collect();
            let init: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31) ^ 0xA5).collect();
            // Cover all 256 byte values on 323+ byte lengths and spot-check on shorter lengths.
            let step = if len == 323 { 1 } else { 13 };
            for coeff in (0..=255u8).step_by(step) {
                let mut got = init.clone();
                let mut expected = init.clone();
                rs_gf256_madd_slice(&mut got, &src, coeff).expect("madd_slice");
                gf256_reference_madd(&mut expected, &src, coeff);
                assert_eq!(got, expected, "mismatch at len={len}, coeff={coeff}");
            }
        }
        // Explicitly test every (byte, coeff) in 0..=255 x 0..=255 over a 256-byte vector 0..=255.
        let all_bytes: Vec<u8> = (0..=255u8).collect();
        let init: Vec<u8> = (0..=255u8).map(|x| x ^ 0x5A).collect();
        for coeff in 0..=255u8 {
            let mut got = init.clone();
            let mut expected = init.clone();
            rs_gf256_madd_slice(&mut got, &all_bytes, coeff).expect("madd_slice 256");
            gf256_reference_madd(&mut expected, &all_bytes, coeff);
            assert_eq!(got, expected, "exhaustive 256x256 mismatch at coeff={coeff}");
        }
    }

    #[test]
    fn test_gf256_madd_multi_and_backends() {
        let lengths = [0usize, 1, 15, 16, 31, 32, 63, 64, 129, 4099];
        for &len in &lengths {
            let src: Vec<u8> = (0..len).map(|i| ((i * 73) ^ (i >> 3)) as u8).collect();
            for m in 1..=7usize {
                let mut coeffs: Vec<u8> = (0..m).map(|k| ((k * 37 + 1) & 0xFF) as u8).collect();
                if m >= 3 {
                    coeffs[1] = 0; // Also verify zero-coeff handling inside madd_multi.
                }
                let mut dsts: Vec<Vec<u8>> = (0..m)
                    .map(|k| (0..len).map(|i| (i ^ (k * 53)) as u8).collect())
                    .collect();
                let mut expected = dsts.clone();
                for (e, &c) in expected.iter_mut().zip(coeffs.iter()) {
                    gf256_reference_madd(e, &src, c);
                }
                let mut slices: Vec<&mut [u8]> = dsts.iter_mut().map(|v| v.as_mut_slice()).collect();
                rs_gf256_madd_multi(&mut slices, &src, &coeffs).expect("madd_multi");
                assert_eq!(dsts, expected, "madd_multi mismatch m={m} len={len}");
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            fn check_group<const N: usize>(
                name: &str,
                f: unsafe fn(&mut [&mut [u8]], &[u8], &[u8]),
            ) {
                let mut src: Vec<u8> = (0..=255u8).collect();
                src.extend(0..67u8); // 323 bytes = 5*64 + 3 (hits AVX-512, AVX2, SSSE3, and tail)
                for &len in &[15usize, 16, 31, 32, 63, 64, 65, 129, 323] {
                    let s = &src[..len];
                    for base in (0..=255u8).step_by(if len == 323 && N == 1 { 1 } else { 17 }) {
                        let coeffs: Vec<u8> = (0..N)
                            .map(|k| base.wrapping_add((k as u8).wrapping_mul(59)))
                            .collect();
                        let mut got: Vec<Vec<u8>> = (0..N)
                            .map(|k| (0..len).map(|i| (i as u8).wrapping_add(k as u8 * 19)).collect())
                            .collect();
                        let mut expected = got.clone();
                        for (e, &c) in expected.iter_mut().zip(coeffs.iter()) {
                            gf256_reference_madd(e, s, c);
                        }
                        let mut slices: Vec<&mut [u8]> =
                            got.iter_mut().map(|v| v.as_mut_slice()).collect();
                        // SAFETY: caller verified target features before passing `f`.
                        unsafe { f(&mut slices, s, &coeffs) };
                        assert_eq!(got, expected, "{name}<{N}> mismatch len={len} base={base}");
                    }
                }
            }

            #[cfg(all(
                not(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "gfni")),
                not(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "gfni")),
                not(all(target_arch = "x86_64", target_feature = "avx512bw")),
                not(all(target_arch = "x86_64", target_feature = "avx2")),
            ))]
            if std::arch::is_x86_feature_detected!("ssse3") {
                check_group::<1>("ssse3", rs_gf256_madd_ssse3::<1>);
                check_group::<2>("ssse3", rs_gf256_madd_ssse3::<2>);
                check_group::<4>("ssse3", rs_gf256_madd_ssse3::<4>);
            }
            #[cfg(all(
                not(all(target_feature = "avx512f", target_feature = "gfni")),
                not(all(target_feature = "avx2", target_feature = "gfni")),
                not(target_feature = "avx512bw"),
            ))]
            if std::arch::is_x86_feature_detected!("avx2") {
                check_group::<1>("avx2", rs_gf256_madd_avx2::<1>);
                check_group::<2>("avx2", rs_gf256_madd_avx2::<2>);
                check_group::<4>("avx2", rs_gf256_madd_avx2::<4>);
            }
            #[cfg(all(
                not(all(target_feature = "avx512f", target_feature = "gfni")),
                not(all(target_feature = "avx2", target_feature = "gfni")),
            ))]
            if std::arch::is_x86_feature_detected!("avx512bw") {
                check_group::<1>("avx512bw", rs_gf256_madd_avx512bw::<1>);
                check_group::<2>("avx512bw", rs_gf256_madd_avx512bw::<2>);
                check_group::<4>("avx512bw", rs_gf256_madd_avx512bw::<4>);
            }
            #[cfg(not(all(target_feature = "avx512f", target_feature = "gfni")))]
            if std::arch::is_x86_feature_detected!("avx2")
                && std::arch::is_x86_feature_detected!("gfni")
            {
                check_group::<1>("avx2_gfni", rs_gf256_madd_avx2_gfni::<1>);
                check_group::<2>("avx2_gfni", rs_gf256_madd_avx2_gfni::<2>);
                check_group::<4>("avx2_gfni", rs_gf256_madd_avx2_gfni::<4>);
            }
            if std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("gfni")
            {
                check_group::<1>("avx512_gfni", rs_gf256_madd_avx512_gfni::<1>);
                check_group::<2>("avx512_gfni", rs_gf256_madd_avx512_gfni::<2>);
                check_group::<4>("avx512_gfni", rs_gf256_madd_avx512_gfni::<4>);
            }
        }
    }

    #[test]
    fn test_boot_ecc_encode_verify_clean_and_repair_all_pages() {
        let mut clean = vec![0u8; DEFAULT_BOOT_SIZE];
        for i in 0..(BOOT_DATA_PAGES * PAGE_SIZE) {
            clean[i] = ((i * 131) ^ (i >> 5) ^ 0x3C) as u8;
        }
        boot_ecc_encode(&mut clean).expect("boot_ecc_encode");
        assert!(boot_ecc_verify_clean(&clean));

        for page in 0..BOOT_PAGES {
            let mut damaged = clean.clone();
            for off in [0usize, 17, 255, PAGE_SIZE - 1] {
                damaged[page * PAGE_SIZE + off] ^= 0xA5;
            }
            assert!(!boot_ecc_verify_clean(&damaged), "clean check passed on corrupt page {page}");
            let repaired = boot_ecc_verify_and_repair(&mut damaged).expect("repair single page");
            assert_eq!(repaired, Some(page));
            assert_eq!(damaged, clean);
            assert!(boot_ecc_verify_clean(&damaged));
        }

        // Dual page corruption must fail cleanly.
        let mut dual = clean;
        dual[13] ^= 0xFF;
        dual[7 * PAGE_SIZE + 123] ^= 0xFF;
        assert!(!boot_ecc_verify_clean(&dual));
        assert!(matches!(
            boot_ecc_verify_and_repair(&mut dual),
            Err(VzError::CorruptUnrecoverable)
        ));
    }
}
