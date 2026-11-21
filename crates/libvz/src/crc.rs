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
    #[cfg(all(
        target_arch = "aarch64",
        not(target_feature = "crc"),
        feature = "std"
    ))]
    {
        std::arch::is_aarch64_feature_detected!("crc")
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", any(target_feature = "sse4.2", feature = "std")),
        all(target_arch = "x86", any(target_feature = "sse4.2", feature = "std")),
        all(target_arch = "aarch64", any(target_feature = "crc", feature = "std")),
    )))]
    {
        false
    }
}

const CRC32C_POLY_REFLECTED: u32 = 0x82F6_3B78;

#[cfg(all(
    target_arch = "x86_64",
    any(target_feature = "pclmulqdq", target_feature = "vpclmulqdq", feature = "std")
))]
#[inline]
const fn crc32c_xn_ref(bits: usize) -> u32 {
    let mut r = 0x8000_0000u32;
    let mut i = 0usize;
    while i < bits {
        r = (r >> 1) ^ ((r & 1).wrapping_neg() & CRC32C_POLY_REFLECTED);
        i += 1;
    }
    r
}

#[cfg(all(
    target_arch = "x86_64",
    any(target_feature = "pclmulqdq", target_feature = "vpclmulqdq", feature = "std")
))]
#[inline]
const fn crc32c_fold_consts(stride_bytes: usize) -> (u64, u64) {
    let k_lo = (crc32c_xn_ref(8 * stride_bytes + 32) as u64) << 1;
    let k_hi = (crc32c_xn_ref(8 * stride_bytes - 32) as u64) << 1;
    (k_lo, k_hi)
}

#[cfg(all(target_arch = "x86_64", any(target_feature = "sse4.2", feature = "std")))]
#[target_feature(enable = "sse4.2")]
#[inline]
unsafe fn crc32c_update_x86_64_sse42(mut crc: u32, data: &[u8]) -> u32 {
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

#[cfg(all(target_arch = "x86_64", any(target_feature = "sse4.2", feature = "std")))]
#[target_feature(enable = "sse4.2")]
#[inline]
unsafe fn crc32c_reduce_xmm_sse42(x: core::arch::x86_64::__m128i) -> u32 {
    use core::arch::x86_64::{_mm_crc32_u64, _mm_extract_epi64};
    let lo = _mm_extract_epi64::<0>(x) as u64;
    let hi = _mm_extract_epi64::<1>(x) as u64;
    let c = _mm_crc32_u64(0, lo);
    _mm_crc32_u64(c, hi) as u32
}

#[cfg(all(
    target_arch = "x86_64",
    not(all(target_feature = "avx512f", target_feature = "vpclmulqdq", target_feature = "sse4.2")),
    not(all(target_feature = "avx2", target_feature = "vpclmulqdq", target_feature = "sse4.2")),
    any(all(target_feature = "sse4.2", target_feature = "pclmulqdq"), feature = "std")
))]
#[target_feature(enable = "sse4.2,pclmulqdq")]
unsafe fn crc32c_update_x86_64_pclmul(crc: u32, data: &[u8]) -> u32 {
    use core::arch::x86_64::{
        __m128i, _mm_clmulepi64_si128, _mm_cvtsi32_si128, _mm_loadu_si128, _mm_set_epi64x,
        _mm_xor_si128,
    };
    if data.len() < 64 {
        // SAFETY: SSE4.2 is enabled by target_feature.
        return unsafe { crc32c_update_x86_64_sse42(crc, data) };
    }
    let (k64_lo, k64_hi) = const { crc32c_fold_consts(64) };
    let (k16_lo, k16_hi) = const { crc32c_fold_consts(16) };
    let k64 = _mm_set_epi64x(k64_hi as i64, k64_lo as i64);
    let k16 = _mm_set_epi64x(k16_hi as i64, k16_lo as i64);

    // SAFETY: checked data.len() >= 64 and chunk lengths in loop.
    unsafe {
        let mut ptr = data.as_ptr();
        let mut rem = data.len();

        let mut x0 = _mm_loadu_si128(ptr as *const __m128i);
        x0 = _mm_xor_si128(x0, _mm_cvtsi32_si128(crc as i32));
        let mut x1 = _mm_loadu_si128(ptr.add(16) as *const __m128i);
        let mut x2 = _mm_loadu_si128(ptr.add(32) as *const __m128i);
        let mut x3 = _mm_loadu_si128(ptr.add(48) as *const __m128i);
        ptr = ptr.add(64);
        rem -= 64;

        let fold128 = |acc: __m128i, next: __m128i, k: __m128i| -> __m128i {
            let lo = _mm_clmulepi64_si128::<0x00>(acc, k);
            let hi = _mm_clmulepi64_si128::<0x11>(acc, k);
            _mm_xor_si128(next, _mm_xor_si128(lo, hi))
        };

        while rem >= 64 {
            let n0 = _mm_loadu_si128(ptr as *const __m128i);
            let n1 = _mm_loadu_si128(ptr.add(16) as *const __m128i);
            let n2 = _mm_loadu_si128(ptr.add(32) as *const __m128i);
            let n3 = _mm_loadu_si128(ptr.add(48) as *const __m128i);
            x0 = fold128(x0, n0, k64);
            x1 = fold128(x1, n1, k64);
            x2 = fold128(x2, n2, k64);
            x3 = fold128(x3, n3, k64);
            ptr = ptr.add(64);
            rem -= 64;
        }

        let mut acc = fold128(x0, x1, k16);
        acc = fold128(acc, x2, k16);
        acc = fold128(acc, x3, k16);

        while rem >= 16 {
            let next = _mm_loadu_si128(ptr as *const __m128i);
            acc = fold128(acc, next, k16);
            ptr = ptr.add(16);
            rem -= 16;
        }

        let c = crc32c_reduce_xmm_sse42(acc);
        crc32c_update_x86_64_sse42(c, core::slice::from_raw_parts(ptr, rem))
    }
}

#[cfg(all(
    target_arch = "x86_64",
    not(all(target_feature = "avx512f", target_feature = "vpclmulqdq", target_feature = "sse4.2")),
    any(all(target_feature = "avx2", target_feature = "vpclmulqdq", target_feature = "sse4.2"), feature = "std")
))]
#[target_feature(enable = "avx2,vpclmulqdq,sse4.2")]
unsafe fn crc32c_update_x86_64_vpclmul_256(crc: u32, data: &[u8]) -> u32 {
    use core::arch::x86_64::{
        __m256i, _mm256_castsi256_si128, _mm256_clmulepi64_epi128, _mm256_extracti128_si256,
        _mm256_loadu_si256, _mm256_set_epi32, _mm256_set_epi64x, _mm256_xor_si256,
        _mm_clmulepi64_si128, _mm_loadu_si128, _mm_set_epi64x, _mm_xor_si128,
    };
    if data.len() < 128 {
        // SAFETY: SSE4.2 is enabled by target_feature.
        return unsafe { crc32c_update_x86_64_sse42(crc, data) };
    }
    let (k128_lo, k128_hi) = const { crc32c_fold_consts(128) };
    let (k32_lo, k32_hi) = const { crc32c_fold_consts(32) };
    let (k16_lo, k16_hi) = const { crc32c_fold_consts(16) };
    let k128 = _mm256_set_epi64x(k128_hi as i64, k128_lo as i64, k128_hi as i64, k128_lo as i64);
    let k32 = _mm256_set_epi64x(k32_hi as i64, k32_lo as i64, k32_hi as i64, k32_lo as i64);
    let k16 = _mm_set_epi64x(k16_hi as i64, k16_lo as i64);

    // SAFETY: checked data.len() >= 128 and pointer arithmetic bounded by rem.
    unsafe {
        let mut ptr = data.as_ptr();
        let mut rem = data.len();

        let mut y0 = _mm256_loadu_si256(ptr as *const __m256i);
        y0 = _mm256_xor_si256(y0, _mm256_set_epi32(0, 0, 0, 0, 0, 0, 0, crc as i32));
        let mut y1 = _mm256_loadu_si256(ptr.add(32) as *const __m256i);
        let mut y2 = _mm256_loadu_si256(ptr.add(64) as *const __m256i);
        let mut y3 = _mm256_loadu_si256(ptr.add(96) as *const __m256i);
        ptr = ptr.add(128);
        rem -= 128;

        let fold256 = |acc: __m256i, next: __m256i, k: __m256i| -> __m256i {
            let lo = _mm256_clmulepi64_epi128::<0x00>(acc, k);
            let hi = _mm256_clmulepi64_epi128::<0x11>(acc, k);
            _mm256_xor_si256(next, _mm256_xor_si256(lo, hi))
        };

        while rem >= 128 {
            let n0 = _mm256_loadu_si256(ptr as *const __m256i);
            let n1 = _mm256_loadu_si256(ptr.add(32) as *const __m256i);
            let n2 = _mm256_loadu_si256(ptr.add(64) as *const __m256i);
            let n3 = _mm256_loadu_si256(ptr.add(96) as *const __m256i);
            y0 = fold256(y0, n0, k128);
            y1 = fold256(y1, n1, k128);
            y2 = fold256(y2, n2, k128);
            y3 = fold256(y3, n3, k128);
            ptr = ptr.add(128);
            rem -= 128;
        }

        let mut acc256 = fold256(y0, y1, k32);
        acc256 = fold256(acc256, y2, k32);
        acc256 = fold256(acc256, y3, k32);

        while rem >= 32 {
            let next = _mm256_loadu_si256(ptr as *const __m256i);
            acc256 = fold256(acc256, next, k32);
            ptr = ptr.add(32);
            rem -= 32;
        }

        let lo128 = _mm256_castsi256_si128(acc256);
        let hi128 = _mm256_extracti128_si256::<1>(acc256);
        let mut x = _mm_xor_si128(
            hi128,
            _mm_xor_si128(
                _mm_clmulepi64_si128::<0x00>(lo128, k16),
                _mm_clmulepi64_si128::<0x11>(lo128, k16),
            ),
        );

        while rem >= 16 {
            let next = _mm_loadu_si128(ptr as *const core::arch::x86_64::__m128i);
            let lo = _mm_clmulepi64_si128::<0x00>(x, k16);
            let hi = _mm_clmulepi64_si128::<0x11>(x, k16);
            x = _mm_xor_si128(next, _mm_xor_si128(lo, hi));
            ptr = ptr.add(16);
            rem -= 16;
        }

        let c = crc32c_reduce_xmm_sse42(x);
        crc32c_update_x86_64_sse42(c, core::slice::from_raw_parts(ptr, rem))
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(all(target_feature = "avx512f", target_feature = "vpclmulqdq", target_feature = "sse4.2"), feature = "std")
))]
#[target_feature(enable = "avx512f,vpclmulqdq,sse4.2")]
unsafe fn crc32c_update_x86_64_vpclmul_512(crc: u32, data: &[u8]) -> u32 {
    use core::arch::x86_64::{
        __m512i, _mm512_castsi512_si128, _mm512_clmulepi64_epi128, _mm512_extracti32x4_epi32,
        _mm512_loadu_si512, _mm512_set_epi32, _mm512_set_epi64, _mm512_xor_si512,
        _mm_clmulepi64_si128, _mm_loadu_si128, _mm_set_epi64x, _mm_xor_si128,
    };
    if data.len() < 256 {
        // SAFETY: SSE4.2 is enabled by target_feature.
        return unsafe { crc32c_update_x86_64_sse42(crc, data) };
    }
    let (k256_lo, k256_hi) = const { crc32c_fold_consts(256) };
    let (k64_lo, k64_hi) = const { crc32c_fold_consts(64) };
    let (k16_lo, k16_hi) = const { crc32c_fold_consts(16) };
    let k256 = _mm512_set_epi64(
        k256_hi as i64, k256_lo as i64, k256_hi as i64, k256_lo as i64,
        k256_hi as i64, k256_lo as i64, k256_hi as i64, k256_lo as i64,
    );
    let k64 = _mm512_set_epi64(
        k64_hi as i64, k64_lo as i64, k64_hi as i64, k64_lo as i64,
        k64_hi as i64, k64_lo as i64, k64_hi as i64, k64_lo as i64,
    );
    let k16 = _mm_set_epi64x(k16_hi as i64, k16_lo as i64);

    // SAFETY: checked data.len() >= 256 and pointer arithmetic bounded by rem.
    unsafe {
        let mut ptr = data.as_ptr();
        let mut rem = data.len();

        let mut z0 = _mm512_loadu_si512(ptr as *const __m512i);
        z0 = _mm512_xor_si512(
            z0,
            _mm512_set_epi32(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, crc as i32),
        );
        let mut z1 = _mm512_loadu_si512(ptr.add(64) as *const __m512i);
        let mut z2 = _mm512_loadu_si512(ptr.add(128) as *const __m512i);
        let mut z3 = _mm512_loadu_si512(ptr.add(192) as *const __m512i);
        ptr = ptr.add(256);
        rem -= 256;

        let fold512 = |acc: __m512i, next: __m512i, k: __m512i| -> __m512i {
            let lo = _mm512_clmulepi64_epi128::<0x00>(acc, k);
            let hi = _mm512_clmulepi64_epi128::<0x11>(acc, k);
            _mm512_xor_si512(next, _mm512_xor_si512(lo, hi))
        };

        while rem >= 256 {
            let n0 = _mm512_loadu_si512(ptr as *const __m512i);
            let n1 = _mm512_loadu_si512(ptr.add(64) as *const __m512i);
            let n2 = _mm512_loadu_si512(ptr.add(128) as *const __m512i);
            let n3 = _mm512_loadu_si512(ptr.add(192) as *const __m512i);
            z0 = fold512(z0, n0, k256);
            z1 = fold512(z1, n1, k256);
            z2 = fold512(z2, n2, k256);
            z3 = fold512(z3, n3, k256);
            ptr = ptr.add(256);
            rem -= 256;
        }

        let mut acc512 = fold512(z0, z1, k64);
        acc512 = fold512(acc512, z2, k64);
        acc512 = fold512(acc512, z3, k64);

        while rem >= 64 {
            let next = _mm512_loadu_si512(ptr as *const __m512i);
            acc512 = fold512(acc512, next, k64);
            ptr = ptr.add(64);
            rem -= 64;
        }

        let l0 = _mm512_castsi512_si128(acc512);
        let l1 = _mm512_extracti32x4_epi32::<1>(acc512);
        let l2 = _mm512_extracti32x4_epi32::<2>(acc512);
        let l3 = _mm512_extracti32x4_epi32::<3>(acc512);
        let fold128 = |acc: core::arch::x86_64::__m128i, next: core::arch::x86_64::__m128i| {
            let lo = _mm_clmulepi64_si128::<0x00>(acc, k16);
            let hi = _mm_clmulepi64_si128::<0x11>(acc, k16);
            _mm_xor_si128(next, _mm_xor_si128(lo, hi))
        };
        let mut x = fold128(l0, l1);
        x = fold128(x, l2);
        x = fold128(x, l3);

        while rem >= 16 {
            let next = _mm_loadu_si128(ptr as *const core::arch::x86_64::__m128i);
            x = fold128(x, next);
            ptr = ptr.add(16);
            rem -= 16;
        }

        let c = crc32c_reduce_xmm_sse42(x);
        crc32c_update_x86_64_sse42(c, core::slice::from_raw_parts(ptr, rem))
    }
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

#[inline]
const fn gf2_matrix_times_const(mat: &[u32; 32], mut vec: u32) -> u32 {
    let mut sum = 0u32;
    while vec != 0 {
        let idx = vec.trailing_zeros() as usize;
        sum ^= mat[idx];
        vec &= vec - 1;
    }
    sum
}

#[inline]
const fn gf2_matrix_square_const(mat: &[u32; 32]) -> [u32; 32] {
    let mut square = [0u32; 32];
    let mut n = 0usize;
    while n < 32 {
        square[n] = gf2_matrix_times_const(mat, mat[n]);
        n += 1;
    }
    square
}

const fn build_shift_pow2_tables() -> [[u32; 32]; 64] {
    let mut tables = [[0u32; 32]; 64];
    let mut one_bit = [0u32; 32];
    one_bit[0] = CRC32C_POLY_REFLECTED;
    let mut row = 1u32;
    let mut n = 1usize;
    while n < 32 {
        one_bit[n] = row;
        row <<= 1;
        n += 1;
    }
    let two_bits = gf2_matrix_square_const(&one_bit);
    let four_bits = gf2_matrix_square_const(&two_bits);
    tables[0] = gf2_matrix_square_const(&four_bits);
    let mut b = 1usize;
    while b < 64 {
        tables[b] = gf2_matrix_square_const(&tables[b - 1]);
        b += 1;
    }
    tables
}

const CRC32C_SHIFT_POW2: [[u32; 32]; 64] = build_shift_pow2_tables();

/// Multiplies a CRC32C state `crc` by `x^(8 * len)` modulo the Castagnoli polynomial (`0x1EDC_6F41`).
///
/// Equivalent to feeding `len` zero bytes through the CRC shift register without hashing them.
pub const fn crc32c_shift_zeros(mut crc: u32, mut len: usize) -> u32 {
    if len == 0 || crc == 0 {
        return crc;
    }
    while len != 0 {
        let bit = len.trailing_zeros() as usize;
        crc = gf2_matrix_times_const(&CRC32C_SHIFT_POW2[bit], crc);
        len &= len - 1;
    }
    crc
}

/// Combines two independent Castagnoli CRC32C checksums (`crc1 = crc32c(a)`, `crc2 = crc32c(b)`)
/// into `crc32c(a || b)` in `O(log len2)` time without re-reading `a` or `b`.
#[inline]
pub const fn crc32c_combine(crc1: u32, crc2: u32, len2: usize) -> u32 {
    if len2 == 0 {
        return crc1;
    }
    crc32c_shift_zeros(crc1, len2) ^ crc2
}

#[cfg(all(target_arch = "aarch64", any(target_feature = "crc", feature = "std")))]
const fn build_shift_matrix(len: usize) -> [u32; 32] {
    let mut mat = [0u32; 32];
    let mut i = 0usize;
    while i < 32 {
        mat[i] = crc32c_shift_zeros(1u32 << i, len);
        i += 1;
    }
    mat
}

#[cfg(all(target_arch = "aarch64", any(target_feature = "crc", feature = "std")))]
#[target_feature(enable = "crc")]
unsafe fn crc32c_update_aarch64_crc(mut crc: u32, mut data: &[u8]) -> u32 {
    use core::arch::aarch64::{__crc32cb, __crc32cd};
    const MAT_1024: [u32; 32] = build_shift_matrix(1024);
    const MAT_2048: [u32; 32] = build_shift_matrix(2048);

    const LANE: usize = 1024;
    const STRIDE: usize = LANE * 3;
    while data.len() >= STRIDE {
        let (blk, rest) = data.split_at(STRIDE);
        let (b0, tail01) = blk.split_at(LANE);
        let (b1, b2) = tail01.split_at(LANE);
        let mut c0 = crc;
        let mut c1 = 0xFFFF_FFFFu32;
        let mut c2 = 0xFFFF_FFFFu32;
        let mut idx = 0usize;
        while idx < LANE {
            let v0 = u64::from_le_bytes([
                b0[idx],
                b0[idx + 1],
                b0[idx + 2],
                b0[idx + 3],
                b0[idx + 4],
                b0[idx + 5],
                b0[idx + 6],
                b0[idx + 7],
            ]);
            let v1 = u64::from_le_bytes([
                b1[idx],
                b1[idx + 1],
                b1[idx + 2],
                b1[idx + 3],
                b1[idx + 4],
                b1[idx + 5],
                b1[idx + 6],
                b1[idx + 7],
            ]);
            let v2 = u64::from_le_bytes([
                b2[idx],
                b2[idx + 1],
                b2[idx + 2],
                b2[idx + 3],
                b2[idx + 4],
                b2[idx + 5],
                b2[idx + 6],
                b2[idx + 7],
            ]);
            c0 = __crc32cd(c0, v0);
            c1 = __crc32cd(c1, v1);
            c2 = __crc32cd(c2, v2);
            idx += 8;
        }
        crc = gf2_matrix_times_const(&MAT_2048, !c0) ^ gf2_matrix_times_const(&MAT_1024, !c1) ^ c2;
        data = rest;
    }

    let mut chunks = data.chunks_exact(8);
    for chunk in chunks.by_ref() {
        let v = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        crc = __crc32cd(crc, v);
    }
    for &b in chunks.remainder() {
        crc = __crc32cb(crc, b);
    }
    crc
}

/// Streaming Castagnoli CRC32C update.
///
/// Pass `0xFFFF_FFFF` as initial `crc`, and finalize with `!crc`. Uses tiered x86_64
/// (`AVX-512 VPCLMULQDQ`, `AVX2 VPCLMULQDQ`, `SSE4.2+PCLMULQDQ`, `SSE4.2`), x86 `SSE4.2`,
/// or `aarch64` 3-way ARMv8 CRC hardware instructions when available, falling back to a portable
/// `#![no_std]` Slice-by-8 implementation otherwise.
#[inline]
pub fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(all(
            target_feature = "avx512f",
            target_feature = "vpclmulqdq",
            target_feature = "sse4.2"
        ))]
        {
            return if data.len() >= 256 {
                // SAFETY: target features verified statically via #[cfg].
                unsafe { crc32c_update_x86_64_vpclmul_512(crc, data) }
            } else {
                // SAFETY: target feature sse4.2 verified statically via #[cfg].
                unsafe { crc32c_update_x86_64_sse42(crc, data) }
            };
        }

        #[cfg(all(
            not(all(
                target_feature = "avx512f",
                target_feature = "vpclmulqdq",
                target_feature = "sse4.2"
            )),
            target_feature = "avx2",
            target_feature = "vpclmulqdq",
            target_feature = "sse4.2"
        ))]
        {
            #[cfg(feature = "std")]
            if data.len() >= 512
                && std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("vpclmulqdq")
            {
                // SAFETY: runtime CPU detection confirmed AVX-512F + VPCLMULQDQ + SSE4.2.
                return unsafe { crc32c_update_x86_64_vpclmul_512(crc, data) };
            }
            return if data.len() >= 256 {
                // SAFETY: target features verified statically via #[cfg].
                unsafe { crc32c_update_x86_64_vpclmul_256(crc, data) }
            } else {
                // SAFETY: target feature sse4.2 verified statically via #[cfg].
                unsafe { crc32c_update_x86_64_sse42(crc, data) }
            };
        }

        #[cfg(all(
            not(all(
                target_feature = "avx512f",
                target_feature = "vpclmulqdq",
                target_feature = "sse4.2"
            )),
            not(all(
                target_feature = "avx2",
                target_feature = "vpclmulqdq",
                target_feature = "sse4.2"
            )),
            target_feature = "sse4.2",
            target_feature = "pclmulqdq"
        ))]
        {
            #[cfg(feature = "std")]
            if data.len() >= 512
                && std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("vpclmulqdq")
            {
                // SAFETY: runtime CPU detection confirmed AVX-512F + VPCLMULQDQ + SSE4.2.
                return unsafe { crc32c_update_x86_64_vpclmul_512(crc, data) };
            }
            #[cfg(feature = "std")]
            if data.len() >= 256
                && std::arch::is_x86_feature_detected!("avx2")
                && std::arch::is_x86_feature_detected!("vpclmulqdq")
            {
                // SAFETY: runtime CPU detection confirmed AVX2 + VPCLMULQDQ + SSE4.2.
                return unsafe { crc32c_update_x86_64_vpclmul_256(crc, data) };
            }
            return if data.len() >= 256 {
                // SAFETY: target features verified statically via #[cfg].
                unsafe { crc32c_update_x86_64_pclmul(crc, data) }
            } else {
                // SAFETY: target feature sse4.2 verified statically via #[cfg].
                unsafe { crc32c_update_x86_64_sse42(crc, data) }
            };
        }

        #[cfg(all(
            not(all(
                target_feature = "avx512f",
                target_feature = "vpclmulqdq",
                target_feature = "sse4.2"
            )),
            not(all(
                target_feature = "avx2",
                target_feature = "vpclmulqdq",
                target_feature = "sse4.2"
            )),
            not(all(target_feature = "sse4.2", target_feature = "pclmulqdq")),
            target_feature = "sse4.2"
        ))]
        {
            #[cfg(feature = "std")]
            if data.len() >= 256 {
                if data.len() >= 512
                    && std::arch::is_x86_feature_detected!("avx512f")
                    && std::arch::is_x86_feature_detected!("vpclmulqdq")
                {
                    return unsafe { crc32c_update_x86_64_vpclmul_512(crc, data) };
                }
                if std::arch::is_x86_feature_detected!("avx2")
                    && std::arch::is_x86_feature_detected!("vpclmulqdq")
                {
                    return unsafe { crc32c_update_x86_64_vpclmul_256(crc, data) };
                }
                if std::arch::is_x86_feature_detected!("pclmulqdq") {
                    return unsafe { crc32c_update_x86_64_pclmul(crc, data) };
                }
            }
            // SAFETY: target feature sse4.2 verified statically via #[cfg].
            return unsafe { crc32c_update_x86_64_sse42(crc, data) };
        }

        #[cfg(all(not(target_feature = "sse4.2"), feature = "std"))]
        {
            if std::arch::is_x86_feature_detected!("sse4.2") {
                if data.len() >= 256 {
                    if data.len() >= 512
                        && std::arch::is_x86_feature_detected!("avx512f")
                        && std::arch::is_x86_feature_detected!("vpclmulqdq")
                    {
                        // SAFETY: runtime detection confirmed AVX-512F + VPCLMULQDQ + SSE4.2.
                        return unsafe { crc32c_update_x86_64_vpclmul_512(crc, data) };
                    }
                    if std::arch::is_x86_feature_detected!("avx2")
                        && std::arch::is_x86_feature_detected!("vpclmulqdq")
                    {
                        // SAFETY: runtime detection confirmed AVX2 + VPCLMULQDQ + SSE4.2.
                        return unsafe { crc32c_update_x86_64_vpclmul_256(crc, data) };
                    }
                    if std::arch::is_x86_feature_detected!("pclmulqdq") {
                        // SAFETY: runtime detection confirmed PCLMULQDQ + SSE4.2.
                        return unsafe { crc32c_update_x86_64_pclmul(crc, data) };
                    }
                }
                // SAFETY: runtime detection confirmed SSE4.2.
                return unsafe { crc32c_update_x86_64_sse42(crc, data) };
            }
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
        // SAFETY: `target_feature = "crc"` is verified statically via `#[cfg]`.
        return unsafe { crc32c_update_aarch64_crc(crc, data) };
    }

    #[cfg(all(
        target_arch = "aarch64",
        not(target_feature = "crc"),
        feature = "std"
    ))]
    {
        if std::arch::is_aarch64_feature_detected!("crc") {
            // SAFETY: runtime CPU feature detection confirmed ARMv8 CRC support.
            return unsafe { crc32c_update_aarch64_crc(crc, data) };
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_combine_matches_concat_all_lengths() {
        let mut buf = [0u8; 4099];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((i * 73 + 19) & 0xFF) as u8;
        }
        for &split in &[0usize, 1, 2, 7, 15, 16, 63, 64, 127, 511, 1024, 2048, 4099] {
            let (a, b) = buf.split_at(split);
            let ca = crc32c(a);
            let cb = crc32c(b);
            assert_eq!(crc32c_combine(ca, cb, b.len()), crc32c(&buf), "split={split}");
        }
    }

    #[test]
    fn test_crc32c_hw_tiers_differential_against_sw() {
        let mut buf = vec![0u8; 65_600];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((i.wrapping_mul(131) ^ (i >> 5)) & 0xFF) as u8;
        }

        let mut test_lens: Vec<usize> = (0..=1024).collect();
        test_lens.extend_from_slice(&[1025, 2047, 2048, 2049, 4095, 4096, 4097, 16_384, 65_537]);

        for &len in &test_lens {
            for &align in &[0usize, 1, 3, 7] {
                let slice = &buf[align..align + len];
                let sw = !crc32c_update_sw(0xFFFF_FFFF, slice);
                assert_eq!(crc32c(slice), sw, "crc32c len={len} align={align}");

                // Streaming non-default IV split check.
                let (head, tail) = slice.split_at(len / 3);
                let iv = 0x1234_5678u32;
                let sw_split = !crc32c_update_sw(crc32c_update_sw(iv, head), tail);
                assert_eq!(
                    !crc32c_update(crc32c_update(iv, head), tail),
                    sw_split,
                    "split len={len} align={align}"
                );

                #[cfg(all(target_arch = "x86_64", any(target_feature = "sse4.2", feature = "std")))]
                if std::arch::is_x86_feature_detected!("sse4.2") {
                    let got = !unsafe { crc32c_update_x86_64_sse42(0xFFFF_FFFF, slice) };
                    assert_eq!(got, sw, "sse42 len={len} align={align}");
                }

                #[cfg(all(
                    target_arch = "x86_64",
                    not(all(target_feature = "avx512f", target_feature = "vpclmulqdq", target_feature = "sse4.2")),
                    not(all(target_feature = "avx2", target_feature = "vpclmulqdq", target_feature = "sse4.2")),
                    any(all(target_feature = "sse4.2", target_feature = "pclmulqdq"), feature = "std")
                ))]
                if std::arch::is_x86_feature_detected!("sse4.2")
                    && std::arch::is_x86_feature_detected!("pclmulqdq")
                {
                    let got = !unsafe { crc32c_update_x86_64_pclmul(0xFFFF_FFFF, slice) };
                    assert_eq!(got, sw, "pclmul len={len} align={align}");
                    let got_iv = !unsafe {
                        crc32c_update_x86_64_pclmul(
                            crc32c_update_x86_64_pclmul(iv, head),
                            tail,
                        )
                    };
                    assert_eq!(got_iv, sw_split, "pclmul split len={len}");
                }

                #[cfg(all(
                    target_arch = "x86_64",
                    not(all(target_feature = "avx512f", target_feature = "vpclmulqdq", target_feature = "sse4.2")),
                    any(all(target_feature = "avx2", target_feature = "vpclmulqdq", target_feature = "sse4.2"), feature = "std")
                ))]
                if std::arch::is_x86_feature_detected!("avx2")
                    && std::arch::is_x86_feature_detected!("vpclmulqdq")
                    && std::arch::is_x86_feature_detected!("sse4.2")
                {
                    let got = !unsafe { crc32c_update_x86_64_vpclmul_256(0xFFFF_FFFF, slice) };
                    assert_eq!(got, sw, "vpclmul_256 len={len} align={align}");
                    let got_iv = !unsafe {
                        crc32c_update_x86_64_vpclmul_256(
                            crc32c_update_x86_64_vpclmul_256(iv, head),
                            tail,
                        )
                    };
                    assert_eq!(got_iv, sw_split, "vpclmul_256 split len={len}");
                }

                #[cfg(all(
                    target_arch = "x86_64",
                    any(all(target_feature = "avx512f", target_feature = "vpclmulqdq", target_feature = "sse4.2"), feature = "std")
                ))]
                if std::arch::is_x86_feature_detected!("avx512f")
                    && std::arch::is_x86_feature_detected!("vpclmulqdq")
                    && std::arch::is_x86_feature_detected!("sse4.2")
                {
                    let got = !unsafe { crc32c_update_x86_64_vpclmul_512(0xFFFF_FFFF, slice) };
                    assert_eq!(got, sw, "vpclmul_512 len={len} align={align}");
                    let got_iv = !unsafe {
                        crc32c_update_x86_64_vpclmul_512(
                            crc32c_update_x86_64_vpclmul_512(iv, head),
                            tail,
                        )
                    };
                    assert_eq!(got_iv, sw_split, "vpclmul_512 split len={len}");
                }
            }
        }
    }
}
