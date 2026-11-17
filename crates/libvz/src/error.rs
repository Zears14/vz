use core::fmt;

/// Error conditions returned by VZ encoding, decoding, validation, ECC, crypto, and I/O routines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VzError {
    /// Expected magic signature did not match.
    BadMagic,
    /// Computed CRC32C did not match the stored checksum.
    CrcMismatch,
    /// One or more unsupported `incompat_flags` bits were set on the active header slot.
    IncompatibleFeature,
    /// Input or output slice was shorter than required by the wire structure or payload.
    BufferTooSmall,
    /// Corruption exceeded ECC repair capability (e.g., 2+ Boot Block pages or >M RS clusters).
    CorruptUnrecoverable,
    /// Requested entry or extended metadata record was not present.
    NotFound,
    /// Numeric value exceeded wire encoding limits (e.g., LE-VINT >= 2^62 or integer overflow).
    ValueOverflow,
    /// Structural invariant violation (e.g., misaligned cluster length, `inline_data.len > 27`).
    BadFormat,
    /// Underlying I/O failure or unexpected EOF.
    IoError,
    /// Cryptographic key derivation, wrapping, or AEAD authentication failure.
    CryptoError,
    /// Compression or decompression failure.
    CompressionError,
    /// Requested codec, hash algorithm, or feature is unsupported in this build.
    Unsupported,
    /// Caller-supplied path, parameter, or configuration was invalid.
    InvalidInput,
    /// Duplicate path or entry conflict.
    AlreadyExists,
}

impl fmt::Display for VzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::BadMagic => "bad VZ magic signature",
            Self::CrcMismatch => "VZ CRC32C checksum mismatch",
            Self::IncompatibleFeature => "unsupported VZ incompatible feature flag",
            Self::BufferTooSmall => "buffer too small for VZ structure or payload",
            Self::CorruptUnrecoverable => "VZ corruption exceeds ECC recovery capacity",
            Self::NotFound => "VZ entry or metadata not found",
            Self::ValueOverflow => "VZ value or length arithmetic overflow",
            Self::BadFormat => "malformed VZ wire structure",
            Self::IoError => "VZ I/O error",
            Self::CryptoError => "VZ cryptographic authentication or key error",
            Self::CompressionError => "VZ compression or decompression error",
            Self::Unsupported => "unsupported VZ codec, hash, or feature",
            Self::InvalidInput => "invalid VZ input or path",
            Self::AlreadyExists => "duplicate VZ path or entry",
        };
        f.write_str(msg)
    }
}

impl VzError {
    /// Maps this error to a standard POSIX / Linux errno code (for FUSE3 / VFS integration).
    #[inline]
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::NotFound => 2,             // ENOENT
            Self::IoError => 5,              // EIO
            Self::CrcMismatch => 5,          // EIO
            Self::CorruptUnrecoverable => 5, // EIO
            Self::BadMagic => 5,             // EIO
            Self::BadFormat => 5,            // EIO
            Self::CryptoError => 13,         // EACCES
            Self::CompressionError => 5,     // EIO
            Self::AlreadyExists => 17,       // EEXIST
            Self::InvalidInput => 22,        // EINVAL
            Self::BufferTooSmall => 22,      // EINVAL
            Self::Unsupported => 38,         // ENOSYS
            Self::IncompatibleFeature => 38, // ENOSYS
            Self::ValueOverflow => 75,       // EOVERFLOW
        }
    }
}

impl core::error::Error for VzError {}
