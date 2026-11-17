use crate::crc::hash64;
use crate::error::VzError;
use crate::wire::{HASH_ALGO_BLAKE3, HASH_ALGO_BUILTIN, HASH_ALGO_XXH3_64};

/// Pluggable 64-bit path/basename hashing interface.
pub trait PathHasher: Send + Sync {
    /// Returns the `HeaderSlot::hash_algo` identifier for this hasher.
    fn algo_id(&self) -> u8;

    /// Computes the 64-bit hash over `data`.
    fn hash(&self, data: &[u8]) -> Result<u64, VzError>;
}

/// Standard VZ path hasher selected by `HASH_ALGO_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgoHasher(pub u8);

impl AlgoHasher {
    /// Creates an [`AlgoHasher`] for `algo_id`, returning `Err(VzError::Unsupported)`
    /// if the algorithm is unknown or disabled at compile time.
    pub fn new(algo_id: u8) -> Result<Self, VzError> {
        match algo_id {
            HASH_ALGO_BUILTIN => Ok(Self(algo_id)),
            HASH_ALGO_XXH3_64 => {
                #[cfg(feature = "hashes")]
                {
                    Ok(Self(algo_id))
                }
                #[cfg(not(feature = "hashes"))]
                {
                    Err(VzError::Unsupported)
                }
            }
            HASH_ALGO_BLAKE3 => {
                #[cfg(feature = "hashes")]
                {
                    Ok(Self(algo_id))
                }
                #[cfg(not(feature = "hashes"))]
                {
                    Err(VzError::Unsupported)
                }
            }
            _ => Err(VzError::Unsupported),
        }
    }
}

impl PathHasher for AlgoHasher {
    #[inline]
    fn algo_id(&self) -> u8 {
        self.0
    }

    #[inline]
    fn hash(&self, data: &[u8]) -> Result<u64, VzError> {
        match self.0 {
            HASH_ALGO_BUILTIN => Ok(hash64(data)),
            HASH_ALGO_XXH3_64 => {
                #[cfg(feature = "hashes")]
                {
                    Ok(xxhash_rust::xxh3::xxh3_64(data))
                }
                #[cfg(not(feature = "hashes"))]
                {
                    let _ = data;
                    Err(VzError::Unsupported)
                }
            }
            HASH_ALGO_BLAKE3 => {
                #[cfg(feature = "hashes")]
                {
                    let digest = blake3::hash(data);
                    let bytes = digest.as_bytes();
                    Ok(u64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]))
                }
                #[cfg(not(feature = "hashes"))]
                {
                    let _ = data;
                    Err(VzError::Unsupported)
                }
            }
            _ => Err(VzError::Unsupported),
        }
    }
}

/// Pluggable closure/function hasher for custom hashing or synthetic collision testing.
#[derive(Debug, Clone, Copy)]
pub struct FnHasher<F> {
    algo_id: u8,
    func: F,
}

impl<F> FnHasher<F> {
    /// Wraps a custom hash function `func` advertised under `algo_id`.
    pub const fn new(algo_id: u8, func: F) -> Self {
        Self { algo_id, func }
    }
}

impl<F> PathHasher for FnHasher<F>
where
    F: Fn(&[u8]) -> u64 + Send + Sync,
{
    #[inline]
    fn algo_id(&self) -> u8 {
        self.algo_id
    }

    #[inline]
    fn hash(&self, data: &[u8]) -> Result<u64, VzError> {
        Ok((self.func)(data))
    }
}
