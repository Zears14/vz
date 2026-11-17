use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::error::VzError;

/// Random-access range reader abstraction (memory slices, `File`, `Mmap`, HTTP Range, etc.).
pub trait RangeReader {
    /// Reads exactly `buf.len()` bytes starting at byte `offset`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError>;

    /// Returns the total byte length of the backing archive.
    fn total_len(&self) -> Result<u64, VzError>;

    /// Optional zero-copy view of the entire archive when resident in contiguous memory.
    ///
    /// Returns `None` for non-memory or instrumented readers (such as `File` or [`CountingRangeReader`]).
    #[inline]
    fn contiguous_bytes(&self) -> Option<&[u8]> {
        None
    }
}

impl<T: RangeReader + ?Sized> RangeReader for &T {
    #[inline]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        (**self).read_at(offset, buf)
    }

    #[inline]
    fn total_len(&self) -> Result<u64, VzError> {
        (**self).total_len()
    }

    #[inline]
    fn contiguous_bytes(&self) -> Option<&[u8]> {
        (**self).contiguous_bytes()
    }
}

/// Zero-copy [`RangeReader`] backed by an in-memory `&[u8]` slice.
#[derive(Debug, Clone, Copy)]
pub struct SliceRangeReader<'a>(pub &'a [u8]);

impl<'a> RangeReader for SliceRangeReader<'a> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        let start = usize::try_from(offset).map_err(|_| VzError::ValueOverflow)?;
        let end = start.checked_add(buf.len()).ok_or(VzError::ValueOverflow)?;
        if end > self.0.len() {
            return Err(VzError::BufferTooSmall);
        }
        buf.copy_from_slice(&self.0[start..end]);
        Ok(())
    }

    fn total_len(&self) -> Result<u64, VzError> {
        Ok(self.0.len() as u64)
    }

    #[inline]
    fn contiguous_bytes(&self) -> Option<&[u8]> {
        Some(self.0)
    }
}

impl RangeReader for [u8] {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        SliceRangeReader(self).read_at(offset, buf)
    }

    fn total_len(&self) -> Result<u64, VzError> {
        Ok(self.len() as u64)
    }

    #[inline]
    fn contiguous_bytes(&self) -> Option<&[u8]> {
        Some(self)
    }
}

/// Instrumentation wrapper tracking exact `read_at` call count (RTTs) and total bytes transferred.
#[derive(Debug)]
pub struct CountingRangeReader<R> {
    inner: R,
    reads: AtomicUsize,
    bytes_read: AtomicU64,
}

impl<R> CountingRangeReader<R> {
    /// Wraps `inner` with zeroed read counters.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            reads: AtomicUsize::new(0),
            bytes_read: AtomicU64::new(0),
        }
    }

    /// Returns the number of `read_at` calls (HTTP Range RTTs) issued so far.
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }

    /// Returns the total bytes requested across all `read_at` calls.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    /// Resets both counters to zero.
    pub fn reset(&self) {
        self.reads.store(0, Ordering::Relaxed);
        self.bytes_read.store(0, Ordering::Relaxed);
    }

    /// Returns a reference to the wrapped reader.
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// Unwraps and returns the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: RangeReader> RangeReader for CountingRangeReader<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes_read
            .fetch_add(buf.len() as u64, Ordering::Relaxed);
        self.inner.read_at(offset, buf)
    }

    fn total_len(&self) -> Result<u64, VzError> {
        self.inner.total_len()
    }
}

#[cfg(feature = "std")]
impl RangeReader for std::fs::File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.read_exact_at(buf, offset)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => VzError::BufferTooSmall,
                    _ => VzError::IoError,
                })
        }
        #[cfg(not(unix))]
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut file_ref = self;
            file_ref
                .seek(SeekFrom::Start(offset))
                .map_err(|_| VzError::IoError)?;
            file_ref.read_exact(buf).map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => VzError::BufferTooSmall,
                _ => VzError::IoError,
            })
        }
    }

    fn total_len(&self) -> Result<u64, VzError> {
        self.metadata().map(|m| m.len()).map_err(|_| VzError::IoError)
    }
}

#[cfg(feature = "std")]
impl RangeReader for std::vec::Vec<u8> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        SliceRangeReader(self.as_slice()).read_at(offset, buf)
    }

    fn total_len(&self) -> Result<u64, VzError> {
        Ok(self.len() as u64)
    }

    #[inline]
    fn contiguous_bytes(&self) -> Option<&[u8]> {
        Some(self.as_slice())
    }
}

#[cfg(feature = "std")]
impl<T: AsRef<[u8]>> RangeReader for std::io::Cursor<T> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        SliceRangeReader(self.get_ref().as_ref()).read_at(offset, buf)
    }

    fn total_len(&self) -> Result<u64, VzError> {
        Ok(self.get_ref().as_ref().len() as u64)
    }

    #[inline]
    fn contiguous_bytes(&self) -> Option<&[u8]> {
        Some(self.get_ref().as_ref())
    }
}

/// Memory-mapped [`RangeReader`] backed by `memmap2::Mmap`.
#[cfg(feature = "mmap")]
#[derive(Debug)]
pub struct MmapRangeReader {
    mmap: memmap2::Mmap,
}

#[cfg(feature = "mmap")]
impl MmapRangeReader {
    /// Opens a read-only memory map over `file`.
    ///
    /// # Safety
    /// Assumes the underlying file is not concurrently truncated or mutated by another process
    /// while mapped.
    pub unsafe fn from_file(file: &std::fs::File) -> Result<Self, VzError> {
        // SAFETY: Caller guarantees the mapped file is not concurrently mutated/truncated.
        let mmap = unsafe { memmap2::Mmap::map(file) }.map_err(|_| VzError::IoError)?;
        Ok(Self { mmap })
    }

    /// Returns the entire mapped archive as a zero-copy byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.mmap
    }
}

#[cfg(feature = "mmap")]
impl RangeReader for MmapRangeReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        SliceRangeReader(self.as_slice()).read_at(offset, buf)
    }

    fn total_len(&self) -> Result<u64, VzError> {
        Ok(self.mmap.len() as u64)
    }

    #[inline]
    fn contiguous_bytes(&self) -> Option<&[u8]> {
        Some(self.as_slice())
    }
}
