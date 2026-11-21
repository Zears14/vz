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

#[cfg(feature = "std")]
static NEXT_SHARD_SLOT: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "std")]
std::thread_local! {
    static SHARD_SLOT: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) };
}

/// Multi-fd [`RangeReader`] opening independent kernel file descriptors per shard to eliminate
/// shared `struct file::f_count` atomic contention during high-concurrency `pread` workloads.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct ShardedFileReader {
    #[cfg(unix)]
    shards: Box<[std::fs::File]>,
    #[cfg(not(unix))]
    shards: Box<[std::sync::Mutex<std::fs::File>]>,
}

#[cfg(feature = "std")]
impl ShardedFileReader {
    /// Opens `path` using a default shard count sized to CPU parallelism (`1..=32`).
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, VzError> {
        let count = crate::parallel::cached_parallelism().clamp(1, 32);
        Self::open_with_shards(path, count)
    }

    /// Opens `path` using `shards` independent file descriptors (`shards >= 1`).
    pub fn open_with_shards(
        path: impl AsRef<std::path::Path>,
        shards: usize,
    ) -> Result<Self, VzError> {
        let target = shards.max(1);
        let path_ref = path.as_ref();
        #[cfg(unix)]
        let mut opened = Vec::with_capacity(target);
        #[cfg(not(unix))]
        let mut opened = Vec::with_capacity(target);
        for i in 0..target {
            match std::fs::File::open(path_ref) {
                Ok(f) => {
                    #[cfg(unix)]
                    opened.push(f);
                    #[cfg(not(unix))]
                    opened.push(std::sync::Mutex::new(f));
                }
                Err(_) if i > 0 => break,
                Err(_) => return Err(VzError::IoError),
            }
        }
        Ok(Self {
            shards: opened.into_boxed_slice(),
        })
    }

    /// Returns the active number of file descriptor shards.
    #[inline]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    #[inline]
    fn thread_shard_idx(&self) -> usize {
        let slot = SHARD_SLOT
            .try_with(|cell| match cell.get() {
                Some(id) => id,
                None => {
                    let id = NEXT_SHARD_SLOT.fetch_add(1, Ordering::Relaxed);
                    cell.set(Some(id));
                    id
                }
            })
            .unwrap_or(0);
        slot % self.shards.len()
    }
}

#[cfg(feature = "std")]
impl RangeReader for ShardedFileReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        let idx = self.thread_shard_idx();
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.shards[idx]
                .read_exact_at(buf, offset)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => VzError::BufferTooSmall,
                    _ => VzError::IoError,
                })
        }
        #[cfg(not(unix))]
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut guard = self.shards[idx].lock().map_err(|_| VzError::IoError)?;
            guard
                .seek(SeekFrom::Start(offset))
                .map_err(|_| VzError::IoError)?;
            guard.read_exact(buf).map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => VzError::BufferTooSmall,
                _ => VzError::IoError,
            })
        }
    }

    fn total_len(&self) -> Result<u64, VzError> {
        #[cfg(unix)]
        {
            self.shards[0]
                .metadata()
                .map(|m| m.len())
                .map_err(|_| VzError::IoError)
        }
        #[cfg(not(unix))]
        {
            let guard = self.shards[0].lock().map_err(|_| VzError::IoError)?;
            guard
                .metadata()
                .map(|m| m.len())
                .map_err(|_| VzError::IoError)
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::reader::VzReader;
    use crate::writer::{VzWriter, VzWriterConfig};

    #[test]
    fn test_sharded_file_reader_concurrent_and_eof() {
        let tf = tempfile::NamedTempFile::new().unwrap();
        {
            let mut w = VzWriter::new(tf.reopen().unwrap(), VzWriterConfig::default()).unwrap();
            for i in 0..200usize {
                w.add_file(
                    &format!("/s/{:02}/f_{i:04}.bin", i % 10),
                    format!("payload-{i:04}-data-padding-over-inline-threshold").as_bytes(),
                )
                .unwrap();
            }
            w.finish().unwrap();
        }

        let sharded = ShardedFileReader::open_with_shards(tf.path(), 4).unwrap();
        assert_eq!(sharded.shard_count(), 4);
        let len = sharded.total_len().unwrap();
        assert!(len > 0);
        let mut eof_buf = [0u8; 16];
        assert_eq!(
            sharded.read_at(len.saturating_sub(4), &mut eof_buf),
            Err(VzError::BufferTooSmall)
        );

        let reader = Arc::new(VzReader::open(sharded).unwrap());
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..8usize)
                .map(|tid| {
                    let r = Arc::clone(&reader);
                    s.spawn(move || {
                        let mut scratch = Vec::new();
                        for step in 0..50usize {
                            let i = (tid * 17 + step) % 200;
                            let path = format!("/s/{:02}/f_{i:04}.bin", i % 10);
                            r.read_file_into(&path, &mut scratch).unwrap();
                            let exp = format!("payload-{i:04}-data-padding-over-inline-threshold");
                            assert_eq!(scratch.as_slice(), exp.as_bytes());
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
        });
    }
}
