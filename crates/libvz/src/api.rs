//! Intuitive high-level Rust API over the `libvz` container engine.
//!
//! For byte-level wire structs, B+Tree views, CRC32C, Boot ECC, Reed-Solomon primitives, and
//! custom `RangeReader` implementations, see [`crate::low_level`].

use std::fs::{self, File};
use std::io::{BufWriter, Cursor, Seek, Write};
use std::path::Path;

use crate::codec::EncryptionKey;
use crate::error::VzError;
use crate::ext_meta::{DictEntry, SchemaEntry};
use crate::io::{RangeReader, SliceRangeReader};
#[cfg(feature = "mmap")]
use crate::io::MmapRangeReader;
use crate::reader::{ResolvedEntry, VzReader, VzReaderOptions, VzStat, repair_file, verify_archive, VerifyReport, RepairReport};
use crate::wire::{CODEC_LZ4, CODEC_NONE, CODEC_ZSTD, KIND_DIR, KIND_MASK};
use crate::writer::{
    CompactOptions, EntryOptions, LsmAppendWriter, VzWriter, VzWriterConfig,
    compact_archive_with_options,
};

/// High-level payload compression configuration for [`ArchiveBuilder`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Compression {
    /// Store payloads uncompressed (`CODEC_NONE`, `<= 27 B` payloads auto-inline).
    #[default]
    None,
    /// Fast LZ4 framing (`CODEC_LZ4`).
    Lz4,
    /// Zstandard compression at explicit level (`CODEC_ZSTD`, default `3`).
    Zstd { level: i32 },
}

impl Compression {
    /// Default balanced Zstandard compression (`level = 3`).
    pub const fn zstd() -> Self {
        Self::Zstd { level: 3 }
    }
}

/// Fluent builder for creating `.vz` archives cleanly.
#[derive(Debug, Clone, Default)]
pub struct ArchiveBuilder {
    config: VzWriterConfig,
    default_dict_id: Option<u32>,
}

impl ArchiveBuilder {
    /// Starts configuring a new archive with default v1.0 settings (64 KiB Boot Block + Boot ECC).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the default payload compression codec.
    pub fn compression(mut self, comp: Compression) -> Self {
        match comp {
            Compression::None => self.config.default_codec = CODEC_NONE,
            Compression::Lz4 => self.config.default_codec = CODEC_LZ4,
            Compression::Zstd { level } => {
                self.config.default_codec = CODEC_ZSTD;
                self.config.zstd_level = level;
            }
        }
        self
    }

    /// Attaches a shared Zstd dictionary (`TAG_DICT_TABLE`) and makes it default for new files.
    pub fn zstd_dictionary(mut self, dict_id: u32, dict_bytes: Vec<u8>, level: i32) -> Self {
        self.config.default_codec = CODEC_ZSTD;
        self.config.zstd_level = level;
        self.config.dicts.push(DictEntry {
            dict_id,
            codec: CODEC_ZSTD,
            flags: 0,
            bytes: dict_bytes,
        });
        self.default_dict_id = Some(dict_id);
        self
    }

    /// Enables or disables 4 KiB Boot Block self-healing ECC (`COMPAT_BOOT_ECC`).
    pub fn boot_ecc(mut self, enabled: bool) -> Self {
        self.config.enable_boot_ecc = enabled;
        self
    }

    /// Enables Reed-Solomon `GF(2^8)` erasure parity stripes `(K, M)` (`K + M <= 256`).
    pub fn rs_parity(mut self, data_k: u16, parity_m: u16) -> Self {
        self.config.rs_parity = Some((data_k, parity_m));
        self
    }

    /// Sets the target payload cluster grouping size in bytes (also chunk threshold).
    pub fn cluster_size(mut self, bytes: usize) -> Self {
        self.config.target_cluster_size = bytes;
        self
    }

    /// Sets the directory/entry hash algorithm (`HASH_ALGO_*`).
    pub fn hash_algo(mut self, algo: u8) -> Self {
        self.config.hash_algo = algo;
        self
    }

    /// Attaches schemas to `TAG_SCHEMA_TABLE`.
    pub fn schemas(mut self, schemas: Vec<SchemaEntry>) -> Self {
        self.config.schemas = schemas;
        self
    }

    /// Protects all payloads with password-derived Argon2id + `XChaCha20-Poly1305` AEAD.
    pub fn password(mut self, password: impl AsRef<[u8]>) -> Self {
        self.config.encryption = Some(EncryptionKey::from_password(password));
        self
    }

    /// Protects all payloads with a raw 256-bit key + `XChaCha20-Poly1305` AEAD.
    pub fn raw_key(mut self, key: [u8; 32]) -> Self {
        self.config.encryption = Some(EncryptionKey::Raw256(key));
        self
    }

    /// Creates a buffered file-backed [`ArchiveWriter`] at `path`.
    pub fn create<P: AsRef<Path>>(self, path: P) -> Result<ArchiveWriter<BufWriter<File>>, VzError> {
        let f = File::create(path).map_err(|_| VzError::IoError)?;
        self.build(BufWriter::with_capacity(256 * 1024, f))
    }

    /// Creates an in-memory [`ArchiveWriter`] backed by `Vec<u8>`.
    pub fn in_memory(self) -> Result<ArchiveWriter<Cursor<Vec<u8>>>, VzError> {
        self.build(Cursor::new(Vec::new()))
    }

    /// Builds an [`ArchiveWriter`] around an arbitrary `Write + Seek` sink.
    pub fn build<W: Write + Seek>(self, writer: W) -> Result<ArchiveWriter<W>, VzError> {
        let inner = VzWriter::new(writer, self.config)?;
        Ok(ArchiveWriter {
            inner,
            default_dict_id: self.default_dict_id,
        })
    }
}

/// High-level archive construction session returned by [`ArchiveBuilder`].
pub struct ArchiveWriter<W: Write + Seek> {
    inner: VzWriter<W>,
    default_dict_id: Option<u32>,
}

impl<W: Write + Seek> ArchiveWriter<W> {
    /// Adds a regular file with builder defaults.
    pub fn add(&mut self, path: &str, data: &[u8]) -> Result<&mut Self, VzError> {
        let opts = EntryOptions {
            dict_id: self.default_dict_id,
            ..Default::default()
        };
        self.inner.add_file_with_options(path, data, opts)?;
        Ok(self)
    }

    /// Adds an entry with explicit [`EntryOptions`] (does not override `opts.codec` or `opts.dict_id`).
    pub fn add_with(
        &mut self,
        path: &str,
        data: &[u8],
        opts: EntryOptions,
    ) -> Result<&mut Self, VzError> {
        self.inner.add_file_with_options(path, data, opts)?;
        Ok(self)
    }

    /// Streams a file directly from host filesystem path `host_path` into `archive_path`
    /// in bounded memory.
    pub fn add_file<P: AsRef<Path>>(
        &mut self,
        archive_path: &str,
        host_path: P,
    ) -> Result<&mut Self, VzError> {
        let f = File::open(host_path).map_err(|_| VzError::IoError)?;
        let opts = EntryOptions {
            dict_id: self.default_dict_id,
            ..Default::default()
        };
        self.inner.add_file_reader(archive_path, f, opts)?;
        Ok(self)
    }

    /// Adds a directory entry (`KIND_DIR`, `0o755`).
    pub fn add_dir(&mut self, path: &str) -> Result<&mut Self, VzError> {
        self.inner.add_dir(path, 0o755, 0)?;
        Ok(self)
    }

    /// Adds a sparse file with explicit non-zero `(offset, bytes)` extents.
    pub fn add_sparse(
        &mut self,
        path: &str,
        logical_size: u64,
        extents: &[(u64, &[u8])],
    ) -> Result<&mut Self, VzError> {
        let opts = EntryOptions {
            dict_id: self.default_dict_id,
            ..Default::default()
        };
        self.inner.add_sparse_file(path, logical_size, extents, opts)?;
        Ok(self)
    }

    /// Adds a hardlink pointing to `target_path`.
    pub fn add_hardlink(&mut self, link_path: &str, target_path: &str) -> Result<&mut Self, VzError> {
        self.inner.add_hardlink(link_path, target_path)?;
        Ok(self)
    }

    /// Finalizes the archive index, Boot Block, ECC, and returns the underlying writer.
    pub fn finish(self) -> Result<W, VzError> {
        self.inner.finish()
    }

    /// Borrows the underlying low-level [`VzWriter`].
    pub fn inner(&self) -> &VzWriter<W> {
        &self.inner
    }

    /// Mutably borrows the underlying low-level [`VzWriter`].
    pub fn inner_mut(&mut self) -> &mut VzWriter<W> {
        &mut self.inner
    }
}

/// High-level read/inspect/extract/compact handle over a `.vz` container.
pub struct Archive<R: RangeReader> {
    reader: VzReader<R>,
}

impl Archive<File> {
    /// Opens an existing `.vz` archive file on disk (performing automatic single-page Boot ECC repair).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, VzError> {
        let f = File::open(path).map_err(|_| VzError::IoError)?;
        Ok(Self {
            reader: VzReader::open(f)?,
        })
    }

    /// Opens an encrypted `.vz` archive file on disk using `key`.
    pub fn open_encrypted<P: AsRef<Path>>(path: P, key: EncryptionKey) -> Result<Self, VzError> {
        let f = File::open(path).map_err(|_| VzError::IoError)?;
        Ok(Self {
            reader: VzReader::open_with_options(
                f,
                VzReaderOptions {
                    encryption: Some(key),
                    repair_boot_ecc: true,
                },
            )?,
        })
    }

    /// Verifies Boot ECC, cluster links/CRCs, B+Tree nodes, and RS parity on `path`.
    pub fn verify_file<P: AsRef<Path>>(
        path: P,
        encryption: Option<EncryptionKey>,
    ) -> Result<VerifyReport, VzError> {
        let f = File::open(path).map_err(|_| VzError::IoError)?;
        verify_archive(&f, encryption)
    }

    /// Repairs single-page Boot ECC and `<= M` RS-corrupted clusters at `path` in-place.
    pub fn repair_in_place<P: AsRef<Path>>(path: P) -> Result<RepairReport, VzError> {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| VzError::IoError)?;
        repair_file(&mut f)
    }

    /// Opens an incremental LSM overlay append session (`LsmAppendWriter`) on `path`.
    pub fn append_session<P: AsRef<Path>>(
        path: P,
        encryption: Option<EncryptionKey>,
    ) -> Result<LsmAppendWriter<File>, VzError> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| VzError::IoError)?;
        LsmAppendWriter::open(f, encryption, 512, 128)
    }
}

#[cfg(feature = "mmap")]
impl Archive<MmapRangeReader> {
    /// Opens an existing `.vz` file using a read-only zero-copy memory map (`mmap`).
    ///
    /// # Safety
    /// Assumes the file is not truncated or modified concurrently while mapped.
    pub unsafe fn open_mmap<P: AsRef<Path>>(
        path: P,
        encryption: Option<EncryptionKey>,
    ) -> Result<Self, VzError> {
        let f = File::open(path).map_err(|_| VzError::IoError)?;
        // SAFETY: Caller guarantees file immutability while mapped.
        let mmap = unsafe { MmapRangeReader::from_file(&f)? };
        Ok(Self {
            reader: VzReader::open_with_options(
                mmap,
                VzReaderOptions {
                    encryption,
                    repair_boot_ecc: true,
                },
            )?,
        })
    }
}

impl<'a> Archive<SliceRangeReader<'a>> {
    /// Opens a `.vz` archive directly from an in-memory byte slice.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, VzError> {
        Ok(Self {
            reader: VzReader::open(SliceRangeReader(bytes))?,
        })
    }

    /// Opens an encrypted `.vz` archive from an in-memory byte slice.
    pub fn from_bytes_encrypted(bytes: &'a [u8], key: EncryptionKey) -> Result<Self, VzError> {
        Ok(Self {
            reader: VzReader::open_with_options(
                SliceRangeReader(bytes),
                VzReaderOptions {
                    encryption: Some(key),
                    repair_boot_ecc: true,
                },
            )?,
        })
    }
}

impl Archive<Vec<u8>> {
    /// Opens an owned byte buffer containing a `.vz` archive.
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, VzError> {
        Ok(Self {
            reader: VzReader::open(bytes)?,
        })
    }
}

impl<R: RangeReader> Archive<R> {
    /// Wraps an already-opened custom [`RangeReader`] with explicit [`VzReaderOptions`].
    pub fn open_reader(reader: R, options: VzReaderOptions) -> Result<Self, VzError> {
        Ok(Self {
            reader: VzReader::open_with_options(reader, options)?,
        })
    }

    /// Reads the entire decoded payload of `path`.
    pub fn get(&self, path: &str) -> Result<Vec<u8>, VzError> {
        self.reader.read_file(path)
    }

    /// Reads byte slice `[offset, offset + len)` of `path` (clamped at EOF).
    pub fn get_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, VzError> {
        self.reader.read_file_range(path, offset, len)
    }

    /// Reads metadata for `path`.
    pub fn stat(&self, path: &str) -> Result<VzStat, VzError> {
        self.reader.stat(path)
    }

    /// Returns `true` if `path` exists in the active archive view.
    pub fn exists(&self, path: &str) -> Result<bool, VzError> {
        self.reader.exists(path)
    }

    /// Lists all live entries in directory `dir_path`.
    pub fn ls(&self, dir_path: &str) -> Result<Vec<VzStat>, VzError> {
        self.reader.readdir(dir_path)
    }

    /// Fast bulk sequential extractor streaming every live entry in cluster order.
    pub fn extract_all_with<F>(&self, visitor: F) -> Result<(), VzError>
    where
        F: FnMut(&ResolvedEntry, &[u8]) -> Result<(), VzError>,
    {
        self.reader.extract_all_with(visitor)
    }

    /// Extracts all live files and directories into `dest_dir` on the filesystem.
    pub fn extract_to<P: AsRef<Path>>(&self, dest_dir: P) -> Result<usize, VzError> {
        let dest = dest_dir.as_ref();
        fs::create_dir_all(dest).map_err(|_| VzError::IoError)?;
        let mut count = 0usize;
        self.reader.extract_all_with(|entry, data| {
            let rel_dir = entry.stat.parent_path.trim_start_matches('/');
            let host_dir = if rel_dir.is_empty() {
                dest.to_path_buf()
            } else {
                dest.join(rel_dir)
            };
            fs::create_dir_all(&host_dir).map_err(|_| VzError::IoError)?;
            let host_path = host_dir.join(&entry.stat.name);
            if (entry.stat.kind & KIND_MASK) == KIND_DIR {
                fs::create_dir_all(&host_path).map_err(|_| VzError::IoError)?;
            } else {
                fs::write(&host_path, data).map_err(|_| VzError::IoError)?;
            }
            count += 1;
            Ok(())
        })?;
        Ok(count)
    }

    /// Compacts this archive into a new single-run file at `dest_path` (stripping LSM overlays back
    /// to `1`, deleting tombstones, and copying payloads without re-encoding by default).
    pub fn compact_to<P: AsRef<Path>>(
        &self,
        dest_path: P,
        options: CompactOptions,
    ) -> Result<(), VzError> {
        let f = File::create(dest_path).map_err(|_| VzError::IoError)?;
        let bw = self.compact_to_writer(BufWriter::with_capacity(256 * 1024, f), options)?;
        bw.into_inner().map_err(|_| VzError::IoError)?;
        Ok(())
    }

    /// Compacts this archive into an arbitrary seekable writer (zero re-encoding by default).
    pub fn compact_to_writer<W: Write + Seek>(
        &self,
        writer: W,
        options: CompactOptions,
    ) -> Result<W, VzError> {
        compact_archive_with_options(&self.reader, writer, options)
    }

    /// Borrows the underlying low-level [`VzReader`].
    pub fn reader(&self) -> &VzReader<R> {
        &self.reader
    }

    /// Consumes this wrapper and returns the inner [`VzReader`].
    pub fn into_reader(self) -> VzReader<R> {
        self.reader
    }
}
