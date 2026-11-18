use std::ffi::{c_char, c_void};
use std::fs::File;
use std::io::BufWriter;
use std::mem::ManuallyDrop;
use std::ptr;
use std::sync::Arc;

use libvz::fuse::{FuseFileHandle, FuseFileKind, FuseVolume};
use libvz::{
    CODEC_LZ4, CODEC_NONE, CODEC_ZSTD, HASH_ALGO_BLAKE3, HASH_ALGO_BUILTIN, HASH_ALGO_XXH3_64,
    KIND_BLK, KIND_CHR, KIND_DIR, KIND_FIFO, KIND_LNK, KIND_MASK, KIND_REG, KIND_SOCK,
    LsmAppendWriter, MmapRangeReader, RangeReader, VzError, VzReader, VzStat, VzStreamedFile,
    VzWriter,
};

use crate::{alloc_c_string, free_c_string};

/// FFI status codes returned by every fallible `vz_*` function.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum VzStatus {
    VZ_OK = 0,
    VZ_ERR_NULL_PTR = -1,
    VZ_ERR_INVALID_UTF8 = -2,
    VZ_ERR_BAD_MAGIC = 1,
    VZ_ERR_CRC_MISMATCH = 2,
    VZ_ERR_INCOMPATIBLE_FEATURE = 3,
    VZ_ERR_BUFFER_TOO_SMALL = 4,
    VZ_ERR_CORRUPT_UNRECOVERABLE = 5,
    VZ_ERR_NOT_FOUND = 6,
    VZ_ERR_VALUE_OVERFLOW = 7,
    VZ_ERR_BAD_FORMAT = 8,
    VZ_ERR_IO = 9,
    VZ_ERR_CRYPTO = 10,
    VZ_ERR_COMPRESSION = 11,
    VZ_ERR_UNSUPPORTED = 12,
    VZ_ERR_INVALID_INPUT = 13,
    VZ_ERR_ALREADY_EXISTS = 14,
}

impl From<VzError> for VzStatus {
    fn from(e: VzError) -> Self {
        match e {
            VzError::BadMagic => Self::VZ_ERR_BAD_MAGIC,
            VzError::CrcMismatch => Self::VZ_ERR_CRC_MISMATCH,
            VzError::IncompatibleFeature => Self::VZ_ERR_INCOMPATIBLE_FEATURE,
            VzError::BufferTooSmall => Self::VZ_ERR_BUFFER_TOO_SMALL,
            VzError::CorruptUnrecoverable => Self::VZ_ERR_CORRUPT_UNRECOVERABLE,
            VzError::NotFound => Self::VZ_ERR_NOT_FOUND,
            VzError::ValueOverflow => Self::VZ_ERR_VALUE_OVERFLOW,
            VzError::BadFormat => Self::VZ_ERR_BAD_FORMAT,
            VzError::IoError => Self::VZ_ERR_IO,
            VzError::CryptoError => Self::VZ_ERR_CRYPTO,
            VzError::CompressionError => Self::VZ_ERR_COMPRESSION,
            VzError::Unsupported => Self::VZ_ERR_UNSUPPORTED,
            VzError::InvalidInput => Self::VZ_ERR_INVALID_INPUT,
            VzError::AlreadyExists => Self::VZ_ERR_ALREADY_EXISTS,
        }
    }
}

/// Payload compression codecs supported by VZ v1.0.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum VzCodec {
    VZ_CODEC_NONE = 0,
    VZ_CODEC_LZ4 = 1,
    VZ_CODEC_ZSTD = 2,
}

const _: () = assert!(VzCodec::VZ_CODEC_NONE as u8 == CODEC_NONE);
const _: () = assert!(VzCodec::VZ_CODEC_LZ4 as u8 == CODEC_LZ4);
const _: () = assert!(VzCodec::VZ_CODEC_ZSTD as u8 == CODEC_ZSTD);

/// Directory/entry path hashing algorithms supported by VZ v1.0.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum VzHashAlgo {
    VZ_HASH_BUILTIN = 0,
    VZ_HASH_XXH3_64 = 1,
    VZ_HASH_BLAKE3 = 2,
}

const _: () = assert!(VzHashAlgo::VZ_HASH_BUILTIN as u8 == HASH_ALGO_BUILTIN);
const _: () = assert!(VzHashAlgo::VZ_HASH_XXH3_64 as u8 == HASH_ALGO_XXH3_64);
const _: () = assert!(VzHashAlgo::VZ_HASH_BLAKE3 as u8 == HASH_ALGO_BLAKE3);

/// POSIX / VFS entry kind discriminator.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum VzFileKind {
    VZ_KIND_REG = 0,
    VZ_KIND_DIR = 1,
    VZ_KIND_LNK = 2,
    VZ_KIND_FIFO = 3,
    VZ_KIND_CHR = 4,
    VZ_KIND_BLK = 5,
    VZ_KIND_SOCK = 6,
    VZ_KIND_OTHER = 255,
}

impl VzFileKind {
    pub(crate) fn to_wire(self) -> Option<u16> {
        match self {
            Self::VZ_KIND_REG => Some(KIND_REG),
            Self::VZ_KIND_DIR => Some(KIND_DIR),
            Self::VZ_KIND_LNK => Some(KIND_LNK),
            Self::VZ_KIND_FIFO => Some(KIND_FIFO),
            Self::VZ_KIND_CHR => Some(KIND_CHR),
            Self::VZ_KIND_BLK => Some(KIND_BLK),
            Self::VZ_KIND_SOCK => Some(KIND_SOCK),
            Self::VZ_KIND_OTHER => None,
        }
    }

    pub(crate) fn from_wire(kind_bits: u16) -> Self {
        match kind_bits & KIND_MASK {
            KIND_REG => Self::VZ_KIND_REG,
            KIND_DIR => Self::VZ_KIND_DIR,
            KIND_LNK => Self::VZ_KIND_LNK,
            KIND_FIFO => Self::VZ_KIND_FIFO,
            KIND_CHR => Self::VZ_KIND_CHR,
            KIND_BLK => Self::VZ_KIND_BLK,
            KIND_SOCK => Self::VZ_KIND_SOCK,
            _ => Self::VZ_KIND_OTHER,
        }
    }

    pub(crate) fn from_fuse(k: FuseFileKind) -> Self {
        match k {
            FuseFileKind::RegularFile => Self::VZ_KIND_REG,
            FuseFileKind::Directory => Self::VZ_KIND_DIR,
            FuseFileKind::Symlink => Self::VZ_KIND_LNK,
            FuseFileKind::NamedPipe => Self::VZ_KIND_FIFO,
            FuseFileKind::CharDevice => Self::VZ_KIND_CHR,
            FuseFileKind::BlockDevice => Self::VZ_KIND_BLK,
            FuseFileKind::Socket => Self::VZ_KIND_SOCK,
        }
    }
}

/// Owned byte buffer returned from `vz_*` read functions. Must be freed with [`vz_bytes_free`].
#[repr(C)]
pub struct VzBytes {
    pub data: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl VzBytes {
    pub(crate) fn from_vec(mut v: Vec<u8>) -> Self {
        let len = v.len();
        let cap = v.capacity();
        let data = v.as_mut_ptr();
        let _ = ManuallyDrop::new(v);
        Self { data, len, cap }
    }

    pub(crate) fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Entry metadata returned by [`vz_archive_stat`] and [`vz_archive_readdir`].
#[repr(C)]
pub struct VzStatC {
    pub entry_id: u64,
    pub size: u64,
    pub stored_size: u64,
    pub mtime_ns: i64,
    pub mode: u16,
    pub kind: VzFileKind,
    pub codec: u8,
    pub is_inline: bool,
    pub is_sparse: bool,
    pub is_multi_cluster: bool,
    pub parent_path: *mut c_char,
    pub name: *mut c_char,
}

impl VzStatC {
    pub(crate) fn from_vz_stat(s: &VzStat) -> Result<Self, VzStatus> {
        let parent_c = alloc_c_string(&s.parent_path)?;
        let name_c = match alloc_c_string(&s.name) {
            Ok(n) => n,
            Err(err) => {
                unsafe { free_c_string(parent_c) };
                return Err(err);
            }
        };
        Ok(Self {
            entry_id: s.entry_id,
            size: s.size,
            stored_size: s.stored_size,
            mtime_ns: s.mtime_ns,
            mode: s.mode,
            kind: VzFileKind::from_wire(s.kind),
            codec: s.codec,
            is_inline: s.is_inline,
            is_sparse: s.is_sparse,
            is_multi_cluster: s.is_multi_cluster,
            parent_path: parent_c,
            name: name_c,
        })
    }
}

/// Directory listing returned by [`vz_archive_readdir`]. Must be freed with [`vz_dir_list_free`].
#[repr(C)]
pub struct VzDirList {
    pub items: *mut VzStatC,
    pub len: usize,
    pub cap: usize,
}

/// Archive open options for [`vz_archive_open`], [`vz_archive_open_memory`], [`vz_append_open`],
/// and [`vz_verify_file`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VzOpenOptions {
    /// Use memory-mapped zero-copy reads (`mmap`) when opening files (`true` recommended).
    pub use_mmap: bool,
    /// Repair single-page Boot Block ECC errors automatically on open (`true` recommended).
    pub repair_boot_ecc: bool,
    /// Key mode: `0` = none, `1` = raw 256-bit key (`raw_key`), `2` = Argon2id passphrase.
    pub encryption_mode: u8,
    pub raw_key: [u8; 32],
    /// Optional NUL-terminated UTF-8 passphrase when `encryption_mode == 2`.
    pub passphrase: *const c_char,
}

/// Archive writer configuration for [`vz_writer_create`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VzWriterConfigC {
    pub default_codec: VzCodec,
    pub hash_algo: VzHashAlgo,
    pub zstd_level: i32,
    pub target_cluster_size: usize,
    pub multi_cluster_threshold: usize,
    pub max_leaf_entries: u16,
    pub max_route_entries: u16,
    pub enable_boot_ecc: bool,
    /// Set `rs_parity_m > 0` and `rs_parity_k > 0` to enable `RS_GF256(K, M)` parity clusters.
    pub rs_parity_k: u16,
    pub rs_parity_m: u16,
    /// Key mode: `0` = none, `1` = raw 256-bit key, `2` = Argon2id passphrase.
    pub encryption_mode: u8,
    pub raw_key: [u8; 32],
    pub passphrase: *const c_char,
}

/// Zero-allocation entry view yielded to [`VzReaddirVisitorFn`] by [`vz_archive_readdir_visit`].
/// `name` passed to the callback is NOT NUL-terminated; inspect `name_len`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VzStatViewC {
    pub entry_id: u64,
    pub size: u64,
    pub stored_size: u64,
    pub mtime_ns: i64,
    pub mode: u16,
    pub kind: VzFileKind,
    pub codec: u8,
    pub is_inline: bool,
    pub is_sparse: bool,
    pub is_multi_cluster: bool,
}

/// Callback invoked by [`vz_archive_readdir_visit`]. Return `true` to continue, `false` to stop.
pub type VzReaddirVisitorFn = Option<
    unsafe extern "C" fn(
        stat: *const VzStatViewC,
        name: *const c_char,
        name_len: usize,
        user_data: *mut c_void,
    ) -> bool,
>;

/// Per-entry options for [`vz_writer_add_file`], [`vz_writer_file_begin`], and [`vz_append_add_file`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VzEntryOptionsC {
    /// Set `override_codec == true` to override archive default codec with `codec`.
    pub override_codec: bool,
    pub codec: VzCodec,
    pub mode: u16,
    pub mtime_ns: i64,
    pub has_owner: bool,
    pub uid: u32,
    pub gid: u32,
    pub has_btime: bool,
    pub btime_ns: i64,
}

/// Compaction options for [`vz_archive_compact`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VzCompactOptionsC {
    /// `true` preserves existing compressed payloads without re-encoding (`override_codec == false`).
    pub zero_reencode: bool,
    pub codec: VzCodec,
    pub zstd_level: i32,
    pub target_cluster_size: usize,
    pub enable_boot_ecc: bool,
    /// Optional Reed-Solomon `GF(2^8)` parity `(K, M)` on compacted output (`0` = disabled/inherit).
    pub rs_parity_k: u16,
    pub rs_parity_m: u16,
}

/// Integrity verification summary filled by [`vz_verify_file`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VzVerifyReportC {
    pub boot_ecc_ok: bool,
    pub boot_ecc_repaired: bool,
    pub boot_ecc_repaired_page: usize,
    pub clusters_checked: usize,
    pub parity_stripes_checked: usize,
    pub error_count: usize,
}

/// Repair summary filled by [`vz_repair_file`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VzRepairReportC {
    pub boot_repaired: bool,
    pub boot_repaired_page: usize,
    pub data_clusters_repaired: usize,
    pub parity_clusters_repaired: usize,
}

/// POSIX inode attributes for C FUSE3 integrations.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VzFuseAttrC {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime_sec: i64,
    pub atime_nsec: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
    pub crtime_sec: i64,
    pub crtime_nsec: u32,
    pub kind: VzFileKind,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
}

impl From<libvz::FuseAttr> for VzFuseAttrC {
    fn from(a: libvz::FuseAttr) -> Self {
        Self {
            ino: a.ino,
            size: a.size,
            blocks: a.blocks,
            atime_sec: a.atime_sec,
            atime_nsec: a.atime_nsec,
            mtime_sec: a.mtime_sec,
            mtime_nsec: a.mtime_nsec,
            ctime_sec: a.ctime_sec,
            ctime_nsec: a.ctime_nsec,
            crtime_sec: a.crtime_sec,
            crtime_nsec: a.crtime_nsec,
            kind: VzFileKind::from_fuse(a.kind),
            perm: a.perm,
            nlink: a.nlink,
            uid: a.uid,
            gid: a.gid,
            rdev: a.rdev,
            blksize: a.blksize,
        }
    }
}

/// Directory entry + attributes returned by [`vz_fuse_readdirplus`].
#[repr(C)]
pub struct VzFuseDirEntryPlusC {
    pub ino: u64,
    pub offset: u64,
    pub kind: VzFileKind,
    pub name: *mut c_char,
    pub attr: VzFuseAttrC,
}

/// Paginated `readdirplus` result list. Must be freed with [`vz_fuse_dir_free`].
#[repr(C)]
pub struct VzFuseDirListC {
    pub items: *mut VzFuseDirEntryPlusC,
    pub len: usize,
    pub cap: usize,
}

/// Filesystem statistics returned by [`vz_fuse_statfs`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VzFuseStatFsC {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

// ============================================================================
// OPAQUE HANDLE TYPES
// ============================================================================

pub(crate) enum DynRangeReader {
    File(File),
    Mmap(MmapRangeReader),
    Bytes(Vec<u8>),
}

impl RangeReader for DynRangeReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), VzError> {
        match self {
            Self::File(f) => f.read_at(offset, buf),
            Self::Mmap(m) => m.read_at(offset, buf),
            Self::Bytes(v) => v.read_at(offset, buf),
        }
    }

    fn total_len(&self) -> Result<u64, VzError> {
        match self {
            Self::File(f) => f.total_len(),
            Self::Mmap(m) => m.total_len(),
            Self::Bytes(v) => v.total_len(),
        }
    }

    fn contiguous_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::File(_) => None,
            Self::Mmap(m) => m.contiguous_bytes(),
            Self::Bytes(v) => Some(v.as_slice()),
        }
    }
}

/// Opaque read-only archive handle. Freed with [`vz_archive_close`].
pub struct VzArchive {
    pub(crate) reader: Arc<VzReader<DynRangeReader>>,
}

/// Opaque streaming archive writer handle. Finalized via [`vz_writer_finish`] or [`vz_writer_abort`].
pub struct VzWriterHandle {
    pub(crate) writer: Option<VzWriter<BufWriter<File>>>,
}

/// Opaque chunked streaming file handle started by [`vz_writer_file_begin`].
pub struct VzStreamFileHandle {
    pub(crate) state: Option<VzStreamedFile>,
}

/// Opaque incremental LSM overlay writer handle. Finalized via [`vz_append_finish`] or [`vz_append_abort`].
pub struct VzAppendHandle {
    pub(crate) writer: Option<LsmAppendWriter<File>>,
}

/// Opaque mounted FUSE3 VFS volume handle. Freed with [`vz_fuse_unmount`].
pub struct VzFuseVol {
    pub(crate) vol: FuseVolume<DynRangeReader>,
}

/// Opaque open FUSE3 file handle (`fh`). Freed with [`vz_fuse_close`].
pub struct VzFuseFh {
    pub(crate) fh: FuseFileHandle,
}

