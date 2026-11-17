//! C/C++ FFI bindings for `libvz` (`libvz.so` / `libvz.a` + `cbindgen`-generated `vz.h`).
//!
//! All `extern "C"` functions validate pointers, never panic/unwrap inside library paths,
//! and return explicit [`VzStatus`] error codes (with optional thread-local detail via
//! [`vz_last_error`]).

#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_void};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::mem::ManuallyDrop;
use std::ptr;
use std::slice;
use std::sync::Arc;

use libvz::fuse::{FUSE_ROOT_ID, FuseFileHandle, FuseFileKind, FuseVolume};
use libvz::{
    CODEC_LZ4, CODEC_NONE, CODEC_ZSTD, CompactOptions, EncryptionKey, EntryOptions, ExtTime,
    HASH_ALGO_BLAKE3, HASH_ALGO_BUILTIN, HASH_ALGO_XXH3_64, KIND_BLK, KIND_CHR, KIND_DIR,
    KIND_FIFO, KIND_LNK, KIND_MASK, KIND_REG, KIND_SOCK, LsmAppendWriter, MmapRangeReader,
    OwnerEntry, RangeReader, VzError, VzReader, VzReaderOptions, VzStat, VzStreamedFile, VzWriter,
    VzWriterConfig, compact_archive_with_options, repair_file, verify_archive,
};

/// ABI version bumped on breaking C/C++ layout or symbol changes.
pub const VZ_ABI_VERSION: u32 = 1;

/// Root inode ID (`1`) exported for C/C++ FUSE3 consumers.
pub const VZ_FUSE_ROOT_ID: u64 = 1;
const _: () = assert!(VZ_FUSE_ROOT_ID == FUSE_ROOT_ID);

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        if let Ok(mut guard) = slot.try_borrow_mut() {
            *guard = None;
        }
    });
}

fn set_last_error(msg: &str) {
    let clean = msg.replace('\0', " ");
    if let Ok(cstr) = CString::new(clean) {
        LAST_ERROR.with(|slot| {
            if let Ok(mut guard) = slot.try_borrow_mut() {
                *guard = Some(cstr);
            }
        });
    }
}

fn fail(status: VzStatus, msg: &str) -> VzStatus {
    set_last_error(msg);
    status
}

fn fail_vz(err: VzError) -> VzStatus {
    let status = VzStatus::from(err);
    set_last_error(&format!("{err:?}"));
    status
}

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
    fn to_wire(self) -> Option<u16> {
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

    fn from_wire(kind_bits: u16) -> Self {
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

    fn from_fuse(k: FuseFileKind) -> Self {
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
    fn from_vec(mut v: Vec<u8>) -> Self {
        let len = v.len();
        let cap = v.capacity();
        let data = v.as_mut_ptr();
        let _ = ManuallyDrop::new(v);
        Self { data, len, cap }
    }

    fn empty() -> Self {
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
    fn from_vz_stat(s: &VzStat) -> Result<Self, VzStatus> {
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

enum DynRangeReader {
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
    reader: Arc<VzReader<DynRangeReader>>,
}

/// Opaque streaming archive writer handle. Finalized via [`vz_writer_finish`] or [`vz_writer_abort`].
pub struct VzWriterHandle {
    writer: Option<VzWriter<BufWriter<File>>>,
}

/// Opaque chunked streaming file handle started by [`vz_writer_file_begin`].
pub struct VzStreamFileHandle {
    state: Option<VzStreamedFile>,
}

/// Opaque incremental LSM overlay writer handle. Finalized via [`vz_append_finish`] or [`vz_append_abort`].
pub struct VzAppendHandle {
    writer: Option<LsmAppendWriter<File>>,
}

/// Opaque mounted FUSE3 VFS volume handle. Freed with [`vz_fuse_unmount`].
pub struct VzFuseVol {
    vol: FuseVolume<DynRangeReader>,
}

/// Opaque open FUSE3 file handle (`fh`). Freed with [`vz_fuse_close`].
pub struct VzFuseFh {
    fh: FuseFileHandle,
}

// ============================================================================
// STRING / KEY / OPTION CONVERSION HELPERS
// ============================================================================

fn alloc_c_string(s: &str) -> Result<*mut c_char, VzStatus> {
    let clean = s.replace('\0', "");
    CString::new(clean)
        .map(CString::into_raw)
        .map_err(|_| fail(VzStatus::VZ_ERR_INVALID_UTF8, "interior nul in string"))
}

unsafe fn free_c_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)) };
    }
}

unsafe fn read_c_str<'a>(ptr: *const c_char) -> Result<&'a str, VzStatus> {
    if ptr.is_null() {
        return Err(fail(VzStatus::VZ_ERR_NULL_PTR, "unexpected null string pointer"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| fail(VzStatus::VZ_ERR_INVALID_UTF8, "string is not valid UTF-8"))
}

unsafe fn parse_key(
    mode: u8,
    raw_key: &[u8; 32],
    passphrase: *const c_char,
) -> Result<Option<EncryptionKey>, VzStatus> {
    match mode {
        0 => Ok(None),
        1 => Ok(Some(EncryptionKey::Raw256(*raw_key))),
        2 => {
            let pass = unsafe { read_c_str(passphrase)? };
            Ok(Some(EncryptionKey::from_password(pass)))
        }
        _ => Err(fail(VzStatus::VZ_ERR_INVALID_INPUT, "invalid encryption_mode (expected 0, 1, or 2)")),
    }
}

// ============================================================================
// STATUS, ERROR REPORTING & DEFAULTS
// ============================================================================

/// Returns the compiled C ABI version (`VZ_ABI_VERSION`).
#[unsafe(no_mangle)]
pub extern "C" fn vz_abi_version() -> u32 {
    VZ_ABI_VERSION
}

/// Returns a thread-local NUL-terminated description of the most recent FFI error (or `""`).
#[unsafe(no_mangle)]
pub extern "C" fn vz_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| match slot.try_borrow() {
        Ok(guard) => match guard.as_ref() {
            Some(cstr) => cstr.as_ptr(),
            None => c"".as_ptr(),
        },
        Err(_) => c"".as_ptr(),
    })
}

/// Returns a static NUL-terminated name for `status`.
#[unsafe(no_mangle)]
pub extern "C" fn vz_status_str(status: VzStatus) -> *const c_char {
    match status {
        VzStatus::VZ_OK => c"ok".as_ptr(),
        VzStatus::VZ_ERR_NULL_PTR => c"null pointer".as_ptr(),
        VzStatus::VZ_ERR_INVALID_UTF8 => c"invalid utf-8".as_ptr(),
        VzStatus::VZ_ERR_BAD_MAGIC => c"bad magic".as_ptr(),
        VzStatus::VZ_ERR_CRC_MISMATCH => c"crc32c mismatch".as_ptr(),
        VzStatus::VZ_ERR_INCOMPATIBLE_FEATURE => c"incompatible feature flag".as_ptr(),
        VzStatus::VZ_ERR_BUFFER_TOO_SMALL => c"buffer too small".as_ptr(),
        VzStatus::VZ_ERR_CORRUPT_UNRECOVERABLE => c"corruption exceeds ecc capacity".as_ptr(),
        VzStatus::VZ_ERR_NOT_FOUND => c"not found".as_ptr(),
        VzStatus::VZ_ERR_VALUE_OVERFLOW => c"integer overflow".as_ptr(),
        VzStatus::VZ_ERR_BAD_FORMAT => c"malformed wire format".as_ptr(),
        VzStatus::VZ_ERR_IO => c"i/o error".as_ptr(),
        VzStatus::VZ_ERR_CRYPTO => c"cryptographic authentication or key error".as_ptr(),
        VzStatus::VZ_ERR_COMPRESSION => c"compression or decompression error".as_ptr(),
        VzStatus::VZ_ERR_UNSUPPORTED => c"unsupported codec, hash, or feature".as_ptr(),
        VzStatus::VZ_ERR_INVALID_INPUT => c"invalid input".as_ptr(),
        VzStatus::VZ_ERR_ALREADY_EXISTS => c"already exists".as_ptr(),
    }
}

/// Converts [`VzStatus`] to a POSIX `errno` value (`0` for `VzStatus::VZ_OK`).
#[unsafe(no_mangle)]
pub extern "C" fn vz_status_to_errno(status: VzStatus) -> i32 {
    match status {
        VzStatus::VZ_OK => 0,
        VzStatus::VZ_ERR_NULL_PTR | VzStatus::VZ_ERR_INVALID_UTF8 | VzStatus::VZ_ERR_INVALID_INPUT => 22, // EINVAL
        VzStatus::VZ_ERR_BAD_MAGIC => VzError::BadMagic.to_errno(),
        VzStatus::VZ_ERR_CRC_MISMATCH => VzError::CrcMismatch.to_errno(),
        VzStatus::VZ_ERR_INCOMPATIBLE_FEATURE => VzError::IncompatibleFeature.to_errno(),
        VzStatus::VZ_ERR_BUFFER_TOO_SMALL => VzError::BufferTooSmall.to_errno(),
        VzStatus::VZ_ERR_CORRUPT_UNRECOVERABLE => VzError::CorruptUnrecoverable.to_errno(),
        VzStatus::VZ_ERR_NOT_FOUND => VzError::NotFound.to_errno(),
        VzStatus::VZ_ERR_VALUE_OVERFLOW => VzError::ValueOverflow.to_errno(),
        VzStatus::VZ_ERR_BAD_FORMAT => VzError::BadFormat.to_errno(),
        VzStatus::VZ_ERR_IO => VzError::IoError.to_errno(),
        VzStatus::VZ_ERR_CRYPTO => VzError::CryptoError.to_errno(),
        VzStatus::VZ_ERR_COMPRESSION => VzError::CompressionError.to_errno(),
        VzStatus::VZ_ERR_UNSUPPORTED => VzError::Unsupported.to_errno(),
        VzStatus::VZ_ERR_ALREADY_EXISTS => VzError::AlreadyExists.to_errno(),
    }
}

/// Returns default [`VzOpenOptions`] (`use_mmap = true`, `repair_boot_ecc = true`, unencrypted).
#[unsafe(no_mangle)]
pub extern "C" fn vz_open_options_default() -> VzOpenOptions {
    VzOpenOptions {
        use_mmap: true,
        repair_boot_ecc: true,
        encryption_mode: 0,
        raw_key: [0u8; 32],
        passphrase: ptr::null(),
    }
}

/// Returns default [`VzWriterConfigC`] matching [`VzWriterConfig::default()`].
#[unsafe(no_mangle)]
pub extern "C" fn vz_writer_config_default() -> VzWriterConfigC {
    let d = VzWriterConfig::default();
    VzWriterConfigC {
        default_codec: match d.default_codec {
            CODEC_LZ4 => VzCodec::VZ_CODEC_LZ4,
            CODEC_ZSTD => VzCodec::VZ_CODEC_ZSTD,
            _ => VzCodec::VZ_CODEC_NONE,
        },
        hash_algo: VzHashAlgo::VZ_HASH_BUILTIN,
        zstd_level: d.zstd_level,
        target_cluster_size: d.target_cluster_size,
        multi_cluster_threshold: d.multi_cluster_threshold,
        max_leaf_entries: d.max_leaf_entries as u16,
        max_route_entries: d.max_route_entries as u16,
        enable_boot_ecc: d.enable_boot_ecc,
        rs_parity_k: 0,
        rs_parity_m: 0,
        encryption_mode: 0,
        raw_key: [0u8; 32],
        passphrase: ptr::null(),
    }
}

/// Returns default [`VzEntryOptionsC`] (`0644`, inherits archive default codec).
#[unsafe(no_mangle)]
pub extern "C" fn vz_entry_options_default() -> VzEntryOptionsC {
    VzEntryOptionsC {
        override_codec: false,
        codec: VzCodec::VZ_CODEC_NONE,
        mode: 0o644,
        mtime_ns: 0,
        has_owner: false,
        uid: 0,
        gid: 0,
        has_btime: false,
        btime_ns: 0,
    }
}

/// Returns default [`VzCompactOptionsC`] (`zero_reencode = true`, `enable_boot_ecc = true`).
#[unsafe(no_mangle)]
pub extern "C" fn vz_compact_options_default() -> VzCompactOptionsC {
    let d = CompactOptions::default();
    VzCompactOptionsC {
        zero_reencode: true,
        codec: VzCodec::VZ_CODEC_ZSTD,
        zstd_level: d.zstd_level,
        target_cluster_size: d.target_cluster_size.unwrap_or(1024 * 1024),
        enable_boot_ecc: d.enable_boot_ecc.unwrap_or(true),
        rs_parity_k: 0,
        rs_parity_m: 0,
    }
}

fn split_ns(ns: i64) -> (i64, u32) {
    (
        ns.div_euclid(1_000_000_000),
        ns.rem_euclid(1_000_000_000) as u32,
    )
}

unsafe fn parse_entry_options(kind: u16, opts: *const VzEntryOptionsC) -> EntryOptions {
    if opts.is_null() {
        return EntryOptions {
            kind,
            ..Default::default()
        };
    }
    let o = unsafe { *opts };
    let ext_time = if o.has_btime {
        let (mtime_sec, mtime_nsec) = split_ns(o.mtime_ns);
        let (btime_sec, btime_nsec) = split_ns(o.btime_ns);
        Some(ExtTime {
            mtime_sec,
            btime_sec,
            mtime_nsec,
            btime_nsec,
        })
    } else {
        None
    };
    let owner = if o.has_owner {
        Some(OwnerEntry {
            uid: o.uid,
            gid: o.gid,
            uname: String::new(),
            gname: String::new(),
        })
    } else {
        None
    };
    EntryOptions {
        kind,
        mode: o.mode,
        mtime_ns: o.mtime_ns,
        ext_time,
        owner,
        codec: if o.override_codec {
            Some(o.codec as u8)
        } else {
            None
        },
        ..Default::default()
    }
}

// ============================================================================
// MEMORY FREE HELPERS
// ============================================================================

/// Frees a [`VzBytes`] buffer previously returned by `vz_*` read functions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_bytes_free(buf: *mut VzBytes) {
    if buf.is_null() {
        return;
    }
    let b = unsafe { &mut *buf };
    if !b.data.is_null() && b.cap > 0 {
        unsafe { drop(Vec::from_raw_parts(b.data, b.len, b.cap)) };
    }
    b.data = ptr::null_mut();
    b.len = 0;
    b.cap = 0;
}

/// Frees string fields owned by [`VzStatC`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_stat_free(stat: *mut VzStatC) {
    if stat.is_null() {
        return;
    }
    let s = unsafe { &mut *stat };
    unsafe {
        free_c_string(s.parent_path);
        free_c_string(s.name);
    }
    s.parent_path = ptr::null_mut();
    s.name = ptr::null_mut();
}

/// Frees a [`VzDirList`] previously populated by [`vz_archive_readdir`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_dir_list_free(list: *mut VzDirList) {
    if list.is_null() {
        return;
    }
    let l = unsafe { &mut *list };
    if !l.items.is_null() && l.cap > 0 {
        let mut items = unsafe { Vec::from_raw_parts(l.items, l.len, l.cap) };
        for it in &mut items {
            unsafe { vz_stat_free(it as *mut VzStatC) };
        }
    }
    l.items = ptr::null_mut();
    l.len = 0;
    l.cap = 0;
}

/// Frees a [`VzFuseDirListC`] previously populated by [`vz_fuse_readdirplus`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_dir_free(list: *mut VzFuseDirListC) {
    if list.is_null() {
        return;
    }
    let l = unsafe { &mut *list };
    if !l.items.is_null() && l.cap > 0 {
        let mut items = unsafe { Vec::from_raw_parts(l.items, l.len, l.cap) };
        for it in &mut items {
            unsafe { free_c_string(it.name) };
            it.name = ptr::null_mut();
        }
    }
    l.items = ptr::null_mut();
    l.len = 0;
    l.cap = 0;
}

// ============================================================================
// READER API (`VzArchive`)
// ============================================================================

/// Opens an existing `.vz` archive file on disk (via `mmap` or `File` `pread`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_open(
    path: *const c_char,
    opts: *const VzOpenOptions,
    out: *mut *mut VzArchive,
) -> VzStatus {
    clear_last_error();
    if out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "out pointer is null");
    }
    unsafe { *out = ptr::null_mut() };
    let path_str = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let o = if opts.is_null() {
        vz_open_options_default()
    } else {
        unsafe { *opts }
    };
    let key = match unsafe { parse_key(o.encryption_mode, &o.raw_key, o.passphrase) } {
        Ok(k) => k,
        Err(st) => return st,
    };
    let f = match File::open(path_str) {
        Ok(file) => file,
        Err(e) => return fail(VzStatus::VZ_ERR_IO, &e.to_string()),
    };
    let dyn_reader = if o.use_mmap {
        // SAFETY: Caller ensures opened archive is not truncated concurrently while mapped.
        match unsafe { MmapRangeReader::from_file(&f) } {
            Ok(mm) => DynRangeReader::Mmap(mm),
            Err(_) => DynRangeReader::File(f),
        }
    } else {
        DynRangeReader::File(f)
    };
    let reader = match VzReader::open_with_options(
        dyn_reader,
        VzReaderOptions {
            encryption: key,
            repair_boot_ecc: o.repair_boot_ecc,
        },
    ) {
        Ok(r) => r,
        Err(e) => return fail_vz(e),
    };
    unsafe {
        *out = Box::into_raw(Box::new(VzArchive {
            reader: Arc::new(reader),
        }));
    }
    VzStatus::VZ_OK
}

/// Opens a `.vz` archive from an in-memory byte buffer (copies `data[0..len]` safely).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_open_memory(
    data: *const u8,
    len: usize,
    opts: *const VzOpenOptions,
    out: *mut *mut VzArchive,
) -> VzStatus {
    clear_last_error();
    if out.is_null() || (len > 0 && data.is_null()) {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer passed to vz_archive_open_memory");
    }
    unsafe { *out = ptr::null_mut() };
    let o = if opts.is_null() {
        vz_open_options_default()
    } else {
        unsafe { *opts }
    };
    let key = match unsafe { parse_key(o.encryption_mode, &o.raw_key, o.passphrase) } {
        Ok(k) => k,
        Err(st) => return st,
    };
    let owned = if len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(data, len) }.to_vec()
    };
    let reader = match VzReader::open_with_options(
        DynRangeReader::Bytes(owned),
        VzReaderOptions {
            encryption: key,
            repair_boot_ecc: o.repair_boot_ecc,
        },
    ) {
        Ok(r) => r,
        Err(e) => return fail_vz(e),
    };
    unsafe {
        *out = Box::into_raw(Box::new(VzArchive {
            reader: Arc::new(reader),
        }));
    }
    VzStatus::VZ_OK
}

/// Closes and frees a [`VzArchive`] handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_close(arc: *mut VzArchive) {
    if !arc.is_null() {
        unsafe { drop(Box::from_raw(arc)) };
    }
}

/// Returns total live entries recorded in the active Boot Block slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_total_entries(arc: *const VzArchive) -> u64 {
    if arc.is_null() {
        return 0;
    }
    unsafe { &*arc }.reader.active_slot().total_entries
}

/// Returns the active LSM overlay run count (`1` for single-run / compacted containers).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_lsm_runs(arc: *const VzArchive) -> u32 {
    if arc.is_null() {
        return 0;
    }
    u32::from(unsafe { &*arc }.reader.active_slot().lsm_run_count)
}

/// Returns the active Boot Block slot generation counter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_generation(arc: *const VzArchive) -> u64 {
    if arc.is_null() {
        return 0;
    }
    unsafe { &*arc }.reader.active_slot().generation
}

/// Looks up metadata for `path` in `O(log N)` time. Caller must free `out` via [`vz_stat_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_stat(
    arc: *const VzArchive,
    path: *const c_char,
    out: *mut VzStatC,
) -> VzStatus {
    clear_last_error();
    if arc.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_archive_stat");
    }
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    match unsafe { &*arc }.reader.stat(p) {
        Ok(st) => match VzStatC::from_vz_stat(&st) {
            Ok(c) => {
                unsafe { *out = c };
                VzStatus::VZ_OK
            }
            Err(status) => status,
        },
        Err(e) => fail_vz(e),
    }
}

/// Sets `*out_exists` to `true` if `path` exists cleanly in the live overlay view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_exists(
    arc: *const VzArchive,
    path: *const c_char,
    out_exists: *mut bool,
) -> VzStatus {
    clear_last_error();
    if arc.is_null() || out_exists.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_archive_exists");
    }
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    match unsafe { &*arc }.reader.exists(p) {
        Ok(b) => {
            unsafe { *out_exists = b };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Reads and decodes the entire file payload at `path`. Caller must free `out` via [`vz_bytes_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_read(
    arc: *const VzArchive,
    path: *const c_char,
    out: *mut VzBytes,
) -> VzStatus {
    clear_last_error();
    if arc.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_archive_read");
    }
    unsafe { *out = VzBytes::empty() };
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    match unsafe { &*arc }.reader.read_file(p) {
        Ok(data) => {
            unsafe { *out = VzBytes::from_vec(data) };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Reads `[offset, offset + len)` of `path` (clamped at EOF). Caller must free `out` via [`vz_bytes_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_read_range(
    arc: *const VzArchive,
    path: *const c_char,
    offset: u64,
    len: usize,
    out: *mut VzBytes,
) -> VzStatus {
    clear_last_error();
    if arc.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_archive_read_range");
    }
    unsafe { *out = VzBytes::empty() };
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    match unsafe { &*arc }.reader.read_file_range(p, offset, len) {
        Ok(data) => {
            unsafe { *out = VzBytes::from_vec(data) };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Zero-copy range read into caller-provided `dst[0..dst_cap]` at `offset` (up to `len` bytes,
/// clamped at EOF). Sets `*out_written` to actual bytes written; returns `VZ_ERR_BUFFER_TOO_SMALL`
/// if `dst_cap` is smaller than the clamped read size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_read_range_into(
    arc: *const VzArchive,
    path: *const c_char,
    offset: u64,
    len: usize,
    dst: *mut u8,
    dst_cap: usize,
    out_written: *mut usize,
) -> VzStatus {
    clear_last_error();
    if arc.is_null() || out_written.is_null() || (len > 0 && dst_cap > 0 && dst.is_null()) {
        return fail(
            VzStatus::VZ_ERR_NULL_PTR,
            "null pointer in vz_archive_read_range_into",
        );
    }
    unsafe { *out_written = 0 };
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    if len == 0 {
        return VzStatus::VZ_OK;
    }
    let reader = &unsafe { &*arc }.reader;
    let stat = match reader.stat(p) {
        Ok(s) => s,
        Err(e) => return fail_vz(e),
    };
    if offset >= stat.size {
        return VzStatus::VZ_OK;
    }
    let want = usize::try_from((stat.size - offset).min(len as u64)).unwrap_or(len);
    if dst_cap < want {
        return fail(VzStatus::VZ_ERR_BUFFER_TOO_SMALL, "dst_cap smaller than read size");
    }
    if want == 0 {
        return VzStatus::VZ_OK;
    }
    if dst.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "dst pointer is null");
    }
    let slice = unsafe { slice::from_raw_parts_mut(dst, want) };
    match reader.read_file_range_into(p, offset, slice) {
        Ok(n) => {
            unsafe { *out_written = n };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Zero-allocation directory iteration invoking `visitor` for each entry in `dir_path`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_readdir_visit(
    arc: *const VzArchive,
    dir_path: *const c_char,
    visitor: VzReaddirVisitorFn,
    user_data: *mut c_void,
) -> VzStatus {
    clear_last_error();
    if arc.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "arc pointer is null");
    }
    let Some(cb) = visitor else {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "visitor callback is null");
    };
    let dir = match unsafe { read_c_str(dir_path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let mut stopped = false;
    let res = unsafe { &*arc }.reader.readdir_visit(dir, |ent| {
        if stopped {
            return Ok(());
        }
        let de = &ent.entry;
        let stored_size = match de.payload {
            libvz::DirPayload::Ref { stored_size, .. } => stored_size,
            libvz::DirPayload::Inline { len, .. } => u64::from(len),
        };
        let view = VzStatViewC {
            entry_id: u64::from(de.entry_id_lo),
            size: de.raw_size(),
            stored_size,
            mtime_ns: de.mtime_ns,
            mode: de.posix_mode & 0x0FFF,
            kind: VzFileKind::from_wire(de.kind()),
            codec: de.codec(),
            is_inline: de.is_inline(),
            is_sparse: de.is_sparse(),
            is_multi_cluster: de.is_multi_cluster(),
        };
        let keep_going = unsafe {
            cb(
                &view as *const VzStatViewC,
                ent.name.as_ptr().cast::<c_char>(),
                ent.name.len(),
                user_data,
            )
        };
        if !keep_going {
            stopped = true;
        }
        Ok(())
    });
    res.map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Lists live child entries under directory `dir_path`. Caller must free `out` via [`vz_dir_list_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_readdir(
    arc: *const VzArchive,
    dir_path: *const c_char,
    out: *mut VzDirList,
) -> VzStatus {
    clear_last_error();
    if arc.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_archive_readdir");
    }
    unsafe {
        *out = VzDirList {
            items: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
    }
    let dir = match unsafe { read_c_str(dir_path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let entries = match unsafe { &*arc }.reader.readdir(dir) {
        Ok(list) => list,
        Err(e) => return fail_vz(e),
    };
    let mut c_items: Vec<VzStatC> = Vec::with_capacity(entries.len());
    for entry in &entries {
        match VzStatC::from_vz_stat(entry) {
            Ok(c) => c_items.push(c),
            Err(status) => {
                for mut item in c_items {
                    unsafe { vz_stat_free(&mut item as *mut VzStatC) };
                }
                return status;
            }
        }
    }
    let len = c_items.len();
    let cap = c_items.capacity();
    let ptr = c_items.as_mut_ptr();
    let _ = ManuallyDrop::new(c_items);
    unsafe {
        *out = VzDirList {
            items: ptr,
            len,
            cap,
        };
    }
    VzStatus::VZ_OK
}

/// Extracts all live files and directories in cluster order into `dest_dir`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_extract_to(
    arc: *const VzArchive,
    dest_dir: *const c_char,
    out_count: *mut usize,
) -> VzStatus {
    clear_last_error();
    if arc.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "arc pointer is null");
    }
    let dest_s = match unsafe { read_c_str(dest_dir) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let dest = std::path::Path::new(dest_s);
    if let Err(e) = std::fs::create_dir_all(dest) {
        return fail(VzStatus::VZ_ERR_IO, &e.to_string());
    }
    let mut count = 0usize;
    let res = unsafe { &*arc }.reader.extract_all_with(|entry, data| {
        let rel_dir = entry.stat.parent_path.trim_start_matches('/');
        let host_dir = if rel_dir.is_empty() {
            dest.to_path_buf()
        } else {
            dest.join(rel_dir)
        };
        std::fs::create_dir_all(&host_dir).map_err(|_| VzError::IoError)?;
        let host_path = host_dir.join(&entry.stat.name);
        if (entry.stat.kind & KIND_MASK) == KIND_DIR {
            std::fs::create_dir_all(&host_path).map_err(|_| VzError::IoError)?;
        } else {
            std::fs::write(&host_path, data).map_err(|_| VzError::IoError)?;
        }
        count += 1;
        Ok(())
    });
    match res {
        Ok(()) => {
            if !out_count.is_null() {
                unsafe { *out_count = count };
            }
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Compacts `arc` into a fresh single-run container at `dest_path` (zero re-encoding by default).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_compact(
    arc: *const VzArchive,
    dest_path: *const c_char,
    opts: *const VzCompactOptionsC,
) -> VzStatus {
    clear_last_error();
    if arc.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "arc pointer is null");
    }
    let dest = match unsafe { read_c_str(dest_path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let c = if opts.is_null() {
        vz_compact_options_default()
    } else {
        unsafe { *opts }
    };
    let copts = CompactOptions {
        reencode_codec: if c.zero_reencode {
            None
        } else {
            Some(c.codec as u8)
        },
        zstd_level: c.zstd_level,
        target_cluster_size: if c.target_cluster_size > 0 {
            Some(c.target_cluster_size)
        } else {
            None
        },
        enable_boot_ecc: Some(c.enable_boot_ecc),
        rs_parity: if c.rs_parity_k > 0 && c.rs_parity_m > 0 {
            Some((c.rs_parity_k, c.rs_parity_m))
        } else {
            None
        },
        ..Default::default()
    };
    let f = match File::create(dest) {
        Ok(file) => file,
        Err(e) => return fail(VzStatus::VZ_ERR_IO, &e.to_string()),
    };
    let bw = BufWriter::with_capacity(256 * 1024, f);
    match compact_archive_with_options(&unsafe { &*arc }.reader, bw, copts) {
        Ok(mut writer_done) => {
            if let Err(e) = writer_done.flush() {
                return fail(VzStatus::VZ_ERR_IO, &e.to_string());
            }
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Verifies Boot ECC, cluster CRCs, B+Tree structure, and RS parity on `path`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_verify_file(
    path: *const c_char,
    opts: *const VzOpenOptions,
    out: *mut VzVerifyReportC,
) -> VzStatus {
    clear_last_error();
    if out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "out pointer is null");
    }
    let path_str = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let o = if opts.is_null() {
        vz_open_options_default()
    } else {
        unsafe { *opts }
    };
    let key = match unsafe { parse_key(o.encryption_mode, &o.raw_key, o.passphrase) } {
        Ok(k) => k,
        Err(st) => return st,
    };
    let f = match File::open(path_str) {
        Ok(file) => file,
        Err(e) => return fail(VzStatus::VZ_ERR_IO, &e.to_string()),
    };
    match verify_archive(&f, key) {
        Ok(rep) => {
            unsafe {
                *out = VzVerifyReportC {
                    boot_ecc_ok: rep.boot_ecc_ok,
                    boot_ecc_repaired: rep.boot_ecc_repaired_page.is_some(),
                    boot_ecc_repaired_page: rep.boot_ecc_repaired_page.unwrap_or(0),
                    clusters_checked: rep.clusters_checked,
                    parity_stripes_checked: rep.parity_stripes_checked,
                    error_count: rep.errors.len(),
                };
            }
            if rep.is_clean() {
                VzStatus::VZ_OK
            } else {
                fail(VzStatus::VZ_ERR_BAD_FORMAT, &rep.errors.join("; "))
            }
        }
        Err(e) => fail_vz(e),
    }
}

/// Repairs single-page Boot ECC and `<= M` RS-corrupted clusters at `path` in-place.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_repair_file(
    path: *const c_char,
    out: *mut VzRepairReportC,
) -> VzStatus {
    clear_last_error();
    let path_str = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let mut f = match OpenOptions::new().read(true).write(true).open(path_str) {
        Ok(file) => file,
        Err(e) => return fail(VzStatus::VZ_ERR_IO, &e.to_string()),
    };
    match repair_file(&mut f) {
        Ok(rep) => {
            if !out.is_null() {
                unsafe {
                    *out = VzRepairReportC {
                        boot_repaired: rep.boot_page_repaired.is_some(),
                        boot_repaired_page: rep.boot_page_repaired.unwrap_or(0),
                        data_clusters_repaired: rep.data_clusters_repaired,
                        parity_clusters_repaired: rep.parity_clusters_repaired,
                    };
                }
            }
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

// ============================================================================
// WRITER API (`VzWriterHandle`)
// ============================================================================

/// Creates a new `.vz` archive file at `path`. Finalize with [`vz_writer_finish`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_create(
    path: *const c_char,
    cfg: *const VzWriterConfigC,
    out: *mut *mut VzWriterHandle,
) -> VzStatus {
    clear_last_error();
    if out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "out pointer is null");
    }
    unsafe { *out = ptr::null_mut() };
    let path_str = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let c = if cfg.is_null() {
        vz_writer_config_default()
    } else {
        unsafe { *cfg }
    };
    let key = match unsafe { parse_key(c.encryption_mode, &c.raw_key, c.passphrase) } {
        Ok(k) => k,
        Err(st) => return st,
    };
    let f = match File::create(path_str) {
        Ok(file) => file,
        Err(e) => return fail(VzStatus::VZ_ERR_IO, &e.to_string()),
    };
    let mut wcfg = VzWriterConfig {
        default_codec: c.default_codec as u8,
        hash_algo: c.hash_algo as u8,
        zstd_level: c.zstd_level,
        target_cluster_size: c.target_cluster_size,
        multi_cluster_threshold: c.multi_cluster_threshold,
        max_leaf_entries: usize::from(c.max_leaf_entries),
        max_route_entries: usize::from(c.max_route_entries),
        enable_boot_ecc: c.enable_boot_ecc,
        encryption: key,
        ..Default::default()
    };
    if c.rs_parity_k > 0 && c.rs_parity_m > 0 {
        wcfg.rs_parity = Some((c.rs_parity_k, c.rs_parity_m));
    }
    let bw = BufWriter::with_capacity(256 * 1024, f);
    match VzWriter::new(bw, wcfg) {
        Ok(writer) => {
            unsafe { *out = Box::into_raw(Box::new(VzWriterHandle { writer: Some(writer) })) };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Adds an explicit directory (`KIND_DIR`) to `w`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_add_dir(
    w: *mut VzWriterHandle,
    path: *const c_char,
    mode: u16,
    mtime_ns: i64,
) -> VzStatus {
    clear_last_error();
    if w.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "writer handle is null");
    }
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let Some(ref mut writer) = unsafe { &mut *w }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "writer already finalized");
    };
    writer.add_dir(p, mode, mtime_ns).map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Adds a regular file payload `data[0..len]` at `path`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_add_file(
    w: *mut VzWriterHandle,
    path: *const c_char,
    data: *const u8,
    len: usize,
    opts: *const VzEntryOptionsC,
) -> VzStatus {
    clear_last_error();
    if w.is_null() || (len > 0 && data.is_null()) {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_writer_add_file");
    }
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let bytes = if len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(data, len) }
    };
    let eo = unsafe { parse_entry_options(KIND_REG, opts) };
    let Some(ref mut writer) = unsafe { &mut *w }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "writer already finalized");
    };
    writer
        .add_file_with_options(p, bytes, eo)
        .map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Adds a special filesystem node (`VZ_KIND_FIFO`, `VZ_KIND_CHR`, `VZ_KIND_BLK`, `VZ_KIND_SOCK`,
/// or `VZ_KIND_DIR`) using the provided [`VzEntryOptionsC`] (optional).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_add_special(
    w: *mut VzWriterHandle,
    path: *const c_char,
    kind: VzFileKind,
    opts: *const VzEntryOptionsC,
) -> VzStatus {
    clear_last_error();
    if w.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "writer handle is null");
    }
    let Some(wire_kind) = kind.to_wire() else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "unsupported VzFileKind");
    };
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let eo = unsafe { parse_entry_options(wire_kind, opts) };
    let Some(ref mut writer) = unsafe { &mut *w }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "writer already finalized");
    };
    writer
        .add_file_with_options(p, &[], eo)
        .map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Begins writing a potentially multi-GB file incrementally in `O(cluster_size)` memory.
/// Feed chunks via [`vz_writer_file_write`] and close with [`vz_writer_file_end`] (or [`vz_writer_file_abort`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_file_begin(
    w: *mut VzWriterHandle,
    path: *const c_char,
    opts: *const VzEntryOptionsC,
    out: *mut *mut VzStreamFileHandle,
) -> VzStatus {
    clear_last_error();
    if w.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_writer_file_begin");
    }
    unsafe { *out = ptr::null_mut() };
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let eo = unsafe { parse_entry_options(KIND_REG, opts) };
    let Some(ref mut writer) = unsafe { &mut *w }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "writer already finalized");
    };
    match writer.begin_streamed_file(p, eo) {
        Ok(sf) => {
            unsafe {
                *out = Box::into_raw(Box::new(VzStreamFileHandle { state: Some(sf) }));
            }
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Writes `data[0..len]` into an active [`VzStreamFileHandle`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_file_write(
    w: *mut VzWriterHandle,
    sf: *mut VzStreamFileHandle,
    data: *const u8,
    len: usize,
) -> VzStatus {
    clear_last_error();
    if w.is_null() || sf.is_null() || (len > 0 && data.is_null()) {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_writer_file_write");
    }
    if len == 0 {
        return VzStatus::VZ_OK;
    }
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let Some(ref mut writer) = unsafe { &mut *w }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "writer already finalized");
    };
    let Some(ref mut state) = unsafe { &mut *sf }.state else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "streamed file already finished");
    };
    writer
        .write_streamed_chunk(state, slice)
        .map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Finalizes a streamed file into `w` and frees `sf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_file_end(
    w: *mut VzWriterHandle,
    sf: *mut VzStreamFileHandle,
) -> VzStatus {
    clear_last_error();
    if w.is_null() || sf.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_writer_file_end");
    }
    let mut boxed_sf = unsafe { Box::from_raw(sf) };
    let Some(state) = boxed_sf.state.take() else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "streamed file already finished");
    };
    let Some(ref mut writer) = unsafe { &mut *w }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "writer already finalized");
    };
    writer
        .finish_streamed_file(state)
        .map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Aborts and frees an unfinished [`VzStreamFileHandle`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_file_abort(sf: *mut VzStreamFileHandle) {
    if !sf.is_null() {
        unsafe { drop(Box::from_raw(sf)) };
    }
}

/// Adds a symbolic link (`KIND_LNK`) pointing to `target`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_add_symlink(
    w: *mut VzWriterHandle,
    link_path: *const c_char,
    target: *const c_char,
    mode: u16,
    mtime_ns: i64,
) -> VzStatus {
    clear_last_error();
    if w.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "writer handle is null");
    }
    let lp = match unsafe { read_c_str(link_path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let tgt = match unsafe { read_c_str(target) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let Some(ref mut writer) = unsafe { &mut *w }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "writer already finalized");
    };
    writer
        .add_file_with_options(
            lp,
            tgt.as_bytes(),
            EntryOptions {
                kind: KIND_LNK,
                mode,
                mtime_ns,
                ..Default::default()
            },
        )
        .map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Adds a hardlink sharing the existing target entry's `entry_id` and payload.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_add_hardlink(
    w: *mut VzWriterHandle,
    link_path: *const c_char,
    target_path: *const c_char,
) -> VzStatus {
    clear_last_error();
    if w.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "writer handle is null");
    }
    let lp = match unsafe { read_c_str(link_path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let tp = match unsafe { read_c_str(target_path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let Some(ref mut writer) = unsafe { &mut *w }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "writer already finalized");
    };
    writer.add_hardlink(lp, tp).map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Finalizes the archive B+Tree & Boot Block, flushes to disk, and frees `w`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_finish(w: *mut VzWriterHandle) -> VzStatus {
    clear_last_error();
    if w.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "writer handle is null");
    }
    let mut boxed = unsafe { Box::from_raw(w) };
    let Some(writer) = boxed.writer.take() else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "writer already finalized");
    };
    match writer.finish() {
        Ok(mut bw) => {
            if let Err(e) = bw.flush() {
                return fail(VzStatus::VZ_ERR_IO, &e.to_string());
            }
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Aborts and frees an unfinalized [`VzWriterHandle`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_writer_abort(w: *mut VzWriterHandle) {
    if !w.is_null() {
        unsafe { drop(Box::from_raw(w)) };
    }
}

// ============================================================================
// LSM OVERLAY APPEND API (`VzAppendHandle`)
// ============================================================================

/// Opens an existing `.vz` archive at `path` for incremental LSM delta overlay append.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_append_open(
    path: *const c_char,
    opts: *const VzOpenOptions,
    out: *mut *mut VzAppendHandle,
) -> VzStatus {
    clear_last_error();
    if out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "out pointer is null");
    }
    unsafe { *out = ptr::null_mut() };
    let path_str = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let o = if opts.is_null() {
        vz_open_options_default()
    } else {
        unsafe { *opts }
    };
    let key = match unsafe { parse_key(o.encryption_mode, &o.raw_key, o.passphrase) } {
        Ok(k) => k,
        Err(st) => return st,
    };
    let f = match OpenOptions::new().read(true).write(true).open(path_str) {
        Ok(file) => file,
        Err(e) => return fail(VzStatus::VZ_ERR_IO, &e.to_string()),
    };
    match LsmAppendWriter::open(f, key, 1024, 128) {
        Ok(writer) => {
            unsafe { *out = Box::into_raw(Box::new(VzAppendHandle { writer: Some(writer) })) };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Appends or overwrites a directory (`KIND_DIR`) inside the active LSM delta run.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_append_add_dir(
    a: *mut VzAppendHandle,
    path: *const c_char,
    mode: u16,
    mtime_ns: i64,
) -> VzStatus {
    clear_last_error();
    if a.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "append handle is null");
    }
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let Some(ref mut writer) = unsafe { &mut *a }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "append handle already finalized");
    };
    writer.add_dir(p, mode, mtime_ns).map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Appends or overwrites a regular file payload inside the active LSM delta run.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_append_add_file(
    a: *mut VzAppendHandle,
    path: *const c_char,
    data: *const u8,
    len: usize,
    opts: *const VzEntryOptionsC,
) -> VzStatus {
    clear_last_error();
    if a.is_null() || (len > 0 && data.is_null()) {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_append_add_file");
    }
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let bytes = if len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(data, len) }
    };
    let eo = unsafe { parse_entry_options(KIND_REG, opts) };
    let Some(ref mut writer) = unsafe { &mut *a }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "append handle already finalized");
    };
    writer
        .add_file_with_options(p, bytes, eo)
        .map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Appends or overwrites a symbolic link (`KIND_LNK`) inside the active LSM delta run.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_append_add_symlink(
    a: *mut VzAppendHandle,
    link_path: *const c_char,
    target: *const c_char,
    mode: u16,
    mtime_ns: i64,
) -> VzStatus {
    clear_last_error();
    if a.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "append handle is null");
    }
    let lp = match unsafe { read_c_str(link_path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let tgt = match unsafe { read_c_str(target) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let Some(ref mut writer) = unsafe { &mut *a }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "append handle already finalized");
    };
    writer
        .add_symlink(lp, tgt, mode, mtime_ns)
        .map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Appends a hardlink sharing an existing entry's `entry_id` and payload inside the LSM delta run.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_append_add_hardlink(
    a: *mut VzAppendHandle,
    link_path: *const c_char,
    target_path: *const c_char,
) -> VzStatus {
    clear_last_error();
    if a.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "append handle is null");
    }
    let lp = match unsafe { read_c_str(link_path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let tp = match unsafe { read_c_str(target_path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let Some(ref mut writer) = unsafe { &mut *a }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "append handle already finalized");
    };
    writer
        .add_hardlink(lp, tp)
        .map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Emits a `FLAG_TOMBSTONE` deletion record for `path` in the LSM delta run.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_append_delete(
    a: *mut VzAppendHandle,
    path: *const c_char,
) -> VzStatus {
    clear_last_error();
    if a.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "append handle is null");
    }
    let p = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let Some(ref mut writer) = unsafe { &mut *a }.writer else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "append handle already finalized");
    };
    writer.delete(p).map_or_else(fail_vz, |()| VzStatus::VZ_OK)
}

/// Commits the LSM delta run, updates the Boot Block slot + ECC, and frees `a`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_append_finish(a: *mut VzAppendHandle) -> VzStatus {
    clear_last_error();
    if a.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "append handle is null");
    }
    let mut boxed = unsafe { Box::from_raw(a) };
    let Some(writer) = boxed.writer.take() else {
        return fail(VzStatus::VZ_ERR_INVALID_INPUT, "append handle already finalized");
    };
    match writer.finish() {
        Ok(mut f) => {
            if let Err(e) = f.flush() {
                return fail(VzStatus::VZ_ERR_IO, &e.to_string());
            }
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Aborts and frees an unfinalized [`VzAppendHandle`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_append_abort(a: *mut VzAppendHandle) {
    if !a.is_null() {
        unsafe { drop(Box::from_raw(a)) };
    }
}

// ============================================================================
// FUSE3 VFS API (`VzFuseVol`, `VzFuseFh`)
// ============================================================================

/// Mounts an opened [`VzArchive`] into an in-memory `O(1)`/`O(log N)` FUSE3 volume.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_mount(
    arc: *const VzArchive,
    out: *mut *mut VzFuseVol,
) -> VzStatus {
    clear_last_error();
    if arc.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_mount");
    }
    unsafe { *out = ptr::null_mut() };
    let r = Arc::clone(&unsafe { &*arc }.reader);
    match FuseVolume::mount(r) {
        Ok(vol) => {
            unsafe { *out = Box::into_raw(Box::new(VzFuseVol { vol })) };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Unmounts and frees a [`VzFuseVol`] handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_unmount(vol: *mut VzFuseVol) {
    if !vol.is_null() {
        unsafe { drop(Box::from_raw(vol)) };
    }
}

/// FUSE3 `getattr(ino)` (`O(1)`, zero disk I/O).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_getattr(
    vol: *const VzFuseVol,
    ino: u64,
    out: *mut VzFuseAttrC,
) -> VzStatus {
    clear_last_error();
    if vol.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_getattr");
    }
    match unsafe { &*vol }.vol.getattr(ino) {
        Ok(attr) => {
            unsafe { *out = attr.into() };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// FUSE3 `lookup(parent_ino, name)` (`O(log dir_len)`, zero disk I/O).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_lookup(
    vol: *const VzFuseVol,
    parent_ino: u64,
    name: *const c_char,
    out: *mut VzFuseAttrC,
) -> VzStatus {
    clear_last_error();
    if vol.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_lookup");
    }
    let n = match unsafe { read_c_str(name) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    match unsafe { &*vol }.vol.lookup(parent_ino, n) {
        Ok(attr) => {
            unsafe { *out = attr.into() };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// FUSE3 `readdirplus(ino, offset, limit)` paginated listing with full attributes (zero disk I/O).
/// Caller must free `out` via [`vz_fuse_dir_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_readdirplus(
    vol: *const VzFuseVol,
    ino: u64,
    offset: u64,
    limit: usize,
    out: *mut VzFuseDirListC,
) -> VzStatus {
    clear_last_error();
    if vol.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_readdirplus");
    }
    unsafe {
        *out = VzFuseDirListC {
            items: ptr::null_mut(),
            len: 0,
            cap: 0,
        };
    }
    let entries = match unsafe { &*vol }.vol.readdirplus(ino, offset, limit) {
        Ok(list) => list,
        Err(e) => return fail_vz(e),
    };
    let mut c_items: Vec<VzFuseDirEntryPlusC> = Vec::with_capacity(entries.len());
    for ent in entries {
        let name_ptr = match alloc_c_string(&ent.name) {
            Ok(p) => p,
            Err(status) => {
                for it in c_items {
                    unsafe { free_c_string(it.name) };
                }
                return status;
            }
        };
        c_items.push(VzFuseDirEntryPlusC {
            ino: ent.ino,
            offset: ent.offset,
            kind: VzFileKind::from_fuse(ent.kind),
            name: name_ptr,
            attr: ent.attr.into(),
        });
    }
    let len = c_items.len();
    let cap = c_items.capacity();
    let ptr = c_items.as_mut_ptr();
    let _ = ManuallyDrop::new(c_items);
    unsafe {
        *out = VzFuseDirListC {
            items: ptr,
            len,
            cap,
        };
    }
    VzStatus::VZ_OK
}

/// Opens a FUSE3 file handle (`fh`) on `ino`, pre-loading any `TAG_CHUNK_TABLE` once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_open(
    vol: *const VzFuseVol,
    ino: u64,
    out: *mut *mut VzFuseFh,
) -> VzStatus {
    clear_last_error();
    if vol.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_open");
    }
    unsafe { *out = ptr::null_mut() };
    match unsafe { &*vol }.vol.open(ino) {
        Ok(fh) => {
            unsafe { *out = Box::into_raw(Box::new(VzFuseFh { fh })) };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Closes and frees a [`VzFuseFh`] handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_close(fh: *mut VzFuseFh) {
    if !fh.is_null() {
        unsafe { drop(Box::from_raw(fh)) };
    }
}

/// Reads `[offset, offset + len)` from `fh` (chunk-cached for compressed/encrypted streams,
/// exact `read_at` for `CODEC_NONE`, zero-I/O for sparse holes). Caller frees `out` via [`vz_bytes_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_read(
    vol: *const VzFuseVol,
    fh: *const VzFuseFh,
    offset: u64,
    len: usize,
    out: *mut VzBytes,
) -> VzStatus {
    clear_last_error();
    if vol.is_null() || fh.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_read");
    }
    unsafe { *out = VzBytes::empty() };
    match unsafe { &*vol }.vol.read(&unsafe { &*fh }.fh, offset, len) {
        Ok(data) => {
            unsafe { *out = VzBytes::from_vec(data) };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Zero-copy FUSE3 `read(fh, offset, len)` directly into caller-provided `dst[0..dst_cap]`.
/// Sets `*out_written` to actual bytes written; returns `VZ_ERR_BUFFER_TOO_SMALL` if `dst_cap`
/// is smaller than the clamped read size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_read_into(
    vol: *const VzFuseVol,
    fh: *const VzFuseFh,
    offset: u64,
    len: usize,
    dst: *mut u8,
    dst_cap: usize,
    out_written: *mut usize,
) -> VzStatus {
    clear_last_error();
    if vol.is_null() || fh.is_null() || out_written.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_read_into");
    }
    unsafe { *out_written = 0 };
    if len == 0 {
        return VzStatus::VZ_OK;
    }
    let handle = &unsafe { &*fh }.fh;
    let file_size = handle.attr().size;
    if offset >= file_size {
        return VzStatus::VZ_OK;
    }
    let want = usize::try_from((file_size - offset).min(len as u64)).unwrap_or(len);
    if dst_cap < want {
        return fail(
            VzStatus::VZ_ERR_BUFFER_TOO_SMALL,
            "dst_cap smaller than read size",
        );
    }
    if want == 0 {
        return VzStatus::VZ_OK;
    }
    if dst.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "dst pointer is null");
    }
    let slice = unsafe { slice::from_raw_parts_mut(dst, want) };
    match unsafe { &*vol }.vol.read_into(handle, offset, slice) {
        Ok(n) => {
            unsafe { *out_written = n };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// FUSE3 `readlink(ino)`: reads symlink target bytes for `VZ_KIND_LNK` inodes.
/// Caller frees `out` via [`vz_bytes_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_readlink(
    vol: *const VzFuseVol,
    ino: u64,
    out: *mut VzBytes,
) -> VzStatus {
    clear_last_error();
    if vol.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_readlink");
    }
    unsafe { *out = VzBytes::empty() };
    match unsafe { &*vol }.vol.readlink(ino) {
        Ok(data) => {
            unsafe { *out = VzBytes::from_vec(data) };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// FUSE3 `getxattr(ino, name)`: `O(xattrs.len())` zero-I/O extended attribute read.
/// Caller frees `out` via [`vz_bytes_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_getxattr(
    vol: *const VzFuseVol,
    ino: u64,
    name: *const c_char,
    out: *mut VzBytes,
) -> VzStatus {
    clear_last_error();
    if vol.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_getxattr");
    }
    unsafe { *out = VzBytes::empty() };
    let n = match unsafe { read_c_str(name) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    match unsafe { &*vol }.vol.getxattr(ino, n) {
        Ok(slice) => {
            unsafe { *out = VzBytes::from_vec(slice.to_vec()) };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// FUSE3 `listxattr(ino)`: returns NUL-separated POSIX attribute names (`name1\0name2\0...`).
/// Caller frees `out` via [`vz_bytes_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_listxattr(
    vol: *const VzFuseVol,
    ino: u64,
    out: *mut VzBytes,
) -> VzStatus {
    clear_last_error();
    if vol.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_listxattr");
    }
    unsafe { *out = VzBytes::empty() };
    match unsafe { &*vol }.vol.listxattr(ino) {
        Ok(names) => {
            let cap: usize = names.iter().map(|s| s.len() + 1).sum();
            let mut packed = Vec::with_capacity(cap);
            for s in names {
                packed.extend_from_slice(s.as_bytes());
                packed.push(0);
            }
            unsafe { *out = VzBytes::from_vec(packed) };
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

/// Fills container-wide `statfs` counters from `vol`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_fuse_statfs(
    vol: *const VzFuseVol,
    out: *mut VzFuseStatFsC,
) -> VzStatus {
    clear_last_error();
    if vol.is_null() || out.is_null() {
        return fail(VzStatus::VZ_ERR_NULL_PTR, "null pointer in vz_fuse_statfs");
    }
    let st = unsafe { &*vol }.vol.statfs();
    unsafe {
        *out = VzFuseStatFsC {
            blocks: st.blocks,
            bfree: st.bfree,
            bavail: st.bavail,
            files: st.files,
            ffree: st.ffree,
            bsize: st.bsize,
            namelen: st.namelen,
            frsize: st.frsize,
        };
    }
    VzStatus::VZ_OK
}
