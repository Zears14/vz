//! C/C++ FFI bindings for `libvz` (`libvz.so` / `libvz.a` + `cbindgen`-generated `vz.h`).
//!
//! All `extern "C"` functions validate pointers, never panic/unwrap inside library paths,
//! and return explicit [`VzStatus`] error codes (with optional thread-local detail via
//! [`vz_last_error`]).

#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::ptr;

use libvz::fuse::FUSE_ROOT_ID;
use libvz::{CompactOptions, EncryptionKey, EntryOptions, ExtTime, OwnerEntry, VzError, VzWriterConfig};

pub mod archive;
pub mod fuse;
pub mod types;
pub mod writer;

pub use archive::*;
pub use fuse::*;
pub use types::*;
pub use writer::*;

/// ABI version bumped on breaking C/C++ layout or symbol changes.
pub const VZ_ABI_VERSION: u32 = 1;

/// Root inode ID (`1`) exported for C/C++ FUSE3 consumers.
pub const VZ_FUSE_ROOT_ID: u64 = 1;
const _: () = assert!(VZ_FUSE_ROOT_ID == FUSE_ROOT_ID);

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub(crate) fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        if let Ok(mut guard) = slot.try_borrow_mut() {
            *guard = None;
        }
    });
}

pub(crate) fn set_last_error(msg: &str) {
    let clean = msg.replace('\0', " ");
    if let Ok(cstr) = CString::new(clean) {
        LAST_ERROR.with(|slot| {
            if let Ok(mut guard) = slot.try_borrow_mut() {
                *guard = Some(cstr);
            }
        });
    }
}

pub(crate) fn fail(status: VzStatus, msg: &str) -> VzStatus {
    set_last_error(msg);
    status
}

pub(crate) fn fail_vz(err: VzError) -> VzStatus {
    let status = VzStatus::from(err);
    set_last_error(&format!("{err:?}"));
    status
}

// ============================================================================
// STRING / KEY / OPTION CONVERSION HELPERS
// ============================================================================

pub(crate) fn alloc_c_string(s: &str) -> Result<*mut c_char, VzStatus> {
    let clean = s.replace('\0', "");
    CString::new(clean)
        .map(CString::into_raw)
        .map_err(|_| fail(VzStatus::VZ_ERR_INVALID_UTF8, "interior nul in string"))
}

pub(crate) unsafe fn free_c_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)) };
    }
}

pub(crate) unsafe fn read_c_str<'a>(ptr: *const c_char) -> Result<&'a str, VzStatus> {
    if ptr.is_null() {
        return Err(fail(VzStatus::VZ_ERR_NULL_PTR, "unexpected null string pointer"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| fail(VzStatus::VZ_ERR_INVALID_UTF8, "string is not valid UTF-8"))
}

pub(crate) unsafe fn parse_key(
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
            libvz::CODEC_LZ4 => VzCodec::VZ_CODEC_LZ4,
            libvz::CODEC_ZSTD => VzCodec::VZ_CODEC_ZSTD,
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

pub(crate) fn split_ns(ns: i64) -> (i64, u32) {
    (
        ns.div_euclid(1_000_000_000),
        ns.rem_euclid(1_000_000_000) as u32,
    )
}

pub(crate) unsafe fn parse_entry_options(kind: u16, opts: *const VzEntryOptionsC) -> EntryOptions {
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

