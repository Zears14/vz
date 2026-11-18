use std::ffi::c_char;
use std::mem::ManuallyDrop;
use std::ptr;
use std::slice;
use std::sync::Arc;

use libvz::fuse::FuseVolume;

use crate::types::*;
use crate::{alloc_c_string, clear_last_error, fail, fail_vz, free_c_string, read_c_str};

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
