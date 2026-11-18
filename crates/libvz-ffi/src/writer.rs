use std::ffi::c_char;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::ptr;
use std::slice;

use libvz::{EntryOptions, KIND_LNK, KIND_REG, LsmAppendWriter, VzWriter, VzWriterConfig};

use crate::types::*;
use crate::{
    clear_last_error, fail, fail_vz, parse_entry_options, parse_key, read_c_str,
    vz_open_options_default, vz_writer_config_default,
};

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

