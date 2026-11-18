use std::ffi::{c_char, c_void};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::mem::ManuallyDrop;
use std::ptr;
use std::slice;
use std::sync::Arc;

use libvz::{
    CompactOptions, InPlaceCompactOptions, KIND_DIR, KIND_MASK, MmapRangeReader, VzError,
    VzReader, VzReaderOptions, compact_archive_with_options, compact_file_in_place, repair_file,
    verify_archive,
};

use crate::types::*;
use crate::{
    clear_last_error, fail, fail_vz, parse_key, read_c_str, vz_compact_options_default,
    vz_open_options_default, vz_stat_free,
};

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

/// Compacts (or resumes an interrupted compaction of) `path` in-place using bounded RAM (`batch_bytes`,
/// defaulting to `4 MiB` when `0`) and zero `2x` disk duplication.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vz_archive_compact_in_place(
    path: *const c_char,
    open_opts: *const VzOpenOptions,
    compact_opts: *const VzCompactOptionsC,
    batch_bytes: usize,
    out_compacted_bytes: *mut u64,
) -> VzStatus {
    clear_last_error();
    let path_str = match unsafe { read_c_str(path) } {
        Ok(s) => s,
        Err(st) => return st,
    };
    let o = if open_opts.is_null() {
        vz_open_options_default()
    } else {
        unsafe { *open_opts }
    };
    let key = match unsafe { parse_key(o.encryption_mode, &o.raw_key, o.passphrase) } {
        Ok(k) => k,
        Err(st) => return st,
    };
    let mut copts = InPlaceCompactOptions {
        encryption: key,
        ..Default::default()
    };
    if batch_bytes > 0 {
        copts.batch_bytes = batch_bytes;
    }
    if !compact_opts.is_null() {
        let c = unsafe { *compact_opts };
        copts.enable_boot_ecc = Some(c.enable_boot_ecc);
        if c.target_cluster_size > 0 {
            copts.target_cluster_size = Some(c.target_cluster_size);
        }
        if c.rs_parity_k > 0 && c.rs_parity_m > 0 {
            copts.rs_parity = Some((c.rs_parity_k, c.rs_parity_m));
        }
    }
    let mut f = match OpenOptions::new().read(true).write(true).open(path_str) {
        Ok(file) => file,
        Err(e) => return fail(VzStatus::VZ_ERR_IO, &e.to_string()),
    };
    match compact_file_in_place(&mut f, copts) {
        Ok(rep) => {
            if !out_compacted_bytes.is_null() {
                unsafe { *out_compacted_bytes = rep.compacted_bytes };
            }
            VzStatus::VZ_OK
        }
        Err(e) => fail_vz(e),
    }
}

