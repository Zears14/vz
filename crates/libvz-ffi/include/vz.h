#ifndef VZ_H
#define VZ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ABI version bumped on breaking C/C++ layout or symbol changes.
#define VZ_ABI_VERSION 1

// Root inode ID (`1`) exported for C/C++ FUSE3 consumers.
#define VZ_FUSE_ROOT_ID 1

// FFI status codes returned by every fallible `vz_*` function.
enum VzStatus
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : int32_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
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
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum VzStatus VzStatus;
#else
typedef int32_t VzStatus;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

// Payload compression codecs supported by VZ v1.0.
enum VzCodec
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint8_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
    VZ_CODEC_NONE = 0,
    VZ_CODEC_LZ4 = 1,
    VZ_CODEC_ZSTD = 2,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum VzCodec VzCodec;
#else
typedef uint8_t VzCodec;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

// Directory/entry path hashing algorithms supported by VZ v1.0.
enum VzHashAlgo
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint8_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
    VZ_HASH_BUILTIN = 0,
    VZ_HASH_XXH3_64 = 1,
    VZ_HASH_BLAKE3 = 2,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum VzHashAlgo VzHashAlgo;
#else
typedef uint8_t VzHashAlgo;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

// POSIX / VFS entry kind discriminator.
enum VzFileKind
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint8_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
    VZ_KIND_REG = 0,
    VZ_KIND_DIR = 1,
    VZ_KIND_LNK = 2,
    VZ_KIND_FIFO = 3,
    VZ_KIND_CHR = 4,
    VZ_KIND_BLK = 5,
    VZ_KIND_SOCK = 6,
    VZ_KIND_OTHER = 255,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum VzFileKind VzFileKind;
#else
typedef uint8_t VzFileKind;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

// Opaque incremental LSM overlay writer handle. Finalized via [`vz_append_finish`] or [`vz_append_abort`].
typedef struct VzAppendHandle VzAppendHandle;

// Opaque read-only archive handle. Freed with [`vz_archive_close`].
typedef struct VzArchive VzArchive;

// Opaque open FUSE3 file handle (`fh`). Freed with [`vz_fuse_close`].
typedef struct VzFuseFh VzFuseFh;

// Opaque mounted FUSE3 VFS volume handle. Freed with [`vz_fuse_unmount`].
typedef struct VzFuseVol VzFuseVol;

// Opaque chunked streaming file handle started by [`vz_writer_file_begin`].
typedef struct VzStreamFileHandle VzStreamFileHandle;

// Opaque streaming archive writer handle. Finalized via [`vz_writer_finish`] or [`vz_writer_abort`].
typedef struct VzWriterHandle VzWriterHandle;

// Archive open options for [`vz_archive_open`], [`vz_archive_open_memory`], [`vz_append_open`],
// and [`vz_verify_file`].
typedef struct VzOpenOptions {
    // Use memory-mapped zero-copy reads (`mmap`) when opening files (`true` recommended).
    bool use_mmap;
    // Repair single-page Boot Block ECC errors automatically on open (`true` recommended).
    bool repair_boot_ecc;
    // Key mode: `0` = none, `1` = raw 256-bit key (`raw_key`), `2` = Argon2id passphrase.
    uint8_t encryption_mode;
    uint8_t raw_key[32];
    // Optional NUL-terminated UTF-8 passphrase when `encryption_mode == 2`.
    const char *passphrase;
} VzOpenOptions;

// Archive writer configuration for [`vz_writer_create`].
typedef struct VzWriterConfigC {
    VzCodec default_codec;
    VzHashAlgo hash_algo;
    int32_t zstd_level;
    uintptr_t target_cluster_size;
    uintptr_t multi_cluster_threshold;
    uint16_t max_leaf_entries;
    uint16_t max_route_entries;
    bool enable_boot_ecc;
    // Set `rs_parity_m > 0` and `rs_parity_k > 0` to enable `RS_GF256(K, M)` parity clusters.
    uint16_t rs_parity_k;
    uint16_t rs_parity_m;
    // Key mode: `0` = none, `1` = raw 256-bit key, `2` = Argon2id passphrase.
    uint8_t encryption_mode;
    uint8_t raw_key[32];
    const char *passphrase;
} VzWriterConfigC;

// Per-entry options for [`vz_writer_add_file`], [`vz_writer_file_begin`], and [`vz_append_add_file`].
typedef struct VzEntryOptionsC {
    // Set `override_codec == true` to override archive default codec with `codec`.
    bool override_codec;
    VzCodec codec;
    uint16_t mode;
    int64_t mtime_ns;
    bool has_owner;
    uint32_t uid;
    uint32_t gid;
    bool has_btime;
    int64_t btime_ns;
} VzEntryOptionsC;

// Compaction options for [`vz_archive_compact`].
typedef struct VzCompactOptionsC {
    // `true` preserves existing compressed payloads without re-encoding (`override_codec == false`).
    bool zero_reencode;
    VzCodec codec;
    int32_t zstd_level;
    uintptr_t target_cluster_size;
    bool enable_boot_ecc;
    // Optional Reed-Solomon `GF(2^8)` parity `(K, M)` on compacted output (`0` = disabled/inherit).
    uint16_t rs_parity_k;
    uint16_t rs_parity_m;
} VzCompactOptionsC;

// Owned byte buffer returned from `vz_*` read functions. Must be freed with [`vz_bytes_free`].
typedef struct VzBytes {
    uint8_t *data;
    uintptr_t len;
    uintptr_t cap;
} VzBytes;

// Entry metadata returned by [`vz_archive_stat`] and [`vz_archive_readdir`].
typedef struct VzStatC {
    uint64_t entry_id;
    uint64_t size;
    uint64_t stored_size;
    int64_t mtime_ns;
    uint16_t mode;
    VzFileKind kind;
    uint8_t codec;
    bool is_inline;
    bool is_sparse;
    bool is_multi_cluster;
    char *parent_path;
    char *name;
} VzStatC;

// Directory listing returned by [`vz_archive_readdir`]. Must be freed with [`vz_dir_list_free`].
typedef struct VzDirList {
    struct VzStatC *items;
    uintptr_t len;
    uintptr_t cap;
} VzDirList;

// POSIX inode attributes for C FUSE3 integrations.
typedef struct VzFuseAttrC {
    uint64_t ino;
    uint64_t size;
    uint64_t blocks;
    int64_t atime_sec;
    uint32_t atime_nsec;
    int64_t mtime_sec;
    uint32_t mtime_nsec;
    int64_t ctime_sec;
    uint32_t ctime_nsec;
    int64_t crtime_sec;
    uint32_t crtime_nsec;
    VzFileKind kind;
    uint16_t perm;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint32_t rdev;
    uint32_t blksize;
} VzFuseAttrC;

// Directory entry + attributes returned by [`vz_fuse_readdirplus`].
typedef struct VzFuseDirEntryPlusC {
    uint64_t ino;
    uint64_t offset;
    VzFileKind kind;
    char *name;
    struct VzFuseAttrC attr;
} VzFuseDirEntryPlusC;

// Paginated `readdirplus` result list. Must be freed with [`vz_fuse_dir_free`].
typedef struct VzFuseDirListC {
    struct VzFuseDirEntryPlusC *items;
    uintptr_t len;
    uintptr_t cap;
} VzFuseDirListC;

// Zero-allocation entry view yielded to [`VzReaddirVisitorFn`] by [`vz_archive_readdir_visit`].
// `name` passed to the callback is NOT NUL-terminated; inspect `name_len`.
typedef struct VzStatViewC {
    uint64_t entry_id;
    uint64_t size;
    uint64_t stored_size;
    int64_t mtime_ns;
    uint16_t mode;
    VzFileKind kind;
    uint8_t codec;
    bool is_inline;
    bool is_sparse;
    bool is_multi_cluster;
} VzStatViewC;

// Callback invoked by [`vz_archive_readdir_visit`]. Return `true` to continue, `false` to stop.
typedef bool (*VzReaddirVisitorFn)(const struct VzStatViewC *stat,
                                   const char *name,
                                   uintptr_t name_len,
                                   void *user_data);

// Integrity verification summary filled by [`vz_verify_file`].
typedef struct VzVerifyReportC {
    bool boot_ecc_ok;
    bool boot_ecc_repaired;
    uintptr_t boot_ecc_repaired_page;
    uintptr_t clusters_checked;
    uintptr_t parity_stripes_checked;
    uintptr_t error_count;
} VzVerifyReportC;

// Repair summary filled by [`vz_repair_file`].
typedef struct VzRepairReportC {
    bool boot_repaired;
    uintptr_t boot_repaired_page;
    uintptr_t data_clusters_repaired;
    uintptr_t parity_clusters_repaired;
} VzRepairReportC;

// Filesystem statistics returned by [`vz_fuse_statfs`].
typedef struct VzFuseStatFsC {
    uint64_t blocks;
    uint64_t bfree;
    uint64_t bavail;
    uint64_t files;
    uint64_t ffree;
    uint32_t bsize;
    uint32_t namelen;
    uint32_t frsize;
} VzFuseStatFsC;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Returns the compiled C ABI version (`VZ_ABI_VERSION`).
uint32_t vz_abi_version(void);

// Returns a thread-local NUL-terminated description of the most recent FFI error (or `""`).
const char *vz_last_error(void);

// Returns a static NUL-terminated name for `status`.
const char *vz_status_str(VzStatus status);

// Converts [`VzStatus`] to a POSIX `errno` value (`0` for `VzStatus::VZ_OK`).
int32_t vz_status_to_errno(VzStatus status);

// Returns default [`VzOpenOptions`] (`use_mmap = true`, `repair_boot_ecc = true`, unencrypted).
struct VzOpenOptions vz_open_options_default(void);

// Returns default [`VzWriterConfigC`] matching [`VzWriterConfig::default()`].
struct VzWriterConfigC vz_writer_config_default(void);

// Returns default [`VzEntryOptionsC`] (`0644`, inherits archive default codec).
struct VzEntryOptionsC vz_entry_options_default(void);

// Returns default [`VzCompactOptionsC`] (`zero_reencode = true`, `enable_boot_ecc = true`).
struct VzCompactOptionsC vz_compact_options_default(void);

// Frees a [`VzBytes`] buffer previously returned by `vz_*` read functions.
void vz_bytes_free(struct VzBytes *buf);

// Frees string fields owned by [`VzStatC`].
void vz_stat_free(struct VzStatC *stat);

// Frees a [`VzDirList`] previously populated by [`vz_archive_readdir`].
void vz_dir_list_free(struct VzDirList *list);

// Frees a [`VzFuseDirListC`] previously populated by [`vz_fuse_readdirplus`].
void vz_fuse_dir_free(struct VzFuseDirListC *list);

// Opens an existing `.vz` archive file on disk (via `mmap` or `File` `pread`).
VzStatus vz_archive_open(const char *path,
                         const struct VzOpenOptions *opts,
                         struct VzArchive **out);

// Opens a `.vz` archive from an in-memory byte buffer (copies `data[0..len]` safely).
VzStatus vz_archive_open_memory(const uint8_t *data,
                                uintptr_t len,
                                const struct VzOpenOptions *opts,
                                struct VzArchive **out);

// Closes and frees a [`VzArchive`] handle.
void vz_archive_close(struct VzArchive *arc);

// Returns total live entries recorded in the active Boot Block slot.
uint64_t vz_archive_total_entries(const struct VzArchive *arc);

// Returns the active LSM overlay run count (`1` for single-run / compacted containers).
uint32_t vz_archive_lsm_runs(const struct VzArchive *arc);

// Returns the active Boot Block slot generation counter.
uint64_t vz_archive_generation(const struct VzArchive *arc);

// Looks up metadata for `path` in `O(log N)` time. Caller must free `out` via [`vz_stat_free`].
VzStatus vz_archive_stat(const struct VzArchive *arc, const char *path, struct VzStatC *out);

// Sets `*out_exists` to `true` if `path` exists cleanly in the live overlay view.
VzStatus vz_archive_exists(const struct VzArchive *arc, const char *path, bool *out_exists);

// Reads and decodes the entire file payload at `path`. Caller must free `out` via [`vz_bytes_free`].
VzStatus vz_archive_read(const struct VzArchive *arc,
                         const char *path,
                         struct VzBytes *out);

// Reads `[offset, offset + len)` of `path` (clamped at EOF). Caller must free `out` via [`vz_bytes_free`].
VzStatus vz_archive_read_range(const struct VzArchive *arc,
                               const char *path,
                               uint64_t offset,
                               uintptr_t len,
                               struct VzBytes *out);

// Zero-copy range read into caller-provided `dst[0..dst_cap]` at `offset` (up to `len` bytes,
// clamped at EOF). Sets `*out_written` to actual bytes written; returns `VZ_ERR_BUFFER_TOO_SMALL`
// if `dst_cap` is smaller than the clamped read size.
VzStatus vz_archive_read_range_into(const struct VzArchive *arc,
                                    const char *path,
                                    uint64_t offset,
                                    uintptr_t len,
                                    uint8_t *dst,
                                    uintptr_t dst_cap,
                                    uintptr_t *out_written);

// Zero-allocation directory iteration invoking `visitor` for each entry in `dir_path`.
VzStatus vz_archive_readdir_visit(const struct VzArchive *arc,
                                  const char *dir_path,
                                  VzReaddirVisitorFn visitor,
                                  void *user_data);

// Lists live child entries under directory `dir_path`. Caller must free `out` via [`vz_dir_list_free`].
VzStatus vz_archive_readdir(const struct VzArchive *arc,
                            const char *dir_path,
                            struct VzDirList *out);

// Extracts all live files and directories in cluster order into `dest_dir`.
VzStatus vz_archive_extract_to(const struct VzArchive *arc,
                               const char *dest_dir,
                               uintptr_t *out_count);

// Compacts `arc` into a fresh single-run container at `dest_path` (zero re-encoding by default).
VzStatus vz_archive_compact(const struct VzArchive *arc,
                            const char *dest_path,
                            const struct VzCompactOptionsC *opts);

// Verifies Boot ECC, cluster CRCs, B+Tree structure, and RS parity on `path`.
VzStatus vz_verify_file(const char *path,
                        const struct VzOpenOptions *opts,
                        struct VzVerifyReportC *out);

// Repairs single-page Boot ECC and `<= M` RS-corrupted clusters at `path` in-place.
VzStatus vz_repair_file(const char *path, struct VzRepairReportC *out);

// Mounts an opened [`VzArchive`] into an in-memory `O(1)`/`O(log N)` FUSE3 volume.
VzStatus vz_fuse_mount(const struct VzArchive *arc, struct VzFuseVol **out);

// Unmounts and frees a [`VzFuseVol`] handle.
void vz_fuse_unmount(struct VzFuseVol *vol);

// FUSE3 `getattr(ino)` (`O(1)`, zero disk I/O).
VzStatus vz_fuse_getattr(const struct VzFuseVol *vol, uint64_t ino, struct VzFuseAttrC *out);

// FUSE3 `lookup(parent_ino, name)` (`O(log dir_len)`, zero disk I/O).
VzStatus vz_fuse_lookup(const struct VzFuseVol *vol,
                        uint64_t parent_ino,
                        const char *name,
                        struct VzFuseAttrC *out);

// FUSE3 `readdirplus(ino, offset, limit)` paginated listing with full attributes (zero disk I/O).
// Caller must free `out` via [`vz_fuse_dir_free`].
VzStatus vz_fuse_readdirplus(const struct VzFuseVol *vol,
                             uint64_t ino,
                             uint64_t offset,
                             uintptr_t limit,
                             struct VzFuseDirListC *out);

// Opens a FUSE3 file handle (`fh`) on `ino`, pre-loading any `TAG_CHUNK_TABLE` once.
VzStatus vz_fuse_open(const struct VzFuseVol *vol, uint64_t ino, struct VzFuseFh **out);

// Closes and frees a [`VzFuseFh`] handle.
void vz_fuse_close(struct VzFuseFh *fh);

// Reads `[offset, offset + len)` from `fh` (chunk-cached for compressed/encrypted streams,
// exact `read_at` for `CODEC_NONE`, zero-I/O for sparse holes). Caller frees `out` via [`vz_bytes_free`].
VzStatus vz_fuse_read(const struct VzFuseVol *vol,
                      const struct VzFuseFh *fh,
                      uint64_t offset,
                      uintptr_t len,
                      struct VzBytes *out);

// Zero-copy FUSE3 `read(fh, offset, len)` directly into caller-provided `dst[0..dst_cap]`.
// Sets `*out_written` to actual bytes written; returns `VZ_ERR_BUFFER_TOO_SMALL` if `dst_cap`
// is smaller than the clamped read size.
VzStatus vz_fuse_read_into(const struct VzFuseVol *vol,
                           const struct VzFuseFh *fh,
                           uint64_t offset,
                           uintptr_t len,
                           uint8_t *dst,
                           uintptr_t dst_cap,
                           uintptr_t *out_written);

// FUSE3 `readlink(ino)`: reads symlink target bytes for `VZ_KIND_LNK` inodes.
// Caller frees `out` via [`vz_bytes_free`].
VzStatus vz_fuse_readlink(const struct VzFuseVol *vol, uint64_t ino, struct VzBytes *out);

// FUSE3 `getxattr(ino, name)`: `O(xattrs.len())` zero-I/O extended attribute read.
// Caller frees `out` via [`vz_bytes_free`].
VzStatus vz_fuse_getxattr(const struct VzFuseVol *vol,
                          uint64_t ino,
                          const char *name,
                          struct VzBytes *out);

// FUSE3 `listxattr(ino)`: returns NUL-separated POSIX attribute names (`name1\0name2\0...`).
// Caller frees `out` via [`vz_bytes_free`].
VzStatus vz_fuse_listxattr(const struct VzFuseVol *vol, uint64_t ino, struct VzBytes *out);

// Fills container-wide `statfs` counters from `vol`.
VzStatus vz_fuse_statfs(const struct VzFuseVol *vol, struct VzFuseStatFsC *out);

// Creates a new `.vz` archive file at `path`. Finalize with [`vz_writer_finish`].
VzStatus vz_writer_create(const char *path,
                          const struct VzWriterConfigC *cfg,
                          struct VzWriterHandle **out);

// Adds an explicit directory (`KIND_DIR`) to `w`.
VzStatus vz_writer_add_dir(struct VzWriterHandle *w,
                           const char *path,
                           uint16_t mode,
                           int64_t mtime_ns);

// Adds a regular file payload `data[0..len]` at `path`.
VzStatus vz_writer_add_file(struct VzWriterHandle *w,
                            const char *path,
                            const uint8_t *data,
                            uintptr_t len,
                            const struct VzEntryOptionsC *opts);

// Adds a special filesystem node (`VZ_KIND_FIFO`, `VZ_KIND_CHR`, `VZ_KIND_BLK`, `VZ_KIND_SOCK`,
// or `VZ_KIND_DIR`) using the provided [`VzEntryOptionsC`] (optional).
VzStatus vz_writer_add_special(struct VzWriterHandle *w,
                               const char *path,
                               VzFileKind kind,
                               const struct VzEntryOptionsC *opts);

// Begins writing a potentially multi-GB file incrementally in `O(cluster_size)` memory.
// Feed chunks via [`vz_writer_file_write`] and close with [`vz_writer_file_end`] (or [`vz_writer_file_abort`]).
VzStatus vz_writer_file_begin(struct VzWriterHandle *w,
                              const char *path,
                              const struct VzEntryOptionsC *opts,
                              struct VzStreamFileHandle **out);

// Writes `data[0..len]` into an active [`VzStreamFileHandle`].
VzStatus vz_writer_file_write(struct VzWriterHandle *w,
                              struct VzStreamFileHandle *sf,
                              const uint8_t *data,
                              uintptr_t len);

// Finalizes a streamed file into `w` and frees `sf`.
VzStatus vz_writer_file_end(struct VzWriterHandle *w, struct VzStreamFileHandle *sf);

// Aborts and frees an unfinished [`VzStreamFileHandle`].
void vz_writer_file_abort(struct VzStreamFileHandle *sf);

// Adds a symbolic link (`KIND_LNK`) pointing to `target`.
VzStatus vz_writer_add_symlink(struct VzWriterHandle *w,
                               const char *link_path,
                               const char *target,
                               uint16_t mode,
                               int64_t mtime_ns);

// Adds a hardlink sharing the existing target entry's `entry_id` and payload.
VzStatus vz_writer_add_hardlink(struct VzWriterHandle *w,
                                const char *link_path,
                                const char *target_path);

// Finalizes the archive B+Tree & Boot Block, flushes to disk, and frees `w`.
VzStatus vz_writer_finish(struct VzWriterHandle *w);

// Aborts and frees an unfinalized [`VzWriterHandle`].
void vz_writer_abort(struct VzWriterHandle *w);

// Opens an existing `.vz` archive at `path` for incremental LSM delta overlay append.
VzStatus vz_append_open(const char *path,
                        const struct VzOpenOptions *opts,
                        struct VzAppendHandle **out);

// Appends or overwrites a directory (`KIND_DIR`) inside the active LSM delta run.
VzStatus vz_append_add_dir(struct VzAppendHandle *a,
                           const char *path,
                           uint16_t mode,
                           int64_t mtime_ns);

// Appends or overwrites a regular file payload inside the active LSM delta run.
VzStatus vz_append_add_file(struct VzAppendHandle *a,
                            const char *path,
                            const uint8_t *data,
                            uintptr_t len,
                            const struct VzEntryOptionsC *opts);

// Appends or overwrites a symbolic link (`KIND_LNK`) inside the active LSM delta run.
VzStatus vz_append_add_symlink(struct VzAppendHandle *a,
                               const char *link_path,
                               const char *target,
                               uint16_t mode,
                               int64_t mtime_ns);

// Appends a hardlink sharing an existing entry's `entry_id` and payload inside the LSM delta run.
VzStatus vz_append_add_hardlink(struct VzAppendHandle *a,
                                const char *link_path,
                                const char *target_path);

// Emits a `FLAG_TOMBSTONE` deletion record for `path` in the LSM delta run.
VzStatus vz_append_delete(struct VzAppendHandle *a, const char *path);

// Commits the LSM delta run, updates the Boot Block slot + ECC, and frees `a`.
VzStatus vz_append_finish(struct VzAppendHandle *a);

// Aborts and frees an unfinalized [`VzAppendHandle`].
void vz_append_abort(struct VzAppendHandle *a);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* VZ_H */
