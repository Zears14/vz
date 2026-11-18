//! High-performance FUSE3 / VFS adapter index and stateful open-file read cache (`FuseVolume`).
//!
//! Eliminates FUSE3-hostile bottlenecks while remaining 100% compatible with the VZ v1.0 wire spec:
//! - **`O(1)` Inode Lookup & Hardlinks:** Maps POSIX FUSE `ino` (`FUSE_ROOT_ID = 1`) cleanly with
//!   hardlink deduplication (`nlink >= 2`) and automatic implicit parent directory synthesis.
//! - **Zero-I/O Metadata & `readdir` / `readdirplus` Pagination:** Serves `getattr`, `lookup`,
//!   `getxattr`, `listxattr`, `statfs`, `readdir(offset)`, and `readdirplus(offset)` in memory.
//! - **Stateful Chunk/Payload Caching & `O(log C)` Multi-Cluster Seeking:** `open(ino)` pre-fetches
//!   `TAG_CHUNK_TABLE` once, `CODEC_NONE` unencrypted reads issue exact byte-range `pread`s with zero
//!   whole-cluster amplification, compressed/encrypted sequential VFS `4 KiB`–`128 KiB` reads reuse
//!   the active decompressed chunk (`O(cluster_size)` RAM), and sparse holes return zeros with zero I/O.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::VzError;
use crate::ext_meta::{ChunkExtent, ExtCodecMeta, SparseExtent, Xattr};
use crate::io::RangeReader;
use crate::reader::VzReader;
use crate::wire::{
    CODEC_MASK, CODEC_NONE, DirPayload, FLAG_MULTI_CLUSTER, FLAG_SPARSE, KIND_BLK, KIND_CHR,
    KIND_DIR, KIND_FIFO, KIND_LNK, KIND_MASK, KIND_SOCK,
};

/// POSIX / libfuse3 standard root inode number (`/`).
pub const FUSE_ROOT_ID: u64 = 1;

/// FUSE3 / POSIX file type enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseFileKind {
    Directory,
    RegularFile,
    Symlink,
    NamedPipe,
    CharDevice,
    BlockDevice,
    Socket,
}

impl FuseFileKind {
    fn from_wire_kind(kind: u16) -> Self {
        match kind & KIND_MASK {
            KIND_DIR => Self::Directory,
            KIND_LNK => Self::Symlink,
            KIND_FIFO => Self::NamedPipe,
            KIND_CHR => Self::CharDevice,
            KIND_BLK => Self::BlockDevice,
            KIND_SOCK => Self::Socket,
            _ => Self::RegularFile,
        }
    }
}

/// FUSE3 file attributes (`struct stat` equivalent) served in `O(1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseAttr {
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
    pub kind: FuseFileKind,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
}

/// Entry yielded by [`FuseVolume::readdir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseDirEntry {
    pub ino: u64,
    pub offset: u64,
    pub kind: FuseFileKind,
    pub name: String,
}

/// Entry yielded by [`FuseVolume::readdirplus`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuseDirEntryPlus {
    pub ino: u64,
    pub offset: u64,
    pub kind: FuseFileKind,
    pub name: String,
    pub attr: FuseAttr,
}

/// Filesystem statistics yielded by [`FuseVolume::statfs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseStatFs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

#[derive(Clone)]
enum PayloadSource {
    None,
    Inline(Arc<[u8]>),
    Ref {
        data_offset: u64,
        stored_size: u64,
        raw_size: u64,
        in_cluster_offset: u32,
        flags_and_codec: u8,
        ext_codec: Option<ExtCodecMeta>,
        sparse_extents: Option<Vec<SparseExtent>>,
        entry_id: u64,
        run_generation: u64,
    },
}

struct InodeNode {
    attr: FuseAttr,
    parent_ino: u64,
    /// Sorted by basename for `O(log child_count)` binary search on `lookup()`.
    children: Vec<(String, u64)>,
    xattrs: Vec<Xattr>,
    payload: PayloadSource,
}

#[derive(Clone)]
struct CachedChunk {
    chunk_idx: usize,
    data: Arc<[u8]>,
}

enum OpenPayload {
    Inline(Arc<[u8]>),
    SingleCluster {
        cluster_offset: u64,
        in_cluster_offset: u32,
        stored_size: u64,
        raw_size: u64,
        codec: u8,
        ext_codec: Option<ExtCodecMeta>,
        entry_id: u64,
        run_generation: u64,
        cache: Mutex<Option<Arc<[u8]>>>,
    },
    MultiCluster {
        extents: Vec<ChunkExtent>,
        /// Inclusive cumulative end raw offset for each extent (`O(log C)` chunk lookup).
        chunk_ends: Vec<u64>,
        raw_size: u64,
        codec: u8,
        ext_codec: Option<ExtCodecMeta>,
        entry_id: u64,
        run_generation: u64,
        cache: Mutex<Option<CachedChunk>>,
    },
    Sparse {
        data_offset: u64,
        in_cluster_offset: u32,
        stored_size: u64,
        raw_size: u64,
        is_multi_cluster: bool,
        codec: u8,
        ext_codec: Option<ExtCodecMeta>,
        extents: Vec<SparseExtent>,
        entry_id: u64,
        run_generation: u64,
        packed_cache: Mutex<Option<Arc<[u8]>>>,
    },
}

/// Stateful open file descriptor handle (`fh`) returned by [`FuseVolume::open`].
#[derive(Clone)]
pub struct FuseFileHandle {
    ino: u64,
    attr: FuseAttr,
    payload: Arc<OpenPayload>,
}

impl FuseFileHandle {
    /// Returns the inode number bound to this open file handle.
    #[inline]
    pub fn ino(&self) -> u64 {
        self.ino
    }

    /// Returns cached POSIX file attributes for this handle.
    #[inline]
    pub fn attr(&self) -> FuseAttr {
        self.attr
    }
}

/// Ready-to-mount in-memory FUSE3 volume over a [`VzReader<R>`].
pub struct FuseVolume<R: RangeReader> {
    reader: Arc<VzReader<R>>,
    /// Index `ino - 1` holds the inode slot (`FUSE_ROOT_ID = 1` lives at `inodes[0]`).
    inodes: Vec<InodeNode>,
    total_raw_bytes: u64,
}

fn split_mtime_ns(mtime_ns: i64) -> (i64, u32) {
    let sec = mtime_ns.div_euclid(1_000_000_000);
    let nsec = mtime_ns.rem_euclid(1_000_000_000) as u32;
    (sec, nsec)
}

impl<R: RangeReader> FuseVolume<R> {
    /// Mounts `reader` by building a compact `O(1)` inode table, resolving LSM overlays &
    /// tombstones, wiring hardlinks (`nlink`), and synthesizing any implicit parent directories.
    pub fn mount(reader: Arc<VzReader<R>>) -> Result<Self, VzError> {
        let live = reader.list_all_live()?;
        let mut nodes = Vec::with_capacity(live.len() + 2);
        // Reserve inode 1 (index 0) for root "/".
        nodes.push(InodeNode {
            attr: FuseAttr {
                ino: FUSE_ROOT_ID,
                size: 0,
                blocks: 0,
                atime_sec: 0,
                atime_nsec: 0,
                mtime_sec: 0,
                mtime_nsec: 0,
                ctime_sec: 0,
                ctime_nsec: 0,
                crtime_sec: 0,
                crtime_nsec: 0,
                kind: FuseFileKind::Directory,
                perm: 0o755,
                nlink: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 65_536,
            },
            parent_ino: FUSE_ROOT_ID,
            children: Vec::new(),
            xattrs: Vec::new(),
            payload: PayloadSource::None,
        });

        let mut dir_path_to_ino: HashMap<String, u64> = HashMap::new();
        dir_path_to_ino.insert("/".to_string(), FUSE_ROOT_ID);

        // Hardlink map: archival `entry_id` -> `(ino, raw_size, stored_size)` for non-directory files.
        let mut hardlink_ino: HashMap<u64, (u64, u64, u64)> = HashMap::new();
        let mut total_raw_bytes = 0u64;

        // First create explicit directory entries so directory permissions/timestamps win.
        for entry in &live {
            if (entry.stat.kind & KIND_MASK) != KIND_DIR {
                continue;
            }
            if entry.stat.parent_path.is_empty() || entry.stat.name.is_empty() {
                continue;
            }
            let full_dir = if entry.stat.parent_path == "/" {
                format!("/{}", entry.stat.name)
            } else {
                format!("{}/{}", entry.stat.parent_path, entry.stat.name)
            };
            let parent_ino = if entry.stat.parent_path == "/" {
                FUSE_ROOT_ID
            } else if let Some(&ino) = dir_path_to_ino.get(&entry.stat.parent_path) {
                ino
            } else {
                ensure_dir_chain(&entry.stat.parent_path, &mut nodes, &mut dir_path_to_ino)
            };
            let ino = if let Some(&existing_ino) = dir_path_to_ino.get(&full_dir) {
                existing_ino
            } else {
                let new_ino = (nodes.len() + 1) as u64;
                nodes.push(InodeNode {
                    attr: FuseAttr {
                        ino: new_ino,
                        size: 0,
                        blocks: 0,
                        atime_sec: 0,
                        atime_nsec: 0,
                        mtime_sec: 0,
                        mtime_nsec: 0,
                        ctime_sec: 0,
                        ctime_nsec: 0,
                        crtime_sec: 0,
                        crtime_nsec: 0,
                        kind: FuseFileKind::Directory,
                        perm: 0o755,
                        nlink: 2,
                        uid: 0,
                        gid: 0,
                        rdev: 0,
                        blksize: 65_536,
                    },
                    parent_ino,
                    children: Vec::new(),
                    xattrs: Vec::new(),
                    payload: PayloadSource::None,
                });
                nodes[(parent_ino - 1) as usize]
                    .children
                    .push((entry.stat.name.clone(), new_ino));
                dir_path_to_ino.insert(full_dir, new_ino);
                new_ino
            };
            let slot = &mut nodes[(ino - 1) as usize];
            apply_entry_metadata_to_attr(&mut slot.attr, entry, FuseFileKind::Directory);
            slot.xattrs = entry.stat.xattrs.clone();
        }

        // Next register all non-directory entries (regular files, symlinks, tensors, special).
        for entry in live {
            if (entry.stat.kind & KIND_MASK) == KIND_DIR {
                continue;
            }
            let parent_ino = if entry.stat.parent_path.is_empty() || entry.stat.parent_path == "/" {
                FUSE_ROOT_ID
            } else if let Some(&ino) = dir_path_to_ino.get(&entry.stat.parent_path) {
                ino
            } else {
                ensure_dir_chain(&entry.stat.parent_path, &mut nodes, &mut dir_path_to_ino)
            };

            // Disambiguate rare archive builds whose implicit children share identical basenames.
            let name = entry.stat.name.clone();
            let kind = FuseFileKind::from_wire_kind(entry.stat.kind);

            if let Some(&(shared_ino, expected_size, expected_stored)) =
                hardlink_ino.get(&entry.stat.entry_id)
                && expected_size == entry.stat.size
                && expected_stored == entry.stat.stored_size
            {
                nodes[(shared_ino - 1) as usize].attr.nlink =
                    nodes[(shared_ino - 1) as usize].attr.nlink.saturating_add(1);
                nodes[(parent_ino - 1) as usize]
                    .children
                    .push((name, shared_ino));
                continue;
            }

            let new_ino = (nodes.len() + 1) as u64;
            let mut attr = FuseAttr {
                ino: new_ino,
                size: entry.stat.size,
                blocks: if entry.stat.is_sparse {
                    entry.stat.stored_size.div_ceil(512)
                } else {
                    entry.stat.size.div_ceil(512)
                },
                atime_sec: 0,
                atime_nsec: 0,
                mtime_sec: 0,
                mtime_nsec: 0,
                ctime_sec: 0,
                ctime_nsec: 0,
                crtime_sec: 0,
                crtime_nsec: 0,
                kind,
                perm: entry.stat.mode & 0o7777,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 65_536,
            };
            apply_entry_metadata_to_attr(&mut attr, &entry, kind);

            let payload = match entry.dir_entry.payload {
                DirPayload::Inline { bytes, len } => {
                    PayloadSource::Inline(Arc::from(&bytes[..len as usize]))
                }
                DirPayload::Ref {
                    data_offset,
                    stored_size,
                    raw_size,
                    in_cluster_offset,
                } => PayloadSource::Ref {
                    data_offset,
                    stored_size,
                    raw_size,
                    in_cluster_offset,
                    flags_and_codec: entry.dir_entry.flags_and_codec,
                    ext_codec: entry.ext_codec.clone(),
                    sparse_extents: entry.sparse_extents.clone(),
                    entry_id: entry.stat.entry_id,
                    run_generation: entry.run_generation,
                },
            };

            total_raw_bytes = total_raw_bytes.saturating_add(entry.stat.size);
            if matches!(kind, FuseFileKind::RegularFile) {
                hardlink_ino.insert(
                    entry.stat.entry_id,
                    (new_ino, entry.stat.size, entry.stat.stored_size),
                );
            }
            nodes.push(InodeNode {
                attr,
                parent_ino,
                children: Vec::new(),
                xattrs: entry.stat.xattrs,
                payload,
            });
            nodes[(parent_ino - 1) as usize]
                .children
                .push((name, new_ino));
        }

        // Compute exact POSIX `nlink` for directories (`2 + subdir count`) and sort child tables.
        let mut dir_nlinks: Vec<u32> = vec![2u32; nodes.len()];
        for (idx, n) in nodes.iter().enumerate() {
            if idx != 0 && n.attr.kind == FuseFileKind::Directory {
                let pidx = (n.parent_ino - 1) as usize;
                dir_nlinks[pidx] = dir_nlinks[pidx].saturating_add(1);
            }
        }
        for (idx, n) in nodes.iter_mut().enumerate() {
            if n.attr.kind == FuseFileKind::Directory {
                n.attr.nlink = dir_nlinks[idx];
                n.children.sort_by(|a, b| a.0.cmp(&b.0));
                n.children.dedup_by(|a, b| a.0 == b.0);
            }
        }

        Ok(Self {
            reader,
            inodes: nodes,
            total_raw_bytes,
        })
    }

    /// Borrows the underlying [`VzReader<R>`].
    pub fn reader(&self) -> &Arc<VzReader<R>> {
        &self.reader
    }

    fn slot(&self, ino: u64) -> Result<&InodeNode, VzError> {
        if ino == 0 {
            return Err(VzError::NotFound);
        }
        let idx = usize::try_from(ino - 1).map_err(|_| VzError::NotFound)?;
        self.inodes.get(idx).ok_or(VzError::NotFound)
    }

    /// FUSE3 `getattr(ino)`: `O(1)` attribute lookup with zero I/O.
    #[inline]
    pub fn getattr(&self, ino: u64) -> Result<FuseAttr, VzError> {
        Ok(self.slot(ino)?.attr)
    }

    /// FUSE3 `lookup(parent_ino, name)`: `O(log dir_len)` binary search with zero I/O.
    pub fn lookup(&self, parent_ino: u64, name: &str) -> Result<FuseAttr, VzError> {
        let parent = self.slot(parent_ino)?;
        if parent.attr.kind != FuseFileKind::Directory {
            return Err(VzError::InvalidInput);
        }
        if name == "." {
            return Ok(parent.attr);
        }
        if name == ".." {
            return self.getattr(parent.parent_ino);
        }
        let idx = parent
            .children
            .binary_search_by(|(child_name, _)| child_name.as_str().cmp(name))
            .map_err(|_| VzError::NotFound)?;
        let child_ino = parent.children[idx].1;
        self.getattr(child_ino)
    }

    /// FUSE3 paginated `readdir(parent_ino, offset, max_entries)`.
    ///
    /// Yields `.` at `offset = 0`, `..` at `offset = 1`, and sorted directory children starting at
    /// `offset = 2`. Next-page cursor for entry `e` is `e.offset`.
    pub fn readdir(
        &self,
        parent_ino: u64,
        offset: u64,
        max_entries: usize,
    ) -> Result<Vec<FuseDirEntry>, VzError> {
        let plus = self.readdirplus(parent_ino, offset, max_entries)?;
        Ok(plus
            .into_iter()
            .map(|p| FuseDirEntry {
                ino: p.ino,
                offset: p.offset,
                kind: p.kind,
                name: p.name,
            })
            .collect())
    }

    /// FUSE3 paginated `readdirplus(parent_ino, offset, max_entries)` returning entries AND
    /// attributes in memory with zero disk I/O (eliminating per-entry `lookup`/`getattr` calls).
    pub fn readdirplus(
        &self,
        parent_ino: u64,
        offset: u64,
        max_entries: usize,
    ) -> Result<Vec<FuseDirEntryPlus>, VzError> {
        let parent = self.slot(parent_ino)?;
        if parent.attr.kind != FuseFileKind::Directory {
            return Err(VzError::InvalidInput);
        }
        if max_entries == 0 {
            return Ok(Vec::new());
        }

        let total_items = 2 + parent.children.len();
        let start = usize::try_from(offset).unwrap_or(total_items);
        if start >= total_items {
            return Ok(Vec::new());
        }
        let end = total_items.min(start.saturating_add(max_entries));
        let mut out = Vec::with_capacity(end - start);

        for pos in start..end {
            let next_off = (pos + 1) as u64;
            match pos {
                0 => out.push(FuseDirEntryPlus {
                    ino: parent_ino,
                    offset: next_off,
                    kind: FuseFileKind::Directory,
                    name: ".".to_string(),
                    attr: parent.attr,
                }),
                1 => {
                    let pp = self.getattr(parent.parent_ino)?;
                    out.push(FuseDirEntryPlus {
                        ino: pp.ino,
                        offset: next_off,
                        kind: FuseFileKind::Directory,
                        name: "..".to_string(),
                        attr: pp,
                    });
                }
                _ => {
                    let (ref name, child_ino) = parent.children[pos - 2];
                    let attr = self.getattr(child_ino)?;
                    out.push(FuseDirEntryPlus {
                        ino: child_ino,
                        offset: next_off,
                        kind: attr.kind,
                        name: name.clone(),
                        attr,
                    });
                }
            }
        }
        Ok(out)
    }

    /// FUSE3 `getxattr(ino, name)`: `O(xattrs.len())` zero-I/O attribute slice lookup.
    pub fn getxattr(&self, ino: u64, name: &str) -> Result<&[u8], VzError> {
        let slot = self.slot(ino)?;
        for x in &slot.xattrs {
            if x.key == name {
                return Ok(&x.value);
            }
        }
        Err(VzError::NotFound)
    }

    /// FUSE3 `listxattr(ino)`: lists extended attribute names in memory with zero I/O.
    pub fn listxattr(&self, ino: u64) -> Result<Vec<&str>, VzError> {
        let slot = self.slot(ino)?;
        Ok(slot.xattrs.iter().map(|x| x.key.as_str()).collect())
    }

    /// FUSE3 `readlink(ino)`: returns symlink target bytes for `FuseFileKind::Symlink`.
    pub fn readlink(&self, ino: u64) -> Result<Vec<u8>, VzError> {
        let slot = self.slot(ino)?;
        if slot.attr.kind != FuseFileKind::Symlink {
            return Err(VzError::InvalidInput);
        }
        let fh = self.open(ino)?;
        self.read(&fh, 0, usize::try_from(slot.attr.size).unwrap_or(4096))
    }

    /// FUSE3 `statfs`: returns container-wide block and inode statistics.
    pub fn statfs(&self) -> FuseStatFs {
        let bsize = 65_536u32;
        FuseStatFs {
            blocks: self.total_raw_bytes.div_ceil(bsize as u64).max(1),
            bfree: 0,
            bavail: 0,
            files: self.inodes.len() as u64,
            ffree: 0,
            bsize,
            namelen: 4096,
            frsize: bsize,
        }
    }

    /// FUSE3 `open(ino)`: constructs a reusable stateful handle (`fh`), pre-loading any
    /// `TAG_CHUNK_TABLE` once so subsequent VFS `read()` calls incur zero tree/table RTTs.
    pub fn open(&self, ino: u64) -> Result<FuseFileHandle, VzError> {
        let slot = self.slot(ino)?;
        if slot.attr.kind == FuseFileKind::Directory {
            return Err(VzError::InvalidInput);
        }
        let open_payload = match &slot.payload {
            PayloadSource::None => OpenPayload::Inline(Arc::from([])),
            PayloadSource::Inline(bytes) => OpenPayload::Inline(Arc::clone(bytes)),
            PayloadSource::Ref {
                data_offset,
                stored_size,
                raw_size,
                in_cluster_offset,
                flags_and_codec,
                ext_codec,
                sparse_extents,
                entry_id,
                run_generation,
            } => {
                let codec = *flags_and_codec & CODEC_MASK;
                let is_sparse = (*flags_and_codec & FLAG_SPARSE) != 0;
                let is_mc = (*flags_and_codec & FLAG_MULTI_CLUSTER) != 0;
                if is_sparse {
                    OpenPayload::Sparse {
                        data_offset: *data_offset,
                        in_cluster_offset: *in_cluster_offset,
                        stored_size: *stored_size,
                        raw_size: *raw_size,
                        is_multi_cluster: is_mc,
                        codec,
                        ext_codec: ext_codec.clone(),
                        extents: sparse_extents.clone().unwrap_or_default(),
                        entry_id: *entry_id,
                        run_generation: *run_generation,
                        packed_cache: Mutex::new(None),
                    }
                } else if is_mc {
                    let extents = self
                        .reader
                        .read_chunk_table_at(*data_offset, *in_cluster_offset)?;
                    let mut chunk_ends = Vec::with_capacity(extents.len());
                    let mut acc = 0u64;
                    for ext in &extents {
                        acc = acc
                            .checked_add(ext.raw_size)
                            .ok_or(VzError::ValueOverflow)?;
                        chunk_ends.push(acc);
                    }
                    OpenPayload::MultiCluster {
                        extents,
                        chunk_ends,
                        raw_size: *raw_size,
                        codec,
                        ext_codec: ext_codec.clone(),
                        entry_id: *entry_id,
                        run_generation: *run_generation,
                        cache: Mutex::new(None),
                    }
                } else {
                    OpenPayload::SingleCluster {
                        cluster_offset: *data_offset,
                        in_cluster_offset: *in_cluster_offset,
                        stored_size: *stored_size,
                        raw_size: *raw_size,
                        codec,
                        ext_codec: ext_codec.clone(),
                        entry_id: *entry_id,
                        run_generation: *run_generation,
                        cache: Mutex::new(None),
                    }
                }
            }
        };

        Ok(FuseFileHandle {
            ino,
            attr: slot.attr,
            payload: Arc::new(open_payload),
        })
    }

    /// FUSE3 `read_into(fh, offset, dst)`: reads up to `dst.len()` bytes at `offset` directly
    /// into caller-provided `dst` (zero intermediate heap allocation for inline, cached, sparse
    /// zero-hole, and unencrypted `CODEC_NONE` `read_at` paths), returning actual bytes written.
    pub fn read_into(
        &self,
        handle: &FuseFileHandle,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, VzError> {
        let len = dst.len();
        if len == 0 {
            return Ok(0);
        }
        match handle.payload.as_ref() {
            OpenPayload::Inline(bytes) => {
                if offset >= bytes.len() as u64 {
                    return Ok(0);
                }
                let s = usize::try_from(offset).map_err(|_| VzError::ValueOverflow)?;
                let take = len.min(bytes.len() - s);
                dst[..take].copy_from_slice(&bytes[s..s + take]);
                Ok(take)
            }
            OpenPayload::SingleCluster {
                cluster_offset,
                in_cluster_offset,
                stored_size,
                raw_size,
                codec,
                ext_codec,
                entry_id,
                run_generation,
                cache,
            } => {
                if offset >= *raw_size {
                    return Ok(0);
                }
                let end = offset.saturating_add(len as u64).min(*raw_size);
                let want = usize::try_from(end - offset).map_err(|_| VzError::ValueOverflow)?;
                let s = usize::try_from(offset).map_err(|_| VzError::ValueOverflow)?;

                if self.reader.crypto_context().is_none()
                    && *codec == CODEC_NONE
                    && ext_codec.is_none()
                {
                    if end > *stored_size {
                        return Err(VzError::BadFormat);
                    }
                    let off = cluster_offset
                        .checked_add(*in_cluster_offset as u64)
                        .and_then(|v| v.checked_add(offset))
                        .ok_or(VzError::ValueOverflow)?;
                    self.reader.reader().read_at(off, &mut dst[..want])?;
                    return Ok(want);
                }

                // Reuse cached decoded single-cluster payload across sequential 4 KiB..128 KiB FUSE reads.
                if let Ok(guard) = cache.lock()
                    && let Some(ref arc) = *guard
                {
                    if s + want > arc.len() {
                        return Err(VzError::BadFormat);
                    }
                    dst[..want].copy_from_slice(&arc[s..s + want]);
                    return Ok(want);
                }

                let decoded: Arc<[u8]> = Arc::from(self.reader.read_single_cluster_payload(
                    *cluster_offset,
                    *in_cluster_offset,
                    *stored_size,
                    *raw_size,
                    *codec,
                    ext_codec.as_ref(),
                    *run_generation,
                    *entry_id,
                )?);
                if s + want > decoded.len() {
                    return Err(VzError::BadFormat);
                }
                dst[..want].copy_from_slice(&decoded[s..s + want]);
                if let Ok(mut guard) = cache.lock() {
                    *guard = Some(decoded);
                }
                Ok(want)
            }
            OpenPayload::MultiCluster {
                extents,
                chunk_ends,
                raw_size,
                codec,
                ext_codec,
                entry_id,
                run_generation,
                cache,
            } => {
                if offset >= *raw_size || extents.is_empty() {
                    return Ok(0);
                }
                let end = offset.saturating_add(len as u64).min(*raw_size);
                let plain_direct = self.reader.crypto_context().is_none()
                    && *codec == CODEC_NONE
                    && ext_codec.is_none();

                // Binary-search the first chunk whose cumulative end > offset (`O(log C)`).
                let first_chunk = chunk_ends.partition_point(|&ce| ce <= offset);
                let mut written = 0usize;
                for (idx, ext) in extents.iter().enumerate().skip(first_chunk) {
                    let chunk_start = if idx == 0 { 0 } else { chunk_ends[idx - 1] };
                    if chunk_start >= end {
                        break;
                    }
                    let chunk_end = chunk_ends[idx];
                    let ov_start = chunk_start.max(offset);
                    let ov_end = chunk_end.min(end);
                    let s = usize::try_from(ov_start - chunk_start)
                        .map_err(|_| VzError::ValueOverflow)?;
                    let e =
                        usize::try_from(ov_end - chunk_start).map_err(|_| VzError::ValueOverflow)?;
                    let take = e - s;

                    if plain_direct {
                        let read_off = ext
                            .cluster_offset
                            .checked_add(ext.in_cluster_offset as u64)
                            .and_then(|v| v.checked_add(s as u64))
                            .ok_or(VzError::ValueOverflow)?;
                        self.reader
                            .reader()
                            .read_at(read_off, &mut dst[written..written + take])?;
                    } else {
                        let chunk_arc = self.load_cached_mc_chunk(
                            cache,
                            idx,
                            ext,
                            *codec,
                            ext_codec.as_ref(),
                            *run_generation,
                            *entry_id,
                        )?;
                        if e > chunk_arc.len() {
                            return Err(VzError::BadFormat);
                        }
                        dst[written..written + take].copy_from_slice(&chunk_arc[s..e]);
                    }
                    written += take;
                }
                Ok(written)
            }
            OpenPayload::Sparse {
                data_offset,
                in_cluster_offset,
                stored_size,
                raw_size,
                is_multi_cluster,
                codec,
                ext_codec,
                extents,
                entry_id,
                run_generation,
                packed_cache,
            } => {
                if offset >= *raw_size {
                    return Ok(0);
                }
                let end = offset.saturating_add(len as u64).min(*raw_size);
                let want = usize::try_from(end - offset).map_err(|_| VzError::ValueOverflow)?;
                dst[..want].fill(0);

                // Short-circuit: if [offset..end) lies completely in a zero hole, avoid ALL I/O.
                let any_overlap = extents.iter().any(|ext| {
                    let es = ext.logical_offset;
                    let ee = es.saturating_add(ext.length);
                    ee > offset && es < end
                });
                if !any_overlap || (*stored_size == 0 && extents.iter().all(|x| x.length == 0)) {
                    return Ok(want);
                }

                let packed: Arc<[u8]> = {
                    if let Ok(guard) = packed_cache.lock()
                        && let Some(ref arc) = *guard
                    {
                        Arc::clone(arc)
                    } else {
                        let total_sparse_data: u64 = extents.iter().map(|e| e.length).sum();
                        let decoded = Arc::<[u8]>::from(self.reader.read_non_inline_bytes(
                            *is_multi_cluster,
                            *data_offset,
                            *in_cluster_offset,
                            *stored_size,
                            total_sparse_data,
                            *codec,
                            ext_codec.as_ref(),
                            *run_generation,
                            *entry_id,
                        )?);
                        if decoded.len() as u64 != total_sparse_data {
                            return Err(VzError::BadFormat);
                        }
                        if let Ok(mut guard) = packed_cache.lock() {
                            *guard = Some(Arc::clone(&decoded));
                        }
                        decoded
                    }
                };

                let mut src_pos = 0u64;
                for ext in extents {
                    let ext_start = ext.logical_offset;
                    let ext_end = ext_start
                        .checked_add(ext.length)
                        .ok_or(VzError::ValueOverflow)?;
                    if ext_end > *raw_size {
                        return Err(VzError::BadFormat);
                    }
                    if ext_end > offset && ext_start < end {
                        let ov_start = ext_start.max(offset);
                        let ov_end = ext_end.min(end);
                        let src_off = usize::try_from(src_pos + (ov_start - ext_start))
                            .map_err(|_| VzError::ValueOverflow)?;
                        let dst_off =
                            usize::try_from(ov_start - offset).map_err(|_| VzError::ValueOverflow)?;
                        let cp_len =
                            usize::try_from(ov_end - ov_start).map_err(|_| VzError::ValueOverflow)?;
                        dst[dst_off..dst_off + cp_len]
                            .copy_from_slice(&packed[src_off..src_off + cp_len]);
                    }
                    src_pos += ext.length;
                }
                Ok(want)
            }
        }
    }

    /// FUSE3 `read(fh, offset, size)`: reads `[offset, offset + len)` cleanly into a newly
    /// allocated `Vec<u8>`.
    pub fn read(
        &self,
        handle: &FuseFileHandle,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, VzError> {
        if len == 0 || offset >= handle.attr.size {
            return Ok(Vec::new());
        }
        let avail = handle.attr.size - offset;
        let want = usize::try_from(avail.min(len as u64)).unwrap_or(len);
        let mut out = vec![0u8; want];
        let n = self.read_into(handle, offset, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn load_cached_mc_chunk(
        &self,
        cache: &Mutex<Option<CachedChunk>>,
        idx: usize,
        ext: &ChunkExtent,
        codec: u8,
        ext_codec: Option<&ExtCodecMeta>,
        run_generation: u64,
        entry_id: u64,
    ) -> Result<Arc<[u8]>, VzError> {
        if let Ok(guard) = cache.lock()
            && let Some(ref cc) = *guard
            && cc.chunk_idx == idx
        {
            return Ok(Arc::clone(&cc.data));
        }
        let decoded: Arc<[u8]> = Arc::from(self.reader.read_single_cluster_payload(
            ext.cluster_offset,
            ext.in_cluster_offset,
            ext.stored_size,
            ext.raw_size,
            codec,
            ext_codec,
            run_generation,
            entry_id,
        )?);
        if let Ok(mut guard) = cache.lock() {
            *guard = Some(CachedChunk {
                chunk_idx: idx,
                data: Arc::clone(&decoded),
            });
        }
        Ok(decoded)
    }
}

fn ensure_dir_chain(
    dir_path: &str,
    nodes: &mut Vec<InodeNode>,
    dir_map: &mut HashMap<String, u64>,
) -> u64 {
    if dir_path.is_empty() || dir_path == "/" {
        return FUSE_ROOT_ID;
    }
    if let Some(&ino) = dir_map.get(dir_path) {
        return ino;
    }
    let mut cur_ino = FUSE_ROOT_ID;
    let mut cur_path = String::new();
    for seg in dir_path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        cur_path.push('/');
        cur_path.push_str(seg);
        if let Some(&ino) = dir_map.get(&cur_path) {
            cur_ino = ino;
            continue;
        }
        let new_ino = (nodes.len() + 1) as u64;
        nodes.push(InodeNode {
            attr: FuseAttr {
                ino: new_ino,
                size: 0,
                blocks: 0,
                atime_sec: 0,
                atime_nsec: 0,
                mtime_sec: 0,
                mtime_nsec: 0,
                ctime_sec: 0,
                ctime_nsec: 0,
                crtime_sec: 0,
                crtime_nsec: 0,
                kind: FuseFileKind::Directory,
                perm: 0o755,
                nlink: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 65_536,
            },
            parent_ino: cur_ino,
            children: Vec::new(),
            xattrs: Vec::new(),
            payload: PayloadSource::None,
        });
        nodes[(cur_ino - 1) as usize]
            .children
            .push((seg.to_string(), new_ino));
        dir_map.insert(cur_path.clone(), new_ino);
        cur_ino = new_ino;
    }
    cur_ino
}

fn apply_entry_metadata_to_attr(
    attr: &mut FuseAttr,
    entry: &crate::reader::ResolvedEntry,
    kind: FuseFileKind,
) {
    attr.kind = kind;
    attr.perm = entry.stat.mode & 0o7777;
    if let Some(ref owner) = entry.stat.owner {
        attr.uid = owner.uid;
        attr.gid = owner.gid;
    }
    if let Some(et) = entry.stat.ext_time {
        attr.atime_sec = et.mtime_sec;
        attr.atime_nsec = et.mtime_nsec;
        attr.mtime_sec = et.mtime_sec;
        attr.mtime_nsec = et.mtime_nsec;
        attr.ctime_sec = et.mtime_sec;
        attr.ctime_nsec = et.mtime_nsec;
        attr.crtime_sec = et.btime_sec;
        attr.crtime_nsec = et.btime_nsec;
    } else {
        let (sec, nsec) = split_mtime_ns(entry.stat.mtime_ns);
        attr.atime_sec = sec;
        attr.atime_nsec = nsec;
        attr.mtime_sec = sec;
        attr.mtime_nsec = nsec;
        attr.ctime_sec = sec;
        attr.ctime_nsec = nsec;
    }
}
