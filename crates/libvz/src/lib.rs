//! # `libvz` — VZ v1.0 High-Level & Low-Level Container Library
//!
//! A `#![no_std]`-compatible, endian-safe implementation of the VZ v1.0 container format.
//!
//! - **High-Level Bindings (`std`):** [`Archive`], [`ArchiveBuilder`], [`ArchiveWriter`],
//!   and [`Compression`] provide ergonomic archive creation, inspection, extraction, range reads,
//!   and zero-re-encoding compaction.
//! - **Low-Level Interface (`low_level`):** Direct access to wire structs, LE-VINT/TLV codecs,
//!   `#![no_std]` CRC32C, 4 KiB Boot ECC, Reed-Solomon `GF(2^8)` erasure coding, B+Tree views,
//!   extended metadata records, cluster scanners, and [`VzReader`]/[`VzWriter`].
//! - **Core (`--no-default-features`):** `error`, `wire`, `crc`, `ecc`, `btree`, `hash`, and `io`
//!   require zero `std` or `alloc`.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod btree;
pub mod crc;
pub mod ecc;
pub mod error;
pub mod hash;
pub mod io;
pub mod wire;

#[cfg(feature = "std")]
pub mod api;
#[cfg(feature = "std")]
pub mod codec;
#[cfg(feature = "std")]
pub mod ext_meta;
#[cfg(feature = "std")]
pub mod fuse;
#[cfg(feature = "std")]
pub mod reader;
#[cfg(feature = "std")]
pub mod rs;
#[cfg(feature = "std")]
pub mod writer;

/// Full low-level container primitives, wire structs, B+Tree views, ECC/RS codecs, and raw engines.
pub mod low_level {
    pub use crate::btree::*;
    pub use crate::crc::*;
    pub use crate::ecc::*;
    pub use crate::error::*;
    pub use crate::hash::*;
    pub use crate::io::*;
    pub use crate::wire::*;
    #[cfg(feature = "std")]
    pub use crate::codec::*;
    #[cfg(feature = "std")]
    pub use crate::ext_meta::*;
    #[cfg(feature = "std")]
    pub use crate::reader::{
        DirEntryRef, RepairReport, ResolvedEntry, VerifyReport, VzReader, VzReaderOptions, VzStat,
        repair_file, repair_read_write_seek, repair_slice, scan_clusters_forward, verify_archive,
        walk_clusters_reverse,
    };
    #[cfg(feature = "std")]
    pub use crate::rs::*;
    #[cfg(feature = "std")]
    pub use crate::writer::{
        CompactOptions, EntryOptions, LsmAppendWriter, PipeFinalizeInfo, VzPipeWriter,
        VzStreamedFile, VzWriter, VzWriterConfig, compact_archive, compact_archive_with_options,
        finalize_pipe_archive,
    };
}

#[cfg(feature = "cli")]
pub mod cli_support {
    //! Shared CLI `clap::ValueEnum` definitions for `vz-cli`.
    use crate::wire::{CODEC_LZ4, CODEC_NONE, CODEC_ZSTD, HASH_ALGO_BLAKE3, HASH_ALGO_BUILTIN, HASH_ALGO_XXH3_64};

    #[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CliCodec {
        None,
        Lz4,
        Zstd,
    }

    impl CliCodec {
        pub fn to_wire(self) -> u8 {
            match self {
                Self::None => CODEC_NONE,
                Self::Lz4 => CODEC_LZ4,
                Self::Zstd => CODEC_ZSTD,
            }
        }
    }

    #[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CliHashAlgo {
        Builtin,
        Xxh3,
        Blake3,
    }

    impl CliHashAlgo {
        pub fn to_wire(self) -> u8 {
            match self {
                Self::Builtin => HASH_ALGO_BUILTIN,
                Self::Xxh3 => HASH_ALGO_XXH3_64,
                Self::Blake3 => HASH_ALGO_BLAKE3,
            }
        }
    }
}

pub use btree::*;
pub use crc::*;
pub use ecc::*;
pub use error::VzError;
pub use hash::*;
pub use io::*;
pub use wire::*;

#[cfg(feature = "std")]
pub use codec::{CryptoContext, EncryptionKey, build_payload_aad};
#[cfg(feature = "std")]
pub use ext_meta::{
    ChunkExtent, CipherHeader, ColChunkStats, ColumnEncoding, ColumnLogicalType, ColumnMeta,
    DataManifestHeader, DictEntry, ExtCodecMeta, LsmRunDesc, OwnerEntry, RootFallback,
    SchemaEntry, SchemaLinkMeta, SparseExtent, TensorDtype, TensorMeta, Xattr,
    normalize_dir_path, split_archive_path,
};
#[cfg(feature = "std")]
pub use reader::{
    DirEntryRef, RepairReport, ResolvedEntry, VerifyReport, VzReader, VzReaderOptions, VzStat,
    repair_file, repair_read_write_seek, repair_slice, scan_clusters_forward, verify_archive,
    walk_clusters_reverse,
};
#[cfg(feature = "std")]
pub use rs::{
    build_cluster_from_body, encode_rs_gf256_stripe, parse_parity_cluster_body,
    recover_rs_gf256_stripe,
};
#[cfg(feature = "std")]
pub use api::{Archive, ArchiveBuilder, ArchiveWriter, Compression};
#[cfg(feature = "std")]
pub use fuse::{
    FUSE_ROOT_ID, FuseAttr, FuseDirEntry, FuseDirEntryPlus, FuseFileHandle, FuseFileKind,
    FuseStatFs, FuseVolume,
};
#[cfg(feature = "std")]
pub use writer::{
    CompactOptions, EntryOptions, InPlaceCompactOptions, InPlaceCompactReport,
    InPlaceCrashPoint, LsmAppendWriter, PipeFinalizeInfo, VzPipeWriter, VzStreamedFile, VzWriter,
    VzWriterConfig, compact_archive, compact_archive_with_options, compact_file_in_place,
    compact_file_in_place_with_hook, finalize_pipe_archive, resume_in_place_compaction,
};
