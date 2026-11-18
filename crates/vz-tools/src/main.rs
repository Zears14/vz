use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::UNIX_EPOCH;

use clap::{Parser, Subcommand};
use libvz::cli_support::{CliCodec, CliHashAlgo};
use libvz::{
    CompactOptions, EncryptionKey, EntryOptions, InPlaceCompactOptions, KIND_DIR, KIND_LNK,
    KIND_REG, LsmAppendWriter, MmapRangeReader, OwnerEntry, VzError, VzPipeWriter, VzReader,
    VzReaderOptions, VzWriter, VzWriterConfig, compact_archive_with_options, compact_file_in_place,
    finalize_pipe_archive, repair_file, scan_clusters_forward, verify_archive,
};

#[derive(Parser)]
#[command(name = "vz", version, about = "VZ (.vz) container format CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Pack a directory tree into a .vz archive
    Pack {
        source: PathBuf,
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = CliCodec::None)]
        codec: CliCodec,
        #[arg(long, default_value_t = 3)]
        level: i32,
        #[arg(long, value_enum, default_value_t = CliHashAlgo::Builtin)]
        hash: CliHashAlgo,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        key_hex: Option<String>,
        /// Reed-Solomon GF(2^8) parity K,M (e.g. 6,3)
        #[arg(long)]
        rs: Option<String>,
        #[arg(long)]
        no_boot_ecc: bool,
        #[arg(long, default_value_t = 1024 * 1024)]
        cluster_size: usize,
        #[arg(long, default_value_t = 512)]
        max_leaf_entries: usize,
        #[arg(long, default_value_t = 128)]
        max_route_entries: usize,
        /// Use streaming pipe writer (finalize Boot Block afterward unless --unfinalized-pipe)
        #[arg(long)]
        pipe: bool,
        #[arg(long)]
        unfinalized_pipe: bool,
    },
    /// Unpack a .vz archive into a destination directory
    Unpack {
        archive: PathBuf,
        dest: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        key_hex: Option<String>,
        #[arg(long)]
        mmap: bool,
    },
    /// List entries in a directory inside a .vz archive
    Ls {
        archive: PathBuf,
        #[arg(default_value = "/")]
        path: String,
        #[arg(short, long)]
        recursive: bool,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        key_hex: Option<String>,
    },
    /// Print detailed metadata for an archive entry
    Stat {
        archive: PathBuf,
        path: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        key_hex: Option<String>,
    },
    /// Stream file contents to stdout
    Cat {
        archive: PathBuf,
        path: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        key_hex: Option<String>,
    },
    /// Verify Boot Block ECC, cluster CRCs, B+Tree nodes, and RS parity
    Verify {
        archive: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        key_hex: Option<String>,
    },
    /// Repair damaged Boot Block pages and RS_GF256 clusters in-place
    Repair { archive: PathBuf },
    /// Append an incremental LSM overlay run (add/overwrite/delete paths)
    Append {
        archive: PathBuf,
        /// Add/overwrite HOST_PATH:ARCHIVE_PATH
        #[arg(long = "add")]
        adds: Vec<String>,
        /// Tombstone-delete ARCHIVE_PATH
        #[arg(long = "delete")]
        deletes: Vec<String>,
        #[arg(long, value_enum, default_value_t = CliCodec::None)]
        codec: CliCodec,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        key_hex: Option<String>,
    },
    /// Compact a multi-run LSM archive into a single-run .vz archive (zero re-encoding by default)
    Compact {
        input: PathBuf,
        output: Option<PathBuf>,
        /// Compact directly in-place using crash-safe EOF bounce journaling (`O(batch)` RAM/disk)
        #[arg(long)]
        in_place: bool,
        /// Bounded RAM & bounce batch window size in MiB for `--in-place` (default 4)
        #[arg(long, default_value_t = 4)]
        batch_mib: usize,
        /// Optional codec override (forces re-encoding instead of zero-reencode compaction)
        #[arg(long, value_enum)]
        codec: Option<CliCodec>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        key_hex: Option<String>,
        #[arg(long)]
        rs: Option<String>,
    },
    /// Inspect header slots, flags, registry tables, LSM runs, and clusters
    Inspect {
        archive: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        key_hex: Option<String>,
    },
}

fn parse_encryption(
    password: Option<String>,
    key_hex: Option<String>,
) -> Result<Option<EncryptionKey>, String> {
    if let Some(hex) = key_hex {
        let hex = hex.trim();
        if hex.len() != 64 {
            return Err("key-hex must be exactly 64 hex characters (32 bytes)".into());
        }
        let mut raw = [0u8; 32];
        for (i, slot) in raw.iter_mut().enumerate() {
            let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| "invalid hex byte in --key-hex".to_string())?;
            *slot = byte;
        }
        return Ok(Some(EncryptionKey::Raw256(raw)));
    }
    if let Some(pw) = password {
        return Ok(Some(EncryptionKey::from_password(pw)));
    }
    Ok(None)
}

fn parse_rs(rs: Option<String>) -> Result<Option<(u16, u16)>, String> {
    let Some(s) = rs else {
        return Ok(None);
    };
    let (k_s, m_s) = s
        .split_once(',')
        .ok_or_else(|| "invalid --rs format; expected K,M (e.g. 6,3)".to_string())?;
    let k: u16 = k_s
        .trim()
        .parse()
        .map_err(|_| "invalid K in --rs".to_string())?;
    let m: u16 = m_s
        .trim()
        .parse()
        .map_err(|_| "invalid M in --rs".to_string())?;
    if k == 0 || m == 0 || (k as usize + m as usize) > 256 {
        return Err("invalid RS parameters: require K >= 1, M >= 1, K + M <= 256".into());
    }
    Ok(Some((k, m)))
}

fn mtime_ns_from_meta(meta: &fs::Metadata) -> i64 {
    match meta.modified() {
        Ok(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
            Err(e) => {
                let d = e.duration();
                -(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
            }
        },
        Err(_) => 0,
    }
}

fn mode_from_meta(meta: &fs::Metadata, _default_mode: u16) -> u16 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() as u16) & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        _default_mode
    }
}

fn owner_from_meta(meta: &fs::Metadata) -> Option<OwnerEntry> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(OwnerEntry {
            uid: meta.uid(),
            gid: meta.gid(),
            uname: String::new(),
            gname: String::new(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

fn collect_tree(
    root: &Path,
    rel_prefix: &str,
    out: &mut Vec<(PathBuf, String, fs::Metadata)>,
) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(root)
        .map_err(|e| format!("failed to read {}: {e}", root.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("dir read error: {e}"))?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let archive_path = if rel_prefix.is_empty() {
            format!("/{name_str}")
        } else {
            format!("{rel_prefix}/{name_str}")
        };
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        out.push((path.clone(), archive_path.clone(), meta.clone()));
        if meta.is_dir() {
            collect_tree(&path, &archive_path, out)?;
        }
    }
    Ok(())
}

fn cmd_pack(
    source: PathBuf,
    output: PathBuf,
    config: VzWriterConfig,
    pipe: bool,
    unfinalized_pipe: bool,
) -> Result<(), String> {
    let mut items = Vec::new();
    collect_tree(&source, "", &mut items)?;

    let out_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output)
        .map_err(|e| format!("cannot create {}: {e}", output.display()))?;

    if pipe || unfinalized_pipe {
        let mut pw = VzPipeWriter::new(out_file, config).map_err(|e| format!("pipe init: {e}"))?;
        for (host_path, arch_path, meta) in items {
            let mtime_ns = mtime_ns_from_meta(&meta);
            let owner = owner_from_meta(&meta);
            let ft = meta.file_type();
            if ft.is_dir() {
                let mode = mode_from_meta(&meta, 0o755);
                pw.add_dir(&arch_path, mode, mtime_ns)
                    .map_err(|e| format!("add_dir {arch_path}: {e}"))?;
            } else if ft.is_symlink() {
                let target = fs::read_link(&host_path)
                    .map_err(|e| format!("read_link {}: {e}", host_path.display()))?;
                let opts = EntryOptions {
                    kind: KIND_LNK,
                    mode: 0o777,
                    mtime_ns,
                    owner,
                    ..Default::default()
                };
                pw.add_file_with_options(&arch_path, target.to_string_lossy().as_bytes(), opts)
                    .map_err(|e| format!("add symlink {arch_path}: {e}"))?;
            } else if ft.is_file() {
                let mode = mode_from_meta(&meta, 0o644);
                let opts = EntryOptions {
                    kind: KIND_REG,
                    mode,
                    mtime_ns,
                    owner,
                    ..Default::default()
                };
                let f = File::open(&host_path)
                    .map_err(|e| format!("open {}: {e}", host_path.display()))?;
                pw.add_file_reader(&arch_path, f, opts)
                    .map_err(|e| format!("add_file {arch_path}: {e}"))?;
            }
        }
        let (mut f, info) = pw.finish().map_err(|e| format!("pipe finish: {e}"))?;
        if !unfinalized_pipe {
            finalize_pipe_archive(&mut f, &info).map_err(|e| format!("pipe finalize: {e}"))?;
        }
        return Ok(());
    }

    let multi_thresh = config.multi_cluster_threshold as u64;
    let mut writer = VzWriter::new(out_file, config).map_err(|e| format!("writer init: {e}"))?;
    let mut reg_batch: Vec<(PathBuf, String, EntryOptions)> = Vec::new();
    let mut batch_bytes = 0usize;

    let flush_batch =
        |writer: &mut VzWriter<File>,
         batch: &mut Vec<(PathBuf, String, EntryOptions)>,
         bytes: &mut usize|
         -> Result<(), String> {
            if batch.is_empty() {
                return Ok(());
            }
            let threads = std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(batch.len());
            let file_bytes: Vec<Vec<u8>> = if threads > 1 && batch.len() >= 8 {
                let chunk_sz = batch.len().div_ceil(threads);
                let results: Vec<Result<Vec<Vec<u8>>, String>> = std::thread::scope(|s| {
                    let handles: Vec<_> = batch
                        .chunks(chunk_sz)
                        .map(|chunk| {
                            s.spawn(move || -> Result<Vec<Vec<u8>>, String> {
                                let mut out = Vec::with_capacity(chunk.len());
                                for (hp, _, _) in chunk {
                                    out.push(
                                        fs::read(hp)
                                            .map_err(|e| format!("read {}: {e}", hp.display()))?,
                                    );
                                }
                                Ok(out)
                            })
                        })
                        .collect();
                    handles
                        .into_iter()
                        .map(|h| h.join().map_err(|_| "worker panicked".to_string())?)
                        .collect()
                });
                let mut merged = Vec::with_capacity(batch.len());
                for r in results {
                    merged.extend(r?);
                }
                merged
            } else {
                let mut merged = Vec::with_capacity(batch.len());
                for (hp, _, _) in batch.iter() {
                    merged.push(fs::read(hp).map_err(|e| format!("read {}: {e}", hp.display()))?);
                }
                merged
            };

            let refs: Vec<(&str, &[u8], &EntryOptions)> = batch
                .iter()
                .zip(file_bytes.iter())
                .map(|((_, ap, opts), data)| (ap.as_str(), data.as_slice(), opts))
                .collect();
            writer
                .add_files_batch(&refs)
                .map_err(|e| format!("add_files_batch: {e}"))?;
            batch.clear();
            *bytes = 0;
            Ok(())
        };

    for (host_path, arch_path, meta) in items {
        let mtime_ns = mtime_ns_from_meta(&meta);
        let owner = owner_from_meta(&meta);
        let ft = meta.file_type();
        if ft.is_dir() {
            let mode = mode_from_meta(&meta, 0o755);
            writer
                .add_dir(&arch_path, mode, mtime_ns)
                .map_err(|e| format!("add_dir {arch_path}: {e}"))?;
        } else if ft.is_symlink() {
            let target = fs::read_link(&host_path)
                .map_err(|e| format!("read_link {}: {e}", host_path.display()))?;
            let opts = EntryOptions {
                kind: KIND_LNK,
                mode: 0o777,
                mtime_ns,
                owner,
                ..Default::default()
            };
            writer
                .add_file_with_options(&arch_path, target.to_string_lossy().as_bytes(), opts)
                .map_err(|e| format!("add symlink {arch_path}: {e}"))?;
        } else if ft.is_file() {
            let mode = mode_from_meta(&meta, 0o644);
            let opts = EntryOptions {
                kind: KIND_REG,
                mode,
                mtime_ns,
                owner,
                ..Default::default()
            };
            let flen = meta.len();
            if flen > multi_thresh {
                flush_batch(&mut writer, &mut reg_batch, &mut batch_bytes)?;
                let f = File::open(&host_path)
                    .map_err(|e| format!("open {}: {e}", host_path.display()))?;
                writer
                    .add_file_reader(&arch_path, f, opts)
                    .map_err(|e| format!("add_file {arch_path}: {e}"))?;
            } else {
                batch_bytes = batch_bytes.saturating_add(flen as usize);
                reg_batch.push((host_path, arch_path, opts));
                if reg_batch.len() >= 512 || batch_bytes >= 8 * 1024 * 1024 {
                    flush_batch(&mut writer, &mut reg_batch, &mut batch_bytes)?;
                }
            }
        }
    }
    flush_batch(&mut writer, &mut reg_batch, &mut batch_bytes)?;
    writer.finish().map_err(|e| format!("finish: {e}"))?;
    Ok(())
}

fn unpack_with_reader<R: libvz::RangeReader>(reader: &VzReader<R>, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| format!("mkdir {}: {e}", dest.display()))?;
    let mut last_dir: Option<PathBuf> = None;
    reader
        .extract_all_with(|item, data| {
            let rel_dir = item.stat.parent_path.trim_start_matches('/');
            let host_dir = if rel_dir.is_empty() {
                dest.to_path_buf()
            } else {
                dest.join(rel_dir)
            };
            if last_dir.as_ref() != Some(&host_dir) {
                fs::create_dir_all(&host_dir).map_err(|_| VzError::IoError)?;
                last_dir = Some(host_dir.clone());
            }
            let host_path = host_dir.join(&item.stat.name);

            if item.stat.kind == KIND_DIR {
                fs::create_dir_all(&host_path).map_err(|_| VzError::IoError)?;
            } else if item.stat.kind == KIND_LNK {
                let target = String::from_utf8_lossy(data).into_owned();
                #[cfg(unix)]
                {
                    if host_path.exists() {
                        let _ = fs::remove_file(&host_path);
                    }
                    std::os::unix::fs::symlink(&target, &host_path)
                        .map_err(|_| VzError::IoError)?;
                }
                #[cfg(not(unix))]
                {
                    fs::write(&host_path, data).map_err(|_| VzError::IoError)?;
                }
            } else {
                fs::write(&host_path, data).map_err(|_| VzError::IoError)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perm = fs::Permissions::from_mode(item.stat.mode as u32);
                    let _ = fs::set_permissions(&host_path, perm);
                }
            }
            Ok(())
        })
        .map_err(|e| format!("extract: {e}"))
}

fn cmd_unpack(
    archive: PathBuf,
    dest: PathBuf,
    encryption: Option<EncryptionKey>,
    use_mmap: bool,
) -> Result<(), String> {
    let f = File::open(&archive).map_err(|e| format!("open {}: {e}", archive.display()))?;
    let opts = VzReaderOptions {
        encryption,
        repair_boot_ecc: true,
    };
    if use_mmap {
        // SAFETY: Archive is opened read-only for the duration of unpack.
        let mmap = unsafe { MmapRangeReader::from_file(&f) }.map_err(|e| format!("mmap: {e}"))?;
        let reader = VzReader::open_with_options(mmap, opts).map_err(|e| format!("open: {e}"))?;
        unpack_with_reader(&reader, &dest)
    } else {
        let reader = VzReader::open_with_options(f, opts).map_err(|e| format!("open: {e}"))?;
        unpack_with_reader(&reader, &dest)
    }
}

fn kind_label(kind: u16) -> &'static str {
    match kind {
        KIND_DIR => "DIR ",
        KIND_REG => "REG ",
        KIND_LNK => "LNK ",
        libvz::KIND_TENSOR => "TNS ",
        libvz::KIND_COLUMN => "COL ",
        libvz::KIND_FIFO => "FIFO",
        libvz::KIND_CHR => "CHR ",
        libvz::KIND_BLK => "BLK ",
        libvz::KIND_SOCK => "SOCK",
        _ => "UNK ",
    }
}

fn print_ls_dir<R: libvz::RangeReader>(
    reader: &VzReader<R>,
    dir: &str,
    recursive: bool,
) -> Result<(), VzError> {
    let items = reader.readdir(dir)?;
    for st in items {
        let full = if dir == "/" {
            format!("/{}", st.name)
        } else {
            format!("{}/{}", dir.trim_end_matches('/'), st.name)
        };
        println!(
            "{} {:04o} {:>10} {}",
            kind_label(st.kind),
            st.mode,
            st.size,
            if recursive { full.as_str() } else { st.name.as_str() }
        );
        if recursive && st.kind == KIND_DIR {
            print_ls_dir(reader, &full, true)?;
        }
    }
    Ok(())
}

struct PipeSafeWriter<W> {
    inner: W,
    broken_pipe: bool,
}

impl<W: Write> Write for PipeSafeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.write(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                self.broken_pipe = true;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.flush() {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                self.broken_pipe = true;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Pack {
            source,
            output,
            codec,
            level,
            hash,
            password,
            key_hex,
            rs,
            no_boot_ecc,
            cluster_size,
            max_leaf_entries,
            max_route_entries,
            pipe,
            unfinalized_pipe,
        } => {
            let encryption = parse_encryption(password, key_hex)?;
            let rs_parity = parse_rs(rs)?;
            let cfg = VzWriterConfig {
                enable_boot_ecc: !no_boot_ecc,
                hash_algo: hash.to_wire(),
                default_codec: codec.to_wire(),
                zstd_level: level,
                target_cluster_size: cluster_size,
                multi_cluster_threshold: cluster_size,
                max_leaf_entries,
                max_route_entries,
                encryption,
                rs_parity,
                ..Default::default()
            };
            cmd_pack(source, output, cfg, pipe, unfinalized_pipe)
        }
        Commands::Unpack {
            archive,
            dest,
            password,
            key_hex,
            mmap,
        } => {
            let encryption = parse_encryption(password, key_hex)?;
            cmd_unpack(archive, dest, encryption, mmap)
        }
        Commands::Ls {
            archive,
            path,
            recursive,
            password,
            key_hex,
        } => {
            let encryption = parse_encryption(password, key_hex)?;
            let f = File::open(&archive).map_err(|e| format!("open: {e}"))?;
            let reader = VzReader::open_with_options(
                f,
                VzReaderOptions {
                    encryption,
                    repair_boot_ecc: true,
                },
            )
            .map_err(|e| format!("open vz: {e}"))?;
            print_ls_dir(&reader, &path, recursive).map_err(|e| format!("ls: {e}"))
        }
        Commands::Stat {
            archive,
            path,
            password,
            key_hex,
        } => {
            let encryption = parse_encryption(password, key_hex)?;
            let f = File::open(&archive).map_err(|e| format!("open: {e}"))?;
            let reader = VzReader::open_with_options(
                f,
                VzReaderOptions {
                    encryption,
                    repair_boot_ecc: true,
                },
            )
            .map_err(|e| format!("open vz: {e}"))?;
            let st = reader.stat(&path).map_err(|e| format!("stat: {e}"))?;
            println!("name: {}", st.name);
            println!("parent: {}", st.parent_path);
            println!("kind: {}", kind_label(st.kind).trim());
            println!("mode: {:04o}", st.mode);
            println!("size: {}", st.size);
            println!("stored_size: {}", st.stored_size);
            println!("entry_id: {}", st.entry_id);
            println!("mtime_ns: {}", st.mtime_ns);
            println!("inline: {}", st.is_inline);
            println!("sparse: {}", st.is_sparse);
            println!("multi_cluster: {}", st.is_multi_cluster);
            println!("codec: {}", st.codec);
            if let Some(et) = st.ext_time {
                println!(
                    "ext_time: mtime=({},{}) btime=({},{})",
                    et.mtime_sec, et.mtime_nsec, et.btime_sec, et.btime_nsec
                );
            }
            if let Some(o) = st.owner {
                if o.uname.is_empty() && o.gname.is_empty() {
                    println!("owner: {}:{}", o.uid, o.gid);
                } else {
                    println!("owner: {}:{} ({}:{})", o.uid, o.gid, o.uname, o.gname);
                }
            }
            if !st.xattrs.is_empty() {
                println!("xattrs: {}", st.xattrs.len());
            }
            if let Some(sid) = st.schema_id {
                println!("schema_id: {sid}");
            }
            Ok(())
        }
        Commands::Cat {
            archive,
            path,
            password,
            key_hex,
        } => {
            let encryption = parse_encryption(password, key_hex)?;
            let f = File::open(&archive).map_err(|e| format!("open: {e}"))?;
            let reader = VzReader::open_with_options(
                f,
                VzReaderOptions {
                    encryption,
                    repair_boot_ecc: true,
                },
            )
            .map_err(|e| format!("open vz: {e}"))?;
            let mut stdout = PipeSafeWriter {
                inner: io::stdout().lock(),
                broken_pipe: false,
            };
            match reader.read_file_to_writer(&path, &mut stdout) {
                Ok(_) => {}
                Err(_) if stdout.broken_pipe => return Ok(()),
                Err(e) => return Err(format!("cat: {e}")),
            }
            match stdout.flush() {
                Ok(()) => Ok(()),
                Err(_) if stdout.broken_pipe => Ok(()),
                Err(e) => Err(format!("flush: {e}")),
            }
        }
        Commands::Verify {
            archive,
            password,
            key_hex,
        } => {
            let encryption = parse_encryption(password, key_hex)?;
            let f = File::open(&archive).map_err(|e| format!("open: {e}"))?;
            let rep = verify_archive(&f, encryption).map_err(|e| format!("verify: {e}"))?;
            println!("boot_ecc_ok: {}", rep.boot_ecc_ok);
            if let Some(p) = rep.boot_ecc_repaired_page {
                println!("boot_ecc_repaired_page_in_mem: {p}");
            }
            println!("clusters_checked: {}", rep.clusters_checked);
            println!("parity_stripes_checked: {}", rep.parity_stripes_checked);
            if !rep.errors.is_empty() {
                for err in &rep.errors {
                    eprintln!("ERROR: {err}");
                }
                return Err(format!("verification failed with {} error(s)", rep.errors.len()));
            }
            Ok(())
        }
        Commands::Repair { archive } => {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&archive)
                .map_err(|e| format!("open rw: {e}"))?;
            let rep = repair_file(&mut f).map_err(|e| format!("repair: {e}"))?;
            println!("boot_page_repaired: {:?}", rep.boot_page_repaired);
            println!("data_clusters_repaired: {}", rep.data_clusters_repaired);
            println!("parity_clusters_repaired: {}", rep.parity_clusters_repaired);
            Ok(())
        }
        Commands::Append {
            archive,
            adds,
            deletes,
            codec,
            password,
            key_hex,
        } => {
            let encryption = parse_encryption(password, key_hex)?;
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&archive)
                .map_err(|e| format!("open rw: {e}"))?;
            let mut app = LsmAppendWriter::open(f, encryption, 512, 128)
                .map_err(|e| format!("append open: {e}"))?;
            for spec in adds {
                let (host, arch) = spec
                    .split_once(':')
                    .ok_or_else(|| format!("--add expects HOST_PATH:ARCHIVE_PATH, got {spec}"))?;
                let bytes = fs::read(host).map_err(|e| format!("read {host}: {e}"))?;
                let opts = EntryOptions {
                    codec: Some(codec.to_wire()),
                    ..Default::default()
                };
                app.add_file_with_options(arch, &bytes, opts)
                    .map_err(|e| format!("append add {arch}: {e}"))?;
            }
            for del in deletes {
                app.delete(&del)
                    .map_err(|e| format!("append delete {del}: {e}"))?;
            }
            app.finish().map_err(|e| format!("append finish: {e}"))?;
            Ok(())
        }
        Commands::Compact {
            input,
            output,
            in_place,
            batch_mib,
            codec,
            password,
            key_hex,
            rs,
        } => {
            let encryption = parse_encryption(password.clone(), key_hex.clone())?;
            let rs_parity = parse_rs(rs)?;
            if in_place {
                if output.is_some() {
                    return Err("--in-place takes no <OUTPUT> path".into());
                }
                if codec.is_some() {
                    return Err("--codec re-encoding cannot be combined with --in-place".into());
                }
                let mut f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&input)
                    .map_err(|e| format!("open {} for in-place compact: {e}", input.display()))?;
                let rep = compact_file_in_place(
                    &mut f,
                    InPlaceCompactOptions {
                        rs_parity,
                        encryption,
                        batch_bytes: batch_mib.max(1).saturating_mul(1024 * 1024),
                        ..Default::default()
                    },
                )
                .map_err(|e| format!("compact --in-place: {e}"))?;
                println!(
                    "compacted in-place ({}): lsm_runs {} -> 1, {} -> {} bytes, batches={}, evacuated={} bytes",
                    if rep.resumed { "resumed" } else { "fresh" },
                    rep.prev_lsm_runs,
                    rep.original_bytes,
                    rep.compacted_bytes,
                    rep.batches_written,
                    rep.evacuated_bytes
                );
                return Ok(());
            }
            let output = output.ok_or_else(|| "missing <OUTPUT> path (or pass --in-place)".to_string())?;
            let in_f = File::open(&input).map_err(|e| format!("open input: {e}"))?;
            let reader = VzReader::open_with_options(
                in_f,
                VzReaderOptions {
                    encryption: encryption.clone(),
                    repair_boot_ecc: true,
                },
            )
            .map_err(|e| format!("open vz: {e}"))?;
            let prev_runs = reader.active_slot().lsm_run_count;
            let out_f = File::create(&output).map_err(|e| format!("create output: {e}"))?;
            let opts = CompactOptions {
                rs_parity,
                encryption,
                reencode_codec: codec.map(|c| c.to_wire()),
                ..Default::default()
            };
            compact_archive_with_options(&reader, out_f, opts)
                .map_err(|e| format!("compact: {e}"))?;
            println!(
                "compacted lsm_runs {prev_runs} -> 1 (zero_reencode={})",
                codec.is_none()
            );
            Ok(())
        }
        Commands::Inspect {
            archive,
            password,
            key_hex,
        } => {
            let encryption = parse_encryption(password, key_hex)?;
            let f = File::open(&archive).map_err(|e| format!("open: {e}"))?;
            let reader = VzReader::open_with_options(
                f,
                VzReaderOptions {
                    encryption,
                    repair_boot_ecc: true,
                },
            )
            .map_err(|e| format!("open vz: {e}"))?;
            let s = reader.active_slot();
            println!("generation: {}", s.generation);
            println!("boot_block_size: {}", s.boot_block_size);
            println!("compat_flags: {:#06x}", s.compat_flags);
            println!("ro_compat_flags: {:#06x}", s.ro_compat_flags);
            println!("incompat_flags: {:#06x}", s.incompat_flags);
            println!("tree_height: {}", s.tree_height);
            println!("hash_algo: {}", s.hash_algo);
            println!("lsm_run_count: {}", s.lsm_run_count);
            println!("registry_offset: {:#06x}", s.registry_offset);
            println!("registry_size: {}", s.registry_size);
            println!("root_node_offset: {:#06x}", s.root_node_offset);
            println!("root_entry_count: {}", s.root_entry_count);
            println!("total_entries: {}", s.total_entries);
            println!("root_fallback_off: {:#x}", s.root_fallback_off);
            println!("owners: {}", reader.owners().len());
            println!("dicts: {}", reader.dicts().len());
            println!("schemas: {}", reader.schemas().len());
            println!("lsm_runs: {}", reader.lsm_runs().len());
            let clusters = scan_clusters_forward(reader.reader(), s.boot_block_size as u64)
                .map_err(|e| format!("scan clusters: {e}"))?;
            println!("clusters_scanned: {}", clusters.len());
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("vz: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
