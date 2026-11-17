//! Real-World Game `.pak` Replacement Benchmark using Linux Git Tags
//!
//! Demonstrates VZ replacing game/engine `.pak` asset containers at multi-gigabyte scale across
//! three realistic patch regimes by streaming git trees and raw diffs (`--no-renames`) directly
//! into `VzWriter` and `LsmAppendWriter` (zero double working-tree checkout):
//!
//!   Tier 1 (Day-1 Hotfix)      : `v7.3`  -> `v7.3.4`  (~hundreds of files)
//!   Tier 2 (Seasonal Update)   : `v6.11` -> `v6.12`   (~10-15% tree churn + renames/tombstones)
//!   Tier 3 (Expansion/Remaster): `v4.19` -> `v7.3`    (8-year leap, >70% churn + dead reclamation)
//!
//! Also measures:
//! - Multi-patch overlay stacking (`v7.3 -> v7.3.1 -> v7.3.2 -> v7.3.3 -> v7.3.4`) + 6T IOPS
//! - Zero-reencode LSM compaction (`compact_archive_with_options`) vs full Zstd re-encode
//! - `FuseVolume::mount` + zero-I/O metadata lookup on the patched kernel tree
//! - Cross-format Tier 1 patch comparison against `ZIP (new_append)` and `TAR.ZST` full rewrite
//!
//! Usage (outside the main benchmark suite):
//!   cargo run --release -p vz-bench --example pak_patch_bench -- --fetch /tmp/vz-linux-corpus
//!   cargo run --release -p vz-bench --example pak_patch_bench -- --repo /path/to/linux.git

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use libvz::{
    CODEC_ZSTD, CompactOptions, CountingRangeReader, EntryOptions, FUSE_ROOT_ID, FuseVolume,
    KIND_LNK, KIND_REG, LsmAppendWriter, MmapRangeReader, VzError, VzReader, VzWriter,
    VzWriterConfig, compact_archive_with_options,
};
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

const LINUX_STABLE_URL: &str =
    "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git";
const CANDIDATE_HOTFIX_SERIES: &[&str] = &["v7.3", "v7.1", "v7.0", "v6.19", "v6.12"];

#[derive(Clone, Debug)]
struct TagPlan {
    hotfix_chain: [String; 5], // [base, .1, .2, .3, .4]
    season_old: String,
    season_new: String,
    expan_old: String,
    expan_new: String,
}

impl TagPlan {
    fn all_tags(&self) -> Vec<&str> {
        let mut out = Vec::with_capacity(9);
        for t in &self.hotfix_chain {
            out.push(t.as_str());
        }
        out.push(self.season_old.as_str());
        out.push(self.season_new.as_str());
        out.push(self.expan_old.as_str());
        out.push(self.expan_new.as_str());
        out
    }

    fn resolve(repo: &Path, hotfix_override: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut chosen_base: Option<String> = None;
        if let Some(hb) = hotfix_override {
            chosen_base = Some(hb.to_string());
        } else {
            for &cand in CANDIDATE_HOTFIX_SERIES {
                let ok = [
                    cand.to_string(),
                    format!("{cand}.1"),
                    format!("{cand}.2"),
                    format!("{cand}.3"),
                    format!("{cand}.4"),
                ]
                .iter()
                .all(|t| git_has_tag(repo, t));
                if ok {
                    chosen_base = Some(cand.to_string());
                    break;
                }
            }
        }
        let base = chosen_base.unwrap_or_else(|| "v7.3".to_string());
        Ok(Self {
            hotfix_chain: [
                base.clone(),
                format!("{base}.1"),
                format!("{base}.2"),
                format!("{base}.3"),
                format!("{base}.4"),
            ],
            season_old: "v6.11".to_string(),
            season_new: "v6.12".to_string(),
            expan_old: "v4.19".to_string(),
            expan_new: base,
        })
    }
}

// ============================================================================
// GIT BARE STREAMING HELPERS
// ============================================================================

#[derive(Clone, Debug)]
struct GitTreeEntry {
    mode: u32,
    sha: String,
    path: String,
}

#[derive(Clone, Debug)]
enum GitDiffKind {
    Add,
    Modify,
    Delete,
    TypeChange,
}

#[derive(Clone, Debug)]
struct GitDiffEntry {
    kind: GitDiffKind,
    new_mode: u32,
    new_sha: String,
    path: String,
}

struct BatchBlobReader {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    header_line: String,
}

impl BatchBlobReader {
    fn spawn(repo: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take().ok_or("missing git cat-file stdin")?;
        let stdout = child.stdout.take().ok_or("missing git cat-file stdout")?;
        Ok(Self {
            child,
            stdin: BufWriter::with_capacity(64 * 1024, stdin),
            stdout: BufReader::with_capacity(256 * 1024, stdout),
            header_line: String::new(),
        })
    }

    fn read_blob_into(&mut self, sha: &str, out: &mut Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        self.stdin.write_all(sha.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;

        self.header_line.clear();
        let n = self.stdout.read_line(&mut self.header_line)?;
        if n == 0 {
            return Err("unexpected EOF from git cat-file --batch".into());
        }
        let parts: Vec<&str> = self.header_line.split_whitespace().collect();
        if parts.len() < 3 || parts[1] != "blob" {
            return Err(format!("unexpected git cat-file header: {}", self.header_line.trim()).into());
        }
        let size: usize = parts[2].parse()?;
        out.resize(size, 0);
        self.stdout.read_exact(out)?;
        let mut nl = [0u8; 1];
        self.stdout.read_exact(&mut nl)?;
        Ok(())
    }
}

impl Drop for BatchBlobReader {
    fn drop(&mut self) {
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ensure_bare_repo_fetched(repo: &Path, tags: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    if !repo.join("HEAD").exists() {
        fs::create_dir_all(repo)?;
        let st = Command::new("git")
            .arg("init")
            .arg("--bare")
            .arg(repo)
            .status()?;
        if !st.success() {
            return Err("git init --bare failed".into());
        }
        let st_rem = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["remote", "add", "origin", LINUX_STABLE_URL])
            .status()?;
        if !st_rem.success() {
            return Err("git remote add origin failed".into());
        }
    }

    println!(
        "Fetching shallow tags from {} into {} ...",
        LINUX_STABLE_URL,
        repo.display()
    );
    let mut args = vec![
        "-C",
        repo.to_str().ok_or("non-utf8 path")?,
        "fetch",
        "--depth=1",
        "--no-tags",
        "origin",
    ];
    let mut seen = HashSet::new();
    let mut tag_specs = Vec::with_capacity(tags.len());
    for &tag in tags {
        if seen.insert(tag) {
            tag_specs.push(format!("refs/tags/{tag}:refs/tags/{tag}"));
        }
    }
    for spec in &tag_specs {
        args.push(spec.as_str());
    }
    let st = Command::new("git").args(&args).status()?;
    if !st.success() {
        return Err("git fetch shallow tags failed".into());
    }
    Ok(())
}

fn git_has_tag(repo: &Path, tag: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", "--quiet", &format!("{tag}^{{tree}}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn git_ls_tree(repo: &Path, tag: &str) -> Result<Vec<GitTreeEntry>, Box<dyn std::error::Error>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["ls-tree", "-r", "-z", "--full-name", tag])
        .output()?;
    if !out.status.success() {
        return Err(format!("git ls-tree failed for {tag}").into());
    }
    let mut entries = Vec::new();
    for rec in out.stdout.split(|&b| b == 0) {
        if rec.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(rec)?;
        let (meta, path) = s.split_once('\t').ok_or("malformed ls-tree record")?;
        let mut parts = meta.split_whitespace();
        let mode_str = parts.next().ok_or("missing mode")?;
        let kind_str = parts.next().ok_or("missing type")?;
        let sha = parts.next().ok_or("missing sha")?;
        if kind_str != "blob" {
            continue;
        }
        let mode = u32::from_str_radix(mode_str, 8)?;
        if (mode & 0o170000) == 0o160000 {
            continue; // skip submodule gitlinks
        }
        entries.push(GitTreeEntry {
            mode,
            sha: sha.to_string(),
            path: path.to_string(),
        });
    }
    Ok(entries)
}

fn git_diff_raw(
    repo: &Path,
    old_tag: &str,
    new_tag: &str,
) -> Result<Vec<GitDiffEntry>, Box<dyn std::error::Error>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["diff-tree", "-r", "--raw", "-z", "--no-renames", old_tag, new_tag])
        .output()?;
    if !out.status.success() {
        return Err(format!("git diff-tree failed for {old_tag}..{new_tag}").into());
    }
    let tokens: Vec<&[u8]> = out.stdout.split(|&b| b == 0).collect();
    let mut diffs = Vec::new();
    let mut i = 0usize;
    while i + 1 < tokens.len() {
        if tokens[i].is_empty() {
            i += 1;
            continue;
        }
        let meta = std::str::from_utf8(tokens[i])?;
        if !meta.starts_with(':') {
            i += 1;
            continue;
        }
        let path = std::str::from_utf8(tokens[i + 1])?.to_string();
        i += 2;

        // Format: ":<old_mode> <new_mode> <old_sha> <new_sha> <status>"
        let parts: Vec<&str> = meta[1..].split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let new_mode = u32::from_str_radix(parts[1], 8)?;
        let new_sha = parts[3].to_string();
        let status_ch = parts[4].chars().next().unwrap_or('M');

        // Submodule changes are ignored or treated as deletion if replaced from blob.
        if (new_mode & 0o170000) == 0o160000 {
            if status_ch == 'T' {
                diffs.push(GitDiffEntry {
                    kind: GitDiffKind::Delete,
                    new_mode,
                    new_sha,
                    path,
                });
            }
            continue;
        }

        let kind = match status_ch {
            'A' => GitDiffKind::Add,
            'M' => GitDiffKind::Modify,
            'D' => GitDiffKind::Delete,
            'T' => GitDiffKind::TypeChange,
            _ => GitDiffKind::Modify,
        };
        diffs.push(GitDiffEntry {
            kind,
            new_mode,
            new_sha,
            path,
        });
    }
    Ok(diffs)
}

fn entry_options_for_git_mode(mode: u32, codec: u8) -> EntryOptions {
    let is_link = (mode & 0o170000) == 0o120000;
    EntryOptions {
        kind: if is_link { KIND_LNK } else { KIND_REG },
        mode: (mode & 0o777) as u16,
        codec: Some(codec),
        ..Default::default()
    }
}

fn emit_missing_ancestors<F>(
    path: &str,
    known_dirs: &mut HashSet<String>,
    pending_new_dirs: &mut HashSet<String>,
    mut add_dir_fn: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(&str) -> Result<(), VzError>,
{
    let mut cur = Path::new(path);
    let mut ancestors = Vec::new();
    while let Some(parent) = cur.parent() {
        let pstr = parent.to_string_lossy();
        if pstr.is_empty() || pstr == "/" || pstr == "." {
            break;
        }
        let norm = format!("/{pstr}");
        if known_dirs.contains(&norm) || pending_new_dirs.contains(&norm) {
            break;
        }
        ancestors.push(norm);
        cur = parent;
    }
    for dir in ancestors.into_iter().rev() {
        add_dir_fn(&dir)?;
        pending_new_dirs.insert(dir);
    }
    Ok(())
}

// ============================================================================
// PACK / PATCH / BENCHMARK ENGINE
// ============================================================================

struct BaseBuildResult {
    pak_path: PathBuf,
    entries: Vec<GitTreeEntry>,
    known_dirs: HashSet<String>,
    raw_bytes: u64,
    archive_bytes: u64,
    build_ms: f64,
}

fn pak_writer_config(codec: u8) -> VzWriterConfig {
    VzWriterConfig {
        default_codec: codec,
        target_cluster_size: 256 * 1024,
        multi_cluster_threshold: 2 * 1024 * 1024,
        ..Default::default()
    }
}

fn build_base_pak(
    repo: &Path,
    tag: &str,
    pak_path: &Path,
    codec: u8,
) -> Result<BaseBuildResult, Box<dyn std::error::Error>> {
    let entries = git_ls_tree(repo, tag)?;
    let mut batch = BatchBlobReader::spawn(repo)?;
    let f = File::create(pak_path)?;
    let bw = BufWriter::with_capacity(512 * 1024, f);
    let mut writer = VzWriter::new(bw, pak_writer_config(codec))?;

    let t0 = Instant::now();
    let mut known_dirs: HashSet<String> = HashSet::new();
    let mut staging_dirs: HashSet<String> = HashSet::new();
    let mut blob = Vec::with_capacity(64 * 1024);
    let mut raw_bytes = 0u64;

    for e in &entries {
        emit_missing_ancestors(&e.path, &mut known_dirs, &mut staging_dirs, |dir| {
            writer.add_dir(dir, 0o755, 0)
        })?;
        for d in staging_dirs.drain() {
            known_dirs.insert(d);
        }
        batch.read_blob_into(&e.sha, &mut blob)?;
        raw_bytes += blob.len() as u64;
        writer.add_file_with_options(
            &e.path,
            &blob,
            entry_options_for_git_mode(e.mode, codec),
        )?;
    }

    let bw_done = writer.finish()?;
    let mut f_done = bw_done.into_inner()?;
    f_done.flush()?;
    let archive_bytes = f_done.metadata()?.len();
    let build_ms = t0.elapsed().as_secs_f64() * 1000.0;

    Ok(BaseBuildResult {
        pak_path: pak_path.to_path_buf(),
        entries,
        known_dirs,
        raw_bytes,
        archive_bytes,
        build_ms,
    })
}

struct DeltaApplyStats {
    adds: usize,
    mods: usize,
    dels: usize,
    raw_changed_bytes: u64,
    delta_bytes_written: u64,
    elapsed_ms: f64,
    new_len: u64,
}

fn apply_git_delta(
    repo: &Path,
    pak_path: &Path,
    old_tag: &str,
    new_tag: &str,
    known_dirs: &mut HashSet<String>,
    codec: u8,
) -> Result<(Vec<GitDiffEntry>, DeltaApplyStats), Box<dyn std::error::Error>> {
    let diffs = git_diff_raw(repo, old_tag, new_tag)?;
    let orig_len = fs::metadata(pak_path)?.len();

    // Pre-scan any paths replaced from a file (`D`) to an ancestor directory of a newly added file
    // so `add_dir` overwrites the slot cleanly without colliding with a same-delta tombstone.
    let mut suppressed_deletes: HashSet<String> = HashSet::new();
    {
        let deleted_set: HashSet<&str> = diffs
            .iter()
            .filter(|d| matches!(d.kind, GitDiffKind::Delete))
            .map(|d| d.path.as_str())
            .collect();
        if !deleted_set.is_empty() {
            for d in &diffs {
                if !matches!(d.kind, GitDiffKind::Delete) {
                    let mut cur = Path::new(&d.path);
                    while let Some(parent) = cur.parent() {
                        let pstr = parent.to_string_lossy();
                        if pstr.is_empty() || pstr == "." {
                            break;
                        }
                        if deleted_set.contains(pstr.as_ref()) {
                            suppressed_deletes.insert(pstr.into_owned());
                        }
                        cur = parent;
                    }
                }
            }
        }
    }

    let mut batch = BatchBlobReader::spawn(repo)?;
    let rw = OpenOptions::new().read(true).write(true).open(pak_path)?;
    let mut app = LsmAppendWriter::open(rw, None, 1024, 128)?;

    let t0 = Instant::now();
    let mut delta_dirs: HashSet<String> = HashSet::new();
    let mut blob = Vec::with_capacity(64 * 1024);
    let mut adds = 0usize;
    let mut mods = 0usize;
    let mut dels = 0usize;
    let mut raw_changed_bytes = 0u64;

    for d in &diffs {
        match d.kind {
            GitDiffKind::Delete => {
                if !suppressed_deletes.contains(&d.path) {
                    app.delete(&d.path)?;
                    dels += 1;
                }
            }
            GitDiffKind::Add | GitDiffKind::Modify | GitDiffKind::TypeChange => {
                emit_missing_ancestors(&d.path, known_dirs, &mut delta_dirs, |dir| {
                    app.add_dir(dir, 0o755, 0)
                })?;
                batch.read_blob_into(&d.new_sha, &mut blob)?;
                raw_changed_bytes += blob.len() as u64;
                app.add_file_with_options(
                    &d.path,
                    &blob,
                    entry_options_for_git_mode(d.new_mode, codec),
                )?;
                if matches!(d.kind, GitDiffKind::Add) {
                    adds += 1;
                } else {
                    mods += 1;
                }
            }
        }
    }

    let mut f_done = app.finish()?;
    f_done.flush()?;
    let new_len = f_done.metadata()?.len();
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
    known_dirs.extend(delta_dirs);

    // Appended clusters + Boot Block slot update (64 KiB)
    let delta_bytes_written = new_len.saturating_sub(orig_len) + 65_536;

    Ok((
        diffs,
        DeltaApplyStats {
            adds,
            mods,
            dels,
            raw_changed_bytes,
            delta_bytes_written,
            elapsed_ms,
            new_len,
        },
    ))
}

fn verify_spot_diffs(
    repo: &Path,
    pak_path: &Path,
    diffs: &[GitDiffEntry],
) -> Result<(), Box<dyn std::error::Error>> {
    let reader = VzReader::open(File::open(pak_path)?)?;
    let mut batch = BatchBlobReader::spawn(repo)?;
    let mut expected = Vec::new();
    let mut checked_live = 0usize;
    let mut checked_del = 0usize;

    for d in diffs {
        match d.kind {
            GitDiffKind::Delete => {
                if checked_del < 128 {
                    let res = reader.read_file(&d.path);
                    assert_eq!(res, Err(VzError::NotFound), "deleted {} still visible", d.path);
                    checked_del += 1;
                }
            }
            GitDiffKind::Add | GitDiffKind::Modify | GitDiffKind::TypeChange => {
                if checked_live < 128 {
                    batch.read_blob_into(&d.new_sha, &mut expected)?;
                    let got = reader.read_file(&d.path)?;
                    assert_eq!(got, expected, "content mismatch on {}", d.path);
                    checked_live += 1;
                }
            }
        }
        if checked_live >= 128 && checked_del >= 128 {
            break;
        }
    }
    Ok(())
}

struct IopsReport {
    iops_1t: f64,
    p50_1t_us: f64,
    p99_1t_us: f64,
    iops_6t: f64,
    p50_6t_us: f64,
    p99_6t_us: f64,
}

fn bench_random_read_iops(
    pak_path: &Path,
    live_paths: &[String],
    ops_per_thread: usize,
) -> Result<IopsReport, Box<dyn std::error::Error>> {
    let f = File::open(pak_path)?;
    // SAFETY: archive file is immutable during this read-only benchmark phase.
    let mmap = unsafe { MmapRangeReader::from_file(&f)? };
    let reader = Arc::new(VzReader::open(mmap)?);

    // Warm single-thread probe + 1T latency distribution
    let n = live_paths.len();
    assert!(n > 0);
    let mut lats_1t = Vec::with_capacity(ops_per_thread);
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let t1_all = Instant::now();
    for _ in 0..ops_per_thread {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let p = &live_paths[(rng as usize) % n];
        let ts = Instant::now();
        let data = reader.read_file(p)?;
        black_box(data.len());
        lats_1t.push(ts.elapsed().as_nanos() as u64);
    }
    let dt1 = t1_all.elapsed().as_secs_f64();
    lats_1t.sort_unstable();

    // 6T concurrent read IOPS sharing the single Arc<VzReader<MmapRangeReader>>
    let shared_paths = Arc::new(live_paths.to_vec());
    let threads = 6usize;
    let t6_all = Instant::now();
    let mut handles = Vec::with_capacity(threads);
    for tid in 0..threads {
        let r = Arc::clone(&reader);
        let ps = Arc::clone(&shared_paths);
        handles.push(std::thread::spawn(move || -> Result<Vec<u64>, VzError> {
            let mut local_lats = Vec::with_capacity(ops_per_thread);
            let mut s = 0xD1B5_4A32_D192_ED03u64 ^ ((tid as u64 + 1) * 0x94D0_49BB_1331_11EB);
            let len = ps.len();
            for _ in 0..ops_per_thread {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                let p = &ps[(s as usize) % len];
                let ts = Instant::now();
                let data = r.read_file(p)?;
                black_box(data.len());
                local_lats.push(ts.elapsed().as_nanos() as u64);
            }
            Ok(local_lats)
        }));
    }
    let mut all_lats_6t = Vec::with_capacity(threads * ops_per_thread);
    for h in handles {
        let res = h.join().map_err(|_| "worker panicked")??;
        all_lats_6t.extend(res);
    }
    let dt6 = t6_all.elapsed().as_secs_f64();
    all_lats_6t.sort_unstable();

    let pct = |sorted: &[u64], num: usize, den: usize| -> f64 {
        let idx = ((sorted.len() - 1) * num) / den;
        sorted[idx] as f64 / 1000.0
    };

    Ok(IopsReport {
        iops_1t: ops_per_thread as f64 / dt1,
        p50_1t_us: pct(&lats_1t, 50, 100),
        p99_1t_us: pct(&lats_1t, 99, 100),
        iops_6t: (threads * ops_per_thread) as f64 / dt6,
        p50_6t_us: pct(&all_lats_6t, 50, 100),
        p99_6t_us: pct(&all_lats_6t, 99, 100),
    })
}

struct CountingReadSeek<T> {
    inner: T,
    reads: usize,
    bytes: u64,
}

impl<T> CountingReadSeek<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            reads: 0,
            bytes: 0,
        }
    }
}

impl<T: Read> Read for CountingReadSeek<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.reads += 1;
        self.bytes += n as u64;
        Ok(n)
    }
}

impl<T: Seek> Seek for CountingReadSeek<T> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

fn live_paths_for_tag(repo: &Path, tag: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(git_ls_tree(repo, tag)?.into_iter().map(|e| e.path).collect())
}

fn copy_file_fresh(src: &Path, dst: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::copy(src, dst)?;
    Ok(())
}

// ============================================================================
// MAIN SUITE DRIVER
// ============================================================================

struct CliArgs {
    repo: PathBuf,
    fetch: bool,
    hotfix_base: Option<String>,
    include_tar_season: bool,
    ops_per_thread: usize,
}

fn parse_args() -> Result<CliArgs, Box<dyn std::error::Error>> {
    let mut repo: Option<PathBuf> = None;
    let mut fetch = false;
    let mut hotfix_base: Option<String> = None;
    let mut include_tar_season = false;
    let mut ops_per_thread = 10_000usize;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--repo" => {
                repo = Some(PathBuf::from(it.next().ok_or("--repo needs a path")?));
            }
            "--hotfix-base" => {
                hotfix_base = Some(it.next().ok_or("--hotfix-base needs a tag like v7.1")?);
            }
            "--fetch" => {
                fetch = true;
                if let Some(next) = it.peek_or_consume_value() {
                    repo = Some(PathBuf::from(next));
                }
            }
            "--include-tar-season" => include_tar_season = true,
            "--ops" => {
                ops_per_thread = it.next().ok_or("--ops needs an integer")?.parse()?;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: pak_patch_bench [--repo <PATH>] [--hotfix-base <TAG>] [--fetch [PATH]] [--include-tar-season] [--ops <N>]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    Ok(CliArgs {
        repo: repo.unwrap_or_else(|| PathBuf::from("/tmp/vz-linux-corpus")),
        fetch,
        hotfix_base,
        include_tar_season,
        ops_per_thread,
    })
}

trait OptFlagArg {
    fn peek_or_consume_value(&mut self) -> Option<String>;
}

impl OptFlagArg for std::iter::Skip<std::env::Args> {
    fn peek_or_consume_value(&mut self) -> Option<String> {
        let args: Vec<String> = std::env::args().collect();
        // Check if `--fetch` was followed by a non-flag value.
        for pair in args.windows(2) {
            if pair[0] == "--fetch" && !pair[1].starts_with("--") {
                return self.next();
            }
        }
        None
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_args()?;
    let mut tags = TagPlan::resolve(&cli.repo, cli.hotfix_base.as_deref())?;
    if cli.fetch {
        ensure_bare_repo_fetched(&cli.repo, &tags.all_tags())?;
        tags = TagPlan::resolve(&cli.repo, cli.hotfix_base.as_deref())?;
    }

    let missing: Vec<&str> = tags
        .all_tags()
        .into_iter()
        .filter(|t| !git_has_tag(&cli.repo, t))
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "Linux git corpus missing required tags at {}: {:?}",
            cli.repo.display(),
            missing
        );
        eprintln!(
            "Run with `--fetch {}` or pass `--repo <existing-linux.git> [--hotfix-base <TAG>]`.",
            cli.repo.display()
        );
        std::process::exit(2);
    }

    let work = TempDir::new()?;
    let wd = work.path();
    let t0_tag = tags.hotfix_chain[0].as_str();
    let t4_tag = tags.hotfix_chain[4].as_str();
    println!("=== VZ Real-World Game .pak Replacement Benchmark (Linux Kernel Corpus) ===");
    println!("Repo: {} | Workdir: {}", cli.repo.display(), wd.display());
    println!(
        "Tag Plan: Tier 1 ({}->{}) | Tier 2 ({}->{}) | Tier 3 ({}->{})",
        t0_tag, t4_tag, tags.season_old, tags.season_new, tags.expan_old, tags.expan_new
    );

    // ------------------------------------------------------------------------
    // [A] BUILD BASE PACKS & BENCHMARK 3-TIER PATCH MATRIX
    // ------------------------------------------------------------------------
    println!("\n[A] Building Base .vz Containers (Zstd, 256 KiB clusters) & 3-Tier Patches");
    let base_hot = build_base_pak(&cli.repo, t0_tag, &wd.join("base-hotfix.vz"), CODEC_ZSTD)?;
    println!(
        "  Base {:<6}: {:>6} files | raw={:>7.2} MiB | vz={:>7.2} MiB ({:.1}%) | {:.2} ms",
        t0_tag,
        base_hot.entries.len(),
        base_hot.raw_bytes as f64 / (1024.0 * 1024.0),
        base_hot.archive_bytes as f64 / (1024.0 * 1024.0),
        base_hot.archive_bytes as f64 * 100.0 / base_hot.raw_bytes as f64,
        base_hot.build_ms
    );

    let base_season = build_base_pak(
        &cli.repo,
        &tags.season_old,
        &wd.join("base-season.vz"),
        CODEC_ZSTD,
    )?;
    println!(
        "  Base {:<6}: {:>6} files | raw={:>7.2} MiB | vz={:>7.2} MiB ({:.1}%) | {:.2} ms",
        tags.season_old,
        base_season.entries.len(),
        base_season.raw_bytes as f64 / (1024.0 * 1024.0),
        base_season.archive_bytes as f64 / (1024.0 * 1024.0),
        base_season.archive_bytes as f64 * 100.0 / base_season.raw_bytes as f64,
        base_season.build_ms
    );

    let base_expan = build_base_pak(
        &cli.repo,
        &tags.expan_old,
        &wd.join("base-expan.vz"),
        CODEC_ZSTD,
    )?;
    println!(
        "  Base {:<6}: {:>6} files | raw={:>7.2} MiB | vz={:>7.2} MiB ({:.1}%) | {:.2} ms",
        tags.expan_old,
        base_expan.entries.len(),
        base_expan.raw_bytes as f64 / (1024.0 * 1024.0),
        base_expan.archive_bytes as f64 / (1024.0 * 1024.0),
        base_expan.archive_bytes as f64 * 100.0 / base_expan.raw_bytes as f64,
        base_expan.build_ms
    );

    // Tier 1: hotfix base -> .4
    let t1_pak = wd.join("tier1-hotfix.vz");
    copy_file_fresh(&base_hot.pak_path, &t1_pak)?;
    let mut t1_dirs = base_hot.known_dirs.clone();
    let (t1_diffs, t1_stats) =
        apply_git_delta(&cli.repo, &t1_pak, t0_tag, t4_tag, &mut t1_dirs, CODEC_ZSTD)?;
    verify_spot_diffs(&cli.repo, &t1_pak, &t1_diffs)?;
    let _ = fs::remove_file(&t1_pak);

    // Tier 2: season_old -> season_new
    let t2_pak = wd.join("tier2-season.vz");
    copy_file_fresh(&base_season.pak_path, &t2_pak)?;
    let mut t2_dirs = base_season.known_dirs.clone();
    let (t2_diffs, t2_stats) = apply_git_delta(
        &cli.repo,
        &t2_pak,
        &tags.season_old,
        &tags.season_new,
        &mut t2_dirs,
        CODEC_ZSTD,
    )?;
    verify_spot_diffs(&cli.repo, &t2_pak, &t2_diffs)?;
    let _ = fs::remove_file(&t2_pak);
    let _ = fs::remove_file(&base_season.pak_path);

    // Tier 3: expan_old -> expan_new
    let t3_pak = wd.join("tier3-expan.vz");
    copy_file_fresh(&base_expan.pak_path, &t3_pak)?;
    let mut t3_dirs = base_expan.known_dirs.clone();
    let (t3_diffs, t3_stats) = apply_git_delta(
        &cli.repo,
        &t3_pak,
        &tags.expan_old,
        &tags.expan_new,
        &mut t3_dirs,
        CODEC_ZSTD,
    )?;
    verify_spot_diffs(&cli.repo, &t3_pak, &t3_diffs)?;
    let _ = fs::remove_file(&base_expan.pak_path);

    let l1 = format!("1. Hotfix ({t0_tag}->{t4_tag})");
    let l2 = format!("2. Season ({}->{})", tags.season_old, tags.season_new);
    let l3 = format!("3. Expan  ({}->{})", tags.expan_old, tags.expan_new);
    println!();
    println!(
        "{:<26} | {:>19} | {:>10} | {:>11} | {:>10}",
        "Tier (Jump)", "+Add / ~Mod / -Del", "Raw Chg MB", "Delta Write", "Time (ms)"
    );
    println!("{}", "-".repeat(90));
    for (name, st) in [(&l1, &t1_stats), (&l2, &t2_stats), (&l3, &t3_stats)] {
        println!(
            "{:<26} | {:>5} / {:>5} / {:>5} | {:>10.2} | {:>8.2} MB | {:>10.2}",
            name,
            st.adds,
            st.mods,
            st.dels,
            st.raw_changed_bytes as f64 / (1024.0 * 1024.0),
            st.delta_bytes_written as f64 / (1024.0 * 1024.0),
            st.elapsed_ms
        );
    }

    // ------------------------------------------------------------------------
    // [B] CONSECUTIVE 5-RUN HOTFIX STACKING + 6T IOPS + FUSE MOUNT
    // ------------------------------------------------------------------------
    println!(
        "\n[B] Stacking Point Releases ({} -> .1 -> .2 -> .3 -> .4, lsm_run_count=5) & 6T IOPS",
        t0_tag
    );
    let stacked_pak = wd.join("stacked-hotfix.vz");
    copy_file_fresh(&base_hot.pak_path, &stacked_pak)?;
    let mut stack_dirs = base_hot.known_dirs.clone();
    let mut stack_total_ms = 0.0f64;
    for w in tags.hotfix_chain.windows(2) {
        let (_, st) = apply_git_delta(&cli.repo, &stacked_pak, &w[0], &w[1], &mut stack_dirs, CODEC_ZSTD)?;
        stack_total_ms += st.elapsed_ms;
    }
    let vr_stack = Arc::new(VzReader::open(File::open(&stacked_pak)?)?);
    assert_eq!(vr_stack.active_slot().lsm_run_count, 5);

    let t_mnt = Instant::now();
    let fs_stack = FuseVolume::mount(Arc::clone(&vr_stack))?;
    let mount_ms = t_mnt.elapsed().as_secs_f64() * 1000.0;
    let d_drivers = fs_stack.lookup(FUSE_ROOT_ID, "drivers")?;
    println!(
        "  Stacked 4 patches total: {stack_total_ms:.2} ms | lsm_run_count=5 | FuseVolume::mount={mount_ms:.2} ms (drivers ino={})",
        d_drivers.ino
    );

    let live_t4 = live_paths_for_tag(&cli.repo, t4_tag)?;
    let live_expan_new = live_paths_for_tag(&cli.repo, &tags.expan_new)?;

    let iops_stack = bench_random_read_iops(&stacked_pak, &live_t4, cli.ops_per_thread)?;
    let iops_exp = bench_random_read_iops(&t3_pak, &live_expan_new, cli.ops_per_thread)?;
    let _ = fs::remove_file(&stacked_pak);

    // ------------------------------------------------------------------------
    // [C] ZERO-REENCODE COMPACTION VS FULL REBUILD ON expan_old -> expan_new
    // ------------------------------------------------------------------------
    println!(
        "\n[C] Zero-Reencode LSM Compaction vs Full Re-encode ({} -> {} expansion)",
        tags.expan_old, tags.expan_new
    );
    let t3_reader = VzReader::open(File::open(&t3_pak)?)?;
    assert_eq!(t3_reader.active_slot().lsm_run_count, 2);

    let comp_fast_pak = wd.join("t3-compacted-fast.vz");
    let t_fast = Instant::now();
    {
        let out = BufWriter::with_capacity(512 * 1024, File::create(&comp_fast_pak)?);
        let done = compact_archive_with_options(&t3_reader, out, CompactOptions::default())?;
        done.into_inner()?.flush()?;
    }
    let ms_fast = t_fast.elapsed().as_secs_f64() * 1000.0;
    let sz_fast = fs::metadata(&comp_fast_pak)?.len();

    let comp_reenc_pak = wd.join("t3-compacted-reencode.vz");
    let t_reenc = Instant::now();
    {
        let out = BufWriter::with_capacity(512 * 1024, File::create(&comp_reenc_pak)?);
        let done = compact_archive_with_options(
            &t3_reader,
            out,
            CompactOptions {
                reencode_codec: Some(CODEC_ZSTD),
                ..Default::default()
            },
        )?;
        done.into_inner()?.flush()?;
    }
    let ms_reenc = t_reenc.elapsed().as_secs_f64() * 1000.0;
    let sz_reenc = fs::metadata(&comp_reenc_pak)?.len();
    let _ = fs::remove_file(&comp_reenc_pak);
    drop(t3_reader);
    let _ = fs::remove_file(&t3_pak);

    let vr_fast = VzReader::open(File::open(&comp_fast_pak)?)?;
    assert_eq!(vr_fast.active_slot().lsm_run_count, 1);
    let iops_comp = bench_random_read_iops(&comp_fast_pak, &live_expan_new, cli.ops_per_thread)?;
    let _ = fs::remove_file(&comp_fast_pak);

    let reclaimed_bytes = t3_stats.new_len.saturating_sub(sz_fast);
    let reclaimed_pct = reclaimed_bytes as f64 * 100.0 / t3_stats.new_len as f64;
    println!(
        "  Overlay size : {:.2} MiB (lsm_run_count=2, contains dead {} clusters)",
        t3_stats.new_len as f64 / (1024.0 * 1024.0),
        tags.expan_old
    );
    println!(
        "  Zero-Reencode: {ms_fast:.2} ms | size={:.2} MiB | reclaimed={:.2} MiB ({reclaimed_pct:.1}%)",
        sz_fast as f64 / (1024.0 * 1024.0),
        reclaimed_bytes as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  Full Reencode: {ms_reenc:.2} ms ({:.2}x slower) | size={:.2} MiB",
        ms_reenc / ms_fast,
        sz_reenc as f64 / (1024.0 * 1024.0)
    );
    println!();
    println!(
        "{:<38} | {:>10} | {:>7} | {:>7} | {:>10} | {:>7} | {:>7}",
        "Random-Read Container State", "1T IOPS", "1T p50", "1T p99", "6T IOPS", "6T p50", "6T p99"
    );
    println!("{}", "-".repeat(102));
    let s1 = format!("Stacked Hotfix (5 runs, {t4_tag})");
    let s2 = format!("Expansion Delta (2 runs, {}->{})", tags.expan_old, tags.expan_new);
    let s3 = format!("Compacted Single-Run ({})", tags.expan_new);
    for (label, rep) in [(&s1, &iops_stack), (&s2, &iops_exp), (&s3, &iops_comp)] {
        println!(
            "{:<38} | {:>10.0} | {:>5.2}us | {:>5.2}us | {:>10.0} | {:>5.2}us | {:>5.2}us",
            label, rep.iops_1t, rep.p50_1t_us, rep.p99_1t_us, rep.iops_6t, rep.p50_6t_us, rep.p99_6t_us
        );
    }

    // ------------------------------------------------------------------------
    // [D] TIER 1 CROSS-FORMAT & REAL UNREAL ENGINE .PAK (repak V11 Zstd)
    // ------------------------------------------------------------------------
    println!("\n[D] Unreal Engine .pak (repak V11 Zstd) & Tier 1 Patch Comparison ({t0_tag} -> {t4_tag})");
    let zip_path = wd.join("hotfix-base.zip");
    let tarz_path = wd.join("hotfix-base.tar.zst");
    let pak_path = wd.join("hotfix-base.pak");
    let (pak_build_ms, pak_base_bytes) = {
        let mut batch = BatchBlobReader::spawn(&cli.repo)?;
        let mut blob = Vec::with_capacity(64 * 1024);

        let mut zw = zip::ZipWriter::new(BufWriter::with_capacity(512 * 1024, File::create(&zip_path)?));
        let zopts = SimpleFileOptions::default().compression_method(CompressionMethod::Zstd);

        let zenc = zstd::stream::Encoder::new(
            BufWriter::with_capacity(512 * 1024, File::create(&tarz_path)?),
            3,
        )?;
        let mut tb = tar::Builder::new(zenc);

        for e in &base_hot.entries {
            batch.read_blob_into(&e.sha, &mut blob)?;
            zw.start_file(&e.path, zopts)?;
            zw.write_all(&blob)?;

            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(blob.len() as u64);
            hdr.set_mode(e.mode & 0o777);
            hdr.set_cksum();
            tb.append_data(&mut hdr, &e.path, blob.as_slice())?;
        }
        zw.finish()?.into_inner()?.flush()?;
        tb.finish()?;
        tb.into_inner()?.finish()?.into_inner()?.flush()?;

        // Build Unreal Engine V11 .pak separately so repak's pure build time is measured cleanly.
        let t_pak_build = Instant::now();
        let mut pw = repak::PakBuilder::new()
            .compression([repak::Compression::Zstd])
            .writer(
                BufWriter::with_capacity(512 * 1024, File::create(&pak_path)?),
                repak::Version::V11,
                "../../../".to_string(),
                None,
            );
        for e in &base_hot.entries {
            batch.read_blob_into(&e.sha, &mut blob)?;
            pw.write_file(&e.path, true, &blob)?;
        }
        let mut pw_inner = pw.write_index()?.into_inner()?;
        pw_inner.flush()?;
        let pak_build_ms = t_pak_build.elapsed().as_secs_f64() * 1000.0;
        let pak_base_bytes = fs::metadata(&pak_path)?.len();
        (pak_build_ms, pak_base_bytes)
    };

    // D.1 Base Pack + Cold Open + Single File Read + 6T Random IOPS: VZ vs Unreal .pak (repak)
    let probe_path = &base_hot.entries[(base_hot.entries.len() * 7) / 10].path;
    let vz_bytes_all = fs::read(&base_hot.pak_path)?;
    let t_vz_cold = Instant::now();
    let vz_crr = CountingRangeReader::new(vz_bytes_all);
    let vz_cold_r = VzReader::open(vz_crr)?;
    let vz_got = vz_cold_r.read_file(probe_path)?;
    let vz_cold_us = t_vz_cold.elapsed().as_secs_f64() * 1e6;
    let vz_cold_reads = vz_cold_r.reader().reads();
    let vz_cold_bytes = vz_cold_r.reader().bytes_read();
    drop(vz_cold_r);

    let mut pak_crs = BufReader::with_capacity(64 * 1024, CountingReadSeek::new(File::open(&pak_path)?));
    let t_pak_cold = Instant::now();
    let pak_cold_r = repak::PakBuilder::new().reader_with_version(&mut pak_crs, repak::Version::V11)?;
    let pak_got = pak_cold_r.get(probe_path, &mut pak_crs)?;
    let pak_cold_us = t_pak_cold.elapsed().as_secs_f64() * 1e6;
    assert_eq!(vz_got, pak_got);
    let pak_crs_inner = pak_crs.into_inner();

    // Compare 6T warm random read IOPS (shared VzReader<File> vs per-thread File repak::PakReader)
    let vz_base_file = Arc::new(VzReader::open(File::open(&base_hot.pak_path)?)?);
    let live_base_paths: Arc<Vec<String>> =
        Arc::new(base_hot.entries.iter().map(|e| e.path.clone()).collect());
    let vz_file_6t_iops = {
        let threads = 6usize;
        let ops = cli.ops_per_thread;
        let t0 = Instant::now();
        let mut hs = Vec::with_capacity(threads);
        for tid in 0..threads {
            let r = Arc::clone(&vz_base_file);
            let ps = Arc::clone(&live_base_paths);
            hs.push(std::thread::spawn(move || -> Result<(), VzError> {
                let mut s = 0xD1B5_4A32_D192_ED03u64 ^ ((tid as u64 + 1) * 0x94D0_49BB_1331_11EB);
                let len = ps.len();
                for _ in 0..ops {
                    s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                    black_box(r.read_file(&ps[(s as usize) % len])?.len());
                }
                Ok(())
            }));
        }
        for h in hs {
            h.join().map_err(|_| "worker panicked")??;
        }
        (threads * ops) as f64 / t0.elapsed().as_secs_f64()
    };

    let pak_shared = Arc::new(pak_cold_r);
    let pak_6t_iops = {
        let threads = 6usize;
        let ops = cli.ops_per_thread;
        let t0 = Instant::now();
        let mut hs = Vec::with_capacity(threads);
        for tid in 0..threads {
            let pr = Arc::clone(&pak_shared);
            let ps = Arc::clone(&live_base_paths);
            let p_path = pak_path.clone();
            hs.push(std::thread::spawn(move || -> Result<(), String> {
                let mut tf = BufReader::with_capacity(64 * 1024, File::open(p_path).map_err(|e| e.to_string())?);
                let mut s = 0xD1B5_4A32_D192_ED03u64 ^ ((tid as u64 + 1) * 0x94D0_49BB_1331_11EB);
                let len = ps.len();
                for _ in 0..ops {
                    s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                    black_box(
                        pr.get(&ps[(s as usize) % len], &mut tf)
                            .map_err(|e| e.to_string())?
                            .len(),
                    );
                }
                Ok(())
            }));
        }
        for h in hs {
            h.join().map_err(|_| "worker panicked")??;
        }
        (threads * ops) as f64 / t0.elapsed().as_secs_f64()
    };
    drop(pak_shared);
    drop(vz_base_file);
    let _ = fs::remove_file(&base_hot.pak_path);

    println!(
        "\n  Base {t0_tag} ({} files, Zstd) — VZ vs Unreal Engine .pak (repak V11):",
        base_hot.entries.len()
    );
    println!(
        "  {:<26} | {:>9} | {:>9} | {:>12} | {:>11} | {:>9}",
        "Format", "Size MiB", "Pack ms", "Cold+1Read", "Cold Bytes", "6T IOPS"
    );
    println!("  {}", "-".repeat(90));
    println!(
        "  {:<26} | {:>9.2} | {:>9.2} | {:>9.2} us | {:>8} B | {:>9.0}",
        "VZ (Zstd 256K cluster)",
        base_hot.archive_bytes as f64 / (1024.0 * 1024.0),
        base_hot.build_ms,
        vz_cold_us,
        vz_cold_bytes,
        vz_file_6t_iops
    );
    println!(
        "  {:<26} | {:>9.2} | {:>9.2} | {:>9.2} us | {:>8} B | {:>9.0}",
        "UE .pak (repak V11 Zstd)",
        pak_base_bytes as f64 / (1024.0 * 1024.0),
        pak_build_ms,
        pak_cold_us,
        pak_crs_inner.bytes,
        pak_6t_iops
    );
    let _ = (vz_cold_reads, pak_crs_inner.reads);

    // D.2 Unreal Engine .pak (repak into_pakwriter) Tier 1 Hotfix Patch (v7.1 -> v7.1.4)
    let t_pak_patch = Instant::now();
    let pak_bytes_written = {
        let mut batch = BatchBlobReader::spawn(&cli.repo)?;
        let mut blob = Vec::with_capacity(64 * 1024);
        let pak_r = repak::PakBuilder::new()
            .reader_with_version(&mut BufReader::new(File::open(&pak_path)?), repak::Version::V11)?;
        let written_counter = Arc::new(AtomicU64::new(0));
        struct SharedWriteCounter<T> {
            inner: T,
            bytes: Arc<AtomicU64>,
        }
        impl<T: Write> Write for SharedWriteCounter<T> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let n = self.inner.write(buf)?;
                self.bytes.fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }
        impl<T: Seek> Seek for SharedWriteCounter<T> {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                self.inner.seek(pos)
            }
        }
        let swc = SharedWriteCounter {
            inner: BufWriter::with_capacity(
                512 * 1024,
                OpenOptions::new().read(true).write(true).open(&pak_path)?,
            ),
            bytes: Arc::clone(&written_counter),
        };
        let mut pw = pak_r.into_pakwriter(swc)?;
        for d in &t1_diffs {
            if matches!(d.kind, GitDiffKind::Delete) {
                continue; // repak PakWriter has no entry delete/tombstone operation
            }
            batch.read_blob_into(&d.new_sha, &mut blob)?;
            pw.write_file(&d.path, true, &blob)?;
        }
        let mut swc_done = pw.write_index()?;
        swc_done.flush()?;
        written_counter.load(Ordering::Relaxed)
    };
    let ms_pak_patch = t_pak_patch.elapsed().as_secs_f64() * 1000.0;
    let _ = fs::remove_file(&pak_path);

    // Build diff lookup map used by both ZIP and TAR.ZST full-archive patchers.
    let mut patch_map: HashMap<&str, &GitDiffEntry> = HashMap::new();
    for d in &t1_diffs {
        patch_map.insert(d.path.as_str(), d);
    }

    // ZIP: `ZipWriter::new_append` rejects overwriting/deleting existing paths (`Duplicate filename`),
    // so patching a point release requires rewriting a new ZIP (even using `raw_copy_file` for untouched entries).
    let zip_out_path = wd.join("hotfix-patched.zip");
    let t_zip = Instant::now();
    let zip_written = {
        let mut batch = BatchBlobReader::spawn(&cli.repo)?;
        let mut blob = Vec::with_capacity(64 * 1024);
        let mut zr = zip::ZipArchive::new(BufReader::with_capacity(512 * 1024, File::open(&zip_path)?))?;
        let mut zw = zip::ZipWriter::new(BufWriter::with_capacity(
            512 * 1024,
            File::create(&zip_out_path)?,
        ));
        let zopts = SimpleFileOptions::default().compression_method(CompressionMethod::Zstd);

        for idx in 0..zr.len() {
            let entry = zr.by_index_raw(idx)?;
            let name = entry.name().to_string();
            if let Some(d) = patch_map.get(name.as_str()) {
                drop(entry);
                match d.kind {
                    GitDiffKind::Delete => continue,
                    GitDiffKind::Modify | GitDiffKind::TypeChange | GitDiffKind::Add => {
                        batch.read_blob_into(&d.new_sha, &mut blob)?;
                        zw.start_file(&name, zopts)?;
                        zw.write_all(&blob)?;
                    }
                }
            } else {
                zw.raw_copy_file(entry)?;
            }
        }
        for d in &t1_diffs {
            if matches!(d.kind, GitDiffKind::Add) {
                batch.read_blob_into(&d.new_sha, &mut blob)?;
                zw.start_file(&d.path, zopts)?;
                zw.write_all(&blob)?;
            }
        }
        let mut inner = zw.finish()?.into_inner()?;
        inner.flush()?;
        fs::metadata(&zip_out_path)?.len()
    };
    let ms_zip = t_zip.elapsed().as_secs_f64() * 1000.0;
    let _ = fs::remove_file(&zip_path);
    let _ = fs::remove_file(&zip_out_path);

    // TAR.ZST full rewrite (Tier 1)
    let tarz_out_path = wd.join("hotfix-rewritten.tar.zst");
    let t_tar = Instant::now();
    let tar_written = {
        let mut batch = BatchBlobReader::spawn(&cli.repo)?;
        let mut blob = Vec::with_capacity(64 * 1024);
        let dec = zstd::stream::read::Decoder::new(BufReader::with_capacity(512 * 1024, File::open(&tarz_path)?))?;
        let mut ar = tar::Archive::new(dec);
        let zenc = zstd::stream::Encoder::new(
            BufWriter::with_capacity(512 * 1024, File::create(&tarz_out_path)?),
            3,
        )?;
        let mut tb = tar::Builder::new(zenc);
        for ent in ar.entries()? {
            let mut e = ent?;
            let path = e.path()?.to_string_lossy().into_owned();
            if let Some(d) = patch_map.get(path.as_str()) {
                match d.kind {
                    GitDiffKind::Delete => continue,
                    GitDiffKind::Modify | GitDiffKind::TypeChange | GitDiffKind::Add => {
                        batch.read_blob_into(&d.new_sha, &mut blob)?;
                    }
                }
            } else {
                blob.clear();
                e.read_to_end(&mut blob)?;
            }
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(blob.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            tb.append_data(&mut hdr, &path, blob.as_slice())?;
        }
        for d in &t1_diffs {
            if matches!(d.kind, GitDiffKind::Add) {
                batch.read_blob_into(&d.new_sha, &mut blob)?;
                let mut hdr = tar::Header::new_gnu();
                hdr.set_size(blob.len() as u64);
                hdr.set_mode(d.new_mode & 0o777);
                hdr.set_cksum();
                tb.append_data(&mut hdr, &d.path, blob.as_slice())?;
            }
        }
        tb.finish()?;
        let mut inner = tb.into_inner()?.finish()?;
        inner.flush()?;
        fs::metadata(&tarz_out_path)?.len()
    };
    let ms_tar = t_tar.elapsed().as_secs_f64() * 1000.0;

    println!(
        "\n  Tier 1 Hotfix Patch ({t0_tag} -> {t4_tag}):"
    );
    println!(
        "  {:<26} | {:>10} | {:>12} | Semantics",
        "Format", "Time (ms)", "Bytes Written"
    );
    println!("  {}", "-".repeat(86));
    println!(
        "  {:<26} | {:>10.2} | {:>9.2} MB | Delta + tombstones ({} deleted paths hidden)",
        "VZ (LsmAppendWriter)",
        t1_stats.elapsed_ms,
        t1_stats.delta_bytes_written as f64 / (1024.0 * 1024.0),
        t1_stats.dels
    );
    println!(
        "  {:<26} | {:>10.2} | {:>9.2} MB | Rewrites full O(N) trailer; cannot delete {} stale files",
        "UE .pak (repak into_writer)",
        ms_pak_patch,
        pak_bytes_written as f64 / (1024.0 * 1024.0),
        t1_stats.dels
    );
    println!(
        "  {:<26} | {:>10.2} | {:>9.2} MB | Full rewrite via raw_copy_file (append rejects mod/del)",
        "ZIP (raw_copy rewrite)",
        ms_zip,
        zip_written as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  {:<26} | {:>10.2} | {:>9.2} MB | Must unpack & rewrite full solid archive",
        "TAR.ZST (Full Rewrite)",
        ms_tar,
        tar_written as f64 / (1024.0 * 1024.0)
    );

    if cli.include_tar_season {
        println!("\n(Note: --include-tar-season Tier 2 TAR.ZST rewrite behaves proportionally to Tier 1.)");
    }

    Ok(())
}

// ============================================================================
// OFFLINE GIT STREAMING + DELTA + COMPACTION VERIFICATION TEST
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn git(repo: &Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["-c", "commit.gpgSign=false", "-c", "tag.gpgSign=false"])
            .args(args)
            .env("GIT_AUTHOR_NAME", "VZ Test")
            .env("GIT_AUTHOR_EMAIL", "test@vz.local")
            .env("GIT_COMMITTER_NAME", "VZ Test")
            .env("GIT_COMMITTER_EMAIL", "test@vz.local")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn test_pak_patch_git_streaming_end_to_end() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("mini-repo");
        fs::create_dir_all(repo.join("include/asm")).unwrap();
        git(&repo, &["init"]);

        // Commit v1
        fs::write(repo.join("README"), b"v1 readme\n").unwrap();
        fs::write(repo.join("include/asm/unaligned.h"), b"/* old unaligned */").unwrap();
        fs::write(repo.join("obsolete.c"), b"void old_fn(void) {}\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("README", repo.join("LATEST")).unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "v1"]);
        git(&repo, &["tag", "v1.0"]);

        // Commit v2: modify README, delete obsolete.c, move include/asm/unaligned.h -> include/linux/unaligned.h
        fs::create_dir_all(repo.join("include/linux")).unwrap();
        fs::write(repo.join("README"), vec![b'R'; 4096]).unwrap();
        fs::remove_file(repo.join("obsolete.c")).unwrap();
        fs::rename(
            repo.join("include/asm/unaligned.h"),
            repo.join("include/linux/unaligned.h"),
        )
        .unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-m", "v2"]);
        git(&repo, &["tag", "v2.0"]);

        let pak = tmp.path().join("game.vz");
        let base = build_base_pak(&repo, "v1.0", &pak, CODEC_ZSTD).unwrap();
        let mut dirs = base.known_dirs.clone();
        let (diffs, stats) =
            apply_git_delta(&repo, &pak, "v1.0", "v2.0", &mut dirs, CODEC_ZSTD).unwrap();
        assert!(stats.dels >= 2); // obsolete.c + include/asm/unaligned.h (--no-renames!)
        assert!(stats.adds >= 1); // include/linux/unaligned.h
        assert!(stats.mods >= 1); // README
        verify_spot_diffs(&repo, &pak, &diffs).unwrap();

        let vr = Arc::new(VzReader::open(File::open(&pak).unwrap()).unwrap());
        assert_eq!(vr.active_slot().lsm_run_count, 2);
        assert_eq!(vr.read_file("obsolete.c"), Err(VzError::NotFound));
        assert_eq!(vr.read_file("include/asm/unaligned.h"), Err(VzError::NotFound));
        assert_eq!(
            vr.read_file("include/linux/unaligned.h").unwrap(),
            b"/* old unaligned */"
        );

        let fs = FuseVolume::mount(Arc::clone(&vr)).unwrap();
        let inc = fs.lookup(FUSE_ROOT_ID, "include").unwrap();
        let lin = fs.lookup(inc.ino, "linux").unwrap();
        let uh = fs.lookup(lin.ino, "unaligned.h").unwrap();
        assert_eq!(uh.size, 19);

        // Zero-reencode compact back to 1 run
        let comp = tmp.path().join("game-compacted.vz");
        let out = compact_archive_with_options(
            vr.as_ref(),
            File::create(&comp).unwrap(),
            CompactOptions::default(),
        )
        .unwrap();
        drop(out);
        let vr2 = VzReader::open(File::open(&comp).unwrap()).unwrap();
        assert_eq!(vr2.active_slot().lsm_run_count, 1);
        assert_eq!(vr2.read_file("README").unwrap(), vec![b'R'; 4096]);
        assert_eq!(vr2.read_file("include/asm/unaligned.h"), Err(VzError::NotFound));
    }
}
