use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;

use libvz::{DEFAULT_BOOT_SIZE, PAGE_SIZE, scan_clusters_forward};

fn vz_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vz")
}

fn dir_diff_equal(a: &Path, b: &Path) {
    let mut ea: Vec<_> = fs::read_dir(a)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let mut eb: Vec<_> = fs::read_dir(b)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    ea.sort();
    eb.sort();
    assert_eq!(ea, eb, "dir mismatch between {} and {}", a.display(), b.display());
    for name in ea {
        let pa = a.join(&name);
        let pb = b.join(&name);
        let ma = fs::symlink_metadata(&pa).unwrap();
        let mb = fs::symlink_metadata(&pb).unwrap();
        assert_eq!(ma.is_dir(), mb.is_dir());
        if ma.is_dir() {
            dir_diff_equal(&pa, &pb);
        } else {
            assert_eq!(fs::read(&pa).unwrap(), fs::read(&pb).unwrap());
        }
    }
}

#[test]
fn test_cli_pack_verify_corrupt_repair_unpack_and_append_compact() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    let arc = tmp.path().join("test.vz");
    let compacted = tmp.path().join("compacted.vz");

    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("tiny.txt"), b"hello inline").unwrap();
    fs::write(src.join("sub/big1.bin"), vec![0x33u8; 8192]).unwrap();
    fs::write(src.join("sub/big2.bin"), vec![0x77u8; 8192]).unwrap();
    fs::write(src.join("sub/big3.bin"), vec![0x99u8; 8192]).unwrap();
    fs::write(src.join("sub/big4.bin"), vec![0xBBu8; 8192]).unwrap();

    // 1. Pack with Zstd + RS(4,2) + small cluster size to produce multiple clusters
    let out = Command::new(vz_bin())
        .args([
            "pack",
            src.to_str().unwrap(),
            arc.to_str().unwrap(),
            "--codec",
            "zstd",
            "--rs",
            "4,2",
            "--cluster-size",
            "4096",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "pack failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 2. Inspect & Ls & Stat & Cat & Verify
    let ins = Command::new(vz_bin())
        .args(["inspect", arc.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(ins.status.success());
    let ins_txt = String::from_utf8_lossy(&ins.stdout);
    assert!(ins_txt.contains("lsm_run_count: 1"));

    let ls = Command::new(vz_bin())
        .args(["ls", arc.to_str().unwrap(), "-r"])
        .output()
        .unwrap();
    assert!(ls.status.success());
    assert!(String::from_utf8_lossy(&ls.stdout).contains("/sub/big1.bin"));

    let stat = Command::new(vz_bin())
        .args(["stat", arc.to_str().unwrap(), "/tiny.txt"])
        .output()
        .unwrap();
    assert!(stat.status.success());
    assert!(String::from_utf8_lossy(&stat.stdout).contains("inline: true"));

    let cat = Command::new(vz_bin())
        .args(["cat", arc.to_str().unwrap(), "/tiny.txt"])
        .output()
        .unwrap();
    assert!(cat.status.success());
    assert_eq!(cat.stdout, b"hello inline");

    let ver = Command::new(vz_bin())
        .args(["verify", arc.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(ver.status.success());

    // 3. Fault-inject: wipe Boot Page 2 AND 2 data clusters (<= M=2)!
    {
        let f_ro = fs::File::open(&arc).unwrap();
        let clusters = scan_clusters_forward(&f_ro, DEFAULT_BOOT_SIZE as u64).unwrap();
        assert!(clusters.len() >= 6);
        let c0 = clusters[0];
        let c1 = clusters[1];
        drop(f_ro);

        let mut f_rw = OpenOptions::new().read(true).write(true).open(&arc).unwrap();
        f_rw.seek(SeekFrom::Start(2 * PAGE_SIZE as u64)).unwrap();
        f_rw.write_all(&vec![0xA5u8; PAGE_SIZE]).unwrap();
        f_rw.seek(SeekFrom::Start(c0.0)).unwrap();
        f_rw.write_all(&vec![0u8; c0.1.cluster_len as usize]).unwrap();
        f_rw.seek(SeekFrom::Start(c1.0)).unwrap();
        f_rw.write_all(&vec![0u8; c1.1.cluster_len as usize]).unwrap();
        f_rw.flush().unwrap();
    }

    // Verify must fail before repair
    let ver_bad = Command::new(vz_bin())
        .args(["verify", arc.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!ver_bad.status.success());

    // Repair!
    let rep = Command::new(vz_bin())
        .args(["repair", arc.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        rep.status.success(),
        "repair failed: {}",
        String::from_utf8_lossy(&rep.stderr)
    );
    let rep_txt = String::from_utf8_lossy(&rep.stdout);
    assert!(rep_txt.contains("boot_page_repaired: Some(2)"));
    assert!(rep_txt.contains("data_clusters_repaired: 2"));

    // Verify clean after repair
    let ver_ok = Command::new(vz_bin())
        .args(["verify", arc.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(ver_ok.status.success());

    // Unpack & byte-for-byte diff
    let unp = Command::new(vz_bin())
        .args(["unpack", arc.to_str().unwrap(), dst.to_str().unwrap(), "--mmap"])
        .output()
        .unwrap();
    assert!(unp.status.success());
    dir_diff_equal(&src, &dst);

    // 4. Append + Compact
    let extra_host = tmp.path().join("extra.txt");
    fs::write(&extra_host, b"appended content").unwrap();
    let app = Command::new(vz_bin())
        .args([
            "append",
            arc.to_str().unwrap(),
            "--add",
            &format!("{}:/extra.txt", extra_host.display()),
            "--delete",
            "/tiny.txt",
        ])
        .output()
        .unwrap();
    assert!(
        app.status.success(),
        "append failed: {}",
        String::from_utf8_lossy(&app.stderr)
    );

    let cmp = Command::new(vz_bin())
        .args(["compact", arc.to_str().unwrap(), compacted.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        cmp.status.success(),
        "compact failed: {}",
        String::from_utf8_lossy(&cmp.stderr)
    );

    let cat_extra = Command::new(vz_bin())
        .args(["cat", compacted.to_str().unwrap(), "/extra.txt"])
        .output()
        .unwrap();
    assert!(cat_extra.status.success());
    assert_eq!(cat_extra.stdout, b"appended content");

    let cat_deleted = Command::new(vz_bin())
        .args(["cat", compacted.to_str().unwrap(), "/tiny.txt"])
        .output()
        .unwrap();
    assert!(!cat_deleted.status.success());
}
