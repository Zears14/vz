use std::path::{Path, PathBuf};
use std::process::Command;

fn locate_libvz_a(manifest_dir: &Path) -> PathBuf {
    let ws_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| ws_root.join("target"));

    for profile in ["debug", "release"] {
        let cand = target_dir.join(profile).join("libvz.a");
        if cand.exists() {
            return cand;
        }
    }

    let st = Command::new("cargo")
        .current_dir(ws_root)
        .args(["build", "-p", "libvz-ffi"])
        .status()
        .expect("failed to invoke cargo build -p libvz-ffi");
    assert!(st.success(), "cargo build -p libvz-ffi failed");
    let built = target_dir.join("debug").join("libvz.a");
    assert!(built.exists(), "libvz.a missing at {}", built.display());
    built
}

#[test]
fn test_cbindgen_c11_and_cpp17_compile_link_and_run() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("include");
    assert!(
        include_dir.join("vz.h").exists(),
        "cbindgen did not generate include/vz.h"
    );
    assert!(include_dir.join("vz.hpp").exists(), "include/vz.hpp missing");

    let libvz_a = locate_libvz_a(&manifest_dir);
    let tmp = tempfile::tempdir().unwrap();

    // Compile & run C11 consumer strictly with -Wall -Wextra -Werror
    let c_bin = tmp.path().join("c_test");
    let c_compile = Command::new("gcc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(&include_dir)
        .arg(manifest_dir.join("examples/c_example.c"))
        .arg(&libvz_a)
        .args(["-lpthread", "-ldl", "-lm", "-o"])
        .arg(&c_bin)
        .output()
        .expect("gcc invocation failed");
    assert!(
        c_compile.status.success(),
        "gcc failed:\n{}",
        String::from_utf8_lossy(&c_compile.stderr)
    );

    let c_arc = tmp.path().join("c_arc.vz");
    let c_comp = tmp.path().join("c_comp.vz");
    let c_run = Command::new(&c_bin).args([&c_arc, &c_comp]).output().unwrap();
    assert!(
        c_run.status.success(),
        "c_example failed:\n{}",
        String::from_utf8_lossy(&c_run.stderr)
    );

    // Compile & run C++17 consumer strictly with -Wall -Wextra -Werror
    let cpp_bin = tmp.path().join("cpp_test");
    let cpp_compile = Command::new("g++")
        .args(["-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(&include_dir)
        .arg(manifest_dir.join("examples/cpp_example.cpp"))
        .arg(&libvz_a)
        .args(["-lpthread", "-ldl", "-lm", "-o"])
        .arg(&cpp_bin)
        .output()
        .expect("g++ invocation failed");
    assert!(
        cpp_compile.status.success(),
        "g++ failed:\n{}",
        String::from_utf8_lossy(&cpp_compile.stderr)
    );

    let cpp_arc = tmp.path().join("cpp_arc.vz");
    let cpp_comp = tmp.path().join("cpp_comp.vz");
    let cpp_run = Command::new(&cpp_bin)
        .args([&cpp_arc, &cpp_comp])
        .output()
        .unwrap();
    assert!(
        cpp_run.status.success(),
        "cpp_example failed:\n{}",
        String::from_utf8_lossy(&cpp_run.stderr)
    );
}
