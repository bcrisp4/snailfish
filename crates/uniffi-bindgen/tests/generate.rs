//! The generator writes the Python module of the binding crate. Without
//! this, a broken generator shows only in `make test-python`, which
//! cargo-mutants does not run.
#![cfg(test)]

use std::path::PathBuf;
use std::process::Command;

#[test]
fn generates_python_module_for_the_binding_library() {
    // Build the cdylib with the same cargo, and read its path from cargo, so
    // the test works with any target directory.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let build = Command::new(cargo)
        .args([
            "build",
            "-p",
            "snailfish-bindings",
            "--lib",
            "--message-format=json",
        ])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let suffix = if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    };
    let lib = String::from_utf8(build.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["target"]["name"] == "snailfish")
        .flat_map(|m| m["filenames"].as_array().cloned().unwrap_or_default())
        .filter_map(|f| f.as_str().map(PathBuf::from))
        .find(|f| f.to_string_lossy().ends_with(suffix))
        .unwrap();
    let out = tempfile::tempdir().unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_uniffi-bindgen"))
        .args(["generate", "--library"])
        .arg(&lib)
        .args(["--language", "python", "--no-format", "--out-dir"])
        .arg(out.path())
        .status()
        .unwrap();
    assert!(status.success());
    let module = std::fs::read_to_string(out.path().join("snailfish.py")).unwrap();
    assert!(module.contains("def check_payload("));
}
