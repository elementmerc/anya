// Integration tests for batch processing

use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_batch_directory() {
    let temp_dir = TempDir::new().unwrap();

    fs::write(temp_dir.path().join("file1.exe"), b"Test 1").unwrap();
    fs::write(temp_dir.path().join("file2.dll"), b"Test 2").unwrap();
    fs::write(temp_dir.path().join("file3.txt"), b"Ignored").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_anya"))
        .arg("--directory")
        .arg(temp_dir.path())
        .arg("--quiet")
        .output()
        .unwrap();

    assert!(output.status.success());
}

#[test]
fn test_batch_recursive() {
    let temp_dir = TempDir::new().unwrap();
    let subdir = temp_dir.path().join("subdir");
    fs::create_dir(&subdir).unwrap();

    fs::write(temp_dir.path().join("root.exe"), b"Root").unwrap();
    fs::write(subdir.join("nested.exe"), b"Nested").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_anya"))
        .arg("--directory")
        .arg(temp_dir.path())
        .arg("--recursive")
        .arg("--quiet")
        .output()
        .unwrap();

    assert!(output.status.success());
}
