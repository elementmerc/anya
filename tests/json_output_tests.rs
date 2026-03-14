// Integration tests for JSON output

use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_json_output_basic() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, b"Hello World").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_anya-security-core"))
        .arg("--file")
        .arg(&test_file)
        .arg("--json")
        .output()
        .unwrap();

    assert!(output.status.success());

    let json_str = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert!(json["hashes"]["md5"].is_string());
    assert!(json["hashes"]["sha1"].is_string());
    assert!(json["hashes"]["sha256"].is_string());
}

#[test]
fn test_json_to_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    let output_file = temp_dir.path().join("output.json");

    fs::write(&test_file, b"Test").unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_anya-security-core"))
        .arg("--file")
        .arg(&test_file)
        .arg("--json")
        .arg("--output")
        .arg(&output_file)
        .status()
        .unwrap();

    assert!(status.success());
    assert!(output_file.exists());

    let contents = fs::read_to_string(&output_file).unwrap();
    let _json: serde_json::Value = serde_json::from_str(&contents).unwrap();
}
