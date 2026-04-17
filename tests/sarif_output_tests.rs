//! Integration tests for `--format sarif` output.
//!
//! Skeleton-stage tests: confirm the CLI flag produces a valid-shape SARIF
//! 2.1.0 document on stdout. Saturday's real-mapping work adds tests for the
//! verdict → result pipeline (MITRE taxonomies, rule metadata, evidence
//! chain mapping).

use std::fs;
use std::process::Command;
use tempfile::TempDir;

const SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

#[test]
fn sarif_output_via_format_flag_is_valid_shape() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("hello.txt");
    fs::write(&test_file, b"Hello World").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_anya"))
        .arg("--file")
        .arg(&test_file)
        .arg("--format")
        .arg("sarif")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "anya --format sarif failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let v: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON ({}): {}", e, body));

    // Top-level required fields
    assert_eq!(v["version"], SARIF_VERSION, "unexpected version");
    assert_eq!(v["$schema"], SCHEMA_URI, "unexpected $schema uri");

    // Exactly one run with Anya identified as the tool
    let runs = v["runs"].as_array().expect("runs is array");
    assert_eq!(runs.len(), 1, "expected exactly one run");
    assert_eq!(runs[0]["tool"]["driver"]["name"], "Anya");
    assert!(
        runs[0]["tool"]["driver"]["informationUri"].is_string(),
        "informationUri should be present and a string (camelCase)"
    );

    // Skeleton contract: results is an empty array, not null, not absent
    let results = runs[0]["results"]
        .as_array()
        .expect("results is array (empty in skeleton)");
    assert!(results.is_empty(), "skeleton should emit empty results[]");
}

#[test]
fn sarif_output_to_file_round_trips() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.bin");
    let output_file = temp_dir.path().join("report.sarif");
    fs::write(&test_file, b"some bytes").unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_anya"))
        .arg("--file")
        .arg(&test_file)
        .arg("--format")
        .arg("sarif")
        .arg("--output")
        .arg(&output_file)
        .status()
        .unwrap();

    assert!(status.success());
    assert!(output_file.exists(), "--output path was not written");

    let body = fs::read_to_string(&output_file).unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).expect("file contents parse as JSON");
    assert_eq!(v["version"], SARIF_VERSION);
    assert_eq!(v["$schema"], SCHEMA_URI);
}
