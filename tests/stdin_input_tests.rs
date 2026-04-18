//! Integration tests for `--file -` stdin input mode.
//!
//! Exercises the stdin-spool-to-tempfile path added in v2.0.5:
//! round-trip on arbitrary bytes, empty-stdin rejection at the
//! boundary, and composition with the SARIF output formatter.

use std::io::Write;
use std::process::{Command, Stdio};

fn spawn_with_stdin(args: &[&str], payload: &[u8]) -> (std::process::Output, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_anya"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn anya");

    {
        let stdin = child.stdin.as_mut().expect("stdin pipe");
        stdin.write_all(payload).expect("write stdin");
    }

    let output = child.wait_with_output().expect("wait anya");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output, stdout, stderr)
}

#[test]
fn stdin_input_round_trip_emits_json_on_arbitrary_bytes() {
    let payload = b"arbitrary stdin bytes for analysis";
    let (out, stdout, _stderr) = spawn_with_stdin(&["--file", "-", "--format", "json"], payload);

    assert!(out.status.success(), "anya --file - should succeed");
    // json branch emits a single JSON object
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout not JSON: {}: {}", e, stdout));
    // Top-level file_format key must be present on every analysis result
    assert!(
        v.get("file_format").is_some(),
        "json output missing file_format field"
    );
}

#[test]
fn stdin_empty_rejected_at_boundary() {
    let (out, _stdout, stderr) = spawn_with_stdin(&["--file", "-"], b"");

    assert!(
        !out.status.success(),
        "empty stdin should produce a non-zero exit"
    );
    assert!(
        stderr.contains("zero bytes") || stderr.contains("empty"),
        "empty stdin error message missing expected wording: {:?}",
        stderr
    );
}

#[test]
fn stdin_sarif_composition_produces_valid_document() {
    let payload = b"stdin + sarif composition probe";
    let (out, stdout, _stderr) = spawn_with_stdin(&["--file", "-", "--format", "sarif"], payload);

    assert!(out.status.success(), "sarif over stdin should succeed");
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout not JSON: {}: {}", e, stdout));
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(
        v["$schema"], "https://json.schemastore.org/sarif-2.1.0.json",
        "schema URI"
    );

    let results = v["runs"][0]["results"]
        .as_array()
        .expect("runs[0].results is array on stdin input");
    assert!(
        !results.is_empty(),
        "verdict carrier emitted even on stdin path"
    );
    assert_eq!(results[0]["ruleId"], "ANYA-V001");
}

#[test]
fn stdin_input_path_placeholder_dash_is_not_taken_as_directory() {
    // Guard: `-` must be interpreted as the stdin placeholder for
    // --file only, never confused with a directory argument. Passing
    // --directory - is not a supported shape.
    let payload = b"directory placeholder probe";
    let (out, _stdout, stderr) = spawn_with_stdin(&["--directory", "-"], payload);
    assert!(
        !out.status.success(),
        "--directory - must not be treated as stdin input"
    );
    // Accept any error path; the point is that the stdin spool only
    // activates on --file -, not on --directory -.
    assert!(
        !stderr.contains("Stdin produced zero bytes"),
        "--directory - should not trip the stdin spool path"
    );
}
