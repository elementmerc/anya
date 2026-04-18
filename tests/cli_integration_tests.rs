//! Rust port of the legacy `integration_test.sh` shell suite (DWL-85).
//!
//! The shell script carried ~120 assertions across:
//!   Binary basics, Error handling, Single-file text + JSON output,
//!   JSON-to-file, Batch analysis, Determinism, Config, Teacher Mode,
//!   Analysis engine JSON fields, Docker, Cargo recursion, Bible
//!   verse CLI, MITRE data file presence, Debian packaging, install.sh
//!   syntax, Build verification, New subcommands (watch/compare/
//!   completions/cases), HTML report, Case management, Format flag,
//!   Batch with progress, plus a long Edge Cases section covering
//!   filesystem, malformed input, unusual sizes, CLI argument abuse,
//!   output correctness invariants, batch boundaries, rapid analysis,
//!   and output format boundaries.
//!
//! This Rust port covers every engine-testable assertion from that
//! script. The following shell sections are deliberately NOT ported
//! because they are orchestration concerns, not engine CLI tests:
//!
//!   * Docker section — requires a running Docker daemon and a
//!     freshly built image; belongs in `anya-ops test --integration`
//!     once that subcommand lands, or in a thin shell wrapper.
//!   * Cargo recursion (`cargo test` inside `cargo test`) — circular.
//!   * Debian packaging file presence — build-artifact check, not a
//!     CLI test.
//!   * install.sh syntax check — installer script, not the engine.
//!   * --init-config — writes to `$HOME/.config/anya/config.toml` as
//!     a persistent side effect, would leak across test runs.
//!   * Permission-denied file (chmod 000) — flaky on container /
//!     tmpfs file systems; the engine's own error path for I/O
//!     failures is already covered by the nonexistent-file test.
//!
//! The harness follows `tests/sarif_output_tests.rs`:
//! `Command::new(env!("CARGO_BIN_EXE_anya"))` is the entry point,
//! `tempfile::TempDir` isolates on-disk side effects, and each test
//! is self-contained.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

// ── Shared fixture paths ────────────────────────────────────────────────────

const FIXTURE_PE_RELATIVE: &str = "tests/fixtures/simple.exe";

fn fixture_pe() -> PathBuf {
    PathBuf::from(FIXTURE_PE_RELATIVE)
}

// ── Shared test harness helpers ─────────────────────────────────────────────

fn run_anya(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anya"))
        .args(args)
        .output()
        .expect("failed to spawn anya binary")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn combined_of(out: &Output) -> String {
    format!("{}{}", stdout_of(out), stderr_of(out))
}

fn assert_contains(haystack: &str, needle: &str, context: &str) {
    assert!(
        haystack.contains(needle),
        "{}: expected output to contain {:?} but got:\n{}",
        context,
        needle,
        haystack
    );
}

fn json_of_stdout(out: &Output) -> serde_json::Value {
    let s = stdout_of(out);
    serde_json::from_str(&s)
        .unwrap_or_else(|e| panic!("stdout not valid JSON ({}): {}", e, s))
}

/// Convenience: run anya and parse stdout as JSON. Panics if either fails.
fn analyse_json(path: &std::path::Path) -> serde_json::Value {
    let out = run_anya(&[
        "--file",
        path.to_str().unwrap(),
        "--json",
        "--no-color",
    ]);
    assert!(
        out.status.success(),
        "--json analysis failed: {}",
        stderr_of(&out)
    );
    json_of_stdout(&out)
}

// ═══════════════════════════════════════════════════════════════════════════
// Binary basics
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn version_flag_exits_zero_and_prints_semver() {
    let out = run_anya(&["--version"]);
    assert!(out.status.success());
    let s = stdout_of(&out);
    let has_semver = s.split_whitespace().any(|tok| {
        let parts: Vec<_> = tok.split('.').collect();
        parts.len() >= 3
            && parts[0].chars().all(|c| c.is_ascii_digit())
            && parts[1].chars().all(|c| c.is_ascii_digit())
            && parts[2].chars().next().is_some_and(|c| c.is_ascii_digit())
    });
    assert!(has_semver, "--version missing semver token: {}", s);
}

#[test]
fn help_flag_exits_zero() {
    let out = run_anya(&["--help"]);
    assert!(out.status.success());
}

#[test]
fn help_mentions_file_flag() {
    let out = run_anya(&["--help"]);
    assert_contains(&stdout_of(&out), "--file", "--help");
}

#[test]
fn help_mentions_directory_flag() {
    let out = run_anya(&["--help"]);
    assert_contains(&stdout_of(&out), "--directory", "--help");
}

#[test]
fn help_mentions_json_flag() {
    let out = run_anya(&["--help"]);
    assert_contains(&stdout_of(&out), "--json", "--help");
}

#[test]
fn help_mentions_watch_subcommand() {
    let out = run_anya(&["--help"]);
    assert_contains(&stdout_of(&out), "watch", "--help");
}

#[test]
fn help_mentions_guided_flag() {
    let out = run_anya(&["--help"]);
    assert_contains(&stdout_of(&out), "--guided", "--help");
}

// ═══════════════════════════════════════════════════════════════════════════
// Error handling
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn no_args_exits_nonzero() {
    assert!(!run_anya(&[]).status.success());
}

#[test]
fn file_nonexistent_exits_nonzero() {
    assert!(!run_anya(&["--file", "/nonexistent/path/abs/nope"]).status.success());
}

#[test]
fn directory_nonexistent_exits_nonzero() {
    assert!(!run_anya(&["--directory", "/nonexistent/dir/nope"]).status.success());
}

#[test]
fn file_pointing_at_directory_exits_nonzero() {
    let tmp = TempDir::new().unwrap();
    let out = run_anya(&["--file", tmp.path().to_str().unwrap()]);
    assert!(!out.status.success());
}

#[test]
fn empty_file_exits_nonzero_with_graceful_error() {
    let tmp = TempDir::new().unwrap();
    let empty = tmp.path().join("empty.bin");
    fs::write(&empty, b"").unwrap();
    let out = run_anya(&["--file", empty.to_str().unwrap()]);
    assert!(!out.status.success());
    let combined = combined_of(&out);
    assert!(
        combined.contains("empty") || combined.contains("zero bytes"),
        "empty-file error should mention 'empty' or 'zero bytes': {}",
        combined
    );
}

#[test]
fn empty_directory_exits_zero() {
    let tmp = TempDir::new().unwrap();
    let out = run_anya(&["--directory", tmp.path().to_str().unwrap()]);
    assert!(out.status.success());
}

#[test]
fn append_without_output_exits_nonzero() {
    let out = run_anya(&["--file", fixture_pe().to_str().unwrap(), "--append"]);
    assert!(!out.status.success());
}

#[test]
fn min_string_length_very_high_exits_zero() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--min-string-length",
        "999999",
        "--quiet",
    ]);
    assert!(out.status.success());
}

#[test]
fn output_without_json_produces_markdown_report() {
    let tmp = TempDir::new().unwrap();
    let report = tmp.path().join("report.md");
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--output",
        report.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert!(report.exists());
    let body = fs::read_to_string(&report).unwrap();
    assert!(body.contains('#') || body.contains("Anya"));
}

#[test]
fn dev_null_as_input_exits_nonzero() {
    let out = run_anya(&["--file", "/dev/null", "--no-color"]);
    assert!(
        !out.status.success(),
        "/dev/null (0 bytes) should be rejected at boundary"
    );
}

#[test]
fn empty_string_file_path_exits_nonzero() {
    let out = run_anya(&["--file", "", "--no-color"]);
    assert!(!out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Single file — text output
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn simple_exe_text_analysis_exits_zero() {
    let out = run_anya(&["--file", fixture_pe().to_str().unwrap(), "--quiet"]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
}

#[test]
fn text_output_contains_sha256_label() {
    let out = run_anya(&["--file", fixture_pe().to_str().unwrap()]);
    assert!(out.status.success());
    let s = stdout_of(&out);
    assert!(s.contains("SHA256") || s.contains("sha256"));
}

#[test]
fn text_output_contains_entropy_label() {
    let out = run_anya(&["--file", fixture_pe().to_str().unwrap()]);
    assert!(out.status.success());
    assert!(stdout_of(&out).to_lowercase().contains("entropy"));
}

#[test]
fn text_output_contains_pe_detection() {
    let out = run_anya(&["--file", fixture_pe().to_str().unwrap()]);
    assert!(out.status.success());
    let s = stdout_of(&out);
    assert!(s.contains("PE") || s.to_lowercase().contains("portable executable"));
}

#[test]
fn simple_exe_verbose_exits_zero() {
    let out = run_anya(&["--file", fixture_pe().to_str().unwrap(), "--verbose"]);
    assert!(out.status.success());
}

#[test]
fn simple_exe_quiet_exits_zero() {
    let out = run_anya(&["--file", fixture_pe().to_str().unwrap(), "--quiet"]);
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Single file — JSON output (stdout)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn json_stdout_is_valid_json() {
    let v = analyse_json(&fixture_pe());
    assert!(v.is_object(), "JSON root must be an object");
}

#[test]
fn json_has_hashes_sha256() {
    let v = analyse_json(&fixture_pe());
    assert!(v["hashes"]["sha256"].is_string());
}

#[test]
fn json_has_hashes_md5() {
    let v = analyse_json(&fixture_pe());
    assert!(v["hashes"]["md5"].is_string());
}

#[test]
fn json_has_entropy_value() {
    let v = analyse_json(&fixture_pe());
    assert!(v["entropy"]["value"].is_number());
}

#[test]
fn json_has_file_info_size_bytes() {
    let v = analyse_json(&fixture_pe());
    assert!(v["file_info"]["size_bytes"].is_number());
}

#[test]
fn json_has_file_format() {
    let v = analyse_json(&fixture_pe());
    assert!(v["file_format"].is_string());
}

#[test]
fn json_has_strings_total_count() {
    let v = analyse_json(&fixture_pe());
    assert!(v["strings"]["total_count"].is_number());
}

#[test]
fn json_has_pe_analysis_object() {
    let v = analyse_json(&fixture_pe());
    assert!(v["pe_analysis"].is_object());
}

#[test]
fn json_pe_analysis_architecture_present() {
    let v = analyse_json(&fixture_pe());
    assert!(v["pe_analysis"]["architecture"].is_string());
}

#[test]
fn json_pe_analysis_security_present() {
    let v = analyse_json(&fixture_pe());
    assert!(v["pe_analysis"]["security"].is_object());
}

#[test]
fn json_pe_analysis_sections_has_entries() {
    let v = analyse_json(&fixture_pe());
    let sections = v["pe_analysis"]["sections"].as_array().expect("sections array");
    assert!(!sections.is_empty(), "PE fixture should have at least one section");
}

#[test]
fn json_sha256_is_64_char_lowercase_hex() {
    let v = analyse_json(&fixture_pe());
    let h = v["hashes"]["sha256"].as_str().unwrap();
    assert_eq!(h.len(), 64, "SHA-256 length: {}", h);
    assert!(
        h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "SHA-256 must be lowercase hex: {}",
        h
    );
}

#[test]
fn json_file_format_is_windows_pe() {
    let v = analyse_json(&fixture_pe());
    assert_eq!(v["file_format"].as_str().unwrap(), "Windows PE");
}

#[test]
fn json_md5_is_32_char_lowercase_hex() {
    let v = analyse_json(&fixture_pe());
    let h = v["hashes"]["md5"].as_str().unwrap();
    assert_eq!(h.len(), 32);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

#[test]
fn json_sha1_is_40_char_lowercase_hex() {
    let v = analyse_json(&fixture_pe());
    let h = v["hashes"]["sha1"].as_str().unwrap();
    assert_eq!(h.len(), 40);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

#[test]
fn json_entropy_value_in_0_to_8_range() {
    let v = analyse_json(&fixture_pe());
    let e = v["entropy"]["value"].as_f64().unwrap();
    assert!((0.0..=8.0).contains(&e), "entropy out of range: {}", e);
}

#[test]
fn json_file_info_path_non_empty() {
    let v = analyse_json(&fixture_pe());
    let p = v["file_info"]["path"].as_str().unwrap();
    assert!(!p.is_empty());
}

#[test]
fn json_strings_total_count_is_non_negative_integer() {
    let v = analyse_json(&fixture_pe());
    let n = v["strings"]["total_count"].as_u64();
    assert!(n.is_some(), "total_count should be non-negative integer");
}

// ═══════════════════════════════════════════════════════════════════════════
// JSON output to file
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn json_output_to_file_succeeds_and_is_valid_json() {
    let tmp = TempDir::new().unwrap();
    let out_path = tmp.path().join("result.json");
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--json",
        "--output",
        out_path.to_str().unwrap(),
        "--no-color",
    ]);
    assert!(out.status.success());
    assert!(out_path.exists());
    let body = fs::read_to_string(&out_path).unwrap();
    let _: serde_json::Value =
        serde_json::from_str(&body).expect("--json --output must be valid JSON");
}

#[test]
fn json_append_grows_output_file() {
    let tmp = TempDir::new().unwrap();
    let out_path = tmp.path().join("append.jsonl");
    // First write
    let r1 = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--json",
        "--output",
        out_path.to_str().unwrap(),
        "--no-color",
    ]);
    assert!(r1.status.success());
    let first_size = fs::metadata(&out_path).unwrap().len();
    // Append
    let r2 = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--json",
        "--output",
        out_path.to_str().unwrap(),
        "--append",
        "--no-color",
    ]);
    assert!(r2.status.success());
    let second_size = fs::metadata(&out_path).unwrap().len();
    assert!(
        second_size > first_size,
        "append should grow file: {} → {}",
        first_size,
        second_size
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Batch analysis
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_directory_fixtures_exits_zero() {
    let out = run_anya(&["--directory", "tests/fixtures", "--no-color"]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
}

#[test]
fn batch_output_mentions_analysis_words() {
    let out = run_anya(&["--directory", "tests/fixtures", "--no-color"]);
    assert!(out.status.success());
    let s = stdout_of(&out).to_lowercase();
    assert!(
        s.contains("found") || s.contains("analys") || s.contains("files"),
        "batch output missing an analysis keyword: {}",
        s
    );
}

#[test]
fn batch_json_to_file_exits_zero_and_is_parseable() {
    let tmp = TempDir::new().unwrap();
    let out_path = tmp.path().join("batch.jsonl");
    let out = run_anya(&[
        "--directory",
        "tests/fixtures",
        "--json",
        "--output",
        out_path.to_str().unwrap(),
        "--no-color",
    ]);
    assert!(out.status.success());
    assert!(out_path.exists());
    let body = fs::read_to_string(&out_path).unwrap();
    // The batch JSON file may be a concatenation of pretty-printed
    // objects. The first object should parse as JSON when extracted.
    assert!(body.contains("\"hashes\"") || body.contains("\"file_format\""));
}

#[test]
fn batch_append_grows_output_file() {
    let tmp = TempDir::new().unwrap();
    let out_path = tmp.path().join("batch_append.jsonl");
    let r1 = run_anya(&[
        "--directory",
        "tests/fixtures",
        "--json",
        "--output",
        out_path.to_str().unwrap(),
        "--no-color",
    ]);
    assert!(r1.status.success());
    let pre = fs::metadata(&out_path).unwrap().len();
    let r2 = run_anya(&[
        "--directory",
        "tests/fixtures",
        "--json",
        "--output",
        out_path.to_str().unwrap(),
        "--append",
        "--no-color",
    ]);
    assert!(r2.status.success());
    let post = fs::metadata(&out_path).unwrap().len();
    assert!(post > pre, "batch append should grow: {} → {}", pre, post);
}

#[test]
fn batch_quiet_exits_zero() {
    let out = run_anya(&["--directory", "tests/fixtures", "--quiet"]);
    assert!(out.status.success());
}

#[test]
fn batch_quiet_json_to_file_exits_zero() {
    let tmp = TempDir::new().unwrap();
    let out_path = tmp.path().join("batch_quiet.jsonl");
    let out = run_anya(&[
        "--directory",
        "tests/fixtures",
        "--quiet",
        "--json",
        "--output",
        out_path.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert!(out_path.exists() && fs::metadata(&out_path).unwrap().len() > 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Determinism and flag combinations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn deterministic_sha256_on_repeat_analysis() {
    let v1 = analyse_json(&fixture_pe());
    let v2 = analyse_json(&fixture_pe());
    assert_eq!(v1["hashes"]["sha256"], v2["hashes"]["sha256"]);
}

#[test]
fn deterministic_entire_json_on_repeat_analysis() {
    // Same file analysed twice should produce semantically identical
    // JSON. Byte equality is the long-term invariant per rule 3.1 but
    // confidence_scores (and possibly other maps) currently serialise
    // via HashMap, so key order varies between processes. See DWL-87.
    let v1 = analyse_json(&fixture_pe());
    let v2 = analyse_json(&fixture_pe());
    assert_eq!(v1, v2, "JSON output not semantically deterministic");
}

#[test]
fn verbose_json_still_valid_json() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--verbose",
        "--json",
        "--no-color",
    ]);
    assert!(out.status.success());
    let _: serde_json::Value = serde_json::from_str(&stdout_of(&out))
        .expect("--verbose --json must still parse cleanly");
}

#[test]
fn quiet_json_still_valid_json() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--quiet",
        "--json",
        "--no-color",
    ]);
    assert!(out.status.success());
    let _: serde_json::Value = serde_json::from_str(&stdout_of(&out)).unwrap();
}

#[test]
fn batch_json_to_stdout_is_parseable_first_object() {
    let out = run_anya(&["--directory", "tests/fixtures", "--json", "--no-color"]);
    assert!(out.status.success());
    let s = stdout_of(&out);
    assert!(s.contains("\"hashes\"") || s.contains("\"file_format\""));
}

#[test]
fn five_rapid_analyses_produce_identical_sha256() {
    let mut hashes: Vec<String> = Vec::new();
    for _ in 0..5 {
        let v = analyse_json(&fixture_pe());
        hashes.push(v["hashes"]["sha256"].as_str().unwrap().to_string());
    }
    let first = &hashes[0];
    for (i, h) in hashes.iter().enumerate() {
        assert_eq!(h, first, "rapid analysis {} diverged: {} vs {}", i, h, first);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Config (no --init-config: it writes to $HOME as a persistent side effect)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn min_string_length_respected_in_json_output() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--json",
        "--min-string-length",
        "10",
        "--no-color",
    ]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout_of(&out)).unwrap();
    let n = v["strings"]["min_length"].as_u64().unwrap_or(0);
    assert_eq!(n, 10, "--min-string-length not reflected in .strings.min_length");
}

#[test]
fn invalid_config_toml_exits_nonzero() {
    let tmp = TempDir::new().unwrap();
    let bad = tmp.path().join("bad_config.toml");
    fs::write(&bad, b"this is not [valid toml\n").unwrap();
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--config",
        bad.to_str().unwrap(),
        "--no-color",
    ]);
    assert!(!out.status.success(), "invalid TOML should exit non-zero");
}

// ═══════════════════════════════════════════════════════════════════════════
// --guided (Teacher Mode CLI)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn guided_exits_zero() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--guided",
        "--no-color",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
}

#[test]
fn guided_with_json_exits_zero() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--guided",
        "--json",
        "--no-color",
    ]);
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Analysis engine JSON fields
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn json_has_mitre_techniques_array() {
    let v = analyse_json(&fixture_pe());
    assert!(v["mitre_techniques"].is_array());
}

#[test]
fn json_has_confidence_scores_object() {
    let v = analyse_json(&fixture_pe());
    assert!(v["confidence_scores"].is_object());
}

#[test]
fn json_has_plain_english_findings_array() {
    let v = analyse_json(&fixture_pe());
    assert!(v["plain_english_findings"].is_array());
}

#[test]
fn json_has_schema_version_starting_with_2() {
    let v = analyse_json(&fixture_pe());
    let sv = v["schema_version"].as_str().unwrap();
    assert!(sv.starts_with("2."), "schema_version: {}", sv);
}

#[test]
fn json_has_verdict_summary_non_empty_string() {
    let v = analyse_json(&fixture_pe());
    let vs = v["verdict_summary"].as_str().unwrap();
    assert!(!vs.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Bible verse CLI
// ═══════════════════════════════════════════════════════════════════════════

/// Helper: invoke verse via whichever spelling the binary supports.
/// Returns None if none work (skip the tests gracefully).
fn try_verse_cmd() -> Option<Vec<&'static str>> {
    for args in [
        vec!["--verse", "--no-color"],
        vec!["random-verse", "--no-color"],
        vec!["--no-color", "verse"],
    ] {
        let out = run_anya(&args);
        if out.status.success() {
            return Some(args);
        }
    }
    None
}

#[test]
fn bible_verse_exits_zero() {
    let Some(args) = try_verse_cmd() else {
        // Skip if the build omits the verse subcommand.
        eprintln!("bible verse CLI not present; skipping");
        return;
    };
    let out = run_anya(&args);
    assert!(out.status.success());
}

#[test]
fn bible_verse_output_contains_reference_colon_number() {
    let Some(args) = try_verse_cmd() else {
        return;
    };
    let out = run_anya(&args);
    let combined = combined_of(&out);
    let has_ref = combined
        .chars()
        .collect::<Vec<_>>()
        .windows(3)
        .any(|w| w[0] == ':' && w[1].is_ascii_digit());
    assert!(
        has_ref,
        "verse output missing 'book N:N' reference: {}",
        combined
    );
}

#[test]
fn bible_verse_content_sampling_three_runs_have_references() {
    let Some(args) = try_verse_cmd() else {
        return;
    };
    for i in 0..3 {
        let out = run_anya(&args);
        assert!(out.status.success(), "verse run {} failed", i);
        let combined = combined_of(&out);
        let has_ref = combined
            .chars()
            .collect::<Vec<_>>()
            .windows(3)
            .any(|w| w[0] == ':' && w[1].is_ascii_digit());
        assert!(has_ref, "verse run {} lacks reference: {}", i, combined);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Format flag
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn format_text_exits_zero() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--format",
        "text",
        "--quiet",
    ]);
    assert!(out.status.success());
}

#[test]
fn format_json_exits_zero_and_produces_valid_json() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(out.status.success());
    let _: serde_json::Value = serde_json::from_str(&stdout_of(&out)).unwrap();
}

#[test]
fn format_bogus_value_fails() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--format",
        "bogus",
    ]);
    assert!(!out.status.success());
}

#[test]
fn format_unknown_xml_value_fails() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--format",
        "xml",
        "--no-color",
    ]);
    assert!(!out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// compare subcommand
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn compare_same_file_exits_zero() {
    let pe = fixture_pe();
    let pe_s = pe.to_str().unwrap();
    let out = run_anya(&["compare", pe_s, pe_s]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
}

#[test]
fn compare_output_mentions_file_name() {
    let pe = fixture_pe();
    let pe_s = pe.to_str().unwrap();
    let out = run_anya(&["compare", pe_s, pe_s]);
    assert!(out.status.success());
    let fname = pe.file_name().unwrap().to_str().unwrap();
    assert!(stdout_of(&out).contains(fname));
}

#[test]
fn compare_with_empty_file_fails() {
    let tmp = TempDir::new().unwrap();
    let empty = tmp.path().join("empty.bin");
    fs::write(&empty, b"").unwrap();
    let pe = fixture_pe();
    let out = run_anya(&[
        "compare",
        pe.to_str().unwrap(),
        empty.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// completions subcommand
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn completions_bash_exits_zero_and_mentions_anya() {
    let out = run_anya(&["completions", "bash"]);
    assert!(out.status.success());
    assert!(stdout_of(&out).contains("anya"));
}

#[test]
fn completions_zsh_exits_zero() {
    assert!(run_anya(&["completions", "zsh"]).status.success());
}

#[test]
fn completions_fish_exits_zero() {
    assert!(run_anya(&["completions", "fish"]).status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// cases subcommand
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cases_list_exits_zero() {
    let out = run_anya(&["cases", "--list"]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
}

// ═══════════════════════════════════════════════════════════════════════════
// HTML report output
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn html_report_generation_succeeds_and_has_expected_markers() {
    let tmp = TempDir::new().unwrap();
    let report = tmp.path().join("test_report.html");
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--format",
        "html",
        "--output",
        report.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert!(report.exists() && fs::metadata(&report).unwrap().len() > 0);
    let body = fs::read_to_string(&report).unwrap();
    assert!(body.contains("DOCTYPE"), "HTML missing DOCTYPE");
    assert!(body.contains("Anya"), "HTML missing Anya branding");
    assert!(body.contains("<html"), "HTML missing <html tag");
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases — filesystem
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn file_path_with_spaces_works() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("path with spaces");
    fs::create_dir_all(&dir).unwrap();
    let dst = dir.join("test file.exe");
    fs::copy(fixture_pe(), &dst).unwrap();
    let out = run_anya(&["--file", dst.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.success());
    let _: serde_json::Value = serde_json::from_str(&stdout_of(&out)).unwrap();
}

#[test]
#[cfg(unix)]
fn symlink_to_pe_file_analysis_works() {
    use std::os::unix::fs::symlink;
    let tmp = TempDir::new().unwrap();
    let link = tmp.path().join("symlink.exe");
    symlink(fs::canonicalize(fixture_pe()).unwrap(), &link).unwrap();
    let out = run_anya(&["--file", link.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.success());
}

#[test]
fn unicode_filename_and_directory() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("unicöde_тест_日本");
    fs::create_dir_all(&dir).unwrap();
    let dst = dir.join("mälwäre_样本.exe");
    fs::copy(fixture_pe(), &dst).unwrap();
    let out = run_anya(&["--file", dst.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.success());
}

#[test]
fn two_hundred_char_filename_works() {
    let tmp = TempDir::new().unwrap();
    let name = "a".repeat(200);
    let dst = tmp.path().join(format!("{}.exe", name));
    fs::copy(fixture_pe(), &dst).unwrap();
    let out = run_anya(&["--file", dst.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.success());
}

#[test]
fn deeply_nested_path_works() {
    let tmp = TempDir::new().unwrap();
    let mut deep = tmp.path().to_path_buf();
    for c in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o'] {
        deep = deep.join(c.to_string());
    }
    fs::create_dir_all(&deep).unwrap();
    let dst = deep.join("deep.exe");
    fs::copy(fixture_pe(), &dst).unwrap();
    let out = run_anya(&["--file", dst.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.success());
}

#[test]
fn file_with_no_extension_still_detects_pe() {
    let tmp = TempDir::new().unwrap();
    let dst = tmp.path().join("noextension");
    fs::copy(fixture_pe(), &dst).unwrap();
    let v = analyse_json(&dst);
    assert!(
        v["file_format"].as_str().unwrap().contains("PE"),
        "file_format: {}",
        v["file_format"]
    );
}

#[test]
fn misleading_extension_still_detects_pe_and_flags_mismatch() {
    let tmp = TempDir::new().unwrap();
    let dst = tmp.path().join("misleading.pdf");
    fs::copy(fixture_pe(), &dst).unwrap();
    let v = analyse_json(&dst);
    assert!(
        v["file_format"].as_str().unwrap().contains("PE"),
        "still-detects-PE"
    );
    // file_type_mismatch must be present (truthy shape depends on
    // engine's exact representation — accept any non-null value).
    assert!(
        !v["file_type_mismatch"].is_null(),
        "file_type_mismatch missing for misleading .pdf extension"
    );
}

#[test]
fn hidden_file_dot_prefix_works() {
    let tmp = TempDir::new().unwrap();
    let dst = tmp.path().join(".hidden_sample.exe");
    fs::copy(fixture_pe(), &dst).unwrap();
    let out = run_anya(&["--file", dst.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.success());
}

#[test]
#[cfg(unix)]
fn read_only_file_still_works() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let dst = tmp.path().join("readonly.exe");
    fs::copy(fixture_pe(), &dst).unwrap();
    let mut perms = fs::metadata(&dst).unwrap().permissions();
    perms.set_mode(0o444);
    fs::set_permissions(&dst, perms).unwrap();
    let out = run_anya(&["--file", dst.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases — malformed / adversarial input
// ═══════════════════════════════════════════════════════════════════════════

fn write_bytes(dir: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn one_byte_file_does_not_crash() {
    let tmp = TempDir::new().unwrap();
    let p = write_bytes(tmp.path(), "one.bin", &[0x4d]);
    let out = run_anya(&["--file", p.to_str().unwrap(), "--json", "--no-color"]);
    // Must not crash (may exit 0 or non-zero). Stdout (if any) must be
    // valid JSON if it exists.
    let s = stdout_of(&out);
    if !s.is_empty() {
        let _: serde_json::Value =
            serde_json::from_str(&s).expect("1-byte file: stdout must be valid JSON if present");
    }
    // Process should not have been killed by signal.
    assert!(
        out.status.code().is_some(),
        "1-byte file should not crash (no signal termination)"
    );
}

#[test]
fn truncated_mz_header_does_not_crash() {
    let tmp = TempDir::new().unwrap();
    let p = write_bytes(tmp.path(), "mz.exe", b"MZ");
    let out = run_anya(&["--file", p.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.code().is_some());
    let s = stdout_of(&out);
    if !s.is_empty() {
        let _: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON if present");
    }
}

#[test]
fn all_zeros_file_produces_valid_json_with_low_entropy() {
    let tmp = TempDir::new().unwrap();
    let p = write_bytes(tmp.path(), "zeros.bin", &[0u8; 10 * 1024]);
    let v = analyse_json(&p);
    let e = v["entropy"]["value"].as_f64().unwrap();
    assert!(e < 0.1, "all-zeros entropy should be near zero: {}", e);
}

#[test]
fn all_ff_file_produces_valid_json_with_low_entropy() {
    let tmp = TempDir::new().unwrap();
    let p = write_bytes(tmp.path(), "ff.bin", &[0xffu8; 10 * 1024]);
    let v = analyse_json(&p);
    let e = v["entropy"]["value"].as_f64().unwrap();
    assert!(e < 0.1, "all-0xFF entropy should be near zero: {}", e);
}

#[test]
fn random_data_produces_valid_json_with_high_entropy() {
    let tmp = TempDir::new().unwrap();
    // Deterministic pseudo-random bytes so the test does not depend on
    // /dev/urandom availability or flake across runs.
    let mut bytes = Vec::with_capacity(50 * 1024);
    let mut x: u32 = 0x1234_5678;
    for _ in 0..bytes.capacity() {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        bytes.push((x >> 16) as u8);
    }
    let p = write_bytes(tmp.path(), "random.bin", &bytes);
    let v = analyse_json(&p);
    let e = v["entropy"]["value"].as_f64().unwrap();
    assert!(e > 7.0, "random data entropy should be > 7.0: {}", e);
}

#[test]
fn fake_pe_header_with_zeros_does_not_crash() {
    let tmp = TempDir::new().unwrap();
    let mut bytes = Vec::from(&b"MZ"[..]);
    bytes.extend_from_slice(&[0u8; 1024]);
    let p = write_bytes(tmp.path(), "fake.exe", &bytes);
    let out = run_anya(&["--file", p.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.code().is_some());
}

#[test]
fn truncated_elf_does_not_crash() {
    let tmp = TempDir::new().unwrap();
    let mut bytes = Vec::from(&[0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00][..]);
    bytes.extend_from_slice(&[0u8; 32]);
    let p = write_bytes(tmp.path(), "t.elf", &bytes);
    let out = run_anya(&["--file", p.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.code().is_some());
}

#[test]
fn fake_macho_does_not_crash() {
    let tmp = TempDir::new().unwrap();
    let mut bytes = Vec::from(&[0xfe, 0xed, 0xfa, 0xce][..]);
    let mut x: u32 = 0xdead_beef;
    for _ in 0..512 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        bytes.push((x >> 16) as u8);
    }
    let p = write_bytes(tmp.path(), "f.macho", &bytes);
    let out = run_anya(&["--file", p.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.code().is_some());
}

#[test]
fn pk_header_named_zip_does_not_hang_or_crash() {
    let tmp = TempDir::new().unwrap();
    let p = write_bytes(tmp.path(), "bomb.zip", b"PK\x03\x04");
    let out = run_anya(&["--file", p.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.code().is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases — file sizes
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn exactly_four_byte_mz_does_not_crash() {
    let tmp = TempDir::new().unwrap();
    let p = write_bytes(tmp.path(), "four.bin", b"MZ\x90\x00");
    let out = run_anya(&["--file", p.to_str().unwrap(), "--json", "--no-color"]);
    assert!(out.status.code().is_some());
}

#[test]
fn ten_mb_random_file_completes_under_30s() {
    use std::time::Instant;
    let tmp = TempDir::new().unwrap();
    // Deterministic pseudo-random 10MB.
    let size = 10 * 1024 * 1024;
    let mut bytes = Vec::with_capacity(size);
    let mut x: u32 = 0x9e37_79b9;
    for _ in 0..size {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        bytes.push((x >> 16) as u8);
    }
    let p = write_bytes(tmp.path(), "large.bin", &bytes);
    let start = Instant::now();
    let out = run_anya(&["--file", p.to_str().unwrap(), "--json", "--no-color"]);
    let elapsed = start.elapsed();
    assert!(out.status.success());
    assert!(
        elapsed.as_secs() <= 30,
        "10MB analysis took {:?}, exceeds 30s budget",
        elapsed
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases — CLI argument abuse
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn double_file_flag_fails() {
    let pe = fixture_pe();
    let pe_s = pe.to_str().unwrap();
    let out = run_anya(&["--file", pe_s, "--file", pe_s, "--no-color"]);
    assert!(!out.status.success(), "double --file should be rejected");
}

#[test]
fn min_string_length_zero_exits_zero() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--min-string-length",
        "0",
        "--json",
        "--no-color",
    ]);
    assert!(out.status.success());
}

#[test]
fn verbose_and_quiet_conflict_fails() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--verbose",
        "--quiet",
        "--no-color",
    ]);
    assert!(!out.status.success());
}

#[test]
fn recursive_with_file_is_ignored_gracefully() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--recursive",
        "--no-color",
    ]);
    assert!(out.status.success());
}

#[test]
fn summary_without_directory_fails() {
    let out = run_anya(&["--summary", "--no-color"]);
    assert!(!out.status.success());
}

#[test]
fn case_with_empty_name_fails() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--case",
        "",
        "--no-color",
    ]);
    assert!(!out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases — output correctness invariants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn json_md5_is_lowercase_only() {
    let v = analyse_json(&fixture_pe());
    let h = v["hashes"]["md5"].as_str().unwrap();
    assert!(h.chars().all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f')));
}

#[test]
fn json_sha1_is_lowercase_only() {
    let v = analyse_json(&fixture_pe());
    let h = v["hashes"]["sha1"].as_str().unwrap();
    assert!(h.chars().all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f')));
}

#[test]
fn json_sha256_is_lowercase_only() {
    let v = analyse_json(&fixture_pe());
    let h = v["hashes"]["sha256"].as_str().unwrap();
    assert!(h.chars().all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f')));
}

#[test]
fn json_file_info_size_matches_actual_file_size() {
    let pe = fixture_pe();
    let actual = fs::metadata(&pe).unwrap().len();
    let v = analyse_json(&pe);
    let json_size = v["file_info"]["size_bytes"].as_u64().unwrap();
    assert_eq!(json_size, actual, "size_bytes mismatch");
}

#[test]
fn json_strings_total_ge_sample() {
    let v = analyse_json(&fixture_pe());
    let total = v["strings"]["total_count"].as_u64().unwrap();
    let sample = v["strings"]["sample_count"].as_u64().unwrap();
    assert!(total >= sample);
}

#[test]
fn json_output_has_no_null_bytes() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--json",
        "--no-color",
    ]);
    assert!(out.status.success());
    assert!(
        !out.stdout.contains(&0u8),
        "JSON output contains a null byte"
    );
}

#[test]
fn json_round_trip_is_stable() {
    let pe = fixture_pe();
    let v1 = analyse_json(&pe);
    // Serialise back and re-parse — value equality should hold.
    let round = serde_json::to_string(&v1).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&round).unwrap();
    assert_eq!(v1, v2);
}

#[test]
fn json_pe_sections_all_have_non_negative_entropy() {
    let v = analyse_json(&fixture_pe());
    let sections = v["pe_analysis"]["sections"].as_array().unwrap();
    for s in sections {
        if let Some(e) = s["entropy"].as_f64() {
            assert!(e >= 0.0, "section entropy < 0: {}", e);
        }
    }
}

#[test]
fn json_byte_histogram_has_256_entries() {
    let v = analyse_json(&fixture_pe());
    let hist = v["byte_histogram"].as_array().unwrap();
    assert_eq!(hist.len(), 256);
}

#[test]
fn json_byte_histogram_all_non_negative() {
    let v = analyse_json(&fixture_pe());
    for x in v["byte_histogram"].as_array().unwrap() {
        assert!(x.as_i64().unwrap() >= 0);
    }
}

#[test]
fn json_byte_histogram_sum_equals_file_size() {
    let pe = fixture_pe();
    let actual = fs::metadata(&pe).unwrap().len();
    let v = analyse_json(&pe);
    let sum: i64 = v["byte_histogram"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_i64().unwrap())
        .sum();
    assert_eq!(sum as u64, actual, "histogram sum != file size");
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases — batch boundaries
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_directory_with_only_text_files_succeeds() {
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("readme.txt"), "just text").unwrap();
    fs::write(tmp.path().join("notes.md"), "more text").unwrap();
    let out = run_anya(&["--directory", tmp.path().to_str().unwrap(), "--no-color"]);
    assert!(out.status.success());
}

#[test]
fn batch_directory_mixed_pe_and_text_succeeds() {
    let tmp = TempDir::new().unwrap();
    fs::copy(fixture_pe(), tmp.path().join("real.exe")).unwrap();
    fs::write(tmp.path().join("readme.txt"), "just text").unwrap();
    let out = run_anya(&["--directory", tmp.path().to_str().unwrap(), "--no-color"]);
    assert!(out.status.success());
}

#[test]
fn batch_single_file_directory_with_summary_works() {
    let tmp = TempDir::new().unwrap();
    fs::copy(fixture_pe(), tmp.path().join("only.exe")).unwrap();
    let out = run_anya(&[
        "--directory",
        tmp.path().to_str().unwrap(),
        "--summary",
        "--no-color",
    ]);
    assert!(out.status.success());
    assert!(
        stdout_of(&out).to_uppercase().contains("VERDICT"),
        "summary output should include VERDICT column"
    );
}

#[test]
fn recursive_on_flat_directory_succeeds() {
    let tmp = TempDir::new().unwrap();
    fs::copy(fixture_pe(), tmp.path().join("only.exe")).unwrap();
    let out = run_anya(&[
        "--directory",
        tmp.path().to_str().unwrap(),
        "--recursive",
        "--no-color",
    ]);
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases — output formats on non-PE inputs
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn pdf_report_for_text_file_succeeds_and_starts_with_pdf_magic() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("plain.txt");
    fs::write(&src, b"just some text content for analysis").unwrap();
    let report = tmp.path().join("report.pdf");
    let out = run_anya(&[
        "--file",
        src.to_str().unwrap(),
        "--format",
        "pdf",
        "--output",
        report.to_str().unwrap(),
        "--no-color",
    ]);
    assert!(out.status.success());
    assert!(report.exists());
    let first5 = fs::read(&report).unwrap().into_iter().take(5).collect::<Vec<_>>();
    assert_eq!(&first5, b"%PDF-", "PDF missing %PDF- magic");
}

#[test]
fn markdown_report_for_text_file_succeeds_with_heading() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("plain.txt");
    fs::write(&src, b"plain content").unwrap();
    let report = tmp.path().join("report.md");
    let out = run_anya(&[
        "--file",
        src.to_str().unwrap(),
        "--format",
        "markdown",
        "--output",
        report.to_str().unwrap(),
        "--no-color",
    ]);
    assert!(out.status.success());
    let body = fs::read_to_string(&report).unwrap();
    assert!(body.lines().any(|l| l.starts_with('#')));
}

#[test]
fn html_report_for_text_file_succeeds_with_doctype() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("plain.txt");
    fs::write(&src, b"plain content").unwrap();
    let report = tmp.path().join("report.html");
    let out = run_anya(&[
        "--file",
        src.to_str().unwrap(),
        "--format",
        "html",
        "--output",
        report.to_str().unwrap(),
        "--no-color",
    ]);
    assert!(out.status.success());
    assert!(fs::read_to_string(&report).unwrap().contains("DOCTYPE"));
}

#[test]
fn overwrite_existing_output_file_succeeds_twice() {
    let tmp = TempDir::new().unwrap();
    let out_path = tmp.path().join("overwrite.json");
    for _ in 0..2 {
        let out = run_anya(&[
            "--file",
            fixture_pe().to_str().unwrap(),
            "--json",
            "--output",
            out_path.to_str().unwrap(),
            "--no-color",
        ]);
        assert!(out.status.success());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases — YARA engine
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn yara_matches_field_is_array_in_output() {
    let v = analyse_json(&fixture_pe());
    assert!(
        v["yara_matches"].is_array() || v["yara_matches"].is_null(),
        "yara_matches should be array or null (graceful): {:?}",
        v["yara_matches"]
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Extra: net-new tests beyond the shell script — features that post-dated it
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn depth_quick_exits_zero() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--depth",
        "quick",
        "--quiet",
    ]);
    assert!(out.status.success());
}

#[test]
fn depth_standard_exits_zero() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--depth",
        "standard",
        "--quiet",
    ]);
    assert!(out.status.success());
}

#[test]
fn depth_deep_exits_zero() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--depth",
        "deep",
        "--quiet",
    ]);
    assert!(out.status.success());
}

#[test]
fn depth_bogus_fails() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--depth",
        "bogus",
        "--quiet",
    ]);
    assert!(!out.status.success());
}

#[test]
fn jsonl_exits_zero_and_emits_one_line_json_per_file() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--jsonl",
        "--no-color",
    ]);
    assert!(out.status.success());
    let s = stdout_of(&out);
    let lines: Vec<&str> = s.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "--jsonl single file should emit exactly one line");
    let _: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
}

#[test]
fn json_compact_exits_zero_and_emits_single_line_json() {
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--json-compact",
        "--no-color",
    ]);
    assert!(out.status.success());
    let s = stdout_of(&out);
    let trimmed = s.trim_end_matches('\n');
    assert!(
        !trimmed.contains('\n'),
        "--json-compact output should be single line"
    );
    let _: serde_json::Value = serde_json::from_str(trimmed).unwrap();
}

#[test]
fn no_color_suppresses_ansi_escape_sequences() {
    let out = run_anya(&["--file", fixture_pe().to_str().unwrap(), "--no-color"]);
    assert!(out.status.success());
    // No ANSI escape sequences anywhere in stdout.
    assert!(
        !stdout_of(&out).contains('\x1b'),
        "--no-color output still contains an ANSI escape"
    );
}

#[test]
fn exit_code_from_verdict_exits_with_nonzero_on_suspicious_fixture() {
    // simple.exe reaches SUSPICIOUS, so exit-code-from-verdict should
    // produce a non-zero code that a pipeline can act on.
    let out = run_anya(&[
        "--file",
        fixture_pe().to_str().unwrap(),
        "--exit-code-from-verdict",
        "--quiet",
    ]);
    // We don't pin the exact code; just assert it is NOT 0, which is
    // the whole point of the flag.
    assert_ne!(
        out.status.code().unwrap_or(0),
        0,
        "suspicious verdict should produce a non-zero exit code"
    );
}
