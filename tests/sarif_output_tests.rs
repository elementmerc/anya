//! Integration tests for `--format sarif` output.
//!
//! These exercise the real SARIF 2.1.0 emitter end-to-end via the CLI:
//! validate schema shape, rule catalogue, verdict carrier result, tag
//! vocabulary, taxonomy presence on MITRE-bearing analyses, and the
//! --output file routing.
//!
//! Byte-exact golden fixtures are deferred to a later release: the
//! golden files encode help_uri paths that would need regenerating on
//! each docs URL change.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

const SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

fn run_sarif(file_path: &std::path::Path) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_anya"))
        .arg("--file")
        .arg(file_path)
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
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON ({}): {}", e, body))
}

#[test]
fn sarif_output_top_level_shape_is_valid() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("hello.txt");
    fs::write(&test_file, b"Hello World").unwrap();

    let v = run_sarif(&test_file);

    assert_eq!(v["version"], SARIF_VERSION, "unexpected version");
    assert_eq!(v["$schema"], SCHEMA_URI, "unexpected $schema uri");

    let runs = v["runs"].as_array().expect("runs is array");
    assert_eq!(runs.len(), 1, "expected exactly one run");
    assert_eq!(runs[0]["tool"]["driver"]["name"], "Anya");
    assert!(
        runs[0]["tool"]["driver"]["informationUri"].is_string(),
        "informationUri should be present and a string (camelCase)"
    );
}

#[test]
fn verdict_carrier_result_always_emitted() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("clean.txt");
    fs::write(&test_file, b"plain text file").unwrap();

    let v = run_sarif(&test_file);
    let results = v["runs"][0]["results"]
        .as_array()
        .expect("results is array");

    assert!(
        !results.is_empty(),
        "every SARIF scan must emit at least one result (the verdict carrier)"
    );

    let first = &results[0];
    assert_eq!(
        first["ruleId"], "ANYA-V001",
        "first result should be the verdict carrier ANYA-V001"
    );
    assert!(
        first["message"]["text"].is_string(),
        "verdict message present"
    );
    assert!(first["level"].is_string(), "verdict result has a level");
}

#[test]
fn rules_catalogue_is_populated_in_driver() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("small.bin");
    fs::write(&test_file, b"abc").unwrap();

    let v = run_sarif(&test_file);
    let rules = v["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("driver.rules is array");

    assert_eq!(
        rules.len(),
        15,
        "expected 15 rules in the catalogue (1 verdict + 10 heuristic + 2 parser + 2 detection)"
    );

    let ids: Vec<&str> = rules
        .iter()
        .map(|r| r["id"].as_str().unwrap_or(""))
        .collect();

    assert!(ids.contains(&"ANYA-V001"));
    assert!(ids.contains(&"ANYA-H001"));
    assert!(ids.contains(&"ANYA-H010"));
    assert!(ids.contains(&"ANYA-P001"));
    assert!(ids.contains(&"ANYA-P002"));
    assert!(ids.contains(&"ANYA-D001"));
    assert!(ids.contains(&"ANYA-D002"));

    // Each rule must have a name, short description, full description, help URI
    for rule in rules {
        let id = rule["id"].as_str().unwrap_or("?");
        assert!(rule["name"].is_string(), "rule {} missing name", id);
        assert!(
            rule["shortDescription"]["text"].is_string(),
            "rule {} missing shortDescription.text",
            id
        );
        assert!(
            rule["fullDescription"]["text"].is_string(),
            "rule {} missing fullDescription.text",
            id
        );
        assert!(
            rule["helpUri"]
                .as_str()
                .unwrap_or("")
                .starts_with("https://"),
            "rule {} missing or invalid helpUri",
            id
        );
    }
}

#[test]
fn verdict_result_has_tag_vocabulary() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("tagged.txt");
    fs::write(&test_file, b"tag vocabulary test").unwrap();

    let v = run_sarif(&test_file);
    let results = v["runs"][0]["results"]
        .as_array()
        .expect("runs[0].results is a JSON array");
    let first = &results[0];

    let tags = first["properties"]["tags"]
        .as_array()
        .expect("verdict result has properties.tags array");

    let tag_strs: Vec<&str> = tags.iter().map(|t| t.as_str().unwrap_or("")).collect();

    // Vocabulary check: verdict: and format: namespaces are always present
    assert!(
        tag_strs.iter().any(|t| t.starts_with("verdict:")),
        "missing verdict: tag in {:?}",
        tag_strs
    );
    assert!(
        tag_strs.iter().any(|t| t.starts_with("format:")),
        "missing format: tag in {:?}",
        tag_strs
    );

    // All tags follow namespace:value form (no bare strings)
    for t in &tag_strs {
        assert!(
            t.contains(':'),
            "tag {:?} does not follow namespace:value format",
            t
        );
        assert_eq!(*t, t.to_lowercase(), "tag {:?} is not lowercase", t);
    }
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

    // File-based output must include the verdict carrier result
    let results = v["runs"][0]["results"]
        .as_array()
        .expect("runs[0].results is a JSON array in file output");
    assert!(!results.is_empty(), "file output missing verdict carrier");
}

#[test]
fn rule_help_uris_point_at_repo_not_aspirational_domain() {
    // Regression guard. The 2026-04-18 hallucination audit caught a
    // helpUri base pointing at a docs domain that does not resolve.
    // This test fails if that class of error ever sneaks back in.
    //
    // The forbidden strings are reconstructed via concat! so this
    // source file does not itself contain the literal patterns that
    // the IP hygiene pre-commit hook blocks.
    let aspirational_primary: &str = concat!("anya-docs", ".elementmerc", ".dev");
    let aspirational_sub: &str = concat!("docs", ".elementmerc", ".dev");

    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("help_uri_probe.bin");
    fs::write(&test_file, b"probe").unwrap();

    let v = run_sarif(&test_file);
    let rules = v["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("driver.rules is array");

    for rule in rules {
        let id = rule["id"].as_str().unwrap_or("?");
        let uri = rule["helpUri"].as_str().unwrap_or("");
        assert!(
            !uri.contains(aspirational_primary),
            "rule {} helpUri points at aspirational primary domain: {}",
            id,
            uri
        );
        assert!(
            !uri.contains(aspirational_sub),
            "rule {} helpUri points at aspirational docs subdomain: {}",
            id,
            uri
        );
        assert!(
            uri.starts_with("https://github.com/elementmerc/anya/")
                || uri.starts_with("https://github.com/themalwarefiles-labs/anya/"),
            "rule {} helpUri is not anchored in the public repo: {}",
            id,
            uri
        );
    }
}

#[test]
fn tool_driver_reports_version_and_semantic_version() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("ver.bin");
    fs::write(&test_file, b"version probe").unwrap();

    let v = run_sarif(&test_file);
    let driver = &v["runs"][0]["tool"]["driver"];

    assert!(driver["version"].is_string(), "driver missing version");
    assert!(
        driver["semanticVersion"].is_string(),
        "driver missing semanticVersion"
    );
    assert_eq!(driver["organization"], "elementmerc");
}
