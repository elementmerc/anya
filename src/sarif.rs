//! SARIF output skeleton for Anya.
//!
//! This is the Friday-Weekend-1 skeleton: enum variant + CLI plumbing + a
//! valid-shape v2.1.0 stub document with an empty `results` array. The real
//! verdict → SARIF result mapping lands Saturday afternoon.
//!
//! SARIF (Static Analysis Results Interchange Format) is the OASIS-standard
//! JSON schema that GitHub Code Scanning, Azure DevOps, GitLab Security,
//! SIEM/SOAR pipelines, and every major static analyser speaks. Enterprise
//! buyers (ResolveHealthware, UK banking sector) require it as a CI output
//! format; "does your tool output SARIF?" is a checkbox on every RFP.
//!
//! Skeleton invariants:
//!   * Output parses as valid JSON and round-trips through serde.
//!   * Top-level `version` is exactly `"2.1.0"`.
//!   * Top-level `$schema` is the schemastore.org canonical URI.
//!   * `runs` has exactly one run with the Anya tool driver identified.
//!   * `results` is an empty array (populated Saturday).
//!
//! Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use crate::output::AnalysisResult;
use serde::{Deserialize, Serialize};

/// Canonical SARIF 2.1.0 schema URI (schemastore.org variant, which GitHub
/// Code Scanning recognises). Saturday's real-impl work will confirm whether
/// the OASIS or schemastore variant is preferred by our integration targets.
pub const SARIF_SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";
pub const SARIF_VERSION: &str = "2.1.0";

/// Top-level SARIF document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SarifOutput {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// One SARIF run — a single invocation of a tool producing a set of results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<serde_json::Value>,
}

/// Tool metadata wrapper. SARIF requires `driver` even if there are no
/// extensions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SarifTool {
    pub driver: SarifToolComponent,
}

/// The analyser itself — name, version, homepage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SarifToolComponent {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "informationUri", skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
}

/// Build a valid-shape SARIF 2.1.0 document for the given analysis.
///
/// The skeleton does NOT map analysis verdicts or evidence into SARIF
/// results yet — that's Saturday's scope. `_analysis` is accepted (and
/// not used) deliberately so the call-site contract is stable when the
/// real mapping lands tomorrow; no caller needs to change.
pub fn render_stub(_analysis: &AnalysisResult) -> SarifOutput {
    SarifOutput {
        schema: SARIF_SCHEMA_URI.to_string(),
        version: SARIF_VERSION.to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolComponent {
                    name: "Anya".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    information_uri: Some("https://github.com/elementmerc/anya".to_string()),
                },
            },
            results: Vec::new(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::AnalysisResult;

    fn minimal_analysis() -> AnalysisResult {
        // Build via Default where possible; AnalysisResult derives Default per
        // output.rs. The skeleton does not read any field off it — tomorrow's
        // mapping will exercise the real fields.
        AnalysisResult::default()
    }

    #[test]
    fn stub_has_required_top_level_fields() {
        let a = minimal_analysis();
        let s = render_stub(&a);
        assert_eq!(s.version, SARIF_VERSION);
        assert_eq!(s.schema, SARIF_SCHEMA_URI);
        assert_eq!(s.runs.len(), 1);
        assert_eq!(s.runs[0].tool.driver.name, "Anya");
        assert!(s.runs[0].results.is_empty());
    }

    #[test]
    fn stub_serialises_to_valid_json() {
        let a = minimal_analysis();
        let s = render_stub(&a);
        let j = serde_json::to_string_pretty(&s).expect("serialises");

        // Must contain the canonical $schema key (note leading $ and JSON escaping)
        assert!(j.contains("\"$schema\""), "missing $schema key: {}", j);
        assert!(j.contains("\"version\": \"2.1.0\""), "missing version: {}", j);
        assert!(j.contains("\"name\": \"Anya\""), "missing tool name: {}", j);
        assert!(
            j.contains("\"informationUri\""),
            "missing informationUri camelCase key: {}",
            j
        );
    }

    #[test]
    fn stub_round_trips_through_serde() {
        let a = minimal_analysis();
        let original = render_stub(&a);
        let j = serde_json::to_string(&original).expect("serialises");
        let parsed: SarifOutput = serde_json::from_str(&j).expect("deserialises");
        assert_eq!(original, parsed, "round-trip altered the SARIF document");
    }

    #[test]
    fn stub_is_parseable_as_generic_json_with_expected_shape() {
        // Parse through serde_json::Value to confirm tools that don't have
        // our typed structs still see the right shape (this is what GitHub
        // Code Scanning does at upload time).
        let a = minimal_analysis();
        let s = render_stub(&a);
        let j = serde_json::to_string(&s).expect("serialises");
        let v: serde_json::Value = serde_json::from_str(&j).expect("parses as Value");

        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["$schema"], SARIF_SCHEMA_URI);
        let runs = v["runs"].as_array().expect("runs is array");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["tool"]["driver"]["name"], "Anya");
        assert!(runs[0]["results"].as_array().unwrap().is_empty());
    }
}
