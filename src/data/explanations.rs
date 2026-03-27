// Ányá - Plain-English analyst findings
// Static lookup: detection_key → PlainEnglishFinding
// Embedded at compile time — no runtime I/O.

use crate::output::{ConfidenceLevel, PlainEnglishFinding};
use std::collections::HashMap;
use std::sync::OnceLock;

static EXPLANATIONS_JSON: &str = anya_data::EXPLANATIONS_JSON;

#[derive(serde::Deserialize)]
struct RawFinding {
    title: String,
    explanation: String,
    why_suspicious: String,
    #[serde(default)]
    malware_families: Vec<String>,
    mitre_technique_id: Option<String>,
    confidence: String,
}

fn build_map() -> HashMap<String, PlainEnglishFinding> {
    let raw: HashMap<String, RawFinding> =
        serde_json::from_str(EXPLANATIONS_JSON).expect("explanations_data.json is malformed");

    raw.into_iter()
        .map(|(key, r)| {
            let finding = PlainEnglishFinding {
                title: r.title,
                explanation: r.explanation,
                why_suspicious: r.why_suspicious,
                malware_families: r.malware_families,
                mitre_technique_id: r.mitre_technique_id,
                confidence: match r.confidence.as_str() {
                    "Critical" => ConfidenceLevel::Critical,
                    "High" => ConfidenceLevel::High,
                    "Medium" => ConfidenceLevel::Medium,
                    _ => ConfidenceLevel::Low,
                },
            };
            (key, finding)
        })
        .collect()
}

static MAP: OnceLock<HashMap<String, PlainEnglishFinding>> = OnceLock::new();

fn get_map() -> &'static HashMap<String, PlainEnglishFinding> {
    MAP.get_or_init(build_map)
}

/// Look up a plain-English finding by key.
pub fn get_explanation(key: &str) -> Option<PlainEnglishFinding> {
    get_map().get(key).cloned()
}

/// Given a list of API names, return relevant plain-English findings.
/// Checks for named API combos and single-API triggers.
pub fn get_explanation_for_api_combo(apis: &[&str]) -> Vec<PlainEnglishFinding> {
    let lower: Vec<String> = apis.iter().map(|s| s.to_lowercase()).collect();
    let mut findings = Vec::new();

    // Process injection combo
    let has_alloc = lower
        .iter()
        .any(|a| a == "virtualallocex" || a == "ntallocatevirtualmemory");
    let has_write = lower.iter().any(|a| a == "writeprocessmemory");
    let has_thread = lower.iter().any(|a| {
        a == "createremotethread" || a == "ntcreatethreadex" || a == "rtlcreateuserthread"
    });
    if has_alloc
        && has_write
        && has_thread
        && let Some(f) = get_explanation("process_injection_combo")
    {
        findings.push(f);
    }

    // LSASS dump combo
    let has_dump = lower.iter().any(|a| a == "minidumpwritedump");
    let has_open = lower.iter().any(|a| a == "openprocess");
    if has_dump
        && has_open
        && let Some(f) = get_explanation("lsass_dump_combo")
    {
        findings.push(f);
    }

    // Keylogger combo
    let has_key = lower
        .iter()
        .any(|a| a == "getasynckeystate" || a == "getkeystate");
    let has_hook = lower.iter().any(|a| a.starts_with("setwindowshookex"));
    if (has_key || has_hook)
        && let Some(f) = get_explanation("keylogger_combo")
    {
        findings.push(f);
    }

    // Debugger check
    let has_debug = lower
        .iter()
        .any(|a| a == "isdebuggerpresent" || a == "checkremotedebuggerpresent");
    if has_debug && let Some(f) = get_explanation("debugger_check") {
        findings.push(f);
    }

    // Persistence
    let has_reg = lower
        .iter()
        .any(|a| a == "regsetvalueex" || a == "regcreatekeyex");
    let has_svc = lower
        .iter()
        .any(|a| a == "createservice" || a == "openscmanager");
    if (has_reg || has_svc)
        && let Some(f) = get_explanation("persistence_combo")
    {
        findings.push(f);
    }

    // Privilege escalation
    if lower
        .iter()
        .any(|a| a == "adjusttokenprivileges" || a == "impersonateloggedonuser")
        && let Some(f) = get_explanation("privilege_escalation")
    {
        findings.push(f);
    }

    // Network
    let has_net = lower
        .iter()
        .any(|a| a.starts_with("internet") || a.starts_with("winhttp") || a == "wsastartup");
    if has_net && let Some(f) = get_explanation("network_combo") {
        findings.push(f);
    }

    // Clipboard
    if lower
        .iter()
        .any(|a| a == "getclipboarddata" || a == "openclipboard")
        && let Some(f) = get_explanation("clipboard_access")
    {
        findings.push(f);
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_explanation_known_key() {
        let f = get_explanation("process_injection_combo");
        assert!(f.is_some());
        let f = f.unwrap();
        assert!(!f.title.is_empty());
        assert!(!f.explanation.is_empty());
    }

    #[test]
    fn test_get_explanation_nonexistent() {
        assert!(get_explanation("nonexistent_key_xyz").is_none());
    }

    #[test]
    fn test_all_findings_have_nonempty_content() {
        for (key, finding) in get_map() {
            assert!(!finding.title.is_empty(), "Empty title for key {key}");
            assert!(
                !finding.explanation.is_empty(),
                "Empty explanation for key {key}"
            );
        }
    }

    #[test]
    fn test_injection_combo_returns_critical() {
        let apis = &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"];
        let findings = get_explanation_for_api_combo(apis);
        assert!(!findings.is_empty());
        assert!(
            findings
                .iter()
                .any(|f| f.confidence == ConfidenceLevel::Critical)
        );
        assert!(
            findings
                .iter()
                .any(|f| { f.mitre_technique_id.as_deref() == Some("T1055.001") })
        );
    }

    #[test]
    fn test_empty_api_list_returns_empty() {
        let findings = get_explanation_for_api_combo(&[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_get_explanation_count() {
        assert!(
            get_map().len() >= 20,
            "Should have at least 20 explanations"
        );
    }

    #[test]
    fn test_explanations_load() {
        // explanations_data.json must parse without panic and be non-empty.
        let map = get_map();
        assert!(
            !map.is_empty(),
            "explanations_data.json must contain at least one entry"
        );
    }

    #[test]
    fn test_t1055_has_simple_explanation() {
        // At least one explanation must reference T1055 (or T1055.xxx) via
        // its mitre_technique_id field.  This validates that process injection
        // — the most common finding — has analyst-facing context.
        let has_t1055 = get_map().values().any(|f| {
            f.mitre_technique_id
                .as_deref()
                .is_some_and(|id| id.starts_with("T1055"))
        });
        assert!(
            has_t1055,
            "At least one explanation must reference a T1055 technique"
        );
    }

    #[test]
    fn test_no_empty_explanations() {
        // Every entry must have non-empty explanation and why_suspicious fields.
        for (key, finding) in get_map() {
            assert!(
                !finding.explanation.is_empty(),
                "Explanation for key '{key}' must not be empty"
            );
            assert!(
                !finding.why_suspicious.is_empty(),
                "why_suspicious for key '{key}' must not be empty"
            );
        }
    }
}
