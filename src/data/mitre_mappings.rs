// Ányá - MITRE ATT&CK mapping table
// Static lookup: API name (lowercase) → Vec<MitreTechnique>
// No network access — data is embedded at compile time.

use crate::output::{ConfidenceLevel, MitreTechnique};
use std::collections::HashMap;
use std::sync::OnceLock;

static MAPPING_JSON: &str = include_str!("mitre_data.json");

#[derive(serde::Deserialize)]
struct RawEntry {
    technique_id: String,
    sub_technique_id: Option<String>,
    technique_name: String,
    tactic: String,
    confidence: String,
}

fn build_map() -> HashMap<String, Vec<MitreTechnique>> {
    let raw: HashMap<String, Vec<RawEntry>> =
        serde_json::from_str(MAPPING_JSON).expect("mitre_data.json is malformed");

    raw.into_iter()
        .map(|(api, entries)| {
            let techniques = entries
                .into_iter()
                .map(|e| MitreTechnique {
                    technique_id: e.technique_id.clone(),
                    sub_technique_id: e.sub_technique_id.clone(),
                    technique_name: e.technique_name.clone(),
                    tactic: e.tactic.clone(),
                    source_indicator: api.clone(),
                    confidence: match e.confidence.as_str() {
                        "Critical" => ConfidenceLevel::Critical,
                        "High" => ConfidenceLevel::High,
                        "Medium" => ConfidenceLevel::Medium,
                        _ => ConfidenceLevel::Low,
                    },
                })
                .collect();
            (api, techniques)
        })
        .collect()
}

static MAP: OnceLock<HashMap<String, Vec<MitreTechnique>>> = OnceLock::new();

fn get_map() -> &'static HashMap<String, Vec<MitreTechnique>> {
    MAP.get_or_init(build_map)
}

/// Return MITRE techniques associated with `api_name` (case-insensitive).
/// Returns an empty Vec for unknown APIs — never panics.
pub fn get_mitre_techniques(api_name: &str) -> Vec<MitreTechnique> {
    let key = api_name.to_lowercase();
    get_map()
        .get(&key)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|mut t| {
            t.source_indicator = api_name.to_string();
            t
        })
        .collect()
}

/// Map all APIs in `imports` to MITRE techniques, deduplicating by technique_id.
pub fn map_techniques_from_imports(imports: &[&str]) -> Vec<MitreTechnique> {
    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();
    for api in imports {
        for t in get_mitre_techniques(api) {
            let key = format!(
                "{}{}",
                t.technique_id,
                t.sub_technique_id.as_deref().unwrap_or("")
            );
            if seen.insert(key) {
                results.push(t);
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_allocex_maps_to_t1055() {
        let techs = get_mitre_techniques("VirtualAllocEx");
        assert!(!techs.is_empty());
        assert!(techs.iter().any(|t| t.technique_id == "T1055"));
    }

    #[test]
    fn test_case_insensitive() {
        let lower = get_mitre_techniques("virtuallocex");
        let upper = get_mitre_techniques("VIRTUALALLOCEX");
        // Both should return same count (VirtualAllocEx vs virtuallocex differ)
        let canonical = get_mitre_techniques("VirtualAllocEx");
        assert_eq!(canonical.len(), upper.len());
        let _ = lower; // different spelling, may be empty
    }

    #[test]
    fn test_unknown_api_returns_empty() {
        let techs = get_mitre_techniques("unknown_api_xyz");
        assert!(techs.is_empty());
    }

    #[test]
    fn test_unknown_api_never_panics() {
        let _ = get_mitre_techniques("");
        let _ = get_mitre_techniques("aaaaaaaaaaaaaaaaaaaaaaaa");
    }

    #[test]
    fn test_isdebuggerpresent_maps_t1622() {
        let techs = get_mitre_techniques("IsDebuggerPresent");
        assert!(techs.iter().any(|t| t.technique_id == "T1622"));
    }

    #[test]
    fn test_setwindowshookex_maps_two_techniques() {
        let techs = get_mitre_techniques("SetWindowsHookEx");
        assert!(techs.len() >= 2);
        assert!(techs.iter().any(|t| t.technique_id == "T1055"));
        assert!(techs.iter().any(|t| t.technique_id == "T1056"));
    }

    #[test]
    fn test_map_techniques_from_imports_deduplicates() {
        let apis = &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"];
        let techs = map_techniques_from_imports(apis);
        // Should have T1055 / T1055.001 at most once
        let t1055_001_count = techs
            .iter()
            .filter(|t| {
                t.technique_id == "T1055"
                    && t.sub_technique_id.as_deref() == Some("001")
            })
            .count();
        assert_eq!(t1055_001_count, 1);
    }
}
