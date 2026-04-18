//! SARIF 2.1.0 output for Anya.
//!
//! Produces an OASIS-spec SARIF log that GitHub Code Scanning, Azure DevOps,
//! GitLab Security, and mainstream SIEM/SOAR pipelines ingest directly.
//! Enterprise buyers (healthcare, banking, MSSPs) require SARIF as a CI
//! output format; this module is the integration surface they read.
//!
//! Shape emitted:
//!   * Top-level `$schema` + `version` = 2.1.0
//!   * One run per invocation with tool driver + rules catalogue
//!   * One `Result` per detected signal (and one verdict carrier result so
//!     every scan emits at least one result — CLEAN included)
//!   * `taxonomies[]` holds a MITRE ATT&CK component with one reporting
//!     descriptor per unique technique surfaced in the run
//!   * `properties.tags[]` on each result carries a colon-prefixed
//!     namespace vocabulary (verdict, mitre, family, confidence, signal,
//!     format) for downstream SIEM filtering
//!
//! Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use crate::output::{AnalysisResult, MitreTechnique};
use anya_scoring::types::ConfidenceLevel;
use serde_sarif::sarif::{
    ArtifactLocation, Location, Message, MultiformatMessageString, PhysicalLocation, PropertyBag,
    ReportingDescriptor, Result as SarifResult, ResultLevel, Run, Sarif, Tool, ToolComponent,
};
use std::collections::{BTreeMap, BTreeSet};

/// Canonical SARIF 2.1.0 schema URI (schemastore variant — the one GitHub
/// Code Scanning validates against).
pub const SARIF_SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";
pub const SARIF_VERSION: &str = "2.1.0";

/// Prefix for rule documentation URIs. Points at the in-repo SARIF_RULES
/// markdown document at `engine/docs/SARIF_RULES.md`, with the rule ID as
/// a lowercase anchor (e.g. `#anya-h001`). A dedicated docs domain will
/// land when the product crosses the first-paying-customer milestone
/// (DWL-86); until then, in-repo markdown is the honest source.
const RULE_HELP_BASE: &str =
    "https://github.com/elementmerc/anya/blob/main/docs/SARIF_RULES.md#";

/// Tool driver metadata.
const TOOL_NAME: &str = "Anya";
const TOOL_ORG: &str = "elementmerc";
const TOOL_INFO_URI: &str = "https://github.com/elementmerc/anya";

/// MITRE taxonomy identity.
const MITRE_NAME: &str = "MITRE ATT&CK";
const MITRE_ORG: &str = "MITRE";
const MITRE_URI: &str = "https://attack.mitre.org/";

// ─────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────

/// Build a SARIF 2.1.0 document for the given analysis.
///
/// `verdict_word` is the top-level verdict string produced by
/// `crate::compute_verdict` (after any known-sample override) — CLEAN,
/// SUSPICIOUS, MALICIOUS, TOOL, PUP, TEST, or UNKNOWN.
pub fn render(analysis: &AnalysisResult, verdict_word: &str) -> Sarif {
    let results = build_results(analysis, verdict_word);
    let taxonomies = build_taxonomies(analysis);

    let run = if taxonomies.is_empty() {
        Run::builder()
            .tool(Tool::builder().driver(build_driver()).build())
            .results(results)
            .build()
    } else {
        Run::builder()
            .tool(Tool::builder().driver(build_driver()).build())
            .results(results)
            .taxonomies(taxonomies)
            .build()
    };

    Sarif::builder()
        .schema(SARIF_SCHEMA_URI.to_string())
        .version(serde_json::Value::String(SARIF_VERSION.to_string()))
        .runs(vec![run])
        .build()
}

// ─────────────────────────────────────────────────────────────────────────
// Tool driver + rule catalogue
// ─────────────────────────────────────────────────────────────────────────

fn build_driver() -> ToolComponent {
    ToolComponent::builder()
        .name(TOOL_NAME.to_string())
        .organization(TOOL_ORG.to_string())
        .version(env!("CARGO_PKG_VERSION").to_string())
        .semantic_version(env!("CARGO_PKG_VERSION").to_string())
        .information_uri(TOOL_INFO_URI.to_string())
        .rules(rules_catalogue())
        .build()
}

/// Static 15-rule hybrid catalogue. One entry per signal category plus one
/// verdict carrier (ANYA-V001) so every scan emits at least one result.
/// Rule IDs are stable across releases; adding a rule bumps the catalogue,
/// never renumbers an existing entry.
fn rules_catalogue() -> Vec<ReportingDescriptor> {
    const ENTRIES: &[(&str, &str, &str, &str)] = &[
        (
            "ANYA-V001",
            "Overall verdict",
            "The file received an overall Anya verdict.",
            "Every Anya scan emits this result. Its level reflects the top-level verdict: error for MALICIOUS, warning for SUSPICIOUS, note for CLEAN / TOOL / PUP / TEST / UNKNOWN. The associated properties.tags array carries the verdict and format namespaces.",
        ),
        (
            "ANYA-H001",
            "Packer or protector detected",
            "A known packer or protector signature was matched in the file.",
            "Packers and protectors compress or encrypt the real payload, forcing static analysis tools to reason over a thin loader layer. The presence of a packer is not itself malicious, but it raises the prior probability of malicious intent, especially when combined with high entropy or suspicious imports.",
        ),
        (
            "ANYA-H002",
            "High or suspicious entropy",
            "The file's Shannon entropy is at or above the suspicious threshold.",
            "Shannon entropy above roughly 7.5 indicates compressed, encrypted, or packed content. Benign installers can reach this range, but it is also the default state of packed malware. Anya reports entropy alongside the context that explains it.",
        ),
        (
            "ANYA-H003",
            "Anti-analysis: debugger detection",
            "The file contains indicators consistent with detecting an attached debugger.",
            "Code that probes for the presence of a debugger typically does so to alter behaviour when under analysis, a pattern strongly associated with malicious intent. Legitimate software rarely needs this defence.",
        ),
        (
            "ANYA-H004",
            "Anti-analysis: virtual machine detection",
            "The file contains indicators consistent with detecting a virtualised environment.",
            "VM detection routines read CPU features, registry keys, driver names, and device signatures characteristic of VirtualBox, VMware, QEMU, or Hyper-V. Malware uses them to stay dormant inside sandboxes.",
        ),
        (
            "ANYA-H005",
            "Anti-analysis: timing evasion",
            "The file contains indicators consistent with timing-based evasion of sandboxes.",
            "Sleep loops, time delta checks, and delayed payload execution defeat automated sandboxes that give each sample a fixed budget. The presence of such routines alongside other indicators is a strong malicious signal.",
        ),
        (
            "ANYA-H006",
            "Anti-analysis: sandbox detection",
            "The file contains indicators consistent with detecting a sandbox environment.",
            "Checks for cursor movement, screen resolution, installed applications, recent documents, and uptime are used to distinguish a real user workstation from an analysis sandbox. Often paired with timing evasion.",
        ),
        (
            "ANYA-H007",
            "Suspicious imports: process injection",
            "The file imports functions associated with injecting code into another process.",
            "APIs such as OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, and NtMapViewOfSection are the building blocks of process injection and hollowing techniques. Their presence does not prove injection, but it narrows the intent considerably.",
        ),
        (
            "ANYA-H008",
            "Suspicious imports: cryptographic API",
            "The file imports cryptographic primitives consistent with payload obfuscation or ransomware behaviour.",
            "Symmetric key setup, key derivation, and bulk encryption APIs appear in legitimate software, but also form the backbone of ransomware and payload obfuscation. Anya reports this signal for analyst review, not as a standalone verdict.",
        ),
        (
            "ANYA-H009",
            "Suspicious imports: registry persistence",
            "The file imports registry APIs consistent with persistence through Run keys or services.",
            "APIs that create or modify HKCU / HKLM Run keys, service entries, or scheduled tasks are the standard persistence mechanism for Windows malware. Legitimate installers also use them; context in the calling code matters.",
        ),
        (
            "ANYA-H010",
            "Suspicious imports: networking",
            "The file imports networking APIs consistent with command and control or data exfiltration.",
            "WinInet, WinHTTP, and Winsock APIs power legitimate updaters and malicious command and control channels alike. The suspicious qualifier reflects the clustering of networking calls with other indicators, not networking by itself.",
        ),
        (
            "ANYA-P001",
            "File type mismatch",
            "The detected magic bytes of the file do not match the claimed extension.",
            "A file that presents as a PDF but is a PE, or as an image but is a script, is a common social engineering vehicle. Anya flags the mismatch as a standalone rule so SIEM correlation can weight it explicitly.",
        ),
        (
            "ANYA-P002",
            "IOC artifacts present",
            "Indicators of compromise (URLs, IPs, hashes, or domains) were extracted from the file.",
            "Indicator presence is informational on its own. Paired with other signals it reinforces a verdict; in isolation it mostly provides pivots for SOC hunting.",
        ),
        (
            "ANYA-D001",
            "Known sample database match",
            "The file matched an entry in Anya's curated known-samples database (tool, PUP, or test file).",
            "Known-sample matches override the heuristic verdict so legitimate dual-use tools (reverse engineering utilities, forensic binaries, test files) are not misclassified as malicious. The subtype (tool / PUP / test) is emitted in the tags.",
        ),
        (
            "ANYA-D002",
            "Known similar digest (KSD) match",
            "The file's TLSH fuzzy hash is within the configured threshold of a known malware sample.",
            "TLSH provides locality-sensitive similarity so packed variants of a family retain a similar hash. A KSD match is strong evidence of family relationship; combined with independent signals it produces a high-confidence verdict.",
        ),
    ];

    ENTRIES
        .iter()
        .map(|(id, name, short, full)| {
            ReportingDescriptor::builder()
                .id((*id).to_string())
                .name((*name).to_string())
                .short_description(multiformat(short))
                .full_description(multiformat(full))
                .help_uri(format!("{}{}", RULE_HELP_BASE, id.to_lowercase()))
                .build()
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────
// Results
// ─────────────────────────────────────────────────────────────────────────

fn build_results(analysis: &AnalysisResult, verdict_word: &str) -> Vec<SarifResult> {
    let mut out: Vec<SarifResult> = Vec::new();
    let file_uri = file_uri_for(&analysis.file_info.path);
    let format_tag = format_tag_from(&analysis.file_format);

    // 1. Verdict carrier — always emitted, keeps "at least one result per scan"
    //    invariant true even for CLEAN files.
    let verdict_level = verdict_to_level(verdict_word);
    let verdict_msg = analysis
        .verdict_summary
        .clone()
        .unwrap_or_else(|| verdict_word.to_string());
    let mut verdict_tags = vec![
        format!("verdict:{}", verdict_word.to_lowercase()),
        format_tag.clone(),
    ];
    if let Some(ref ks) = analysis.known_sample {
        verdict_tags.push(format!("signal:known-sample-{}", ks.verdict.to_lowercase()));
        verdict_tags.push(format!("family:{}", slug(&ks.name)));
    }
    if let Some(ref ksd) = analysis.ksd_match {
        if let Some(family) = ksd_family(ksd) {
            verdict_tags.push(format!("family:{}", slug(&family)));
        }
    }
    out.push(result_builder(
        "ANYA-V001",
        &verdict_msg,
        verdict_level,
        &file_uri,
        verdict_tags,
    ));

    // 2. Per-signal results ─────────────────────────────────────────────────

    // ANYA-H001 — packer
    for p in &analysis.packer_detections {
        let level = confidence_to_level(&p.confidence);
        let tags = vec![
            "signal:packer".to_string(),
            format!("signal:packer-{}", slug(&p.name)),
            format!("confidence:{}", confidence_tag(&p.confidence)),
            format_tag.clone(),
        ];
        let msg = format!(
            "Packer detected: {} via {} ({})",
            p.name, p.method, p.evidence
        );
        out.push(result_builder("ANYA-H001", &msg, level, &file_uri, tags));
    }

    // ANYA-H002 — high / suspicious entropy
    if analysis.entropy.is_suspicious {
        let level = analysis
            .entropy
            .confidence
            .as_ref()
            .map(confidence_to_level)
            .unwrap_or(ResultLevel::Warning);
        let conf_tag = analysis
            .entropy
            .confidence
            .as_ref()
            .map(confidence_tag)
            .unwrap_or("high");
        let tags = vec![
            "signal:entropy-high".to_string(),
            format!("confidence:{}", conf_tag),
            format_tag.clone(),
        ];
        let msg = format!(
            "Entropy {:.3}, classified as {} ({})",
            analysis.entropy.value,
            analysis.entropy.category,
            if analysis.entropy.is_suspicious {
                "suspicious"
            } else {
                "normal"
            }
        );
        out.push(result_builder("ANYA-H002", &msg, level, &file_uri, tags));
    }

    // ANYA-H003..006 — anti-analysis (dispatch by technique string)
    for a in &analysis.anti_analysis_indicators {
        let rule_id = match a.technique.as_str() {
            "DebuggerDetection" => "ANYA-H003",
            "VmDetection" => "ANYA-H004",
            "TimingEvasion" => "ANYA-H005",
            "SandboxDetection" => "ANYA-H006",
            _ => continue, // unknown technique — skip rather than mis-map
        };
        let level = confidence_to_level(&a.confidence);
        let mut tags = vec![
            format!("signal:anti-analysis-{}", slug(&a.technique)),
            format!("confidence:{}", confidence_tag(&a.confidence)),
            format_tag.clone(),
        ];
        if !a.mitre_technique_id.is_empty() {
            tags.push(format!("mitre:{}", a.mitre_technique_id));
        }
        let msg = format!("{}: {}", a.technique, a.evidence);
        out.push(result_builder(rule_id, &msg, level, &file_uri, tags));
    }

    // ANYA-H007..010 — suspicious import clusters (from mitre_techniques mapped from imports)
    //   We classify each MitreTechnique into one of four clusters by the top-level
    //   technique ID so the rule-per-cluster mapping stays stable even as new APIs
    //   join the lookup table. This keeps the rule IDs meaningful for SIEM triage.
    let mut emitted_import_rules: BTreeSet<(&'static str, String)> = BTreeSet::new();
    for t in &analysis.mitre_techniques {
        let rule_id = import_cluster_rule(&t.technique_id);
        let rule_id = match rule_id {
            Some(id) => id,
            None => continue,
        };
        let key = (rule_id, t.source_indicator.clone());
        if !emitted_import_rules.insert(key) {
            continue;
        }
        let level = confidence_to_level(&t.confidence);
        let tags = vec![
            format!("signal:import-{}", slug(&t.technique_name)),
            format!("mitre:{}", mitre_full_id(t)),
            format!("confidence:{}", confidence_tag(&t.confidence)),
            format_tag.clone(),
        ];
        let msg = format!(
            "{} via {} ({})",
            t.technique_name, t.source_indicator, t.tactic
        );
        out.push(result_builder(rule_id, &msg, level, &file_uri, tags));
    }

    // ANYA-P001 — file type mismatch
    if let Some(ref m) = analysis.file_type_mismatch {
        let level = match m.severity {
            crate::output::MismatchSeverity::High => ResultLevel::Warning,
            crate::output::MismatchSeverity::Medium => ResultLevel::Warning,
            crate::output::MismatchSeverity::Low => ResultLevel::Note,
        };
        let sev_tag = match m.severity {
            crate::output::MismatchSeverity::High => "high",
            crate::output::MismatchSeverity::Medium => "medium",
            crate::output::MismatchSeverity::Low => "low",
        };
        let tags = vec![
            "signal:file-type-mismatch".to_string(),
            format!("confidence:{}", sev_tag),
            format_tag.clone(),
        ];
        let msg = format!(
            "Detected type \"{}\" does not match extension \".{}\"",
            m.detected_type, m.claimed_extension
        );
        out.push(result_builder("ANYA-P001", &msg, level, &file_uri, tags));
    }

    // ANYA-P002 — IOC summary
    if let Some(ref ioc) = analysis.ioc_summary {
        let total: usize = ioc.ioc_counts.values().sum();
        if total > 0 {
            let breakdown: Vec<String> = {
                let mut pairs: Vec<(&String, &usize)> = ioc.ioc_counts.iter().collect();
                pairs.sort_by(|a, b| a.0.cmp(b.0));
                pairs
                    .into_iter()
                    .map(|(k, v)| format!("{} {}", v, k))
                    .collect()
            };
            let tags = vec![
                "signal:ioc-artifacts".to_string(),
                format!("confidence:{}", if total >= 10 { "medium" } else { "low" }),
                format_tag.clone(),
            ];
            let msg = format!("IOC artifacts: {}", breakdown.join(", "));
            out.push(result_builder(
                "ANYA-P002",
                &msg,
                ResultLevel::Note,
                &file_uri,
                tags,
            ));
        }
    }

    // ANYA-D001 — known sample
    if let Some(ref ks) = analysis.known_sample {
        let tags = vec![
            format!("signal:known-sample-{}", ks.verdict.to_lowercase()),
            format!("family:{}", slug(&ks.name)),
            "confidence:critical".to_string(),
            format_tag.clone(),
        ];
        let msg = format!("{} ({}): {}", ks.verdict, ks.name, ks.description);
        out.push(result_builder(
            "ANYA-D001",
            &msg,
            ResultLevel::Note,
            &file_uri,
            tags,
        ));
    }

    // ANYA-D002 — KSD match
    if let Some(ref ksd) = analysis.ksd_match {
        let family = ksd_family(ksd).unwrap_or_else(|| "unknown".to_string());
        let distance = ksd_distance(ksd);
        let tags = vec![
            "signal:ksd-match".to_string(),
            format!("family:{}", slug(&family)),
            "confidence:high".to_string(),
            format_tag.clone(),
        ];
        let msg = format!(
            "Known similar digest match, family: {} (TLSH distance: {})",
            family, distance
        );
        out.push(result_builder(
            "ANYA-D002",
            &msg,
            ResultLevel::Warning,
            &file_uri,
            tags,
        ));
    }

    out
}

// ─────────────────────────────────────────────────────────────────────────
// Taxonomies
// ─────────────────────────────────────────────────────────────────────────

fn build_taxonomies(analysis: &AnalysisResult) -> Vec<ToolComponent> {
    let mut by_id: BTreeMap<String, &MitreTechnique> = BTreeMap::new();
    for t in &analysis.mitre_techniques {
        by_id.insert(mitre_full_id(t), t);
    }
    if by_id.is_empty() {
        return Vec::new();
    }

    let taxa: Vec<ReportingDescriptor> = by_id
        .values()
        .map(|t| {
            let full_id = mitre_full_id(t);
            let help = format!(
                "https://attack.mitre.org/techniques/{}/",
                full_id.replace('.', "/")
            );
            let short = format!("{} ({})", t.technique_name, t.tactic);
            ReportingDescriptor::builder()
                .id(full_id.clone())
                .name(t.technique_name.clone())
                .short_description(multiformat(&short))
                .help_uri(help)
                .build()
        })
        .collect();

    vec![ToolComponent::builder()
        .name(MITRE_NAME.to_string())
        .organization(MITRE_ORG.to_string())
        .information_uri(MITRE_URI.to_string())
        .is_comprehensive(false)
        .taxa(taxa)
        .build()]
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

fn result_builder(
    rule_id: &str,
    message_text: &str,
    level: ResultLevel,
    file_uri: &str,
    tags: Vec<String>,
) -> SarifResult {
    let loc = Location::builder()
        .physical_location(
            PhysicalLocation::builder()
                .artifact_location(
                    ArtifactLocation::builder()
                        .uri(file_uri.to_string())
                        .build(),
                )
                .build(),
        )
        .build();

    SarifResult::builder()
        .rule_id(rule_id.to_string())
        .message(Message::builder().text(message_text.to_string()).build())
        .level(
            serde_json::to_value(level)
                .unwrap_or_else(|_| serde_json::Value::String("note".to_string())),
        )
        .locations(vec![loc])
        .properties(tags_property_bag(tags))
        .build()
}

fn tags_property_bag(tags: Vec<String>) -> PropertyBag {
    let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    map.insert(
        "tags".to_string(),
        serde_json::Value::Array(tags.into_iter().map(serde_json::Value::String).collect()),
    );
    PropertyBag::builder().additional_properties(map).build()
}

fn multiformat(text: &str) -> MultiformatMessageString {
    MultiformatMessageString::builder()
        .text(text.to_string())
        .build()
}

fn verdict_to_level(verdict: &str) -> ResultLevel {
    match verdict {
        "MALICIOUS" => ResultLevel::Error,
        "SUSPICIOUS" => ResultLevel::Warning,
        _ => ResultLevel::Note, // CLEAN, TOOL, PUP, TEST, UNKNOWN
    }
}

fn confidence_to_level(c: &ConfidenceLevel) -> ResultLevel {
    match c {
        ConfidenceLevel::Critical => ResultLevel::Error,
        ConfidenceLevel::High => ResultLevel::Warning,
        ConfidenceLevel::Medium => ResultLevel::Warning,
        ConfidenceLevel::Low => ResultLevel::Note,
    }
}

fn confidence_tag(c: &ConfidenceLevel) -> &'static str {
    match c {
        ConfidenceLevel::Critical => "critical",
        ConfidenceLevel::High => "high",
        ConfidenceLevel::Medium => "medium",
        ConfidenceLevel::Low => "low",
    }
}

/// Return the canonical cluster rule for an import-derived MITRE technique.
/// None for techniques that do not belong to one of the four import clusters
/// this catalogue surfaces (e.g. anti-analysis techniques carried on the
/// MitreTechnique array via sources other than imports are handled by the
/// H003..H006 rules via anti_analysis_indicators).
fn import_cluster_rule(technique_id: &str) -> Option<&'static str> {
    // Coarse mapping per MITRE tactic: process injection, crypto/obfuscation,
    // persistence, networking / C2. Identifies the rule independent of
    // sub-technique to keep the catalogue shallow.
    match technique_id {
        // Process injection family
        "T1055" | "T1106" | "T1057" | "T1134" => Some("ANYA-H007"),
        // Crypto / obfuscation
        "T1027" | "T1140" | "T1486" => Some("ANYA-H008"),
        // Registry persistence / services
        "T1547" | "T1112" | "T1543" | "T1053" => Some("ANYA-H009"),
        // Networking / command and control
        "T1071" | "T1095" | "T1105" | "T1571" | "T1041" => Some("ANYA-H010"),
        _ => None,
    }
}

fn mitre_full_id(t: &MitreTechnique) -> String {
    match &t.sub_technique_id {
        Some(sub) => format!("{}.{}", t.technique_id, sub),
        None => t.technique_id.clone(),
    }
}

/// Normalise a string for use in a `family:` or `signal:` tag.
/// Lowercase, keep alphanumerics and hyphens; collapse runs of other
/// characters into a single hyphen; trim leading/trailing hyphens.
fn slug(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_hyphen = true;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_hyphen = false;
        } else if !prev_hyphen {
            out.push('-');
            prev_hyphen = true;
        }
    }
    out.trim_matches('-').to_string()
}

fn format_tag_from(format: &str) -> String {
    let f = format.to_lowercase();
    let canonical = match f.as_str() {
        s if s.starts_with("pe") || s == "portable executable" => "pe",
        s if s.starts_with("elf") => "elf",
        s if s.starts_with("mach") => "macho",
        s if s.starts_with("pdf") => "pdf",
        s if s.starts_with("office") => "office",
        s if s.contains("script") || s == "javascript" || s == "powershell" || s == "vbscript" => {
            "script"
        }
        _ => "other",
    };
    format!("format:{}", canonical)
}

fn file_uri_for(path: &str) -> String {
    // SARIF `artifactLocation.uri` expects a valid URI. Passing the raw path
    // is acceptable when it is a simple filename or a well-formed URI; when
    // it is an absolute filesystem path we leave it to the consumer to
    // interpret. No percent-encoding here: SARIF allows both.
    if path.is_empty() {
        return "unknown".to_string();
    }
    path.to_string()
}

// ─── KsdMatch + IocSummary accessors (decoupled so schema tweaks don't leak) ─

fn ksd_family(ksd: &anya_scoring::ksd::KsdMatch) -> Option<String> {
    Some(ksd.family.clone()).filter(|s| !s.is_empty())
}

fn ksd_distance(ksd: &anya_scoring::ksd::KsdMatch) -> u32 {
    ksd.distance
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::AnalysisResult;

    fn minimal_analysis() -> AnalysisResult {
        AnalysisResult::default()
    }

    #[test]
    fn clean_scan_emits_exactly_one_verdict_result() {
        let a = minimal_analysis();
        let s = render(&a, "CLEAN");
        let runs = &s.runs;
        assert_eq!(runs.len(), 1);
        let results = runs[0].results.as_ref().expect("results");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id.as_deref(), Some("ANYA-V001"));
        // level must be note for CLEAN
        let level = results[0].level.as_ref().unwrap();
        assert_eq!(level, &serde_json::Value::String("note".to_string()));
    }

    #[test]
    fn malicious_verdict_gets_error_level() {
        let a = minimal_analysis();
        let s = render(&a, "MALICIOUS");
        let results = s.runs[0].results.as_ref().unwrap();
        assert_eq!(
            results[0].level.as_ref().unwrap(),
            &serde_json::Value::String("error".to_string())
        );
    }

    #[test]
    fn top_level_shape_is_sarif_210() {
        let a = minimal_analysis();
        let s = render(&a, "CLEAN");
        assert_eq!(s.schema.as_deref(), Some(SARIF_SCHEMA_URI));
        assert_eq!(s.version, serde_json::Value::String("2.1.0".to_string()));
        assert_eq!(s.runs[0].tool.driver.name, "Anya");
    }

    #[test]
    fn rules_catalogue_has_expected_entries() {
        let rules = rules_catalogue();
        assert_eq!(rules.len(), 15);
        let ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"ANYA-V001"));
        assert!(ids.contains(&"ANYA-H001"));
        assert!(ids.contains(&"ANYA-H010"));
        assert!(ids.contains(&"ANYA-P001"));
        assert!(ids.contains(&"ANYA-D002"));
    }

    #[test]
    fn full_round_trip_through_serde() {
        let a = minimal_analysis();
        let s = render(&a, "CLEAN");
        let j = serde_json::to_string(&s).expect("serialises");
        let parsed: Sarif = serde_json::from_str(&j).expect("deserialises");
        assert_eq!(parsed.version, s.version);
        assert_eq!(parsed.schema, s.schema);
    }

    #[test]
    fn slug_normalises_tag_values() {
        assert_eq!(slug("Agent Tesla"), "agent-tesla");
        assert_eq!(slug("UPX 3.96"), "upx-3-96");
        assert_eq!(slug("  --weird--name  "), "weird-name");
        assert_eq!(slug("T1055.001"), "t1055-001");
    }

    #[test]
    fn verdict_tag_always_present_and_lowercase() {
        let a = minimal_analysis();
        let s = render(&a, "SUSPICIOUS");
        let props = s.runs[0].results.as_ref().unwrap()[0]
            .properties
            .as_ref()
            .unwrap();
        let tags = props.additional_properties.get("tags").unwrap();
        let tags_str = serde_json::to_string(tags).unwrap();
        assert!(
            tags_str.contains("verdict:suspicious"),
            "tags: {}",
            tags_str
        );
        assert!(tags_str.contains("format:"), "tags: {}", tags_str);
    }

    #[test]
    fn taxonomies_empty_when_no_mitre_techniques() {
        let a = minimal_analysis();
        let s = render(&a, "CLEAN");
        assert!(s.runs[0]
            .taxonomies
            .as_ref()
            .map(|t| t.is_empty())
            .unwrap_or(true));
    }

    #[test]
    fn format_tag_canonicalises() {
        assert_eq!(format_tag_from("PE/MZ executable"), "format:pe");
        assert_eq!(format_tag_from("ELF 64-bit"), "format:elf");
        assert_eq!(format_tag_from("Mach-O"), "format:macho");
        assert_eq!(format_tag_from("PDF document"), "format:pdf");
        assert_eq!(format_tag_from("JavaScript"), "format:script");
        assert_eq!(format_tag_from("Totally unknown"), "format:other");
    }
}
