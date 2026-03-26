// Ányá — Confidence scoring and risk score calculation
//
// Produces a 0–100 risk score from analysis findings, and maps individual
// indicators to ConfidenceLevel values.
//
// Weight constants and pure confidence-assignment functions are defined in
// the anya-scoring crate; this module re-exports them and provides the
// higher-level functions that depend on core output types (PEAnalysis, etc.).

use crate::output::{
    AnalysisResult, AntiAnalysisFinding, ConfidenceLevel, ELFAnalysis, FileTypeMismatch,
    MachoAnalysis, MitreTechnique, OfficeAnalysis, OrdinalImport, OverlayInfo, PEAnalysis,
    PackerFinding, PdfAnalysis, SectionInfo,
};
use anya_scoring::types::{IocSummary, MismatchSeverity};
use std::collections::HashMap;

// Re-export scoring constants from anya-scoring so existing downstream code still compiles.
pub use anya_scoring::confidence::{
    BONUS_ANTI_ANALYSIS_PER_CATEGORY, BONUS_ELF_NO_NX, BONUS_ELF_NO_PIE, BONUS_ELF_NO_RELRO,
    BONUS_ELF_PACKER, BONUS_ELF_WX_SECTION, BONUS_HIGH_ENTROPY_OVERLAY, BONUS_ORDINAL_KERNEL32,
    BONUS_ORDINAL_NTDLL, BONUS_PACKER_HIGH, BONUS_PACKER_MEDIUM, BONUS_SUSPICIOUS_API_COUNT,
    BONUS_TLS_CALLBACKS, BONUS_WX_SECTION, RankedDetection, WEIGHT_CRITICAL, WEIGHT_HIGH,
    WEIGHT_LOW, WEIGHT_MEDIUM,
};
pub use anya_scoring::confidence::{
    assign_entropy_confidence, assign_ioc_confidence, assign_mismatch_confidence,
    assign_overlay_confidence as assign_overlay_confidence_raw, confidence_from_str,
};

/// Compute a 0–100 risk score from all analysis findings.
///
/// Every detection type contributes: PE, ELF, Mach-O, PDF, Office, IOCs, and
/// file type mismatches. The total is capped at 100.
pub fn calculate_risk_score(
    pe: Option<&PEAnalysis>,
    elf: Option<&ELFAnalysis>,
    mach: Option<&MachoAnalysis>,
    pdf: Option<&PdfAnalysis>,
    office: Option<&OfficeAnalysis>,
    ioc: Option<&IocSummary>,
    mismatch: Option<&FileTypeMismatch>,
) -> u32 {
    let mut score: u32 = 0;

    // ── PE ────────────────────────────────────────────────────────────────────
    if let Some(pe) = pe {
        let api_count = pe.imports.suspicious_api_count;
        let tiers = (api_count / 5) as u32;
        score += BONUS_SUSPICIOUS_API_COUNT * tiers.min(4);

        if pe.sections.iter().any(|s| s.is_wx) {
            score += BONUS_WX_SECTION;
        }

        let best_packer = pe.packers.iter().max_by_key(|p| packer_confidence_ord(p));
        if let Some(pk) = best_packer {
            score += match pk.confidence.as_str() {
                "Critical" | "High" => BONUS_PACKER_HIGH,
                _ => BONUS_PACKER_MEDIUM,
            };
        }

        if let Some(tls) = &pe.tls
            && tls.callback_count > 0
        {
            score += BONUS_TLS_CALLBACKS;
        }

        if pe.overlay.as_ref().is_some_and(|o| o.high_entropy) {
            score += BONUS_HIGH_ENTROPY_OVERLAY;
        }

        score += ordinal_import_bonus(&pe.ordinal_imports);

        let unique_categories = unique_anti_analysis_categories(&pe.anti_analysis);
        score += BONUS_ANTI_ANALYSIS_PER_CATEGORY * (unique_categories as u32).min(4);

        if let Some(cs) = &pe.checksum
            && cs.stored_nonzero
            && !cs.valid
        {
            score += WEIGHT_MEDIUM;
        }
    }

    // ── ELF ──────────────────────────────────────────────────────────────────
    if let Some(elf) = elf {
        if !elf.is_pie {
            score += BONUS_ELF_NO_PIE;
        }
        if !elf.has_nx_stack {
            score += BONUS_ELF_NO_NX;
        }
        if !elf.has_relro {
            score += BONUS_ELF_NO_RELRO;
        }
        if elf.sections.iter().any(|s| s.is_wx) {
            score += BONUS_ELF_WX_SECTION;
        }
        if !elf.packer_indicators.is_empty() {
            score += BONUS_ELF_PACKER;
        }
        let sus_count = elf.imports.suspicious_functions.len() as u32;
        score += WEIGHT_HIGH * sus_count.min(3);

        // New ELF fields
        if !elf.rpath_anomalies.is_empty() {
            score += WEIGHT_MEDIUM; // +8
        }
        if !elf.got_plt_suspicious.is_empty() {
            score += 10;
        }
        if elf.interpreter_suspicious {
            score += 10;
        }
    }

    // ── Mach-O ───────────────────────────────────────────────────────────────
    if let Some(mach) = mach {
        if !mach.has_code_signature {
            score += 15;
        }
        if !mach.pie_enabled {
            score += BONUS_ELF_NO_PIE; // 5 — same weight as ELF
        }
        if !mach.nx_enabled {
            score += BONUS_ELF_NO_NX; // 8
        }
    }

    // ── PDF ──────────────────────────────────────────────────────────────────
    if let Some(pdf) = pdf {
        for obj in &pdf.dangerous_objects {
            let lower = obj.to_lowercase();
            if lower.contains("launch") {
                score += 25; // Critical — can execute commands
            } else if lower.contains("javascript") {
                score += 15; // High — code execution
            } else if lower.contains("embedded") {
                score += 10;
            } else {
                score += 8; // OpenAction, AA, etc.
            }
        }
    }

    // ── Office ───────────────────────────────────────────────────────────────
    if let Some(office) = office {
        if office.has_macros {
            score += 20;
        }
        if office.has_embedded_objects {
            score += 10;
        }
        if office.has_external_links {
            score += 8;
        }
    }

    // ── IOC indicators ───────────────────────────────────────────────────────
    if let Some(ioc) = ioc {
        // .onion domains are critical
        let onion_count = ioc
            .ioc_strings
            .iter()
            .filter(|s| s.value.ends_with(".onion"))
            .count();
        if onion_count > 0 {
            score += 20;
        }

        // Script obfuscation patterns
        let script_count = ioc
            .ioc_counts
            .get("script_obfuscation")
            .copied()
            .unwrap_or(0);
        if script_count >= 2 {
            score += 15;
        } else if script_count == 1 {
            score += 8;
        }

        // Network IOCs (URLs, domains, IPs)
        let net_count = ioc.ioc_counts.get("url").copied().unwrap_or(0)
            + ioc.ioc_counts.get("domain").copied().unwrap_or(0)
            + ioc.ioc_counts.get("ipv4").copied().unwrap_or(0);
        if net_count >= 3 {
            score += 10;
        }
    }

    // ── File type mismatch ───────────────────────────────────────────────────
    if let Some(mm) = mismatch {
        score += match mm.severity {
            MismatchSeverity::High => 20,
            MismatchSeverity::Medium => 10,
            MismatchSeverity::Low => 5,
        };
    }

    score.min(100)
}

/// Assign a `ConfidenceLevel` to a set of MITRE techniques and return a map
/// of technique_id → confidence.  Where an API appears in multiple techniques,
/// the highest confidence wins.
pub fn calculate_confidence(techniques: &[MitreTechnique]) -> HashMap<String, ConfidenceLevel> {
    let tuples: Vec<(String, Option<String>, ConfidenceLevel)> = techniques
        .iter()
        .map(|t| {
            (
                t.technique_id.clone(),
                t.sub_technique_id.clone(),
                t.confidence.clone(),
            )
        })
        .collect();
    anya_scoring::confidence::calculate_confidence(&tuples)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn packer_confidence_ord(p: &PackerFinding) -> u8 {
    match p.confidence.as_str() {
        "Critical" => 3,
        "High" => 2,
        "Medium" => 1,
        _ => 0,
    }
}

fn ordinal_import_bonus(ordinals: &[OrdinalImport]) -> u32 {
    let mut bonus = 0u32;
    for o in ordinals {
        let dll = o.dll.to_lowercase();
        if dll.contains("ntdll") {
            bonus += BONUS_ORDINAL_NTDLL;
        } else if dll.contains("kernel32") {
            bonus += BONUS_ORDINAL_KERNEL32;
        }
    }
    bonus.min(20) // cap ordinal contribution
}

fn unique_anti_analysis_categories(aa: &[AntiAnalysisFinding]) -> usize {
    let mut cats: Vec<&str> = aa.iter().map(|a| a.category.as_str()).collect();
    cats.sort_unstable();
    cats.dedup();
    cats.len()
}

// ── Confidence assignment functions ──────────────────────────────────────────

/// Assign confidence to a suspicious API based on combination rules.
pub fn assign_api_confidence(
    api_name: &str,
    all_api_names: &[&str],
    api_category: &str,
) -> ConfidenceLevel {
    anya_scoring::confidence::assign_api_confidence(
        api_name,
        all_api_names,
        api_category,
        anya_scoring::api_lists::categorize_api,
    )
}

/// Assign confidence to a PE section.
pub fn assign_section_confidence(section: &SectionInfo) -> ConfidenceLevel {
    anya_scoring::confidence::assign_section_confidence(
        section.is_wx,
        section.entropy,
        section.name_anomaly.as_deref(),
    )
}

/// Assign confidence to overlay detection.
pub fn assign_overlay_confidence(overlay: &OverlayInfo, has_authenticode: bool) -> ConfidenceLevel {
    assign_overlay_confidence_raw(overlay.high_entropy, has_authenticode)
}

// ── Top detections helper ───────────────────────────────────────────────────

/// Collect all findings from an AnalysisResult, sort by confidence descending, return top N.
pub fn top_detections(result: &AnalysisResult, n: usize) -> Vec<RankedDetection> {
    let mut all: Vec<RankedDetection> = Vec::new();

    // Packer detections
    for p in &result.packer_detections {
        all.push(RankedDetection {
            description: format!("Packer: {}", p.name),
            confidence: p.confidence.clone(),
        });
    }

    // Anti-analysis indicators
    for a in &result.anti_analysis_indicators {
        all.push(RankedDetection {
            description: format!("Anti-analysis: {} ({})", a.technique, a.evidence),
            confidence: a.confidence.clone(),
        });
    }

    // File type mismatch
    if let Some(ref m) = result.file_type_mismatch {
        all.push(RankedDetection {
            description: format!(
                "File type mismatch: detected {} but extension is {}",
                m.detected_type, m.claimed_extension
            ),
            confidence: assign_mismatch_confidence(&m.severity),
        });
    }

    // TLS callbacks
    if !result.tls_callbacks.is_empty() {
        let count = result.tls_callbacks.len();
        all.push(RankedDetection {
            description: format!("{} TLS callback(s)", count),
            confidence: if count > 2 {
                ConfidenceLevel::Medium
            } else {
                ConfidenceLevel::Low
            },
        });
    }

    // Overlay
    if let Some(ref o) = result.overlay {
        let has_auth = result
            .pe_analysis
            .as_ref()
            .and_then(|pe| pe.authenticode.as_ref())
            .is_some_and(|a| a.present);
        all.push(RankedDetection {
            description: format!("Overlay: {} bytes at offset 0x{:X}", o.size, o.offset),
            confidence: assign_overlay_confidence(o, has_auth),
        });
    }

    // Entropy
    if result.entropy.is_suspicious {
        all.push(RankedDetection {
            description: format!("High file entropy: {:.2}", result.entropy.value),
            confidence: assign_entropy_confidence(result.entropy.value),
        });
    }

    // IOC high-confidence items
    if let Some(ref ioc) = result.ioc_summary {
        for es in &ioc.ioc_strings {
            if let Some(ref ioc_type) = es.ioc_type {
                let conf = assign_ioc_confidence(ioc_type, &es.value);
                if conf >= ConfidenceLevel::High {
                    all.push(RankedDetection {
                        description: format!(
                            "IOC ({}): {}",
                            ioc_type,
                            &es.value[..es.value.len().min(60)]
                        ),
                        confidence: conf,
                    });
                }
            }
        }
    }

    // PDF dangerous objects
    if let Some(ref pdf) = result.pdf_analysis {
        for obj in &pdf.dangerous_objects {
            let conf = if obj.to_lowercase().contains("launch") {
                ConfidenceLevel::Critical
            } else if obj.to_lowercase().contains("javascript") {
                ConfidenceLevel::High
            } else {
                ConfidenceLevel::Medium
            };
            all.push(RankedDetection {
                description: format!("PDF: {}", obj),
                confidence: conf,
            });
        }
    }

    // Office macro/embedded objects
    if let Some(ref office) = result.office_analysis {
        if office.has_macros {
            all.push(RankedDetection {
                description: "Office document contains VBA macros".to_string(),
                confidence: ConfidenceLevel::High,
            });
        }
        if office.has_embedded_objects {
            all.push(RankedDetection {
                description: "Office document has embedded objects".to_string(),
                confidence: ConfidenceLevel::Medium,
            });
        }
        if office.has_external_links {
            all.push(RankedDetection {
                description: "Office document references external URLs".to_string(),
                confidence: ConfidenceLevel::Medium,
            });
        }
    }

    // Mach-O security features
    if let Some(ref mach) = result.mach_analysis {
        if !mach.has_code_signature {
            all.push(RankedDetection {
                description: "Mach-O binary has no code signature".to_string(),
                confidence: ConfidenceLevel::Medium,
            });
        }
        if !mach.pie_enabled {
            all.push(RankedDetection {
                description: "Mach-O binary is not position-independent (no PIE)".to_string(),
                confidence: ConfidenceLevel::Low,
            });
        }
    }

    // Sort descending by confidence
    all.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    all.truncate(n);
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::*;

    fn empty_pe() -> PEAnalysis {
        PEAnalysis {
            architecture: "x64".to_string(),
            is_64bit: true,
            image_base: "0x140000000".to_string(),
            entry_point: "0x1000".to_string(),
            file_type: "EXE".to_string(),
            security: SecurityFeatures {
                aslr_enabled: true,
                dep_enabled: true,
            },
            sections: vec![],
            imports: ImportAnalysis {
                dll_count: 0,
                total_imports: 0,
                suspicious_api_count: 0,
                suspicious_apis: vec![],
                libraries: vec![],
                imports_per_kb: None,
                import_ratio_suspicious: None,
            },
            exports: None,
            imphash: None,
            checksum: None,
            rich_header: None,
            tls: None,
            overlay: None,
            compiler: None,
            packers: vec![],
            anti_analysis: vec![],
            ordinal_imports: vec![],
            authenticode: None,
            version_info: None,
            debug_artifacts: None,
            weak_crypto: vec![],
            compiler_deps: vec![],
        }
    }

    #[test]
    fn test_clean_pe_scores_zero() {
        let pe = empty_pe();
        assert_eq!(
            calculate_risk_score(Some(&pe), None, None, None, None, None, None),
            0
        );
    }

    #[test]
    fn test_wx_section_adds_points() {
        let mut pe = empty_pe();
        pe.sections.push(SectionInfo {
            name: ".evil".to_string(),
            virtual_address: "0x1000".to_string(),
            virtual_size: 0x1000,
            raw_size: 0x200,
            entropy: 7.9,
            is_suspicious: true,
            is_wx: true,
            name_anomaly: None,
            confidence: None,
        });
        let score = calculate_risk_score(Some(&pe), None, None, None, None, None, None);
        assert!(score >= BONUS_WX_SECTION);
    }

    #[test]
    fn test_high_packer_adds_twenty() {
        let mut pe = empty_pe();
        pe.packers.push(PackerFinding {
            name: "UPX".to_string(),
            confidence: "High".to_string(),
            detection_method: "String".to_string(),
        });
        let score = calculate_risk_score(Some(&pe), None, None, None, None, None, None);
        assert!(score >= BONUS_PACKER_HIGH);
    }

    #[test]
    fn test_medium_packer_adds_ten() {
        let mut pe = empty_pe();
        pe.packers.push(PackerFinding {
            name: "unknown packer".to_string(),
            confidence: "Medium".to_string(),
            detection_method: "Entropy".to_string(),
        });
        let score = calculate_risk_score(Some(&pe), None, None, None, None, None, None);
        assert!(score >= BONUS_PACKER_MEDIUM);
        assert!(score < BONUS_PACKER_HIGH); // medium should not add 20
    }

    #[test]
    fn test_tls_callbacks_adds_points() {
        let mut pe = empty_pe();
        pe.tls = Some(TlsInfo {
            callback_count: 2,
            callback_rvas: vec!["0x1234".to_string(), "0x5678".to_string()],
        });
        let score = calculate_risk_score(Some(&pe), None, None, None, None, None, None);
        assert!(score >= BONUS_TLS_CALLBACKS);
    }

    #[test]
    fn test_high_entropy_overlay_adds_points() {
        let mut pe = empty_pe();
        pe.overlay = Some(OverlayInfo {
            offset: 1000,
            size: 500,
            entropy: 7.9,
            high_entropy: true,
            overlay_mime_type: None,
            overlay_characterisation: None,
            confidence: None,
        });
        let score = calculate_risk_score(Some(&pe), None, None, None, None, None, None);
        assert!(score >= BONUS_HIGH_ENTROPY_OVERLAY);
    }

    #[test]
    fn test_low_entropy_overlay_adds_nothing() {
        let mut pe = empty_pe();
        pe.overlay = Some(OverlayInfo {
            offset: 1000,
            size: 500,
            entropy: 3.0,
            high_entropy: false,
            overlay_mime_type: None,
            overlay_characterisation: None,
            confidence: None,
        });
        assert_eq!(
            calculate_risk_score(Some(&pe), None, None, None, None, None, None),
            0
        );
    }

    #[test]
    fn test_ntdll_ordinal_adds_points() {
        let mut pe = empty_pe();
        pe.ordinal_imports.push(OrdinalImport {
            dll: "ntdll.dll".to_string(),
            ordinal: 12,
        });
        let score = calculate_risk_score(Some(&pe), None, None, None, None, None, None);
        assert!(score >= BONUS_ORDINAL_NTDLL);
    }

    #[test]
    fn test_user32_ordinal_adds_nothing() {
        let mut pe = empty_pe();
        pe.ordinal_imports.push(OrdinalImport {
            dll: "user32.dll".to_string(),
            ordinal: 5,
        });
        assert_eq!(
            calculate_risk_score(Some(&pe), None, None, None, None, None, None),
            0
        );
    }

    #[test]
    fn test_anti_analysis_two_categories() {
        let mut pe = empty_pe();
        pe.anti_analysis.push(AntiAnalysisFinding {
            category: "DebuggerDetection".to_string(),
            indicator: "IsDebuggerPresent".to_string(),
        });
        pe.anti_analysis.push(AntiAnalysisFinding {
            category: "VmDetection".to_string(),
            indicator: "GetSystemFirmwareTable".to_string(),
        });
        let score = calculate_risk_score(Some(&pe), None, None, None, None, None, None);
        assert!(score >= 2 * BONUS_ANTI_ANALYSIS_PER_CATEGORY);
    }

    #[test]
    fn test_score_capped_at_100() {
        let mut pe = empty_pe();
        // Pile on many indicators to exceed 100
        pe.imports.suspicious_api_count = 50;
        pe.sections.push(SectionInfo {
            name: ".wx".to_string(),
            virtual_address: "0x1000".to_string(),
            virtual_size: 0x1000,
            raw_size: 0x200,
            entropy: 7.9,
            is_suspicious: true,
            is_wx: true,
            name_anomaly: None,
            confidence: None,
        });
        pe.packers.push(PackerFinding {
            name: "UPX".to_string(),
            confidence: "High".to_string(),
            detection_method: "String".to_string(),
        });
        pe.tls = Some(TlsInfo {
            callback_count: 5,
            callback_rvas: vec!["0x1000".to_string()],
        });
        pe.overlay = Some(OverlayInfo {
            offset: 1000,
            size: 500,
            entropy: 7.9,
            high_entropy: true,
            overlay_mime_type: None,
            overlay_characterisation: None,
            confidence: None,
        });
        pe.anti_analysis.extend([
            AntiAnalysisFinding {
                category: "DebuggerDetection".to_string(),
                indicator: "IsDebuggerPresent".to_string(),
            },
            AntiAnalysisFinding {
                category: "VmDetection".to_string(),
                indicator: "GetSystemFirmwareTable".to_string(),
            },
            AntiAnalysisFinding {
                category: "TimingCheck".to_string(),
                indicator: "GetTickCount".to_string(),
            },
            AntiAnalysisFinding {
                category: "SandboxDetection".to_string(),
                indicator: "SleepEx".to_string(),
            },
        ]);
        pe.ordinal_imports.push(OrdinalImport {
            dll: "ntdll.dll".to_string(),
            ordinal: 12,
        });
        assert_eq!(
            calculate_risk_score(Some(&pe), None, None, None, None, None, None),
            100
        );
    }

    #[test]
    fn test_calculate_confidence_deduplicates_highest() {
        let techniques = vec![
            MitreTechnique {
                technique_id: "T1055".to_string(),
                sub_technique_id: Some("001".to_string()),
                technique_name: "Process Injection".to_string(),
                tactic: "Defense Evasion".to_string(),
                source_indicator: "VirtualAllocEx".to_string(),
                confidence: ConfidenceLevel::High,
            },
            MitreTechnique {
                technique_id: "T1055".to_string(),
                sub_technique_id: Some("001".to_string()),
                technique_name: "Process Injection".to_string(),
                tactic: "Defense Evasion".to_string(),
                source_indicator: "WriteProcessMemory".to_string(),
                confidence: ConfidenceLevel::Critical,
            },
        ];
        let conf = calculate_confidence(&techniques);
        assert_eq!(conf.get("T1055.001"), Some(&ConfidenceLevel::Critical));
    }

    #[test]
    fn test_calculate_confidence_empty() {
        let conf = calculate_confidence(&[]);
        assert!(conf.is_empty());
    }

    #[test]
    fn test_confidence_from_str() {
        assert_eq!(confidence_from_str("High"), ConfidenceLevel::High);
        assert_eq!(confidence_from_str("Critical"), ConfidenceLevel::Critical);
        assert_eq!(confidence_from_str("unknown"), ConfidenceLevel::Low);
    }
}
