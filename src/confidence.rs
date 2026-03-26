// Ányá — Confidence scoring and risk score calculation
//
// Produces a 0–100 risk score from analysis findings, and maps individual
// indicators to ConfidenceLevel values.
//
// Weight constants and pure confidence-assignment functions are defined in
// the anya-scoring crate; this module re-exports them and provides the
// higher-level functions that depend on core output types (PEAnalysis, etc.).

use crate::output::{
    AnalysisResult, AntiAnalysisFinding, ConfidenceLevel, ELFAnalysis, MitreTechnique,
    OrdinalImport, OverlayInfo, PEAnalysis, PackerFinding, SectionInfo,
};
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

/// Compute a 0–100 risk score from an analysis result.
///
/// Scoring rules (additive, capped at 100):
/// - Each suspicious API finding adds points weighted by its severity tier
/// - Packer detection adds 20 (High) or 10 (Medium/Low)
/// - TLS callbacks detected: +10
/// - High-entropy overlay: +15
/// - W+X section: +15
/// - Ordinal imports from ntdll/kernel32: +12/+10
/// - Anti-analysis indicators: +8 per unique category (max 4 categories)
/// - ELF: missing PIE +5, missing NX +8, missing RELRO +5, W+X section +15, packer +20
pub fn calculate_risk_score(pe: Option<&PEAnalysis>, elf: Option<&ELFAnalysis>) -> u32 {
    let mut score: u32 = 0;

    if let Some(pe) = pe {
        // Suspicious API count contribution
        let api_count = pe.imports.suspicious_api_count;
        let tiers = (api_count / 5) as u32; // +5 per group of 5 suspicious APIs, capped at 4 tiers
        score += BONUS_SUSPICIOUS_API_COUNT * tiers.min(4);

        // W+X sections
        if pe.sections.iter().any(|s| s.is_wx) {
            score += BONUS_WX_SECTION;
        }

        // Packer detection
        let best_packer = pe.packers.iter().max_by_key(|p| packer_confidence_ord(p));
        if let Some(pk) = best_packer {
            score += match pk.confidence.as_str() {
                "Critical" | "High" => BONUS_PACKER_HIGH,
                _ => BONUS_PACKER_MEDIUM,
            };
        }

        // TLS callbacks
        if let Some(tls) = &pe.tls
            && tls.callback_count > 0
        {
            score += BONUS_TLS_CALLBACKS;
        }

        // High-entropy overlay
        if pe.overlay.as_ref().is_some_and(|o| o.high_entropy) {
            score += BONUS_HIGH_ENTROPY_OVERLAY;
        }

        // Ordinal imports from sensitive DLLs
        score += ordinal_import_bonus(&pe.ordinal_imports);

        // Anti-analysis categories
        let unique_categories = unique_anti_analysis_categories(&pe.anti_analysis);
        score += BONUS_ANTI_ANALYSIS_PER_CATEGORY * (unique_categories as u32).min(4);

        // Checksum mismatch (stored non-zero but doesn't match computed)
        if let Some(cs) = &pe.checksum
            && cs.stored_nonzero
            && !cs.valid
        {
            score += WEIGHT_MEDIUM;
        }
    }

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
        // Suspicious function imports
        let sus_count = elf.imports.suspicious_functions.len() as u32;
        score += WEIGHT_HIGH * sus_count.min(3);
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
        assert_eq!(calculate_risk_score(Some(&pe), None), 0);
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
        let score = calculate_risk_score(Some(&pe), None);
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
        let score = calculate_risk_score(Some(&pe), None);
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
        let score = calculate_risk_score(Some(&pe), None);
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
        let score = calculate_risk_score(Some(&pe), None);
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
        let score = calculate_risk_score(Some(&pe), None);
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
        assert_eq!(calculate_risk_score(Some(&pe), None), 0);
    }

    #[test]
    fn test_ntdll_ordinal_adds_points() {
        let mut pe = empty_pe();
        pe.ordinal_imports.push(OrdinalImport {
            dll: "ntdll.dll".to_string(),
            ordinal: 12,
        });
        let score = calculate_risk_score(Some(&pe), None);
        assert!(score >= BONUS_ORDINAL_NTDLL);
    }

    #[test]
    fn test_user32_ordinal_adds_nothing() {
        let mut pe = empty_pe();
        pe.ordinal_imports.push(OrdinalImport {
            dll: "user32.dll".to_string(),
            ordinal: 5,
        });
        assert_eq!(calculate_risk_score(Some(&pe), None), 0);
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
        let score = calculate_risk_score(Some(&pe), None);
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
        assert_eq!(calculate_risk_score(Some(&pe), None), 100);
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
