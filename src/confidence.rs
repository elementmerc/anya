// Ányá — Confidence scoring and risk score calculation
//
// Produces a 0–100 risk score from analysis findings, and maps individual
// indicators to ConfidenceLevel values.

use crate::output::{
    AntiAnalysisFinding, ConfidenceLevel, ELFAnalysis, MitreTechnique, OrdinalImport, PEAnalysis,
    PackerFinding,
};
use std::collections::HashMap;

// ── Per-level point weights (exported for use in scoring explanations) ────────

#[allow(dead_code)]
pub const WEIGHT_CRITICAL: u32 = 25;
pub const WEIGHT_HIGH: u32 = 15;
pub const WEIGHT_MEDIUM: u32 = 8;
#[allow(dead_code)]
pub const WEIGHT_LOW: u32 = 3;

// Structural bonus points (not tied to a single indicator confidence level)
const BONUS_PACKER_HIGH: u32 = 20;
const BONUS_PACKER_MEDIUM: u32 = 10;
const BONUS_TLS_CALLBACKS: u32 = 10;
const BONUS_HIGH_ENTROPY_OVERLAY: u32 = 15;
const BONUS_WX_SECTION: u32 = 15;
const BONUS_ORDINAL_NTDLL: u32 = 12;
const BONUS_ORDINAL_KERNEL32: u32 = 10;
const BONUS_SUSPICIOUS_API_COUNT: u32 = 5; // per tier of 5 suspicious APIs
const BONUS_ANTI_ANALYSIS_PER_CATEGORY: u32 = 8;
const BONUS_ELF_NO_PIE: u32 = 5;
const BONUS_ELF_NO_NX: u32 = 8;
const BONUS_ELF_NO_RELRO: u32 = 5;
const BONUS_ELF_WX_SECTION: u32 = 15;
const BONUS_ELF_PACKER: u32 = 20;

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
pub fn calculate_risk_score(
    pe: Option<&PEAnalysis>,
    elf: Option<&ELFAnalysis>,
) -> u32 {
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
        if let Some(tls) = &pe.tls {
            if tls.callback_count > 0 {
                score += BONUS_TLS_CALLBACKS;
            }
        }

        // High-entropy overlay
        if pe.overlay.as_ref().map_or(false, |o| o.high_entropy) {
            score += BONUS_HIGH_ENTROPY_OVERLAY;
        }

        // Ordinal imports from sensitive DLLs
        score += ordinal_import_bonus(&pe.ordinal_imports);

        // Anti-analysis categories
        let unique_categories = unique_anti_analysis_categories(&pe.anti_analysis);
        score += BONUS_ANTI_ANALYSIS_PER_CATEGORY * (unique_categories as u32).min(4);

        // Checksum mismatch (stored non-zero but doesn't match computed)
        if let Some(cs) = &pe.checksum {
            if cs.stored_nonzero && !cs.valid {
                score += WEIGHT_MEDIUM;
            }
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
    let mut map: HashMap<String, ConfidenceLevel> = HashMap::new();
    for t in techniques {
        let key = format!(
            "{}{}",
            t.technique_id,
            t.sub_technique_id
                .as_deref()
                .map(|s| format!(".{}", s))
                .unwrap_or_default()
        );
        let entry = map.entry(key).or_insert(ConfidenceLevel::Low);
        if t.confidence > *entry {
            *entry = t.confidence.clone();
        }
    }
    map
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

/// Convenience: derive `ConfidenceLevel` from a raw PE packer confidence string.
pub fn confidence_from_str(s: &str) -> ConfidenceLevel {
    match s {
        "Critical" => ConfidenceLevel::Critical,
        "High" => ConfidenceLevel::High,
        "Medium" => ConfidenceLevel::Medium,
        _ => ConfidenceLevel::Low,
    }
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
        });
        pe.anti_analysis.extend([
            AntiAnalysisFinding { category: "DebuggerDetection".to_string(), indicator: "IsDebuggerPresent".to_string() },
            AntiAnalysisFinding { category: "VmDetection".to_string(), indicator: "GetSystemFirmwareTable".to_string() },
            AntiAnalysisFinding { category: "TimingCheck".to_string(), indicator: "GetTickCount".to_string() },
            AntiAnalysisFinding { category: "SandboxDetection".to_string(), indicator: "SleepEx".to_string() },
        ]);
        pe.ordinal_imports.push(OrdinalImport { dll: "ntdll.dll".to_string(), ordinal: 12 });
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
