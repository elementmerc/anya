// Ányá — Confidence scoring
//
// Extracts signals from AnalysisResult into SignalSet, then delegates
// scoring to the anya-scoring crate.

use crate::output::{AnalysisResult, ConfidenceLevel, MitreTechnique, SectionInfo};
use anya_scoring::types::{AntiAnalysisSignal, IocSignal, PackerSignal, ScoringResult, SignalSet};
use std::collections::HashMap;

// Re-export scoring functions and types.
pub use anya_scoring::confidence::{
    RankedDetection, assign_entropy_confidence, assign_ioc_confidence, assign_mismatch_confidence,
    assign_overlay_confidence as assign_overlay_confidence_raw, confidence_from_str, score_signals,
};

// Re-export weight constants for tests.
pub use anya_scoring::confidence::{
    BONUS_ANTI_ANALYSIS_PER_CATEGORY, BONUS_ELF_NO_NX, BONUS_ELF_NO_PIE, BONUS_ELF_NO_RELRO,
    BONUS_ELF_PACKER, BONUS_ELF_WX_SECTION, BONUS_HIGH_ENTROPY_OVERLAY, BONUS_ORDINAL_KERNEL32,
    BONUS_ORDINAL_NTDLL, BONUS_PACKER_HIGH, BONUS_PACKER_MEDIUM, BONUS_SUSPICIOUS_API_COUNT,
    BONUS_TLS_CALLBACKS, BONUS_WX_SECTION, WEIGHT_CRITICAL, WEIGHT_HIGH, WEIGHT_LOW, WEIGHT_MEDIUM,
};

/// Extract signals from an AnalysisResult into a SignalSet for scoring.
pub fn extract_signals(result: &AnalysisResult) -> SignalSet {
    let mut s = SignalSet {
        file_format: result.file_format.clone(),
        file_entropy: result.entropy.value,
        entropy_is_suspicious: result.entropy.is_suspicious,
        ..Default::default()
    };

    // ── PE signals ──────────────────────────────────────────────────────
    if let Some(ref pe) = result.pe_analysis {
        s.pe_suspicious_api_count = pe.imports.suspicious_api_count;
        s.pe_suspicious_api_names = pe
            .imports
            .suspicious_apis
            .iter()
            .map(|a| a.name.clone())
            .collect();
        s.pe_suspicious_api_categories = pe
            .imports
            .suspicious_apis
            .iter()
            .map(|a| a.category.clone())
            .collect();
        s.pe_has_wx_sections = pe.sections.iter().any(|sec| sec.is_wx);
        s.pe_wx_section_count = pe.sections.iter().filter(|sec| sec.is_wx).count();
        s.pe_packer_findings = pe
            .packers
            .iter()
            .map(|p| PackerSignal {
                name: p.name.clone(),
                confidence: p.confidence.clone(),
            })
            .collect();
        if let Some(ref tls) = pe.tls {
            s.pe_tls_callback_count = tls.callback_count;
        }
        if let Some(ref o) = pe.overlay {
            s.pe_overlay_high_entropy = o.high_entropy;
            s.pe_overlay_size = o.size;
            s.pe_overlay_offset = o.offset;
        }
        if let Some(ref auth) = pe.authenticode {
            s.pe_has_authenticode = auth.present;
            s.pe_is_microsoft_signed = auth.is_microsoft_signed;
        }
        for o in &pe.ordinal_imports {
            let dll = o.dll.to_lowercase();
            if dll.contains("ntdll") {
                s.pe_ordinal_ntdll_count += 1;
            } else if dll.contains("kernel32") {
                s.pe_ordinal_kernel32_count += 1;
            }
        }
        if let Some(ref cs) = pe.checksum {
            s.pe_checksum_stored_nonzero = cs.stored_nonzero;
            s.pe_checksum_valid = cs.valid;
        }
        s.pe_anti_analysis = pe
            .anti_analysis
            .iter()
            .map(|a| AntiAnalysisSignal {
                technique: a.category.clone(),
                evidence: a.indicator.clone(),
                confidence: "High".to_string(), // anti-analysis is always High
            })
            .collect();
    }

    // ── ELF signals ─────────────────────────────────────────────────────
    if let Some(ref elf) = result.elf_analysis {
        s.elf_is_pie = elf.is_pie;
        s.elf_has_nx = elf.has_nx_stack;
        s.elf_has_relro = elf.has_relro;
        s.elf_has_wx_sections = elf.sections.iter().any(|sec| sec.is_wx);
        s.elf_wx_section_names = elf
            .sections
            .iter()
            .filter(|sec| sec.is_wx)
            .map(|sec| sec.name.clone())
            .collect();
        s.elf_suspicious_function_count = elf.imports.suspicious_functions.len();
        s.elf_packer_indicators = elf
            .packer_indicators
            .iter()
            .map(|p| PackerSignal {
                name: p.name.clone(),
                confidence: p.confidence.clone(),
            })
            .collect();
        s.elf_got_plt_suspicious = elf.got_plt_suspicious.clone();
        s.elf_rpath_anomalies = elf.rpath_anomalies.clone();
        s.elf_interpreter_suspicious = elf.interpreter_suspicious;
        s.elf_interpreter = elf.interpreter.clone();
        s.elf_suspicious_section_names = elf.suspicious_section_names.clone();
    }

    // ── Mach-O signals ──────────────────────────────────────────────────
    if let Some(ref mach) = result.mach_analysis {
        s.macho_has_code_signature = mach.has_code_signature;
        s.macho_pie_enabled = mach.pie_enabled;
        s.macho_nx_enabled = mach.nx_enabled;
    }

    // ── PDF signals ─────────────────────────────────────────────────────
    if let Some(ref pdf) = result.pdf_analysis {
        s.pdf_dangerous_objects = pdf.dangerous_objects.clone();
    }

    // ── Office signals ──────────────────────────────────────────────────
    if let Some(ref office) = result.office_analysis {
        s.office_has_macros = office.has_macros;
        s.office_has_embedded_objects = office.has_embedded_objects;
        s.office_has_external_links = office.has_external_links;
    }

    // ── IOC signals ─────────────────────────────────────────────────────
    if let Some(ref ioc) = result.ioc_summary {
        s.ioc_total_count = ioc.ioc_strings.len();
        s.ioc_strings = ioc
            .ioc_strings
            .iter()
            .map(|es| IocSignal {
                value: es.value.clone(),
                ioc_type: es
                    .ioc_type
                    .as_ref()
                    .map(|t| t.to_string())
                    .unwrap_or_default(),
            })
            .collect();
        s.ioc_net_count = ioc
            .ioc_strings
            .iter()
            .filter(|es| {
                es.ioc_type.as_ref().is_some_and(|t| {
                    matches!(t.to_string().as_str(), "url" | "domain" | "ipv4" | "ipv6")
                })
            })
            .count();
        s.ioc_onion_count = ioc
            .ioc_strings
            .iter()
            .filter(|es| es.value.ends_with(".onion"))
            .count();
        s.ioc_script_obfuscation_count = ioc
            .ioc_counts
            .get("script_obfuscation")
            .copied()
            .unwrap_or(0);
    }

    // ── File type mismatch ──────────────────────────────────────────────
    if let Some(ref m) = result.file_type_mismatch {
        s.mismatch_severity = Some(m.severity.clone());
        s.mismatch_detected_type = Some(m.detected_type.clone());
        s.mismatch_claimed_extension = Some(m.claimed_extension.clone());
    }

    s
}

/// Compute a 0–100 risk score from all analysis findings.
/// Delegates to the scoring crate.
pub fn calculate_risk_score(result: &AnalysisResult) -> u32 {
    let signals = extract_signals(result);
    score_signals(&signals).risk_score
}

/// Collect top N detections from an AnalysisResult, sorted by confidence.
/// Delegates to the scoring crate.
pub fn top_detections(result: &AnalysisResult, n: usize) -> Vec<RankedDetection> {
    let signals = extract_signals(result);
    let scoring = score_signals(&signals);
    scoring
        .detections
        .into_iter()
        .take(n)
        .map(|(desc, conf)| RankedDetection {
            description: desc,
            confidence: conf,
        })
        .collect()
}

/// Score an AnalysisResult and return the full scoring result (verdict + score + detections).
pub fn score_analysis(result: &AnalysisResult) -> ScoringResult {
    let signals = extract_signals(result);
    score_signals(&signals)
}

/// Assign a ConfidenceLevel to MITRE techniques and return technique_id → confidence.
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
pub fn assign_overlay_confidence(
    overlay: &crate::output::OverlayInfo,
    has_authenticode: bool,
) -> ConfidenceLevel {
    assign_overlay_confidence_raw(overlay.high_entropy, has_authenticode)
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

    fn empty_result() -> AnalysisResult {
        AnalysisResult {
            file_info: FileInfo {
                path: "test.exe".to_string(),
                size_bytes: 1000,
                size_kb: 1.0,
                extension: Some("exe".to_string()),
                mime_type: Some("application/x-dosexec".to_string()),
            },
            hashes: Hashes {
                md5: "".to_string(),
                sha1: "".to_string(),
                sha256: "".to_string(),
                tlsh: None,
            },
            entropy: EntropyInfo {
                value: 4.0,
                category: "Moderate".to_string(),
                is_suspicious: false,
                confidence: None,
            },
            strings: StringsInfo {
                min_length: 4,
                total_count: 0,
                samples: vec![],
                sample_count: 0,
                classified: None,
                suppressed_reason: None,
            },
            pe_analysis: None,
            elf_analysis: None,
            file_format: "Windows PE".to_string(),
            imphash: None,
            checksum_valid: None,
            tls_callbacks: vec![],
            ordinal_imports: vec![],
            overlay: None,
            packer_detections: vec![],
            compiler_detection: None,
            anti_analysis_indicators: vec![],
            mitre_techniques: vec![],
            confidence_scores: HashMap::new(),
            plain_english_findings: vec![],
            byte_histogram: None,
            file_type_mismatch: None,
            ioc_summary: None,
            verdict_summary: None,
            top_findings: vec![],
            mach_analysis: None,
            pdf_analysis: None,
            office_analysis: None,
        }
    }

    #[test]
    fn test_clean_pe_scores_low() {
        let mut result = empty_result();
        result.pe_analysis = Some(empty_pe());
        // A minimal PE with no suspicious APIs, no packers, no overlay, etc.
        // may still score > 0 due to structural signals. Should be < 50 (not malicious).
        let score = calculate_risk_score(&result);
        assert!(score < 50, "Clean PE scored {score}, expected < 50");
    }

    #[test]
    fn test_score_capped_at_100() {
        let mut result = empty_result();
        let mut pe = empty_pe();
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
        result.pe_analysis = Some(pe);
        assert_eq!(calculate_risk_score(&result), 100);
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
