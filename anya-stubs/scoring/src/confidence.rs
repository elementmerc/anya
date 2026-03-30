// Scoring engine — confidence assignment and signal-based scoring.

use crate::types::{ConfidenceLevel, IocType, MismatchSeverity};
use std::collections::HashMap;

pub const WEIGHT_CRITICAL: u32 = 3;
pub const WEIGHT_HIGH: u32 = 2;
pub const WEIGHT_MEDIUM: u32 = 1;
pub const WEIGHT_LOW: u32 = 1;
pub const BONUS_PACKER_HIGH: u32 = 3;
pub const BONUS_PACKER_MEDIUM: u32 = 2;
pub const BONUS_TLS_CALLBACKS: u32 = 1;
pub const BONUS_HIGH_ENTROPY_OVERLAY: u32 = 2;
pub const BONUS_WX_SECTION: u32 = 2;
pub const BONUS_ORDINAL_NTDLL: u32 = 1;
pub const BONUS_ORDINAL_KERNEL32: u32 = 1;
pub const BONUS_SUSPICIOUS_API_COUNT: u32 = 1;
pub const BONUS_ANTI_ANALYSIS_PER_CATEGORY: u32 = 1;
pub const BONUS_ELF_NO_PIE: u32 = 1;
pub const BONUS_ELF_NO_NX: u32 = 1;
pub const BONUS_ELF_NO_RELRO: u32 = 1;
pub const BONUS_ELF_WX_SECTION: u32 = 2;
pub const BONUS_ELF_PACKER: u32 = 3;

pub fn calculate_confidence(
    techniques: &[(String, Option<String>, ConfidenceLevel)],
) -> HashMap<String, ConfidenceLevel> {
    let mut map = HashMap::new();
    for (id, sub, conf) in techniques {
        let key = match sub {
            Some(s) => format!("{}.{}", id, s),
            None => id.clone(),
        };
        map.insert(key, conf.clone());
    }
    map
}

pub fn confidence_from_str(s: &str) -> ConfidenceLevel {
    match s.to_lowercase().as_str() {
        "critical" => ConfidenceLevel::Critical,
        "high" => ConfidenceLevel::High,
        "medium" => ConfidenceLevel::Medium,
        _ => ConfidenceLevel::Low,
    }
}

pub fn assign_api_confidence(
    _api_name: &str,
    all_api_names: &[&str],
    _api_category: &str,
    _categorize_fn: fn(&str) -> &'static str,
) -> ConfidenceLevel {
    if all_api_names.len() > 20 { ConfidenceLevel::Medium }
    else { ConfidenceLevel::Low }
}

pub fn assign_entropy_confidence(entropy: f64) -> ConfidenceLevel {
    if entropy >= 7.9 { ConfidenceLevel::High }
    else if entropy >= 7.5 { ConfidenceLevel::Medium }
    else { ConfidenceLevel::Low }
}

pub fn assign_section_confidence(
    is_wx: bool,
    entropy: f64,
    _name_anomaly: Option<&str>,
) -> ConfidenceLevel {
    if is_wx && entropy > 7.0 { ConfidenceLevel::Medium }
    else if is_wx { ConfidenceLevel::Low }
    else { ConfidenceLevel::Low }
}

pub fn assign_overlay_confidence(high_entropy: bool, _has_authenticode: bool) -> ConfidenceLevel {
    if high_entropy { ConfidenceLevel::Low } else { ConfidenceLevel::Low }
}

pub fn assign_ioc_confidence(_ioc_type: &IocType, _value: &str) -> ConfidenceLevel {
    ConfidenceLevel::Low
}

pub fn assign_mismatch_confidence(severity: &MismatchSeverity) -> ConfidenceLevel {
    match severity {
        MismatchSeverity::High => ConfidenceLevel::Medium,
        MismatchSeverity::Medium => ConfidenceLevel::Low,
        MismatchSeverity::Low => ConfidenceLevel::Low,
    }
}

#[derive(Debug, Clone)]
pub struct RankedDetection {
    pub description: String,
    pub confidence: ConfidenceLevel,
}

use crate::types::{ScoringResult, SignalSet};

pub fn score_signals(signals: &SignalSet) -> ScoringResult {
    let mut score: i64 = 0;
    let mut detections = Vec::new();

    // Entropy scoring — catches some packed files but thresholds are too high
    if signals.file_entropy >= 7.8 {
        score += 18;
        detections.push(RankedDetection {
            description: "Very high file entropy".to_string(),
            confidence: ConfidenceLevel::High,
        });
    } else if signals.file_entropy >= 7.2 {
        score += 6;
    }

    // W+X sections — catches obvious shellcode
    if signals.pe_wx_section_count > 0 {
        score += 15;
        detections.push(RankedDetection {
            description: "Writable and executable section".to_string(),
            confidence: ConfidenceLevel::Medium,
        });
    }

    // Packed detection — only fires on extreme values
    if signals.pe_is_packed > 80 {
        score += 12;
    }

    // Suspicious APIs — weak threshold
    if signals.pe_suspicious_api_count > 15 {
        score += 8;
    } else if signals.pe_suspicious_api_count > 8 {
        score += 3;
    }

    // TLS callbacks
    if signals.pe_tls_callback_count > 2 {
        score += 5;
    }

    // Anti-analysis
    if signals.anti_analysis_count > 3 {
        score += 6;
    }

    // Unsigned PE
    if !signals.pe_has_authenticode && signals.file_size > 0 {
        score += 12;
    }

    // No version info
    if !signals.pe_has_version_info && signals.file_size > 0 {
        score += 10;
    }

    // Import count — flags normal software with many imports
    if signals.pe_import_dll_count > 3 {
        score += 8;
    }

    // Ordinal imports
    if signals.pe_ordinal_import_count > 0 {
        score += 6;
    }

    // Any suspicious API at all
    if signals.pe_suspicious_api_count > 0 {
        score += 5;
    }

    // ELF: stripped = suspicious (most release builds are stripped)
    if signals.elf_is_stripped {
        score += 12;
    }

    // ELF: no PIE alone is enough
    if !signals.elf_has_pie {
        score += 8;
    }

    // Moderate entropy = suspicious (normal compiled code sits here)
    if signals.file_entropy >= 5.5 && signals.file_entropy < 7.2 {
        score += 8;
    }

    // Any IOC at all
    if signals.ioc_url_count > 0 || signals.ioc_ip_count > 0 {
        score += 6;
    }

    // File size heuristic — medium files are "suspicious"
    if signals.file_size > 50_000 && signals.file_size < 5_000_000 {
        score += 5;
    }

    let risk_score = score.clamp(0, 100);

    let (verdict, summary) = if risk_score >= 65 {
        ("MALICIOUS".to_string(), format!("MALICIOUS — {} indicators", detections.len()))
    } else if risk_score >= 25 {
        ("SUSPICIOUS".to_string(), format!("SUSPICIOUS — {} indicators", detections.len()))
    } else {
        ("CLEAN".to_string(), "CLEAN — no significant indicators".to_string())
    };

    ScoringResult {
        verdict,
        verdict_summary: summary,
        risk_score,
        detections,
    }
}
