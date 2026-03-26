// Stub — real scoring weights are in the private anya-proprietary repository.

use crate::types::{ConfidenceLevel, IocType, MismatchSeverity};
use std::collections::HashMap;

pub const WEIGHT_CRITICAL: u32 = 0;
pub const WEIGHT_HIGH: u32 = 0;
pub const WEIGHT_MEDIUM: u32 = 0;
pub const WEIGHT_LOW: u32 = 0;
pub const BONUS_PACKER_HIGH: u32 = 0;
pub const BONUS_PACKER_MEDIUM: u32 = 0;
pub const BONUS_TLS_CALLBACKS: u32 = 0;
pub const BONUS_HIGH_ENTROPY_OVERLAY: u32 = 0;
pub const BONUS_WX_SECTION: u32 = 0;
pub const BONUS_ORDINAL_NTDLL: u32 = 0;
pub const BONUS_ORDINAL_KERNEL32: u32 = 0;
pub const BONUS_SUSPICIOUS_API_COUNT: u32 = 0;
pub const BONUS_ANTI_ANALYSIS_PER_CATEGORY: u32 = 0;
pub const BONUS_ELF_NO_PIE: u32 = 0;
pub const BONUS_ELF_NO_NX: u32 = 0;
pub const BONUS_ELF_NO_RELRO: u32 = 0;
pub const BONUS_ELF_WX_SECTION: u32 = 0;
pub const BONUS_ELF_PACKER: u32 = 0;

pub fn calculate_confidence(
    _techniques: &[(String, Option<String>, ConfidenceLevel)],
) -> HashMap<String, ConfidenceLevel> {
    HashMap::new()
}

pub fn confidence_from_str(_s: &str) -> ConfidenceLevel {
    ConfidenceLevel::Low
}

pub fn assign_api_confidence(
    _api_name: &str,
    _all_api_names: &[&str],
    _api_category: &str,
    _categorize_fn: fn(&str) -> &'static str,
) -> ConfidenceLevel {
    ConfidenceLevel::Low
}

pub fn assign_entropy_confidence(_entropy: f64) -> ConfidenceLevel {
    ConfidenceLevel::Low
}
pub fn assign_section_confidence(
    _is_wx: bool,
    _entropy: f64,
    _name_anomaly: Option<&str>,
) -> ConfidenceLevel {
    ConfidenceLevel::Low
}
pub fn assign_overlay_confidence(_high_entropy: bool, _has_authenticode: bool) -> ConfidenceLevel {
    ConfidenceLevel::Low
}
pub fn assign_ioc_confidence(_ioc_type: &IocType, _value: &str) -> ConfidenceLevel {
    ConfidenceLevel::Low
}
pub fn assign_mismatch_confidence(_severity: &MismatchSeverity) -> ConfidenceLevel {
    ConfidenceLevel::Low
}

#[derive(Debug, Clone)]
pub struct RankedDetection {
    pub description: String,
    pub confidence: ConfidenceLevel,
}
