// Stub — real types are in the private anya-proprietary repository.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Ipv4,
    Ipv6,
    Url,
    Domain,
    Email,
    RegistryKey,
    WindowsPath,
    LinuxPath,
    Mutex,
    Base64Blob,
    ScriptObfuscation,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "ipv4"),
            Self::Ipv6 => write!(f, "ipv6"),
            Self::Url => write!(f, "url"),
            Self::Domain => write!(f, "domain"),
            Self::Email => write!(f, "email"),
            Self::RegistryKey => write!(f, "registry_key"),
            Self::WindowsPath => write!(f, "windows_path"),
            Self::LinuxPath => write!(f, "linux_path"),
            Self::Mutex => write!(f, "mutex"),
            Self::Base64Blob => write!(f, "base64_blob"),
            Self::ScriptObfuscation => write!(f, "script_obfuscation"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MismatchSeverity {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for MismatchSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioc_type: Option<IocType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocSummary {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ioc_strings: Vec<ExtractedString>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub ioc_counts: HashMap<String, usize>,
}

// ── Signal extraction types (stubs) ─────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SignalSet {
    pub file_format: String,
    pub file_entropy: f64,
    pub entropy_is_suspicious: bool,
    pub pe_suspicious_api_count: usize,
    pub pe_suspicious_api_names: Vec<String>,
    pub pe_suspicious_api_categories: Vec<String>,
    pub pe_has_wx_sections: bool,
    pub pe_wx_section_count: usize,
    pub pe_packer_findings: Vec<PackerSignal>,
    pub pe_tls_callback_count: usize,
    pub pe_overlay_high_entropy: bool,
    pub pe_overlay_size: usize,
    pub pe_overlay_offset: usize,
    pub pe_has_authenticode: bool,
    pub pe_is_microsoft_signed: bool,
    pub pe_ordinal_ntdll_count: usize,
    pub pe_ordinal_kernel32_count: usize,
    pub pe_checksum_stored_nonzero: bool,
    pub pe_checksum_valid: bool,
    pub pe_anti_analysis: Vec<AntiAnalysisSignal>,
    pub elf_is_pie: bool,
    pub elf_has_nx: bool,
    pub elf_has_relro: bool,
    pub elf_has_wx_sections: bool,
    pub elf_wx_section_names: Vec<String>,
    pub elf_suspicious_function_count: usize,
    pub elf_packer_indicators: Vec<PackerSignal>,
    pub elf_got_plt_suspicious: Vec<String>,
    pub elf_rpath_anomalies: Vec<String>,
    pub elf_interpreter_suspicious: bool,
    pub elf_interpreter: Option<String>,
    pub elf_suspicious_section_names: Vec<String>,
    pub macho_has_code_signature: bool,
    pub macho_pie_enabled: bool,
    pub macho_nx_enabled: bool,
    pub pdf_dangerous_objects: Vec<String>,
    pub office_has_macros: bool,
    pub office_has_embedded_objects: bool,
    pub office_has_external_links: bool,
    pub ioc_strings: Vec<IocSignal>,
    pub ioc_net_count: usize,
    pub ioc_total_count: usize,
    pub ioc_onion_count: usize,
    pub ioc_script_obfuscation_count: usize,
    pub mismatch_severity: Option<MismatchSeverity>,
    pub mismatch_detected_type: Option<String>,
    pub mismatch_claimed_extension: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PackerSignal {
    pub name: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Default)]
pub struct AntiAnalysisSignal {
    pub technique: String,
    pub evidence: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Default)]
pub struct IocSignal {
    pub value: String,
    pub ioc_type: String,
}

#[derive(Debug, Clone)]
pub struct ScoringResult {
    pub verdict: String,
    pub verdict_summary: String,
    pub risk_score: u32,
    pub detections: Vec<(String, ConfidenceLevel)>,
}
