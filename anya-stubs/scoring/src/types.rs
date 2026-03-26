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
