// Ányá - Malware Analysis Platform
// Copyright (C) 2026 Daniel Iwugo
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// For commercial licensing, contact: daniel@themalwarefiles.com

/// JSON output structures for machine-readable analysis results
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// File information
    pub file_info: FileInfo,

    /// Cryptographic hashes
    pub hashes: Hashes,

    /// Entropy analysis
    pub entropy: EntropyInfo,

    /// Extracted strings (limited to first N)
    pub strings: StringsInfo,

    /// PE-specific analysis (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe_analysis: Option<PEAnalysis>,

    /// ELF-specific analysis (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elf_analysis: Option<ELFAnalysis>,

    /// File format type
    pub file_format: String,

    // ── New analysis engine fields ────────────────────────────────────────
    /// Imphash (MD5 of normalised import list) — top-level shortcut
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,

    /// PE checksum validity (true = stored matches computed or stored is zero)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_valid: Option<bool>,

    /// TLS callback virtual addresses
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_callbacks: Vec<TlsCallback>,

    /// Ordinal-only imports — top-level shortcut
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ordinal_imports: Vec<OrdinalImport>,

    /// Overlay bytes appended after the last section
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay: Option<OverlayInfo>,

    /// Detected packers/protectors
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packer_detections: Vec<PackerDetection>,

    /// Detected compiler or language runtime
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_detection: Option<CompilerDetection>,

    /// Anti-analysis technique indicators
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anti_analysis_indicators: Vec<AntiAnalysisIndicator>,

    /// MITRE ATT&CK technique mappings derived from all indicators
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_techniques: Vec<MitreTechnique>,

    /// Per-indicator confidence levels
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub confidence_scores: HashMap<String, ConfidenceLevel>,

    /// Analyst-facing plain-English findings
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plain_english_findings: Vec<PlainEnglishFinding>,

    /// Byte value histogram (256 entries, one per byte value 0x00–0xFF)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_histogram: Option<Vec<u32>>,
}

/// File metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// File path
    pub path: String,

    /// File size in bytes
    pub size_bytes: u64,

    /// File size in KB
    pub size_kb: f64,

    /// File extension if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,

    /// MIME type detected via magic bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Cryptographic hashes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hashes {
    /// MD5 hash (hex)
    pub md5: String,

    /// SHA1 hash (hex)
    pub sha1: String,

    /// SHA256 hash (hex)
    pub sha256: String,

    /// TLSH fuzzy hash (70-char hex, None if file < 50 bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlsh: Option<String>,
}

/// Entropy analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyInfo {
    /// Shannon entropy value (0.0 - 8.0)
    pub value: f64,

    /// Interpretation category
    pub category: String,

    /// Is suspicious (> 7.5)
    pub is_suspicious: bool,
}

/// String extraction results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringsInfo {
    /// Minimum string length used
    pub min_length: usize,

    /// Total count of strings found
    pub total_count: usize,

    /// Sample of extracted strings (limited)
    pub samples: Vec<String>,

    /// Number of samples shown
    pub sample_count: usize,

    /// Classified strings with categories and offsets
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classified: Option<Vec<ClassifiedString>>,
}

/// PE file analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PEAnalysis {
    /// Architecture (32-bit or 64-bit)
    pub architecture: String,

    /// Is 64-bit
    pub is_64bit: bool,

    /// Image base address
    pub image_base: String,

    /// Entry point address
    pub entry_point: String,

    /// File type (EXE or DLL)
    pub file_type: String,

    /// Security features
    pub security: SecurityFeatures,

    /// Section analysis
    pub sections: Vec<SectionInfo>,

    /// Import analysis
    pub imports: ImportAnalysis,

    /// Export analysis (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exports: Option<ExportAnalysis>,

    /// Imphash (MD5 of normalised import list)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,

    /// PE checksum validation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<ChecksumInfo>,

    /// Rich header (MSVC build metadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_header: Option<RichHeaderInfo>,

    /// TLS callbacks (execute before entry point)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,

    /// Overlay data (bytes after last section)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<OverlayInfo>,

    /// Detected compiler / language
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler: Option<CompilerInfo>,

    /// Packer detection results
    pub packers: Vec<PackerFinding>,

    /// Anti-analysis technique indicators
    pub anti_analysis: Vec<AntiAnalysisFinding>,

    /// Ordinal-only imports
    pub ordinal_imports: Vec<OrdinalImport>,

    /// Authenticode signature block (from Security Directory, data dir index 4)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticode: Option<AuthenticodeInfo>,

    /// Version information from VS_VERSIONINFO resource
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<VersionInfo>,

    /// Debug artifacts (PDB path, timestamp, version info anomalies)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_artifacts: Option<DebugArtifacts>,

    /// Weak cryptography indicators found in the binary
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weak_crypto: Vec<WeakCryptoIndicator>,

    /// Compiler dependency manifest
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compiler_deps: Vec<CompilerDep>,
}

/// PE checksum comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumInfo {
    /// Value stored in the PE optional header
    pub stored: u32,
    /// Value computed from the file bytes
    pub computed: u32,
    /// True when stored == computed (or stored == 0, meaning not set)
    pub valid: bool,
    /// False when stored == 0 (common in user-mode apps and malware)
    pub stored_nonzero: bool,
}

/// A single entry decoded from the Rich header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichEntry {
    pub product_id: u16,
    pub build_number: u16,
    pub use_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
}

/// Rich header (XOR-encoded MSVC build metadata between DOS stub and PE signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichHeaderInfo {
    pub xor_key: u32,
    pub entries: Vec<RichEntry>,
}

/// TLS (Thread Local Storage) directory information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub callback_count: usize,
    /// Callback addresses as hex RVA strings
    pub callback_rvas: Vec<String>,
}

/// Overlay (data appended after the last PE section)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayInfo {
    pub offset: usize,
    pub size: usize,
    pub entropy: f64,
    /// True when entropy > 6.8 (high entropy — may warrant further review)
    pub high_entropy: bool,

    /// MIME type of the overlay data detected via magic bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_mime_type: Option<String>,

    /// Human-readable overlay characterisation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_characterisation: Option<String>,
}

/// Detected compiler or language runtime
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerInfo {
    pub name: String,
    /// "High", "Medium", or "Low"
    pub confidence: String,
}

/// A packer or protector detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerFinding {
    pub name: String,
    /// "High", "Medium", or "Low"
    pub confidence: String,
    /// "String", "SectionName", "Entropy", or "Heuristic"
    pub detection_method: String,
}

/// Anti-analysis technique detected via static indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiAnalysisFinding {
    /// "VmDetection", "DebuggerDetection", "TimingCheck", or "SandboxDetection"
    pub category: String,
    /// Specific API name or string pattern that triggered this finding
    pub indicator: String,
}

/// An import resolved only by ordinal (no function name string)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrdinalImport {
    pub dll: String,
    pub ordinal: u16,
}

/// Authenticode (PKCS#7) signature information extracted from the PE Security Directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticodeInfo {
    /// True if a WIN_CERTIFICATE structure was found in the Security Directory
    pub present: bool,
    /// Subject CN of the signing certificate (heuristically extracted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_cn: Option<String>,
    /// Issuer CN of the signing certificate (heuristically extracted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_cn: Option<String>,
    /// True when signer CN contains "Microsoft"
    pub is_microsoft_signed: bool,
    /// Raw certificate block size in bytes
    pub cert_size: u32,

    /// Authenticode status: "Absent", "Present", "Self-signed"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Issuer distinguished name (if parseable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Expiry date as ISO 8601 string (if parseable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

/// Version information extracted from the VS_VERSIONINFO resource (RT_VERSION)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_copyright: Option<String>,
}

/// Security features status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeatures {
    /// ASLR enabled
    pub aslr_enabled: bool,

    /// DEP/NX enabled
    pub dep_enabled: bool,
}

/// Section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Section name
    pub name: String,

    /// Virtual size
    pub virtual_size: u32,

    /// Virtual address
    pub virtual_address: String,

    /// Raw size
    pub raw_size: u32,

    /// Shannon entropy
    pub entropy: f64,

    /// Is suspicious (high entropy)
    pub is_suspicious: bool,

    /// Is writable and executable
    pub is_wx: bool,

    /// Section name anomaly assessment: "Normal", "Elevated", or "Suspicious"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_anomaly: Option<String>,
}

/// Import analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportAnalysis {
    /// Number of imported DLLs
    pub dll_count: usize,

    /// Total number of imports
    pub total_imports: usize,

    /// Number of suspicious APIs detected
    pub suspicious_api_count: usize,

    /// List of suspicious APIs found
    pub suspicious_apis: Vec<SuspiciousAPI>,

    /// List of imported libraries
    pub libraries: Vec<String>,

    /// Imports per KB of file size (total_imports / (file_size / 1024))
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imports_per_kb: Option<f64>,

    /// True if imports_per_kb > 30.0 (anomalous density)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_ratio_suspicious: Option<bool>,
}

/// Suspicious API information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousAPI {
    /// API name
    pub name: String,

    /// Category (e.g., "Code Injection", "Anti-Analysis")
    pub category: String,
}

/// Export analysis (for DLLs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportAnalysis {
    /// Total number of exports
    pub total_count: usize,

    /// Sample of exported functions
    pub samples: Vec<ExportInfo>,
}

/// Individual export information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    /// Function name (if available)
    pub name: String,

    /// RVA (Relative Virtual Address)
    pub rva: String,
}

/// ELF file analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ELFAnalysis {
    pub architecture: String,
    pub is_64bit: bool,
    /// "Executable", "Shared Object", "Core", etc.
    pub file_type: String,
    pub entry_point: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    pub sections: Vec<ElfSectionInfo>,
    pub imports: ElfImportAnalysis,
    /// Position-independent executable
    pub is_pie: bool,
    /// Stack is non-executable (PT_GNU_STACK without PF_X)
    pub has_nx_stack: bool,
    /// RELRO segment present (PT_GNU_RELRO)
    pub has_relro: bool,
    /// Symbol table is stripped
    pub is_stripped: bool,
    pub packer_indicators: Vec<PackerFinding>,

    // ── New ELF analysis fields ───────────────────────────────────────────
    /// GOT/PLT symbols flagged as suspicious
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub got_plt_suspicious: Vec<String>,

    /// RPATH/RUNPATH entries that look anomalous
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpath_anomalies: Vec<String>,

    /// True if .debug_info section is present
    #[serde(default)]
    pub has_dwarf_info: bool,

    /// True if the interpreter path is non-standard
    #[serde(default)]
    pub interpreter_suspicious: bool,

    /// Section names that look unusual or obfuscated
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suspicious_section_names: Vec<String>,

    /// Suspicious libc / syscall wrappers found in dynamic imports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suspicious_libc_calls: Vec<SuspiciousLibcCall>,
}

/// A section from an ELF binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSectionInfo {
    pub name: String,
    pub section_type: String,
    pub size: u64,
    pub entropy: f64,
    pub is_wx: bool,
    pub is_suspicious: bool,
}

/// Import summary for an ELF binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfImportAnalysis {
    pub library_count: usize,
    pub libraries: Vec<String>,
    pub dynamic_symbol_count: usize,
    pub suspicious_functions: Vec<SuspiciousAPI>,
}

// ─────────────────────────────────────────────────────────────────────────────
// New analysis engine structs (v1 engine expansion)
// ─────────────────────────────────────────────────────────────────────────────

/// Confidence level for a detection or finding
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
            ConfidenceLevel::Low => write!(f, "Low"),
            ConfidenceLevel::Medium => write!(f, "Medium"),
            ConfidenceLevel::High => write!(f, "High"),
            ConfidenceLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// A MITRE ATT&CK technique mapped from a static indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    /// Base technique ID (e.g. "T1055")
    pub technique_id: String,
    /// Sub-technique suffix if applicable (e.g. "001")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_technique_id: Option<String>,
    pub technique_name: String,
    pub tactic: String,
    /// The API name or indicator that triggered this mapping
    pub source_indicator: String,
    pub confidence: ConfidenceLevel,
}

/// A plain-English analyst finding surfaced to the UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlainEnglishFinding {
    pub title: String,
    pub explanation: String,
    pub why_suspicious: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub malware_families: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_technique_id: Option<String>,
    pub confidence: ConfidenceLevel,
}

/// Anti-analysis technique detected via static indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiAnalysisIndicator {
    /// "DebuggerDetection", "VmDetection", "TimingEvasion", "SandboxDetection"
    pub technique: String,
    pub evidence: String,
    pub confidence: ConfidenceLevel,
    pub mitre_technique_id: String,
}

/// Packer / protector detection result (richer than PackerFinding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerDetection {
    pub name: String,
    pub confidence: ConfidenceLevel,
    /// Detection method: "String", "SectionName", "Entropy", "Heuristic"
    pub method: String,
    /// Specific evidence that triggered the detection
    pub evidence: String,
}

/// Compiler / language runtime detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerDetection {
    pub compiler: String,
    pub language: String,
    pub confidence: ConfidenceLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// A single TLS callback entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCallback {
    /// Virtual address as hex string
    pub virtual_address: String,
    /// File offset
    pub raw_offset: u64,
}

/// A suspicious libc / syscall wrapper found in an ELF binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousLibcCall {
    pub name: String,
    pub category: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_technique_id: Option<String>,
    pub confidence: ConfidenceLevel,
}

// ─────────────────────────────────────────────────────────────────────────────
// New structs for v1.0.2 analysis features
// ─────────────────────────────────────────────────────────────────────────────

/// Debug artifacts extracted from PE debug directory and version info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugArtifacts {
    /// PDB path from IMAGE_DEBUG_TYPE_CODEVIEW
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdb_path: Option<String>,
    /// True if PE timestamp is zeroed
    pub timestamp_zeroed: bool,
    /// True if version info fields contain suspicious repeated chars
    pub version_info_suspicious: bool,
}

/// Weak cryptography indicator found in the binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakCryptoIndicator {
    /// e.g. "RC4 S-box constants", "MD5 init constants"
    pub name: String,
    /// Human-readable evidence description
    pub evidence: String,
    /// Hex offset where the pattern was found
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
}

/// Compiler dependency manifest entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerDep {
    pub name: String,
    pub description: String,
    /// "Expected", "Suspicious", or "Uncommon"
    pub risk: String,
}

/// A classified extracted string with category and offset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedString {
    pub value: String,
    /// "URL", "IP", "Path", "Registry", "Suspicious", "Base64",
    /// "CryptoConstant", "Command", "Plain"
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_result_serialization() {
        let result = AnalysisResult {
            file_info: FileInfo {
                path: "test.exe".to_string(),
                size_bytes: 1024,
                size_kb: 1.0,
                extension: Some("exe".to_string()),
                mime_type: None,
            },
            hashes: Hashes {
                md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                tlsh: None,
            },
            entropy: EntropyInfo {
                value: 7.8,
                category: "High entropy".to_string(),
                is_suspicious: true,
            },
            strings: StringsInfo {
                min_length: 4,
                total_count: 100,
                samples: vec!["test".to_string(), "sample".to_string()],
                sample_count: 2,
                classified: None,
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
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test.exe"));
        assert!(json.contains("1024"));
        assert!(json.contains("7.8"));
    }

    #[test]
    fn test_file_info_serialization() {
        let file_info = FileInfo {
            path: "/tmp/malware.exe".to_string(),
            size_bytes: 524288,
            size_kb: 512.0,
            extension: Some("exe".to_string()),
            mime_type: None,
        };

        let json = serde_json::to_string_pretty(&file_info).unwrap();
        assert!(json.contains("malware.exe"));
        assert!(json.contains("524288"));
        assert!(json.contains("512"));
    }

    #[test]
    fn test_hashes_serialization() {
        let hashes = Hashes {
            md5: "abc123".to_string(),
            sha1: "def456".to_string(),
            sha256: "789ghi".to_string(),
            tlsh: None,
        };

        let json = serde_json::to_string(&hashes).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("def456"));
        assert!(json.contains("789ghi"));
        assert!(json.contains("md5"));
        assert!(json.contains("sha1"));
        assert!(json.contains("sha256"));
    }

    #[test]
    fn test_entropy_info_serialization() {
        let entropy = EntropyInfo {
            value: 6.5,
            category: "Moderate".to_string(),
            is_suspicious: false,
        };

        let json = serde_json::to_string(&entropy).unwrap();
        assert!(json.contains("6.5"));
        assert!(json.contains("Moderate"));
        assert!(json.contains("false"));
    }

    #[test]
    fn test_strings_info_serialization() {
        let strings = StringsInfo {
            min_length: 4,
            total_count: 42,
            samples: vec!["Hello".to_string(), "World".to_string(), "Test".to_string()],
            sample_count: 3,
            classified: None,
        };

        let json = serde_json::to_string(&strings).unwrap();
        assert!(json.contains("42"));
        assert!(json.contains("Hello"));
        assert!(json.contains("World"));
        assert!(json.contains("Test"));
    }

    #[test]
    fn test_security_features_serialization() {
        let security = SecurityFeatures {
            aslr_enabled: true,
            dep_enabled: false,
        };

        let json = serde_json::to_string(&security).unwrap();

        // Parse back to verify structure
        let parsed: SecurityFeatures = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.aslr_enabled, true);
        assert_eq!(parsed.dep_enabled, false);
    }

    #[test]
    fn test_section_info_serialization() {
        let section = SectionInfo {
            name: ".text".to_string(),
            virtual_size: 4096,
            virtual_address: "0x1000".to_string(),
            raw_size: 4096,
            entropy: 6.2,
            is_suspicious: false,
            is_wx: false,
            name_anomaly: None,
        };

        let json = serde_json::to_string_pretty(&section).unwrap();
        assert!(json.contains(".text"));
        assert!(json.contains("4096"));
        assert!(json.contains("6.2"));
    }

    #[test]
    fn test_suspicious_api_serialization() {
        let api = SuspiciousAPI {
            name: "CreateRemoteThread".to_string(),
            category: "Code Injection".to_string(),
        };

        let json = serde_json::to_string(&api).unwrap();
        assert!(json.contains("CreateRemoteThread"));
        assert!(json.contains("Code Injection"));
    }

    #[test]
    fn test_import_analysis_serialization() {
        let imports = ImportAnalysis {
            dll_count: 5,
            total_imports: 42,
            suspicious_api_count: 3,
            suspicious_apis: vec![SuspiciousAPI {
                name: "VirtualAllocEx".to_string(),
                category: "Code Injection".to_string(),
            }],
            libraries: vec!["kernel32.dll".to_string(), "ntdll.dll".to_string()],
            imports_per_kb: None,
            import_ratio_suspicious: None,
        };

        let json = serde_json::to_string_pretty(&imports).unwrap();
        assert!(json.contains("42"));
        assert!(json.contains("VirtualAllocEx"));
        assert!(json.contains("kernel32.dll"));
    }

    #[test]
    fn test_pe_analysis_serialization() {
        let pe = PEAnalysis {
            architecture: "PE32+ (64-bit)".to_string(),
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
                dll_count: 3,
                total_imports: 25,
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
        };

        let json = serde_json::to_string_pretty(&pe).unwrap();
        assert!(json.contains("PE32+"));
        assert!(json.contains("0x140000000"));
        assert!(json.contains("true"));
    }

    #[test]
    fn test_optional_fields_omitted() {
        // Test that None fields don't appear in JSON
        let result = AnalysisResult {
            file_info: FileInfo {
                path: "test.bin".to_string(),
                size_bytes: 100,
                size_kb: 0.1,
                extension: None, // Should be omitted
                mime_type: None,
            },
            hashes: Hashes {
                md5: "test".to_string(),
                sha1: "test".to_string(),
                sha256: "test".to_string(),
                tlsh: None,
            },
            entropy: EntropyInfo {
                value: 0.0,
                category: "Low".to_string(),
                is_suspicious: false,
            },
            strings: StringsInfo {
                min_length: 4,
                total_count: 0,
                samples: vec![],
                sample_count: 0,
                classified: None,
            },
            pe_analysis: None,  // Should be omitted
            elf_analysis: None, // Should be omitted
            file_format: "Unknown".to_string(),
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
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("pe_analysis"));
        assert!(!json.contains("elf_analysis"));
        assert!(!json.contains("extension"));
    }

    #[test]
    fn test_json_deserialize_roundtrip() {
        // Test that we can serialize and deserialize
        let original = Hashes {
            md5: "abc".to_string(),
            sha1: "def".to_string(),
            sha256: "ghi".to_string(),
            tlsh: None,
        };

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Hashes = serde_json::from_str(&json).unwrap();

        assert_eq!(original.md5, deserialized.md5);
        assert_eq!(original.sha1, deserialized.sha1);
        assert_eq!(original.sha256, deserialized.sha256);
    }

    #[test]
    fn test_pretty_print_formatting() {
        let hashes = Hashes {
            md5: "test".to_string(),
            sha1: "test".to_string(),
            sha256: "test".to_string(),
            tlsh: None,
        };

        let pretty = serde_json::to_string_pretty(&hashes).unwrap();

        // Should have newlines and indentation
        assert!(pretty.contains('\n'));
        assert!(pretty.lines().count() > 1);
    }
}
