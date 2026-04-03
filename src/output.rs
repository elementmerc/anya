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

fn default_schema_version() -> String {
    ANALYSIS_SCHEMA_VERSION.to_string()
}

// Re-export scoring types from anya-scoring so existing code continues to work
pub use anya_scoring::types::{
    ConfidenceLevel, ExtractedString, IocSummary, IocType, MismatchSeverity,
};

/// Schema version for forward/backward compatibility.
/// Bump when fields are added, renamed, or semantics change.
pub const ANALYSIS_SCHEMA_VERSION: &str = "2.0.0";

/// Complete analysis result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisResult {
    /// Schema version — readers can check this before attempting deserialization.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

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
    pub byte_histogram: Option<Vec<u64>>,

    /// File type mismatch between extension and detected magic bytes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_type_mismatch: Option<FileTypeMismatch>,

    /// IOC (Indicator of Compromise) extraction results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioc_summary: Option<IocSummary>,

    /// Human-readable verdict summary (e.g. "MALICIOUS — 4 critical indicators, 2 high")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_summary: Option<String>,

    /// Top N findings by confidence (for summary display)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_findings: Vec<TopFinding>,

    /// Known Sample Database match (TLSH similarity to known malware)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ksd_match: Option<anya_scoring::ksd::KsdMatch>,

    /// Forensic fragment annotation (for sub-100B files associated with known malware)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forensic_fragment: Option<ForensicFragment>,

    /// Known sample match (tool, PUP, or test file — overrides heuristic verdict)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_sample: Option<KnownSampleMatch>,

    /// Family annotation from the malware family context database
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_annotation: Option<FamilyAnnotation>,

    /// Mach-O binary analysis (if applicable)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mach_analysis: Option<MachoAnalysis>,

    /// PDF dangerous object analysis (if applicable)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdf_analysis: Option<PdfAnalysis>,

    /// Office document macro/embedding analysis (if applicable)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub office_analysis: Option<OfficeAnalysis>,

    // ── Script format analysis ────────────────────────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub javascript_analysis: Option<JavaScriptAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub powershell_analysis: Option<PowerShellAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vbscript_analysis: Option<VbScriptAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_script_analysis: Option<ShellScriptAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python_analysis: Option<PythonAnalysis>,

    // ── Document & archive format analysis ────────────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ole_analysis: Option<OleAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtf_analysis: Option<RtfAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zip_analysis: Option<ZipAnalysis>,

    // ── Media, markup & misc format analysis ──────────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html_analysis: Option<HtmlAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xml_analysis: Option<XmlAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_analysis: Option<ImageAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lnk_analysis: Option<LnkAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso_analysis: Option<IsoAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cab_analysis: Option<CabAnalysis>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msi_analysis: Option<MsiAnalysis>,

    /// YARA rule match results (requires `yara` feature)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub yara_matches: Vec<YaraMatchResult>,
}

/// A YARA rule that matched during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatchResult {
    /// Rule identifier (e.g. "APT_Lazarus_Loader")
    pub rule_name: String,
    /// Rule namespace / source file
    pub namespace: String,
    /// Rule description from meta section
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Rule author from meta section
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Tags attached to the rule
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Matched strings with their identifiers and offsets
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_strings: Vec<YaraStringMatch>,
}

/// A single string match within a YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringMatch {
    /// String identifier (e.g. "$s0", "$hex1")
    pub identifier: String,
    /// Byte offset where the match occurred
    pub offset: u64,
    /// Length of the match in bytes
    pub length: u64,
    /// Matched data (truncated to 64 bytes, hex-encoded for binary safety)
    pub data_preview: String,
}

/// A single top finding for JSON output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopFinding {
    pub label: String,
    pub confidence: ConfidenceLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technique_id: Option<String>,
}

/// File metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EntropyInfo {
    /// Shannon entropy value (0.0 - 8.0)
    pub value: f64,

    /// Interpretation category
    pub category: String,

    /// Is suspicious (> 7.5)
    pub is_suspicious: bool,

    /// Confidence level for the entropy assessment
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ConfidenceLevel>,
}

/// String extraction results
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

    /// Reason string extraction was suppressed (e.g. for image files)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed_reason: Option<String>,
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

    /// PE structural anomalies (tampered headers, packing indicators)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<PeAnomaly>,

    /// True if this is a .NET assembly (CLR data directory present)
    #[serde(default)]
    pub is_dotnet: bool,

    /// Composite packed heuristic score (0-100+)
    #[serde(default)]
    pub packed_score: u32,

    /// True if delay-load import directory has entries
    #[serde(default)]
    pub has_delay_imports: bool,

    /// Suspicious import DLL patterns: benign DLL names importing unexpected functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spoofed_imports: Vec<String>,

    /// Embedded executable found in resources
    #[serde(default)]
    pub resource_has_exe: bool,

    /// High-entropy resource section (> 7.0)
    #[serde(default)]
    pub resource_high_entropy: bool,

    /// Resource section > 50% of file size
    #[serde(default)]
    pub resource_oversized: bool,

    /// Executable found in overlay data
    #[serde(default)]
    pub overlay_has_exe: bool,

    /// Strings per KB (low density = likely packed)
    #[serde(default)]
    pub string_density: f64,

    /// .NET metadata analysis (only for .NET assemblies)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dotnet_metadata: Option<crate::dotnet_parser::DotNetMetadata>,
}

/// A PE structural anomaly detected during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnomaly {
    /// Machine-readable identifier
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Severity: "High", "Medium", "Low"
    pub severity: String,
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

    /// Confidence level for checksum finding
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ConfidenceLevel>,
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

    /// Confidence level for overlay finding
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ConfidenceLevel>,
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

    /// MD5 hash of section raw data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,

    /// Confidence that this section is suspicious
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ConfidenceLevel>,
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

    /// Confidence level for this detection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ConfidenceLevel>,

    /// DLL that exports this API (for graph visualization)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dll: Option<String>,
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

// ConfidenceLevel, IocType, MismatchSeverity, ExtractedString, and IocSummary
// are now defined in anya-scoring::types and re-exported above.

/// A mismatch between the file's detected type (magic bytes) and its claimed extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTypeMismatch {
    /// Format detected from magic bytes (e.g. "PE/MZ executable")
    pub detected_type: String,
    /// File extension as claimed by the filename
    pub claimed_extension: String,
    /// Severity of the mismatch
    pub severity: MismatchSeverity,
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
// File-type-specific analysis structures
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

/// Mach-O binary analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachoAnalysis {
    pub architecture: String,
    pub is_64bit: bool,
    pub entry_point: String,
    pub dylib_imports: Vec<String>,
    pub has_code_signature: bool,
    pub pie_enabled: bool,
    pub nx_enabled: bool,
}

/// PDF dangerous object analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfAnalysis {
    pub dangerous_objects: Vec<String>,
    pub risk_indicators: Vec<String>,
}

/// Office document macro/embedding analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficeAnalysis {
    pub has_macros: bool,
    pub has_embedded_objects: bool,
    pub has_external_links: bool,
    pub suspicious_components: Vec<String>,
}

/// Forensic fragment — annotation for sub-100B files associated with known malware.
/// This is NOT a detection — the file is not independently malicious.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicFragment {
    /// Associated malware family from KSD match
    pub associated_family: String,
    /// Brief explanation
    pub explanation: String,
}

/// Known sample match — overrides heuristic verdict for tools, PUPs, and test files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownSampleMatch {
    /// Verdict override: "TOOL", "PUP", or "TEST"
    pub verdict: String,
    /// Category subtitle (e.g. "Dual-use/Security Tool", "Potentially Unwanted Program", "Test File")
    pub category: String,
    /// Name of the tool/program
    pub name: String,
    /// Description for the analyst
    pub description: String,
}

/// Contextual annotation for a malware family from the family annotations database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyAnnotation {
    pub name: String,
    pub category: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Script analysis structures
// ─────────────────────────────────────────────────────────────────────────────

/// JavaScript / JScript static analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaScriptAnalysis {
    /// Obfuscation heuristic score (0–100)
    pub obfuscation_score: u8,
    /// Suspicious patterns detected (eval, ActiveXObject, etc.)
    pub suspicious_patterns: Vec<String>,
    /// Uses eval() or Function() constructor
    pub has_eval: bool,
    /// Creates ActiveXObject (IE/WScript specific)
    pub has_activex: bool,
    /// References WScript.Shell or WScript.CreateObject
    pub has_wscript: bool,
    /// Count of Base64/hex-encoded payload blobs detected
    pub encoded_payloads: usize,
}

/// PowerShell script static analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellAnalysis {
    /// Uses -EncodedCommand / -enc parameter
    pub has_encoded_command: bool,
    /// Download cradle detected (Invoke-WebRequest, Net.WebClient, etc.)
    pub has_download_cradle: bool,
    /// AMSI bypass pattern detected
    pub has_amsi_bypass: bool,
    /// Uses reflection (Assembly::Load, GetType, etc.)
    pub has_reflection: bool,
    /// Obfuscation indicators (tick-mark insertion, concatenation, etc.)
    pub obfuscation_indicators: Vec<String>,
    /// Suspicious cmdlets found
    pub suspicious_cmdlets: Vec<String>,
}

/// VBScript / VBA static analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbScriptAnalysis {
    /// Shell execution detected (WScript.Shell, Shell.Run, etc.)
    pub has_shell_exec: bool,
    /// WMI access detected (GetObject winmgmts)
    pub has_wmi: bool,
    /// Download capability detected (XMLHTTP, ADODB.Stream)
    pub has_download: bool,
    /// Count of Chr() concatenation chains (obfuscation)
    pub chr_chain_count: usize,
    /// Obfuscation heuristic score (0–100)
    pub obfuscation_score: u8,
    /// Suspicious patterns found
    pub suspicious_patterns: Vec<String>,
}

/// Batch / Shell script static analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellScriptAnalysis {
    /// "batch" | "shell" | "unknown"
    pub script_type: String,
    /// Download-then-execute pattern (certutil, curl|bash, etc.)
    pub has_download_execute: bool,
    /// Persistence mechanism (schtasks, crontab, etc.)
    pub has_persistence: bool,
    /// Privilege escalation commands
    pub has_privilege_escalation: bool,
    /// Suspicious commands found
    pub suspicious_commands: Vec<String>,
}

/// Python script static analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonAnalysis {
    /// Uses exec()/eval()/compile()
    pub has_exec_eval: bool,
    /// Uses subprocess/os.system/os.popen
    pub has_subprocess: bool,
    /// Uses socket/urllib/requests
    pub has_network: bool,
    /// Uses ctypes (native code loading)
    pub has_native_code: bool,
    /// Obfuscation indicators
    pub obfuscation_indicators: Vec<String>,
    /// Suspicious import names
    pub suspicious_imports: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Document & archive analysis structures
// ─────────────────────────────────────────────────────────────────────────────

/// OLE Compound Document analysis (Office 97-2003 .doc/.xls/.ppt)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OleAnalysis {
    /// VBA macro streams found
    pub has_macros: bool,
    /// Auto-execute entry points (AutoOpen, Document_Open, etc.)
    pub has_auto_execute: bool,
    /// Names of macro-containing streams
    pub macro_stream_names: Vec<String>,
    /// Embedded OLE objects found
    pub has_embedded_objects: bool,
    /// Suspicious keywords found in macro streams
    pub suspicious_keywords: Vec<String>,
}

/// RTF document analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtfAnalysis {
    /// Embedded objects detected (\objocx, \objemb, \objlink)
    pub has_embedded_objects: bool,
    /// \objdata block present (can contain executables)
    pub has_objdata: bool,
    /// PE header (MZ) found inside \objdata hex stream
    pub contains_pe_bytes: bool,
    /// Suspicious RTF control words
    pub suspicious_control_words: Vec<String>,
}

/// ZIP archive deep analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipAnalysis {
    /// Total number of entries in the archive
    pub entry_count: usize,
    /// Archive contains executable files
    pub has_executables: bool,
    /// Names of executable entries
    pub executable_names: Vec<String>,
    /// Archive contains encrypted/password-protected entries
    pub has_encrypted_entries: bool,
    /// Compression ratio (uncompressed / compressed)
    pub compression_ratio: f64,
    /// Double-extension files detected (e.g., invoice.pdf.exe)
    pub has_double_extensions: bool,
    /// Path traversal entries detected (../)
    pub has_path_traversal: bool,
    /// Other suspicious entries
    pub suspicious_entries: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Media, markup & misc analysis structures
// ─────────────────────────────────────────────────────────────────────────────

/// HTML / HTA file analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtmlAnalysis {
    /// Number of <script> tags found
    pub script_count: usize,
    /// Event handlers with inline code (onload, onerror, etc.)
    pub has_event_handlers: bool,
    /// Hidden iframes detected (width=0 height=0)
    pub has_hidden_iframes: bool,
    /// Embedded objects (Flash, ActiveX, Java applets)
    pub has_embedded_objects: bool,
    /// Form action targets found
    pub has_form_actions: bool,
    /// Meta refresh redirect detected
    pub has_meta_refresh: bool,
    /// Base64-encoded data: URIs found
    pub has_data_uris: bool,
    /// Suspicious elements found
    pub suspicious_elements: Vec<String>,
}

/// XML / SVG file analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmlAnalysis {
    /// DTD declaration present
    pub has_dtd: bool,
    /// External entity references (SYSTEM/PUBLIC — XXE indicator)
    pub has_external_entities: bool,
    /// XSLT with embedded scripts
    pub has_xslt_scripts: bool,
    /// SVG with embedded code (<script>, onload, etc.)
    pub is_svg_with_code: bool,
    /// Suspicious elements found
    pub suspicious_elements: Vec<String>,
}

/// Image file metadata and steganography analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageAnalysis {
    /// Data appended after image EOF marker
    pub has_trailing_data: bool,
    /// Size of trailing data in bytes
    pub trailing_data_size: usize,
    /// Suspicious metadata fields found
    pub has_suspicious_metadata: bool,
    /// Extracted metadata strings of interest
    pub metadata_strings: Vec<String>,
    /// URLs found in metadata or chunks
    pub has_embedded_urls: bool,
}

/// Windows LNK (shortcut) file analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnkAnalysis {
    /// Target path
    pub target_path: String,
    /// Command-line arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    /// Icon file location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_location: Option<String>,
    /// Target is a script interpreter (cmd, powershell, mshta, etc.)
    pub has_suspicious_target: bool,
    /// Arguments contain encoded payloads
    pub has_encoded_args: bool,
    /// Suspicious indicators found
    pub suspicious_indicators: Vec<String>,
}

/// ISO 9660 / disk image analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsoAnalysis {
    /// Volume label
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_label: Option<String>,
    /// Number of files in the image
    pub file_count: usize,
    /// Image contains executable files
    pub has_executables: bool,
    /// Names of executable entries
    pub executable_names: Vec<String>,
    /// AutoRun.inf present
    pub has_autorun: bool,
    /// Suspicious entries found
    pub suspicious_entries: Vec<String>,
}

/// Microsoft CAB archive analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CabAnalysis {
    /// Number of files in the cabinet
    pub file_count: usize,
    /// Contains executable files
    pub has_executables: bool,
    /// Names of executable entries
    pub executable_names: Vec<String>,
    /// Total uncompressed size
    pub total_uncompressed_size: u64,
}

/// MSI installer analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsiAnalysis {
    /// Custom actions present
    pub has_custom_actions: bool,
    /// Embedded binaries in the Binary table
    pub has_embedded_binaries: bool,
    /// Custom action types found
    pub custom_action_types: Vec<String>,
    /// Suspicious property values
    pub suspicious_properties: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────

/// A classified extracted string with category and offset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedString {
    pub value: String,
    /// "URL", "IP", "Path", "Registry", "Suspicious", "Base64",
    /// "CryptoConstant", "Command", "Plain"
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    /// True if this IOC matches known benign infrastructure (CDNs, cloud providers, package registries).
    /// Frontend should grey these out rather than highlighting them as threats.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_benign: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_result_serialization() {
        let result = AnalysisResult {
            schema_version: ANALYSIS_SCHEMA_VERSION.to_string(),
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
                confidence: None,
            },
            strings: StringsInfo {
                min_length: 4,
                total_count: 100,
                samples: vec!["test".to_string(), "sample".to_string()],
                sample_count: 2,
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
            ksd_match: None,
            forensic_fragment: None,
            known_sample: None,
            family_annotation: None,
            top_findings: vec![],
            mach_analysis: None,
            pdf_analysis: None,
            office_analysis: None,
            javascript_analysis: None,
            powershell_analysis: None,
            vbscript_analysis: None,
            shell_script_analysis: None,
            python_analysis: None,
            ole_analysis: None,
            rtf_analysis: None,
            zip_analysis: None,
            html_analysis: None,
            xml_analysis: None,
            image_analysis: None,
            lnk_analysis: None,
            iso_analysis: None,
            cab_analysis: None,
            msi_analysis: None,
            yara_matches: Vec::new(),
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
            confidence: None,
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
            suppressed_reason: None,
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
        assert!(parsed.aslr_enabled);
        assert!(!parsed.dep_enabled);
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
            md5: None,
            confidence: None,
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
            confidence: None,
            dll: Some("kernel32.dll".to_string()),
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
                confidence: None,
                dll: Some("kernel32.dll".to_string()),
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
            anomalies: vec![],
            is_dotnet: false,
            packed_score: 0,
            has_delay_imports: false,
            spoofed_imports: vec![],
            resource_has_exe: false,
            resource_high_entropy: false,
            resource_oversized: false,
            overlay_has_exe: false,
            string_density: 0.0,
            dotnet_metadata: None,
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
            schema_version: ANALYSIS_SCHEMA_VERSION.to_string(),
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
            file_type_mismatch: None,
            ioc_summary: None,
            verdict_summary: None,
            ksd_match: None,
            forensic_fragment: None,
            known_sample: None,
            family_annotation: None,
            top_findings: vec![],
            mach_analysis: None,
            pdf_analysis: None,
            office_analysis: None,
            javascript_analysis: None,
            powershell_analysis: None,
            vbscript_analysis: None,
            shell_script_analysis: None,
            python_analysis: None,
            ole_analysis: None,
            rtf_analysis: None,
            zip_analysis: None,
            html_analysis: None,
            xml_analysis: None,
            image_analysis: None,
            lnk_analysis: None,
            iso_analysis: None,
            cab_analysis: None,
            msi_analysis: None,
            yara_matches: Vec::new(),
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
