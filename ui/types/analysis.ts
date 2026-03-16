// TypeScript types mirroring the Rust output structs in src/output.rs
// Keep in sync with any struct changes.

export interface Hashes {
  md5: string;
  sha1: string;
  sha256: string;
  tlsh?: string;
}

export interface EntropyInfo {
  value: number;
  category: string;
  is_suspicious: boolean;
}

export interface StringsInfo {
  min_length: number;
  total_count: number;
  samples: string[];
  sample_count: number;
  classified?: ClassifiedString[];
}

export interface ClassifiedString {
  value: string;
  category: string;
  offset?: string;
}

export interface SecurityFeatures {
  aslr_enabled: boolean;
  dep_enabled: boolean;
}

export interface SectionInfo {
  name: string;
  virtual_size: number;
  virtual_address: string;
  raw_size: number;
  entropy: number;
  is_suspicious: boolean;
  is_wx: boolean;
  name_anomaly?: string;
}

export interface SuspiciousAPI {
  name: string;
  category: string;
}

export interface ImportAnalysis {
  dll_count: number;
  total_imports: number;
  suspicious_api_count: number;
  suspicious_apis: SuspiciousAPI[];
  libraries: string[];
  imports_per_kb?: number;
  import_ratio_suspicious?: boolean;
}

export interface ExportInfo {
  name: string;
  rva: string;
}

export interface ExportAnalysis {
  total_count: number;
  samples: ExportInfo[];
}

export interface ChecksumInfo {
  stored: number;
  computed: number;
  valid: boolean;
  stored_nonzero: boolean;
}

export interface RichEntry {
  product_id: number;
  build_number: number;
  use_count: number;
  product_name?: string;
}

export interface RichHeaderInfo {
  xor_key: number;
  entries: RichEntry[];
}

export interface TlsInfo {
  callback_count: number;
  callback_rvas: string[];
}

export interface OverlayInfo {
  offset: number;
  size: number;
  entropy: number;
  high_entropy: boolean;
  overlay_mime_type?: string;
  overlay_characterisation?: string;
}

export interface CompilerInfo {
  name: string;
  /** "High" | "Medium" | "Low" */
  confidence: string;
}

export interface PackerFinding {
  name: string;
  /** "High" | "Medium" | "Low" */
  confidence: string;
  /** "String" | "SectionName" | "Entropy" | "Heuristic" */
  detection_method: string;
}

export interface AntiAnalysisFinding {
  /** "VmDetection" | "DebuggerDetection" | "TimingCheck" | "SandboxDetection" */
  category: string;
  indicator: string;
}

export interface OrdinalImport {
  dll: string;
  ordinal: number;
}

export interface AuthenticodeInfo {
  present: boolean;
  signer_cn?: string;
  issuer_cn?: string;
  is_microsoft_signed: boolean;
  cert_size: number;
  status?: string;
  issuer?: string;
  not_after?: string;
}

export interface VersionInfo {
  company_name?: string;
  product_name?: string;
  file_description?: string;
  file_version?: string;
  original_filename?: string;
  legal_copyright?: string;
}

export interface PEAnalysis {
  architecture: string;
  is_64bit: boolean;
  image_base: string;
  entry_point: string;
  file_type: string;
  security: SecurityFeatures;
  sections: SectionInfo[];
  imports: ImportAnalysis;
  exports?: ExportAnalysis;
  imphash?: string;
  checksum?: ChecksumInfo;
  rich_header?: RichHeaderInfo;
  tls?: TlsInfo;
  overlay?: OverlayInfo;
  compiler?: CompilerInfo;
  packers: PackerFinding[];
  anti_analysis: AntiAnalysisFinding[];
  ordinal_imports: OrdinalImport[];
  authenticode?: AuthenticodeInfo;
  version_info?: VersionInfo;
  debug_artifacts?: DebugArtifacts;
  weak_crypto?: WeakCryptoIndicator[];
  compiler_deps?: CompilerDep[];
}

export interface DebugArtifacts {
  pdb_path?: string;
  timestamp_zeroed: boolean;
  version_info_suspicious: boolean;
}

export interface WeakCryptoIndicator {
  name: string;
  evidence: string;
  offset?: string;
}

export interface CompilerDep {
  name: string;
  description: string;
  risk: string;
}

export interface ElfSectionInfo {
  name: string;
  section_type: string;
  size: number;
  entropy: number;
  is_wx: boolean;
  is_suspicious: boolean;
}

export interface ElfImportAnalysis {
  library_count: number;
  libraries: string[];
  dynamic_symbol_count: number;
  suspicious_functions: SuspiciousAPI[];
}

export interface ELFAnalysis {
  architecture: string;
  is_64bit: boolean;
  file_type: string;
  entry_point: string;
  interpreter?: string;
  sections: ElfSectionInfo[];
  imports: ElfImportAnalysis;
  is_pie: boolean;
  has_nx_stack: boolean;
  has_relro: boolean;
  is_stripped: boolean;
  packer_indicators: PackerFinding[];
  // New A1/A5 fields
  got_plt_suspicious?: string[];
  rpath_anomalies?: string[];
  has_dwarf_info?: boolean;
  interpreter_suspicious?: boolean;
  suspicious_section_names?: string[];
  suspicious_libc_calls?: SuspiciousLibcCall[];
}

export interface FileInfo {
  path: string;
  size_bytes: number;
  size_kb: number;
  extension?: string;
  mime_type?: string;
}

// ── New analysis engine types ─────────────────────────────────────────────────

export type ConfidenceLevel = "Low" | "Medium" | "High" | "Critical";

export interface MitreTechnique {
  technique_id: string;
  sub_technique_id?: string;
  technique_name: string;
  tactic: string;
  source_indicator: string;
  confidence: ConfidenceLevel;
}

export interface PlainEnglishFinding {
  title: string;
  explanation: string;
  why_suspicious: string;
  malware_families: string[];
  mitre_technique_id?: string;
  confidence: ConfidenceLevel;
}

export interface AntiAnalysisIndicator {
  technique: string;
  evidence: string;
  confidence: ConfidenceLevel;
  mitre_technique_id: string;
}

export interface PackerDetection {
  name: string;
  confidence: ConfidenceLevel;
  method: string;
  evidence: string;
}

export interface CompilerDetection {
  compiler: string;
  language: string;
  confidence: ConfidenceLevel;
  evidence: string[];
}

export interface TlsCallback {
  virtual_address: string;
  raw_offset: number;
}

export interface SuspiciousLibcCall {
  name: string;
  category: string;
  description: string;
  mitre_technique_id: string;
  confidence: ConfidenceLevel;
}

export interface AnalysisResult {
  file_info: FileInfo;
  hashes: Hashes;
  entropy: EntropyInfo;
  strings: StringsInfo;
  pe_analysis?: PEAnalysis;
  elf_analysis?: ELFAnalysis;
  file_format: string;
  // New analysis engine fields
  imphash?: string;
  checksum_valid?: boolean;
  tls_callbacks?: TlsCallback[];
  ordinal_imports?: OrdinalImport[];
  overlay?: OverlayInfo;
  packer_detections?: PackerDetection[];
  compiler_detection?: CompilerDetection;
  anti_analysis_indicators?: AntiAnalysisIndicator[];
  mitre_techniques?: MitreTechnique[];
  confidence_scores?: Record<string, ConfidenceLevel>;
  plain_english_findings?: PlainEnglishFinding[];
  byte_histogram?: number[];
}

/** Wrapper returned by the analyze_file Tauri command */
export interface AnalyzeResponse {
  result: AnalysisResult;
  risk_score: number;
  is_suspicious: boolean;
}

export interface AppSettings {
  db_path: string;
  theme: "dark" | "light";
  font_size?: "small" | "default" | "large" | "xl";
  /** Always false — hard-coded off, never settable */
  telemetry_enabled: false;
  bible_verses_enabled?: boolean;
}

export interface StoredAnalysis {
  id: number;
  file_name: string;
  file_path: string;
  file_hash: string;
  analysed_at: string;
  risk_score: number;
  result_json: string;
}

export type TabName =
  | "overview"
  | "entropy"
  | "imports"
  | "sections"
  | "strings"
  | "security"
  | "mitre";

export type RiskLevel = "low" | "medium" | "high" | "critical";

// ── Teacher Mode lesson type (mirrors Rust Lesson struct from Tauri command) ──

export interface GlossaryTerm {
  term: string;
  definition: string;
}

export interface LessonContent {
  summary: string;
  explanation: string;
  what_to_look_for: string;
  real_world_example: string;
  next_action: string;
  glossary: GlossaryTerm[];
}

export interface TriggeredLesson {
  id: string;
  title: string;
  category: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  content: LessonContent;
  next_steps: string[];
}

export type StringType = "url" | "ip" | "path" | "registry" | "suspicious" | "default";
