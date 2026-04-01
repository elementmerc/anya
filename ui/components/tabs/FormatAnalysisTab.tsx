import { AlertTriangle, CheckCircle, FileCode, Archive, FileImage, Link2, Disc, Package } from "lucide-react";
import AnimatedEmptyState from "@/components/AnimatedEmptyState";
import type { AnalysisResult } from "@/types/analysis";

interface Props {
  result: AnalysisResult;
}

// ── Shared card components ───────────────────────────────────────────────────

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <h2 style={{
      margin: "0 0 14px",
      fontSize: "var(--font-size-xs)",
      fontWeight: 600,
      textTransform: "uppercase",
      letterSpacing: "0.08em",
      color: "var(--text-muted)",
    }}>
      {children}
    </h2>
  );
}

function InfoRow({ label, value, warn }: { label: string; value: React.ReactNode; warn?: boolean }) {
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "flex-start", padding: "4px 0" }}>
      <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", minWidth: 120, flexShrink: 0 }}>{label}</span>
      <span style={{
        fontSize: "var(--font-size-xs)",
        fontFamily: "var(--font-mono)",
        color: warn ? "var(--risk-high)" : "var(--text-secondary)",
        wordBreak: "break-all",
        fontWeight: warn ? 600 : 400,
      }}>
        {value}
      </span>
    </div>
  );
}

function BoolRow({ label, value, warnWhenTrue = true }: { label: string; value: boolean; warnWhenTrue?: boolean }) {
  const isWarn = warnWhenTrue ? value : !value;
  return (
    <InfoRow
      label={label}
      value={
        <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
          {isWarn
            ? <AlertTriangle size={11} style={{ color: "var(--risk-high)" }} />
            : <CheckCircle size={11} style={{ color: "var(--risk-low)" }} />}
          {value ? "Yes" : "No"}
        </span>
      }
      warn={isWarn}
    />
  );
}

function PatternList({ items, label }: { items: string[]; label: string }) {
  if (items.length === 0) return null;
  return (
    <div style={{ marginTop: 8 }}>
      <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>{label}:</span>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 4 }}>
        {items.map((item, i) => (
          <span key={i} style={{
            fontSize: "var(--font-size-xs)",
            fontFamily: "var(--font-mono)",
            padding: "2px 8px",
            borderRadius: 4,
            background: "rgba(239,68,68,0.08)",
            color: "var(--risk-high)",
            border: "1px solid rgba(239,68,68,0.2)",
          }}>
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}

function FormatCard({ title, icon: Icon, children }: { title: string; icon: typeof FileCode; children: React.ReactNode }) {
  return (
    <div style={{
      background: "var(--bg-surface)",
      border: "1px solid var(--border)",
      borderRadius: "var(--radius)",
      padding: 20,
      display: "flex",
      flexDirection: "column",
      gap: 8,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
        <Icon size={16} style={{ color: "var(--accent)", flexShrink: 0 }} />
        <span style={{ fontSize: "var(--font-size-sm)", fontWeight: 600, color: "var(--text-primary)" }}>{title}</span>
      </div>
      {children}
    </div>
  );
}

// ── Format-specific sections ─────────────────────────────────────────────────

function JavaScriptSection({ result }: Props) {
  const a = result.javascript_analysis;
  if (!a) return null;
  return (
    <FormatCard title="JavaScript Analysis" icon={FileCode}>
      <InfoRow label="Obfuscation" value={`${a.obfuscation_score}/100`} warn={a.obfuscation_score > 30} />
      <BoolRow label="eval() usage" value={a.has_eval} />
      <BoolRow label="ActiveX objects" value={a.has_activex} />
      <BoolRow label="WScript access" value={a.has_wscript} />
      <InfoRow label="Encoded payloads" value={a.encoded_payloads} warn={a.encoded_payloads > 0} />
      <PatternList items={a.suspicious_patterns} label="Suspicious patterns" />
    </FormatCard>
  );
}

function PowerShellSection({ result }: Props) {
  const a = result.powershell_analysis;
  if (!a) return null;
  return (
    <FormatCard title="PowerShell Analysis" icon={FileCode}>
      <BoolRow label="Encoded command" value={a.has_encoded_command} />
      <BoolRow label="Download cradle" value={a.has_download_cradle} />
      <BoolRow label="AMSI bypass" value={a.has_amsi_bypass} />
      <BoolRow label="Reflection usage" value={a.has_reflection} />
      <PatternList items={a.suspicious_cmdlets} label="Suspicious cmdlets" />
      <PatternList items={a.obfuscation_indicators} label="Obfuscation indicators" />
    </FormatCard>
  );
}

function VbScriptSection({ result }: Props) {
  const a = result.vbscript_analysis;
  if (!a) return null;
  return (
    <FormatCard title="VBScript Analysis" icon={FileCode}>
      <BoolRow label="Shell execution" value={a.has_shell_exec} />
      <BoolRow label="WMI access" value={a.has_wmi} />
      <BoolRow label="Download capability" value={a.has_download} />
      <InfoRow label="Chr() chains" value={a.chr_chain_count} warn={a.chr_chain_count > 3} />
      <InfoRow label="Obfuscation" value={`${a.obfuscation_score}/100`} warn={a.obfuscation_score > 30} />
      <PatternList items={a.suspicious_patterns} label="Suspicious patterns" />
    </FormatCard>
  );
}

function ShellScriptSection({ result }: Props) {
  const a = result.shell_script_analysis;
  if (!a) return null;
  return (
    <FormatCard title={`Shell Script Analysis (${a.script_type})`} icon={FileCode}>
      <BoolRow label="Download + execute" value={a.has_download_execute} />
      <BoolRow label="Persistence" value={a.has_persistence} />
      <BoolRow label="Privilege escalation" value={a.has_privilege_escalation} />
      <PatternList items={a.suspicious_commands} label="Suspicious commands" />
    </FormatCard>
  );
}

function PythonSection({ result }: Props) {
  const a = result.python_analysis;
  if (!a) return null;
  return (
    <FormatCard title="Python Analysis" icon={FileCode}>
      <BoolRow label="exec/eval usage" value={a.has_exec_eval} />
      <BoolRow label="subprocess calls" value={a.has_subprocess} />
      <BoolRow label="Network access" value={a.has_network} />
      <BoolRow label="Native code loading" value={a.has_native_code} />
      <PatternList items={a.suspicious_imports} label="Suspicious imports" />
      <PatternList items={a.obfuscation_indicators} label="Obfuscation indicators" />
    </FormatCard>
  );
}

function OleSection({ result }: Props) {
  const a = result.ole_analysis;
  if (!a) return null;
  return (
    <FormatCard title="OLE Document Analysis" icon={FileCode}>
      <BoolRow label="Contains macros" value={a.has_macros} />
      <BoolRow label="Auto-execute macros" value={a.has_auto_execute} />
      <BoolRow label="Embedded objects" value={a.has_embedded_objects} />
      {a.macro_stream_names.length > 0 && (
        <PatternList items={a.macro_stream_names} label="Macro streams" />
      )}
      <PatternList items={a.suspicious_keywords} label="Suspicious keywords" />
    </FormatCard>
  );
}

function RtfSection({ result }: Props) {
  const a = result.rtf_analysis;
  if (!a) return null;
  return (
    <FormatCard title="RTF Analysis" icon={FileCode}>
      <BoolRow label="Embedded objects" value={a.has_embedded_objects} />
      <BoolRow label="Object data streams" value={a.has_objdata} />
      <BoolRow label="Contains PE bytes" value={a.contains_pe_bytes} />
      <PatternList items={a.suspicious_control_words} label="Suspicious control words" />
    </FormatCard>
  );
}

function ZipSection({ result }: Props) {
  const a = result.zip_analysis;
  if (!a) return null;
  return (
    <FormatCard title="ZIP Archive Analysis" icon={Archive}>
      <InfoRow label="Entry count" value={a.entry_count} />
      <BoolRow label="Contains executables" value={a.has_executables} />
      <BoolRow label="Encrypted entries" value={a.has_encrypted_entries} />
      <BoolRow label="Double extensions" value={a.has_double_extensions} />
      <BoolRow label="Path traversal" value={a.has_path_traversal} />
      <InfoRow label="Compression ratio" value={`${a.compression_ratio.toFixed(1)}x`} warn={a.compression_ratio > 100} />
      {a.executable_names.length > 0 && (
        <PatternList items={a.executable_names} label="Executable entries" />
      )}
      <PatternList items={a.suspicious_entries} label="Suspicious entries" />
    </FormatCard>
  );
}

function HtmlSection({ result }: Props) {
  const a = result.html_analysis;
  if (!a) return null;
  return (
    <FormatCard title="HTML / HTA Analysis" icon={FileCode}>
      <InfoRow label="Script tags" value={a.script_count} warn={a.script_count > 3} />
      <BoolRow label="Event handlers" value={a.has_event_handlers} />
      <BoolRow label="Hidden iframes" value={a.has_hidden_iframes} />
      <BoolRow label="Embedded objects" value={a.has_embedded_objects} />
      <BoolRow label="Form actions" value={a.has_form_actions} />
      <BoolRow label="Meta refresh" value={a.has_meta_refresh} />
      <BoolRow label="Data URIs" value={a.has_data_uris} />
      <PatternList items={a.suspicious_elements} label="Suspicious elements" />
    </FormatCard>
  );
}

function XmlSection({ result }: Props) {
  const a = result.xml_analysis;
  if (!a) return null;
  return (
    <FormatCard title="XML / SVG Analysis" icon={FileCode}>
      <BoolRow label="DTD declaration" value={a.has_dtd} />
      <BoolRow label="External entities (XXE)" value={a.has_external_entities} />
      <BoolRow label="XSLT scripts" value={a.has_xslt_scripts} />
      <BoolRow label="SVG with code" value={a.is_svg_with_code} />
      <PatternList items={a.suspicious_elements} label="Suspicious elements" />
    </FormatCard>
  );
}

function ImageSection({ result }: Props) {
  const a = result.image_analysis;
  if (!a) return null;
  return (
    <FormatCard title="Image Analysis" icon={FileImage}>
      <BoolRow label="Trailing data" value={a.has_trailing_data} />
      {a.has_trailing_data && (
        <InfoRow label="Trailing size" value={`${a.trailing_data_size.toLocaleString()} bytes`} warn />
      )}
      <BoolRow label="Suspicious metadata" value={a.has_suspicious_metadata} />
      <BoolRow label="Embedded URLs" value={a.has_embedded_urls} />
      <PatternList items={a.metadata_strings} label="Metadata strings" />
    </FormatCard>
  );
}

function LnkSection({ result }: Props) {
  const a = result.lnk_analysis;
  if (!a) return null;
  return (
    <FormatCard title="Windows Shortcut (LNK) Analysis" icon={Link2}>
      <InfoRow label="Target" value={a.target_path} warn={a.has_suspicious_target} />
      {a.arguments && <InfoRow label="Arguments" value={a.arguments} warn={a.has_encoded_args} />}
      {a.icon_location && <InfoRow label="Icon" value={a.icon_location} />}
      <BoolRow label="Suspicious target" value={a.has_suspicious_target} />
      <BoolRow label="Encoded arguments" value={a.has_encoded_args} />
      <PatternList items={a.suspicious_indicators} label="Indicators" />
    </FormatCard>
  );
}

function IsoSection({ result }: Props) {
  const a = result.iso_analysis;
  if (!a) return null;
  return (
    <FormatCard title="ISO Disk Image Analysis" icon={Disc}>
      {a.volume_label && <InfoRow label="Volume label" value={a.volume_label} />}
      <InfoRow label="File count" value={a.file_count} />
      <BoolRow label="Contains executables" value={a.has_executables} />
      <BoolRow label="AutoRun.inf" value={a.has_autorun} />
      {a.executable_names.length > 0 && (
        <PatternList items={a.executable_names} label="Executable files" />
      )}
      <PatternList items={a.suspicious_entries} label="Suspicious entries" />
    </FormatCard>
  );
}

function CabSection({ result }: Props) {
  const a = result.cab_analysis;
  if (!a) return null;
  return (
    <FormatCard title="CAB Archive Analysis" icon={Package}>
      <InfoRow label="File count" value={a.file_count} />
      <BoolRow label="Contains executables" value={a.has_executables} />
      <InfoRow label="Uncompressed size" value={`${(a.total_uncompressed_size / 1024).toFixed(1)} KB`} />
      {a.executable_names.length > 0 && (
        <PatternList items={a.executable_names} label="Executable entries" />
      )}
    </FormatCard>
  );
}

function MsiSection({ result }: Props) {
  const a = result.msi_analysis;
  if (!a) return null;
  return (
    <FormatCard title="MSI Installer Analysis" icon={Package}>
      <BoolRow label="Custom actions" value={a.has_custom_actions} />
      <BoolRow label="Embedded binaries" value={a.has_embedded_binaries} />
      {a.custom_action_types.length > 0 && (
        <PatternList items={a.custom_action_types} label="Action types" />
      )}
      <PatternList items={a.suspicious_properties} label="Suspicious properties" />
    </FormatCard>
  );
}

function PdfSection({ result }: Props) {
  const a = result.pdf_analysis;
  if (!a) return null;
  return (
    <FormatCard title="PDF Analysis" icon={FileCode}>
      {a.dangerous_objects.length > 0 && (
        <PatternList items={a.dangerous_objects} label="Dangerous objects" />
      )}
      {a.risk_indicators.length > 0 && (
        <PatternList items={a.risk_indicators} label="Risk indicators" />
      )}
      {a.dangerous_objects.length === 0 && a.risk_indicators.length === 0 && (
        <span style={{ fontSize: "var(--font-size-xs)", color: "var(--risk-low)" }}>No dangerous objects detected</span>
      )}
    </FormatCard>
  );
}

function OfficeSection({ result }: Props) {
  const a = result.office_analysis;
  if (!a) return null;
  return (
    <FormatCard title="Office Document Analysis" icon={FileCode}>
      <BoolRow label="Contains macros" value={a.has_macros} />
      <BoolRow label="Embedded objects" value={a.has_embedded_objects} />
      <BoolRow label="External links" value={a.has_external_links} />
      <PatternList items={a.suspicious_components} label="Suspicious components" />
    </FormatCard>
  );
}

// ── Helper: check if any format-specific analysis exists ─────────────────────

export function hasFormatAnalysis(result: AnalysisResult): boolean {
  return !!(
    result.javascript_analysis ||
    result.powershell_analysis ||
    result.vbscript_analysis ||
    result.shell_script_analysis ||
    result.python_analysis ||
    result.ole_analysis ||
    result.rtf_analysis ||
    result.zip_analysis ||
    result.html_analysis ||
    result.xml_analysis ||
    result.image_analysis ||
    result.lnk_analysis ||
    result.iso_analysis ||
    result.cab_analysis ||
    result.msi_analysis ||
    result.pdf_analysis ||
    result.office_analysis
  );
}

// ── Main component ───────────────────────────────────────────────────────────

export default function FormatAnalysisTab({ result }: Props) {
  if (!hasFormatAnalysis(result)) {
    return <AnimatedEmptyState icon="file-search" title="No format-specific analysis" subtitle="This file type doesn't have a dedicated parser. Standard heuristics were applied." />;
  }

  return (
    <div style={{ height: "100%", overflow: "auto", padding: 24 }}>
      <div style={{ maxWidth: 1600, margin: "0 auto", display: "flex", flexDirection: "column", gap: 24 }}>
        <SectionHeader>Format-Specific Analysis</SectionHeader>

        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 360px), 1fr))",
          gap: 16,
        }}>
          <JavaScriptSection result={result} />
          <PowerShellSection result={result} />
          <VbScriptSection result={result} />
          <ShellScriptSection result={result} />
          <PythonSection result={result} />
          <OleSection result={result} />
          <RtfSection result={result} />
          <ZipSection result={result} />
          <HtmlSection result={result} />
          <XmlSection result={result} />
          <ImageSection result={result} />
          <LnkSection result={result} />
          <IsoSection result={result} />
          <CabSection result={result} />
          <MsiSection result={result} />
          <PdfSection result={result} />
          <OfficeSection result={result} />
        </div>
      </div>
    </div>
  );
}
