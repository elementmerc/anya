import React, { useEffect, useState, useContext } from "react";
import { CheckCircle, XCircle, MinusCircle, ShieldCheck, AlertTriangle } from "lucide-react";
import type { AnalysisResult, AuthenticodeInfo } from "@/types/analysis";
import { formatBytes } from "@/lib/utils";
import { TeacherModeContext } from "@/hooks/useTeacherMode";

interface Props {
  result: AnalysisResult;
  packedEntropy?: number;
}

type CardStatus = "enabled" | "disabled" | "na";

function statusColors(s: CardStatus) {
  switch (s) {
    case "enabled":  return { border: "var(--risk-low)",  icon: "var(--risk-low)",  badge: "rgba(74,222,128,0.12)", badgeText: "var(--risk-low)",  label: "Enabled" };
    case "disabled": return { border: "var(--risk-high)", icon: "var(--risk-high)", badge: "rgba(249,115,22,0.12)", badgeText: "var(--risk-high)", label: "Disabled" };
    case "na":       return { border: "var(--border)",    icon: "var(--text-muted)", badge: "var(--bg-elevated)",   badgeText: "var(--text-muted)", label: "N/A" };
  }
}

function AnimatedIcon({ status }: { status: CardStatus }) {
  const [visible, setVisible] = useState(false);
  useEffect(() => { const t = setTimeout(() => setVisible(true), 200); return () => clearTimeout(t); }, []);
  const c = statusColors(status);
  return (
    <div style={{ opacity: visible ? 1 : 0, transition: "opacity 200ms ease-out", display: "flex", alignItems: "center" }}>
      {status === "enabled"  && <CheckCircle  size={28} style={{ color: c.icon }} />}
      {status === "disabled" && <XCircle      size={28} style={{ color: c.icon }} />}
      {status === "na"       && <MinusCircle  size={28} style={{ color: c.icon }} />}
    </div>
  );
}

function FeatureCard({ title, description, status, children, fullWidth, onClick, clickable }: {
  title: string; description: string; status: CardStatus;
  children?: React.ReactNode; fullWidth?: boolean;
  onClick?: () => void; clickable?: boolean;
}) {
  const c = statusColors(status);
  return (
    <div onClick={onClick} style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderLeft: `3px solid ${c.border}`, borderRadius: "var(--radius)", padding: 20, display: "flex", flexDirection: "column", gap: 12, gridColumn: fullWidth ? "1 / -1" : undefined, cursor: clickable ? "pointer" : "default" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <p style={{ margin: 0, fontSize: "var(--font-size-base)", fontWeight: 500, color: "var(--text-primary)" }}>{title}</p>
          <p style={{ margin: "4px 0 0", fontSize: "var(--font-size-xs)", color: "var(--text-muted)", lineHeight: 1.5 }}>{description}</p>
        </div>
        <span style={{ flexShrink: 0, fontSize: "var(--font-size-xs)", fontWeight: 600, padding: "3px 8px", borderRadius: 999, background: c.badge, color: c.badgeText, whiteSpace: "nowrap" }}>
          {c.label}
        </span>
      </div>
      <div style={{ marginTop: 4, paddingTop: 16, borderTop: "1px solid var(--border-subtle)", display: "flex", alignItems: "flex-start", gap: 12 }}>
        <AnimatedIcon status={status} />
        {children && <div style={{ flex: 1, minWidth: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.5 }}>{children}</div>}
      </div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
      <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", minWidth: 100, flexShrink: 0, paddingTop: 1 }}>{label}</span>
      <span className="selectable" style={{ fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", color: "var(--text-secondary)", wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}

function AuthCard({ auth, onClick, clickable }: { auth: AuthenticodeInfo; onClick?: () => void; clickable?: boolean }) {
  return (
    <FeatureCard title="Authenticode" description="Digital signature verification" status={auth.present ? "enabled" : "disabled"} fullWidth={auth.present && !!(auth.signer_cn || auth.issuer_cn)} onClick={onClick} clickable={clickable}>
      {auth.present ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {auth.is_microsoft_signed && (
            <div style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--risk-low)", fontSize: "var(--font-size-xs)", fontWeight: 500 }}>
              <ShieldCheck size={14} /> Microsoft-signed
            </div>
          )}
          {auth.status && <InfoRow label="Status" value={<span style={{ color: auth.status === "Valid" ? "var(--risk-low)" : "var(--risk-medium)" }}>{auth.status}</span>} />}
          {auth.signer_cn   && <InfoRow label="Signer CN"  value={auth.signer_cn} />}
          {auth.issuer_cn   && <InfoRow label="Issuer CN"  value={auth.issuer_cn} />}
          {auth.issuer      && <InfoRow label="Issuer"     value={auth.issuer} />}
          {auth.not_after   && <InfoRow label="Expires"    value={auth.not_after} />}
          {auth.cert_size > 0 && <InfoRow label="Cert size" value={formatBytes(auth.cert_size)} />}
        </div>
      ) : (
        <span style={{ fontSize: "var(--font-size-xs)", color: "var(--risk-high)" }}>No Authenticode signature found.</span>
      )}
    </FeatureCard>
  );
}

const SECTION_HEADER: React.CSSProperties = { margin: "0 0 14px", fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.08em", color: "var(--text-muted)" };
const GRID: React.CSSProperties = { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 280px), 1fr))", gap: 16 };

class SecurityErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: string | null }> {
  state = { error: null as string | null };
  static getDerivedStateFromError(err: Error) { return { error: err.message }; }
  render() {
    if (this.state.error) return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 8 }}>
        <p style={{ color: "var(--risk-medium)" }}>Security tab encountered an error</p>
        <p style={{ color: "var(--text-muted)", fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)" }}>{this.state.error}</p>
      </div>
    );
    return this.props.children;
  }
}

function SecurityTabInner({ result, packedEntropy = 7.0 }: Props) {
  const teacherMode = useContext(TeacherModeContext);
  const pe  = result?.pe_analysis;
  const elf = result?.elf_analysis;
  const cd  = result?.compiler_detection;

  const versionInfoWide = pe?.version_info
    ? [
        pe.version_info.file_description,
        pe.version_info.product_name,
        pe.version_info.company_name,
        pe.version_info.file_version,
        pe.version_info.original_filename,
        pe.version_info.legal_copyright,
      ].some((v) => v && v.length > 30)
    : false;

  const hasYara = (result?.yara_matches?.length ?? 0) > 0;
  if (!pe && !elf && !cd && !hasYara) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <p style={{ color: "var(--text-muted)" }}>No security feature data available.</p>
      </div>
    );
  }

  const sections = pe?.sections ?? elf?.sections ?? [];
  const hiEntropy = sections.filter((s) => s.entropy != null && s.entropy > packedEntropy);

  return (
    <div style={{ height: "100%", overflow: "auto", padding: 24 }}>
      <div style={{ maxWidth: 1600, margin: "0 auto", display: "flex", flexDirection: "column", gap: 24 }}>

        {pe && (
          <section>
            <h2 style={SECTION_HEADER}>Mitigations</h2>
            <div style={GRID}>
              <FeatureCard title="ASLR"           description="Randomises memory addresses to hinder exploitation"                 status={pe.security?.aslr_enabled ? "enabled" : "disabled"} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "aslr" })} clickable={teacherMode?.enabled} />
              <FeatureCard title="DEP / NX"        description="Prevents execution of data pages"                                   status={pe.security?.dep_enabled ? "enabled" : "disabled"} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "dep" })} clickable={teacherMode?.enabled} />
              <FeatureCard title="High-Entropy VA" description="64-bit ASLR with larger address range"                              status={pe.is_64bit ? "enabled" : "na"} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "aslr" })} clickable={teacherMode?.enabled} />
              {pe.authenticode && <AuthCard auth={pe.authenticode} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "authenticode" })} clickable={teacherMode?.enabled} />}
              <FeatureCard title="Section Entropy" description={`Sections with entropy > ${packedEntropy} may contain compressed or encrypted data`} status={hiEntropy.length > 0 ? "disabled" : "enabled"} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "entropy" })} clickable={teacherMode?.enabled}>
                {hiEntropy.length > 0 && hiEntropy.map((s) => (
                  <div key={s.name} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                    <AlertTriangle size={12} style={{ color: "var(--risk-high)", flexShrink: 0 }} />
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-xs)" }}>{s.name || "<unnamed>"} — {s.entropy.toFixed(4)}</span>
                  </div>
                ))}
              </FeatureCard>
              {pe.overlay && (
                <FeatureCard title="Overlay Data" description="Data appended after the last PE section" status={pe.overlay.high_entropy ? "disabled" : "na"} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "overlay" })} clickable={teacherMode?.enabled}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <InfoRow label="Offset"  value={`0x${pe.overlay.offset.toString(16).toUpperCase()}`} />
                    <InfoRow label="Size"    value={formatBytes(pe.overlay.size)} />
                    <InfoRow label="Entropy" value={pe.overlay.entropy.toFixed(4)} />
                    {pe.overlay.overlay_mime_type && <InfoRow label="MIME type" value={pe.overlay.overlay_mime_type} />}
                    {pe.overlay.overlay_characterisation && <InfoRow label="Type" value={pe.overlay.overlay_characterisation} />}
                  </div>
                </FeatureCard>
              )}
              {pe.checksum?.stored_nonzero && (
                <FeatureCard title="PE Checksum" description="Stored vs. computed checksum in the optional header" status={pe.checksum.valid ? "enabled" : "na"} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "checksum" })} clickable={teacherMode?.enabled}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <InfoRow label="Stored"   value={`0x${pe.checksum.stored.toString(16).padStart(8, "0").toUpperCase()}`} />
                    <InfoRow label="Computed" value={`0x${pe.checksum.computed.toString(16).padStart(8, "0").toUpperCase()}`} />
                    <InfoRow label="Match"    value={<span style={{ color: pe.checksum.valid ? "var(--risk-low)" : "var(--risk-medium)" }}>{pe.checksum.valid ? "Valid" : "Mismatch"}</span>} />
                  </div>
                </FeatureCard>
              )}
              {pe.debug_artifacts && (
                <FeatureCard
                  title="Debug Artifacts"
                  description="PDB paths and timestamp anomalies that may indicate tampering"
                  status={pe.debug_artifacts.pdb_path || pe.debug_artifacts.timestamp_zeroed || pe.debug_artifacts.version_info_suspicious ? "disabled" : "enabled"}
                  onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "debug_artifacts" })}
                  clickable={teacherMode?.enabled}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {pe.debug_artifacts.pdb_path && <InfoRow label="PDB path" value={pe.debug_artifacts.pdb_path} />}
                    <InfoRow label="Timestamp" value={pe.debug_artifacts.timestamp_zeroed ? <span style={{ color: "var(--risk-medium)" }}>Zeroed (possible evasion)</span> : <span style={{ color: "var(--risk-low)" }}>Present</span>} />
                    {pe.debug_artifacts.version_info_suspicious && (
                      <InfoRow label="Version info" value={<span style={{ color: "var(--risk-high)" }}>Suspicious — may be forged</span>} />
                    )}
                  </div>
                </FeatureCard>
              )}
              {pe.weak_crypto && pe.weak_crypto.length > 0 && (
                <FeatureCard title="Weak Crypto Indicators" description="Known weak or deprecated cryptographic algorithms detected" status="disabled" fullWidth onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "weak_crypto" })} clickable={teacherMode?.enabled}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    {pe.weak_crypto.map((wc, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                        <AlertTriangle size={12} style={{ color: "var(--risk-high)", flexShrink: 0, marginTop: 2 }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <span style={{ fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-primary)" }}>{wc.name}</span>
                          <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", marginLeft: 8 }}>{wc.evidence}</span>
                          {wc.offset && <span style={{ fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", color: "var(--text-muted)", marginLeft: 8 }}>@ {wc.offset}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </FeatureCard>
              )}
              {/* ── Certificate Reputation ──────────────────────────── */}
              {pe.authenticode?.present && pe.authenticode.signer_cn && (
                <FeatureCard
                  title="Certificate Reputation"
                  description="Publisher trust verification"
                  status={pe.authenticode.is_microsoft_signed ? "enabled" : "na"}
                  onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "cert_reputation" })}
                  clickable={teacherMode?.enabled}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {pe.authenticode.signer_cn && <InfoRow label="Publisher" value={pe.authenticode.signer_cn} />}
                    {pe.authenticode.issuer_cn && <InfoRow label="Issuer" value={pe.authenticode.issuer_cn} />}
                    <InfoRow label="Trust" value={
                      pe.authenticode.is_microsoft_signed
                        ? <span style={{ color: "var(--risk-low)", fontWeight: 600 }}>Trusted Publisher</span>
                        : pe.authenticode.status === "Self-signed"
                          ? <span style={{ color: "var(--risk-high)", fontWeight: 600 }}>Self-signed</span>
                          : <span style={{ color: "var(--risk-medium)", fontWeight: 600 }}>Unknown Publisher</span>
                    } />
                  </div>
                </FeatureCard>
              )}

              {/* ── Known Sample Match (compact) ──────────────────── */}
              {result.ksd_match && (
                <FeatureCard
                  title="Known Sample Match"
                  description="TLSH similarity to known malware"
                  status="disabled"
                  onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "ksd_match" })}
                  clickable={teacherMode?.enabled}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <InfoRow label="Family" value={
                      <span style={{ fontWeight: 600, textTransform: "capitalize" }}>{result.ksd_match.family}</span>
                    } />
                    <InfoRow label="Similarity" value={
                      `${Math.max(0, (1 - result.ksd_match.distance / 200) * 100).toFixed(1)}%`
                    } />
                    <InfoRow label="Confidence" value={
                      <span style={{
                        color: result.ksd_match.confidence === "Critical" ? "var(--risk-critical)"
                          : result.ksd_match.confidence === "High" ? "var(--risk-high)"
                          : "var(--risk-medium)"
                      }}>
                        {result.ksd_match.confidence}
                      </span>
                    } />
                  </div>
                </FeatureCard>
              )}

              {/* ── .NET Metadata ─────────────────────────────────── */}
              {pe.dotnet_metadata && (
                <FeatureCard
                  title=".NET Assembly"
                  description="Managed code metadata analysis"
                  status={pe.dotnet_metadata.known_obfuscator ? "disabled" : "na"}
                  onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "dotnet" })}
                  clickable={teacherMode?.enabled}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {pe.dotnet_metadata.known_obfuscator && (
                      <InfoRow label="Obfuscator" value={
                        <span style={{ color: "var(--risk-high)", fontWeight: 600 }}>{pe.dotnet_metadata.known_obfuscator}</span>
                      } />
                    )}
                    <InfoRow label="Types" value={pe.dotnet_metadata.type_count} />
                    <InfoRow label="Methods" value={pe.dotnet_metadata.method_count} />
                    <InfoRow label="P/Invoke" value={
                      <span style={pe.dotnet_metadata.pinvoke_suspicious ? { color: "var(--risk-high)" } : {}}>
                        {pe.dotnet_metadata.pinvoke_count}{pe.dotnet_metadata.pinvoke_suspicious ? " (suspicious)" : ""}
                      </span>
                    } />
                    <InfoRow label="Reflection" value={pe.dotnet_metadata.reflection_usage ? "Yes" : "No"} />
                    {pe.dotnet_metadata.clr_version && <InfoRow label="CLR" value={pe.dotnet_metadata.clr_version} />}
                  </div>
                </FeatureCard>
              )}

              {/* ── Rich Header ────────────────────────────────────── */}
              {pe.rich_header ? (
                <FeatureCard title="Rich Header" description="Undocumented MSVC build metadata" status="enabled" onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "rich_header" })} clickable={teacherMode?.enabled}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <InfoRow label="Entries" value={pe.rich_header?.entries?.length ?? 0} />
                    {pe.rich_header?.entries?.[0] && (
                      <InfoRow label="First linker" value={`${pe.rich_header.entries[0].product_name ?? pe.rich_header.entries[0].product_id ?? "?"} build ${pe.rich_header.entries[0].build_number ?? "?"}`} />
                    )}
                  </div>
                </FeatureCard>
              ) : pe && (
                <FeatureCard title="Rich Header" description="Undocumented MSVC build metadata" status="disabled" onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "rich_header" })} clickable={teacherMode?.enabled}>
                  <span style={{ fontSize: "var(--font-size-xs)", color: "var(--risk-medium)" }}>
                    No Rich header found — may indicate non-MSVC toolchain or header stripping.
                  </span>
                </FeatureCard>
              )}

              {pe.version_info && (
                <FeatureCard title="Version Info" description="Embedded version resource from the PE file" status="na" fullWidth={versionInfoWide} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "version_info" })} clickable={teacherMode?.enabled}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {pe.version_info.file_description  && <InfoRow label="Description"   value={pe.version_info.file_description} />}
                    {pe.version_info.product_name      && <InfoRow label="Product"       value={pe.version_info.product_name} />}
                    {pe.version_info.company_name      && <InfoRow label="Company"       value={pe.version_info.company_name} />}
                    {pe.version_info.file_version      && <InfoRow label="Version"       value={pe.version_info.file_version} />}
                    {pe.version_info.original_filename && <InfoRow label="Original name" value={pe.version_info.original_filename} />}
                    {pe.version_info.legal_copyright   && <InfoRow label="Copyright"     value={pe.version_info.legal_copyright} />}
                  </div>
                </FeatureCard>
              )}
            </div>
          </section>
        )}

        {/* ── Compiler / Toolchain Detection ──────────────────────── */}
        {cd && (
          <section>
            <h2 style={SECTION_HEADER}>Toolchain Detection</h2>
            <div style={GRID}>
              <FeatureCard
                title={cd.compiler}
                description={`Detected ${cd.language} toolchain`}
                status="na"
                fullWidth={(cd.evidence?.length ?? 0) > 2}
                onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "toolchain" })}
                clickable={teacherMode?.enabled}
              >
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <InfoRow label="Language" value={cd.language} />
                  <InfoRow label="Confidence" value={
                    <span style={{
                      color: cd.confidence === "High" ? "var(--risk-low)" : cd.confidence === "Medium" ? "var(--risk-medium)" : "var(--text-muted)",
                      fontWeight: 600,
                    }}>
                      {cd.confidence}
                    </span>
                  } />
                  {(cd.evidence?.length ?? 0) > 0 && (
                    <div style={{ marginTop: 4 }}>
                      <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>Evidence:</span>
                      <ul style={{ margin: "4px 0 0", paddingLeft: 16, listStyle: "disc" }}>
                        {(cd.evidence ?? []).map((e, i) => (
                          <li key={i} style={{ fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.6 }}>{e}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </FeatureCard>
            </div>
          </section>
        )}

        {elf && (
          <section>
            <h2 style={SECTION_HEADER}>ELF Mitigations</h2>
            <div style={GRID}>
              <FeatureCard title="PIE"      description="Position Independent Executable — enables ASLR for the main binary"  status={elf.is_pie ? "enabled" : "disabled"} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "pie" })} clickable={teacherMode?.enabled} />
              <FeatureCard title="NX Stack" description="Non-executable stack — prevents stack-based shellcode execution"      status={elf.has_nx_stack ? "enabled" : "disabled"} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "nx" })} clickable={teacherMode?.enabled} />
              <FeatureCard title="RELRO"    description="Relocation Read-Only — protects GOT/PLT from overwrite attacks"       status={elf.has_relro ? "enabled" : "disabled"} onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "relro" })} clickable={teacherMode?.enabled} />
              <FeatureCard title="Stripped" description="Symbol table stripped — fewer debug artefacts in the binary"          status="na" onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "stripped" })} clickable={teacherMode?.enabled}>
                <span style={{ color: elf.is_stripped ? "var(--text-muted)" : "var(--text-secondary)" }}>
                  {elf.is_stripped ? "Symbols stripped" : "Symbols present"}
                </span>
              </FeatureCard>
            </div>
          </section>
        )}

        {/* ── YARA Matches ──────────────────────────────────── */}
        {result.yara_matches && result.yara_matches.length > 0 && (
          <section>
            <h2 style={SECTION_HEADER}>YARA Matches</h2>
            <div style={GRID}>
              {result.yara_matches.map((ym, i) => (
                <FeatureCard
                  key={i}
                  title={ym.rule_name}
                  description={ym.description ?? `Matched rule from ${ym.namespace}`}
                  status="disabled"
                  fullWidth={(ym.matched_strings?.length ?? 0) > 3}
                  onClick={() => teacherMode?.enabled && teacherMode.focus({ type: "security", feature: "yara" })}
                  clickable={teacherMode?.enabled}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <InfoRow label="Namespace" value={ym.namespace} />
                    {ym.author && <InfoRow label="Author" value={ym.author} />}
                    {ym.tags?.length > 0 && (
                      <InfoRow label="Tags" value={
                        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                          {ym.tags.map((t, j) => (
                            <span key={j} style={{
                              fontSize: "var(--font-size-xs)",
                              padding: "1px 6px",
                              borderRadius: 4,
                              background: "rgba(99,102,241,0.1)",
                              color: "rgb(129,140,248)",
                              border: "1px solid rgba(99,102,241,0.25)",
                            }}>
                              {t}
                            </span>
                          ))}
                        </div>
                      } />
                    )}
                    <InfoRow label="Matches" value={`${ym.matched_strings?.length ?? 0} string match(es)`} />
                    {(ym.matched_strings ?? []).slice(0, 5).map((ms, j) => (
                      <div key={j} style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 2 }}>
                        <span style={{ fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", color: "var(--risk-medium)", minWidth: 40 }}>{ms.identifier}</span>
                        <span style={{ fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>@ 0x{ms.offset.toString(16).toUpperCase()}</span>
                        <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>({ms.length}B)</span>
                      </div>
                    ))}
                    {(ym.matched_strings?.length ?? 0) > 5 && (
                      <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", fontStyle: "italic" }}>
                        +{ym.matched_strings.length - 5} more match(es)
                      </span>
                    )}
                  </div>
                </FeatureCard>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

export default function SecurityTab(props: Props) {
  return (
    <SecurityErrorBoundary>
      <SecurityTabInner {...props} />
    </SecurityErrorBoundary>
  );
}
