import { useEffect, useState } from "react";
import { CheckCircle, XCircle, MinusCircle, ShieldCheck, AlertTriangle } from "lucide-react";
import type { AnalysisResult, AuthenticodeInfo } from "@/types/analysis";
import { formatBytes } from "@/lib/utils";

interface Props {
  result: AnalysisResult;
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

function FeatureCard({ title, description, status, children, fullWidth }: {
  title: string; description: string; status: CardStatus;
  children?: React.ReactNode; fullWidth?: boolean;
}) {
  const c = statusColors(status);
  return (
    <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderLeft: `3px solid ${c.border}`, borderRadius: "var(--radius)", padding: 20, display: "flex", flexDirection: "column", gap: 12, gridColumn: fullWidth ? "1 / -1" : undefined }}>
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
      <span style={{ fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", color: "var(--text-secondary)", wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}

function AuthCard({ auth }: { auth: AuthenticodeInfo }) {
  return (
    <FeatureCard title="Authenticode" description="Digital signature verification" status={auth.present ? "enabled" : "disabled"} fullWidth={auth.present && !!(auth.signer_cn || auth.issuer_cn)}>
      {auth.present ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {auth.is_microsoft_signed && (
            <div style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--risk-low)", fontSize: "var(--font-size-xs)", fontWeight: 500 }}>
              <ShieldCheck size={14} /> Microsoft-signed
            </div>
          )}
          {auth.signer_cn   && <InfoRow label="Signer CN"  value={auth.signer_cn} />}
          {auth.issuer_cn   && <InfoRow label="Issuer CN"  value={auth.issuer_cn} />}
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

export default function SecurityTab({ result }: Props) {
  const pe  = result.pe_analysis;
  const elf = result.elf_analysis;

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

  if (!pe && !elf) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <p style={{ color: "var(--text-muted)" }}>No security feature data available.</p>
      </div>
    );
  }

  const sections = pe?.sections ?? elf?.sections ?? [];
  const hiEntropy = sections.filter((s) => s.entropy > 7.0);

  return (
    <div style={{ height: "100%", overflow: "auto", padding: 24 }}>
      <div style={{ maxWidth: 1600, margin: "0 auto", display: "flex", flexDirection: "column", gap: 24 }}>

        {pe && (
          <section>
            <h2 style={SECTION_HEADER}>Mitigations</h2>
            <div style={GRID}>
              <FeatureCard title="ASLR"           description="Randomises memory addresses to hinder exploitation"                 status={pe.security.aslr_enabled ? "enabled" : "disabled"} />
              <FeatureCard title="DEP / NX"        description="Prevents execution of data pages"                                   status={pe.security.dep_enabled ? "enabled" : "disabled"} />
              <FeatureCard title="High-Entropy VA" description="64-bit ASLR with larger address range"                              status={pe.is_64bit ? "enabled" : "na"} />
              {pe.authenticode && <AuthCard auth={pe.authenticode} />}
              <FeatureCard title="Section Entropy" description="Sections with entropy > 7.0 may contain compressed or encrypted data" status={hiEntropy.length > 0 ? "disabled" : "enabled"}>
                {hiEntropy.length > 0 && hiEntropy.map((s) => (
                  <div key={s.name} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                    <AlertTriangle size={12} style={{ color: "var(--risk-high)", flexShrink: 0 }} />
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-xs)" }}>{s.name || "<unnamed>"} — {s.entropy.toFixed(4)}</span>
                  </div>
                ))}
              </FeatureCard>
              {pe.overlay && (
                <FeatureCard title="Overlay Data" description="Data appended after the last PE section" status={pe.overlay.high_entropy ? "disabled" : "na"}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <InfoRow label="Offset"  value={`0x${pe.overlay.offset.toString(16).toUpperCase()}`} />
                    <InfoRow label="Size"    value={formatBytes(pe.overlay.size)} />
                    <InfoRow label="Entropy" value={pe.overlay.entropy.toFixed(4)} />
                  </div>
                </FeatureCard>
              )}
              {pe.checksum?.stored_nonzero && (
                <FeatureCard title="PE Checksum" description="Stored vs. computed checksum in the optional header" status={pe.checksum.valid ? "enabled" : "na"}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <InfoRow label="Stored"   value={`0x${pe.checksum.stored.toString(16).padStart(8, "0").toUpperCase()}`} />
                    <InfoRow label="Computed" value={`0x${pe.checksum.computed.toString(16).padStart(8, "0").toUpperCase()}`} />
                    <InfoRow label="Match"    value={<span style={{ color: pe.checksum.valid ? "var(--risk-low)" : "var(--risk-medium)" }}>{pe.checksum.valid ? "Valid" : "Mismatch"}</span>} />
                  </div>
                </FeatureCard>
              )}
              {pe.version_info && (
                <FeatureCard title="Version Info" description="Embedded version resource from the PE file" status="na" fullWidth={versionInfoWide}>
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

        {elf && (
          <section>
            <h2 style={SECTION_HEADER}>ELF Mitigations</h2>
            <div style={GRID}>
              <FeatureCard title="PIE"      description="Position Independent Executable — enables ASLR for the main binary"  status={elf.is_pie ? "enabled" : "disabled"} />
              <FeatureCard title="NX Stack" description="Non-executable stack — prevents stack-based shellcode execution"      status={elf.has_nx_stack ? "enabled" : "disabled"} />
              <FeatureCard title="RELRO"    description="Relocation Read-Only — protects GOT/PLT from overwrite attacks"       status={elf.has_relro ? "enabled" : "disabled"} />
              <FeatureCard title="Stripped" description="Symbol table stripped — fewer debug artefacts in the binary"          status="na">
                <span style={{ color: elf.is_stripped ? "var(--text-muted)" : "var(--text-secondary)" }}>
                  {elf.is_stripped ? "Symbols stripped" : "Symbols present"}
                </span>
              </FeatureCard>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
