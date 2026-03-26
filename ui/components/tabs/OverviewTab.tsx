import { useEffect, useRef, useState } from "react";
import { Copy, Check, Pin } from "lucide-react";
import { formatBytes, copyToClipboard } from "@/lib/utils";
import { getRiskLabel, getRiskColor, getDetectionTags, type DetectionTag } from "@/lib/risk";
import CopyButton from "@/components/CopyButton";

const SEVERITY_COLOR: Record<DetectionTag["severity"], string> = {
  critical: "var(--risk-critical)",
  high:     "var(--risk-high)",
  medium:   "var(--risk-medium)",
  low:      "var(--risk-low)",
};
import type { AnalysisResult } from "@/types/analysis";

interface PinnedFinding {
  type: string;
  label: string;
  detail: string;
}

interface Props {
  result: AnalysisResult;
  riskScore: number;
  onMitreNavigate?: (techId: string) => void;
  pinnedFindings?: PinnedFinding[];
  onPin?: (finding: PinnedFinding) => void;
  onUnpin?: (index: number) => void;
}

// ── SVG risk ring ─────────────────────────────────────────────────────────────
const RADIUS = 42;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function RiskRing({ score, color }: { score: number; color: string }) {
  const [animated, setAnimated] = useState(0);
  const frameRef = useRef<number>(0);

  useEffect(() => {
    const delay = 400;
    const duration = 1200;
    const delayTimer = setTimeout(() => {
      const start = performance.now();
      function tick(now: number) {
        const t = Math.min((now - start) / duration, 1);
        const ease = 1 - Math.pow(1 - t, 3); // ease-out cubic
        setAnimated(Math.round(score * ease));
        if (t < 1) frameRef.current = requestAnimationFrame(tick);
      }
      frameRef.current = requestAnimationFrame(tick);
    }, delay);
    return () => {
      clearTimeout(delayTimer);
      cancelAnimationFrame(frameRef.current);
    };
  }, [score]);

  const filled = (animated / 100) * CIRCUMFERENCE;
  const offset = CIRCUMFERENCE - filled;

  return (
    <div style={{ position: "relative", width: 100, height: 100 }}>
      <svg width={100} height={100} viewBox="0 0 100 100">
        {/* Background track */}
        <circle
          cx={50} cy={50} r={RADIUS}
          fill="none"
          stroke="var(--border)"
          strokeWidth={6}
        />
        {/* Progress arc — rotate so it starts at 12 o'clock */}
        <circle
          cx={50} cy={50} r={RADIUS}
          fill="none"
          stroke={color}
          strokeWidth={6}
          strokeLinecap="round"
          strokeDasharray={`${CIRCUMFERENCE} ${CIRCUMFERENCE}`}
          strokeDashoffset={offset}
          transform="rotate(-90 50 50)"
          style={{ transition: "stroke-dashoffset 16ms linear" }}
        />
      </svg>
      {/* Score number */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <span
          style={{
            fontSize: "calc(var(--font-size-base) * 2)",
            fontWeight: 600,
            lineHeight: 1,
            color,
          }}
        >
          {animated}
        </span>
      </div>
    </div>
  );
}

// ── Copy button ───────────────────────────────────────────────────────────────
function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  async function handle() {
    await copyToClipboard(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  return (
    <button
      onClick={() => void handle()}
      title="Copy"
      style={{
        background: "none",
        border: "none",
        padding: "2px 4px",
        cursor: "pointer",
        color: "var(--text-muted)",
        flexShrink: 0,
        transition: "color 150ms ease-out",
        display: "flex",
        alignItems: "center",
      }}
      onMouseEnter={(e) => ((e.currentTarget as HTMLButtonElement).style.color = "var(--text-primary)")}
      onMouseLeave={(e) => ((e.currentTarget as HTMLButtonElement).style.color = "var(--text-muted)")}
    >
      {copied ? <Check size={13} style={{ color: "var(--risk-low)" }} /> : <Copy size={13} />}
    </button>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function OverviewTab({ result, riskScore, onMitreNavigate, pinnedFindings, onPin, onUnpin }: Props) {
  const label = getRiskLabel(riskScore);
  const color = getRiskColor(riskScore);
  const tags = getDetectionTags(result);

  const pe = result.pe_analysis;
  const fi = result.file_info;

  const timestamp =
    pe && "timestamp" in pe && typeof (pe as Record<string, unknown>).timestamp === "number"
      ? new Date(((pe as Record<string, unknown>).timestamp as number) * 1000).toISOString().slice(0, 10)
      : "—";

  const infoRows: [string, string][] = [
    ["Name",        fi.path.split(/[\\/]/).pop() ?? fi.path],
    ["Size",        formatBytes(fi.size_bytes)],
    ["Format",      result.file_format],
    ["Architecture", pe?.architecture ?? result.elf_analysis?.architecture ?? "—"],
    ["Entry Point", pe?.entry_point ?? result.elf_analysis?.entry_point ?? "—"],
    ["Timestamp",   timestamp],
    ["Subsystem",   pe?.file_type ?? "—"],
  ];

  if (fi.mime_type) {
    infoRows.push(["MIME Type", fi.mime_type]);
  }

  const hashRows: [string, string][] = [
    ["MD5",    result.hashes.md5],
    ["SHA1",   result.hashes.sha1],
    ["SHA256", result.hashes.sha256],
  ];

  if (result.hashes.tlsh) hashRows.push(["TLSH", result.hashes.tlsh]);
  if (pe?.imphash) hashRows.push(["ImpHash", pe.imphash]);

  return (
    <div style={{ height: "100%", overflow: "auto", padding: 24 }}>
      {/* ── C12: Pinned Findings ── */}
      {pinnedFindings && pinnedFindings.length > 0 && (
        <div style={{ maxWidth: 1600, margin: "0 auto 16px" }}>
          <h3 style={{ fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 8 }}>
            Pinned Findings
          </h3>
          {pinnedFindings.map((f, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "6px 12px", background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", marginBottom: 4 }}>
              <span style={{ fontSize: "var(--font-size-sm)", color: "var(--text-primary)", flex: 1 }}>
                <strong>{f.label}</strong> — <span style={{ color: "var(--text-secondary)" }}>{f.detail}</span>
              </span>
              <CopyButton text={`${f.label} — ${f.detail}`} label="Copy finding" />
              {onUnpin && (
                <button
                  onClick={() => onUnpin(i)}
                  style={{ background: "transparent", border: "none", cursor: "pointer", color: "var(--text-muted)", padding: "2px 4px", fontSize: "var(--font-size-sm)", marginLeft: 4 }}
                  title="Unpin"
                >
                  ✕
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      <div
        style={{
          maxWidth: 1600,
          margin: "0 auto",
          display: "grid",
          gridTemplateColumns: "clamp(280px, 30%, 340px) 1fr",
          gap: 24,
          alignItems: "start",
        }}
        className="lg:grid-cols-[340px_1fr] md:grid-cols-2 grid-cols-1"
      >
        {/* ── Left column ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16, minWidth: 0 }}>

          {/* Risk card */}
          <div
            data-tour="risk-ring"
            className="animate-in"
            style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              padding: 24,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 16,
            }}
          >
            <RiskRing score={riskScore} color={color} />
            <p style={{ fontSize: "var(--font-size-base)", color: "var(--text-secondary)", margin: 0 }}>{label}</p>

            {/* Detection tags */}
            {tags.length > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, justifyContent: "center" }}>
                {tags.map((tag) => {
                  const c = SEVERITY_COLOR[tag.severity];
                  return (
                    <span
                      key={tag.label}
                      title={tag.apis.join(", ")}
                      style={{
                        fontSize: "var(--font-size-xs)",
                        padding: "3px 8px",
                        borderRadius: 999,
                        border: `1px solid ${c}66`,
                        background: `${c}1a`,
                        color: c,
                        cursor: "default",
                      }}
                    >
                      {tag.label}
                    </span>
                  );
                })}
              </div>
            )}

          </div>

          {/* File info */}
          <div>
            <p
              style={{
                fontSize: "var(--font-size-xs)",
                fontWeight: 600,
                textTransform: "uppercase",
                letterSpacing: "0.08em",
                color: "var(--text-muted)",
                marginBottom: 12,
              }}
            >
              File Info
            </p>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <tbody>
                {infoRows.map(([key, val], i) => (
                  <tr
                    key={key}
                    className="stagger-row"
                    style={({ "--index": i } as React.CSSProperties)}
                  >
                    <td
                      style={{
                        width: "40%",
                        padding: "6px 8px",
                        fontSize: "var(--font-size-xs)",
                        color: "var(--text-muted)",
                        background: i % 2 === 0 ? "transparent" : "var(--bg-elevated)",
                        borderRadius: i % 2 !== 0 ? "4px 0 0 4px" : 0,
                      }}
                    >
                      {key}
                    </td>
                    <td
                      className="selectable"
                      style={{
                        padding: "6px 8px",
                        fontSize: "var(--font-size-sm)",
                        fontFamily: key === "Entry Point" || key === "Timestamp" ? "var(--font-mono)" : undefined,
                        color: "var(--text-primary)",
                        background: i % 2 === 0 ? "transparent" : "var(--bg-elevated)",
                        borderRadius: i % 2 !== 0 ? "0 4px 4px 0" : 0,
                        wordBreak: "break-all",
                      }}
                    >
                      {val}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── Right column ── */}
        <div style={{ minWidth: 0, display: "flex", flexDirection: "column", gap: 24 }}>
          <p
            style={{
              fontSize: "var(--font-size-xs)",
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              color: "var(--text-muted)",
              marginBottom: 12,
            }}
          >
            Hashes
          </p>
          <div
            style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              overflow: "hidden",
            }}
          >
            {hashRows.map(([label, value], i) => (
              <div
                key={label}
                className="animate-in"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "10px 16px",
                  borderTop: i > 0 ? "1px solid var(--border-subtle)" : undefined,
                }}
              >
                <span
                  style={{
                    fontSize: "var(--font-size-xs)",
                    color: "var(--text-muted)",
                    minWidth: 64,
                    flexShrink: 0,
                  }}
                >
                  {label}
                </span>
                <span
                  className="selectable"
                  style={{
                    flex: 1,
                    fontSize: "var(--font-size-xs)",
                    fontFamily: "var(--font-mono)",
                    color: "var(--text-secondary)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    minWidth: 0,
                  }}
                >
                  {value}
                </span>
                <CopyBtn text={`${label}: ${value}`} />
              </div>
            ))}
          </div>

          {/* ── Analyst Findings ── */}
          {result.plain_english_findings && result.plain_english_findings.length > 0 && (
            <div>
              <p style={{ fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 12 }}>
                Analyst Findings
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {result.plain_english_findings.map((f, i) => {
                  const confColor = f.confidence === "Critical" ? "var(--risk-critical)" : f.confidence === "High" ? "var(--risk-high)" : f.confidence === "Medium" ? "var(--risk-medium)" : "var(--risk-low)";
                  return (
                    <div key={i} className="animate-in" style={{ background: "var(--bg-surface)", border: `1px solid ${confColor}33`, borderLeft: `3px solid ${confColor}`, borderRadius: 8, padding: "14px 16px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                        <span style={{ fontSize: "var(--font-size-sm)", fontWeight: 600, color: "var(--text-primary)", flex: 1 }}>{f.title}</span>
                        {onPin && (
                          <button onClick={() => onPin({ type: "finding", label: f.title, detail: `${f.confidence} — ${f.explanation.slice(0, 80)}` })} style={{ opacity: 0.4, cursor: "pointer", background: "transparent", border: "none", color: "var(--text-muted)", padding: 2, fontSize: 12, flexShrink: 0 }} title="Pin to Overview">
                            <Pin size={12} />
                          </button>
                        )}
                        <CopyButton text={`${f.title}: ${f.explanation}`} label="Copy finding" />
                        <span style={{ fontSize: "var(--font-size-xs)", padding: "1px 7px", borderRadius: 999, background: `${confColor}1a`, color: confColor, border: `1px solid ${confColor}44`, flexShrink: 0 }}>{f.confidence}</span>
                        {f.mitre_technique_id && (
                          <button
                            onClick={() => onMitreNavigate?.(f.mitre_technique_id!)}
                            title={`View ${f.mitre_technique_id} in MITRE tab`}
                            style={{ fontSize: "var(--font-size-xs)", padding: "1px 6px", borderRadius: 4, background: "rgba(99,102,241,0.15)", color: "rgb(129,140,248)", border: "1px solid rgba(99,102,241,0.3)", fontFamily: "var(--font-mono)", fontWeight: 600, flexShrink: 0, cursor: onMitreNavigate ? "pointer" : "default" }}
                          >
                            {f.mitre_technique_id}
                          </button>
                        )}
                      </div>
                      <p className="selectable" style={{ fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", margin: 0, lineHeight: 1.5 }}>{f.explanation}</p>
                      {f.malware_families.length > 0 && (
                        <p style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", margin: "6px 0 0", lineHeight: 1.4 }}>
                          Known families: {f.malware_families.join(", ")}
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ── Compiler Dependencies ── */}
          {pe?.compiler_deps && pe.compiler_deps.length > 0 && (
            <div>
              <p style={{ fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 12 }}>
                Compiler Dependencies
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {pe.compiler_deps.map((dep, i) => {
                  const riskColor = dep.risk === "Suspicious" ? "var(--risk-high)" : dep.risk === "Uncommon" ? "var(--risk-medium)" : "var(--text-muted)";
                  return (
                    <div key={i} className="animate-in" style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: 8, padding: "10px 16px", display: "flex", alignItems: "center", gap: 12 }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <span style={{ fontSize: "var(--font-size-sm)", fontWeight: 500, color: "var(--text-primary)" }}>{dep.name}</span>
                        <p style={{ margin: "2px 0 0", fontSize: "var(--font-size-xs)", color: "var(--text-muted)", lineHeight: 1.4 }}>{dep.description}</p>
                      </div>
                      <span style={{ fontSize: "var(--font-size-xs)", padding: "2px 8px", borderRadius: 999, background: `${riskColor}1a`, color: riskColor, border: `1px solid ${riskColor}44`, flexShrink: 0 }}>{dep.risk}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ── MITRE ATT&CK Techniques ── */}
          {result.mitre_techniques && result.mitre_techniques.length > 0 && (
            <div>
              <p style={{ fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 12 }}>
                MITRE ATT&CK
              </p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {result.mitre_techniques.map((t) => {
                  const id = t.sub_technique_id ? `${t.technique_id}.${t.sub_technique_id}` : t.technique_id;
                  const confColor = t.confidence === "Critical" ? "var(--risk-critical)" : t.confidence === "High" ? "var(--risk-high)" : t.confidence === "Medium" ? "var(--risk-medium)" : "var(--risk-low)";
                  return (
                    <button
                      key={`${id}-${t.source_indicator}`}
                      data-testid="mitre-badge"
                      onClick={() => onMitreNavigate?.(id)}
                      title={`${t.technique_name} (${t.tactic}) — via ${t.source_indicator} · Click to view in MITRE tab`}
                      style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: "var(--font-size-xs)", padding: "3px 8px", borderRadius: 5, background: "rgba(99,102,241,0.1)", color: "rgb(129,140,248)", border: "1px solid rgba(99,102,241,0.25)", fontFamily: "var(--font-mono)", fontWeight: 600, transition: "background 150ms ease-out", cursor: onMitreNavigate ? "pointer" : "default" }}
                      onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(99,102,241,0.2)"; }}
                      onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(99,102,241,0.1)"; }}
                    >
                      <span style={{ width: 6, height: 6, borderRadius: "50%", background: confColor, flexShrink: 0 }} />
                      {id}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
