/**
 * MitreTab — shows only the MITRE ATT&CK techniques detected in the current
 * analysis, grouped by tactic in a horizontal card-column layout.
 */
import { useState, useEffect, useRef } from "react";
import { ExternalLink, X, ChevronDown, ChevronUp, Pin } from "lucide-react";
import AnimatedEmptyState from "@/components/AnimatedEmptyState";
import type { AnalysisResult, MitreTechnique } from "@/types/analysis";
import { useTeacherMode } from "@/hooks/useTeacherMode";
import mitreData from "@/data/mitre_attack.json";

interface PinnedFinding {
  type: string;
  label: string;
  detail: string;
}

interface Props {
  result: AnalysisResult;
  /** Technique ID to highlight on mount (from cross-tab navigation). */
  highlightId?: string | null;
  onPin?: (finding: PinnedFinding) => void;
}

// ── Data helpers ─────────────────────────────────────────────────────────────

interface TechniqueEntry {
  id: string;
  name: string;
  tactic: string;
  description: string;
  subtechniques: { id: string; name: string; description: string }[];
}

const techniqueMap = new Map<string, TechniqueEntry>();
for (const t of (mitreData as { techniques: TechniqueEntry[] }).techniques) {
  techniqueMap.set(t.id, t);
  for (const sub of t.subtechniques) {
    techniqueMap.set(sub.id, { ...sub, tactic: t.tactic, subtechniques: [] });
  }
}

// ── Tactic ordering (ATT&CK Enterprise canonical order) ──────────────────────

const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

function tacticIndex(tactic: string) {
  const idx = TACTIC_ORDER.indexOf(tactic);
  return idx === -1 ? 99 : idx;
}

// ── Group detected techniques by tactic ──────────────────────────────────────

interface DetectedGroup {
  tactic: string;
  techniques: DetectedTechnique[];
}

interface DetectedTechnique {
  /** Parent technique ID, e.g. "T1055" */
  id: string;
  name: string;
  tactic: string;
  description: string;
  indicators: MitreTechnique[];
  detectedSubs: { id: string; name: string }[];
}

function groupTechniques(mitre: MitreTechnique[]): DetectedGroup[] {
  // Map parent_id → DetectedTechnique
  const byParent = new Map<string, DetectedTechnique>();

  for (const m of mitre) {
    const parentId = m.technique_id;
    const subId = m.sub_technique_id ? `${parentId}.${m.sub_technique_id}` : null;
    const catalogEntry = techniqueMap.get(parentId);

    if (!catalogEntry) {
      console.warn(`[MitreTab] Technique ID "${parentId}" detected but not found in mitre_attack.json — rendering fallback card.`);
    }

    if (!byParent.has(parentId)) {
      byParent.set(parentId, {
        id: parentId,
        name: catalogEntry?.name ?? m.technique_name,
        tactic: m.tactic,
        description: catalogEntry?.description ?? "",
        indicators: [],
        detectedSubs: [],
      });
    }

    const entry = byParent.get(parentId)!;
    entry.indicators.push(m);

    if (subId) {
      const subEntry = techniqueMap.get(subId);
      if (subEntry && !entry.detectedSubs.some((s) => s.id === subId)) {
        entry.detectedSubs.push({ id: subId, name: subEntry.name });
      }
    }
  }

  // Group by tactic
  const tacticMap = new Map<string, DetectedTechnique[]>();
  for (const dt of byParent.values()) {
    if (!tacticMap.has(dt.tactic)) tacticMap.set(dt.tactic, []);
    tacticMap.get(dt.tactic)!.push(dt);
  }

  const groups: DetectedGroup[] = [];
  for (const [tactic, techniques] of tacticMap) {
    groups.push({ tactic, techniques });
  }

  return groups.sort((a, b) => tacticIndex(a.tactic) - tacticIndex(b.tactic));
}

// ── Confidence dot ────────────────────────────────────────────────────────────

function ConfidenceDot({ level }: { level: string }) {
  const colors: Record<string, string> = {
    Critical: "var(--risk-critical)",
    High:     "var(--risk-high)",
    Medium:   "var(--risk-medium)",
    Low:      "var(--risk-low)",
  };
  return (
    <span
      title={`${level} confidence`}
      style={{
        width: 7,
        height: 7,
        borderRadius: "50%",
        background: colors[level] ?? "var(--text-muted)",
        flexShrink: 0,
        display: "inline-block",
      }}
    />
  );
}

// ── Technique card ────────────────────────────────────────────────────────────

function TechniqueCard({
  dt,
  highlighted,
  onClick,
  onPin,
}: {
  dt: DetectedTechnique;
  highlighted: boolean;
  onClick: () => void;
  onPin?: (finding: PinnedFinding) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);

  // Scroll into view and pulse when highlighted
  useEffect(() => {
    if (highlighted && ref.current) {
      ref.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [highlighted]);

  const topConf = dt.indicators.reduce((best, m) => {
    const order = ["Low", "Medium", "High", "Critical"];
    return order.indexOf(m.confidence) > order.indexOf(best) ? m.confidence : best;
  }, "Low");

  return (
    <div
      ref={ref}
      data-testid="technique-card"
      onClick={onClick}
      style={{
        background: "var(--bg-surface)",
        border: `1px solid ${highlighted ? "rgba(99,102,241,0.6)" : "var(--border)"}`,
        borderLeft: `3px solid ${highlighted ? "rgb(99,102,241)" : "rgba(251,191,36,0.7)"}`,
        borderRadius: "var(--radius)",
        padding: "10px 12px",
        cursor: "pointer",
        transition: "border 200ms ease-out, transform 150ms ease-out, box-shadow 150ms ease-out",
        animation: highlighted ? "techniqueHighlight 1.5s ease-out" : undefined,
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLDivElement).style.transform = "translateY(-1px)";
        (e.currentTarget as HTMLDivElement).style.boxShadow = "0 4px 12px rgba(0,0,0,0.2)";
        (e.currentTarget as HTMLDivElement).style.borderColor = "rgba(99,102,241,0.4)";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLDivElement).style.transform = "";
        (e.currentTarget as HTMLDivElement).style.boxShadow = "";
        (e.currentTarget as HTMLDivElement).style.borderColor = highlighted ? "rgba(99,102,241,0.6)" : "var(--border)";
      }}
    >
      {/* ID + confidence */}
      <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 5 }}>
        <span
          style={{
            fontSize: 10,
            fontFamily: "var(--font-mono)",
            fontWeight: 700,
            padding: "1px 5px",
            borderRadius: 3,
            background: "rgba(251,191,36,0.12)",
            color: "rgb(251,191,36)",
            border: "1px solid rgba(251,191,36,0.25)",
            flexShrink: 0,
          }}
        >
          {dt.id}
        </span>
        <ConfidenceDot level={topConf} />
        <span style={{ flex: 1 }} />
        <span
          style={{
            fontSize: 10,
            color: "var(--text-muted)",
          }}
        >
          {dt.indicators.length} indicator{dt.indicators.length !== 1 ? "s" : ""}
        </span>
        {onPin && (
          <button
            onClick={(e) => { e.stopPropagation(); onPin({ type: "mitre", label: `${dt.id} ${dt.name}`, detail: `${dt.tactic} — ${dt.indicators.length} indicator(s)` }); }}
            style={{ opacity: 0.4, cursor: "pointer", background: "transparent", border: "none", color: "var(--text-muted)", padding: 2, flexShrink: 0 }}
            title="Pin to Overview"
          >
            <Pin size={10} />
          </button>
        )}
      </div>

      {/* Name */}
      <p
        style={{
          margin: "0 0 5px",
          fontSize: "var(--font-size-xs)",
          fontWeight: 500,
          color: "var(--text-primary)",
          lineHeight: 1.3,
        }}
      >
        {dt.name}
      </p>

      {/* Subtechniques badge */}
      {dt.detectedSubs.length > 0 && (
        <span
          style={{
            fontSize: 10,
            padding: "1px 6px",
            borderRadius: 999,
            background: "rgba(251,191,36,0.08)",
            color: "rgb(251,191,36)",
            border: "1px solid rgba(251,191,36,0.2)",
          }}
        >
          {dt.detectedSubs.length} subtechnique{dt.detectedSubs.length !== 1 ? "s" : ""}
        </span>
      )}
    </div>
  );
}

// ── Technique modal ───────────────────────────────────────────────────────────

function TechniqueModal({
  dt,
  onClose,
}: {
  dt: DetectedTechnique;
  onClose: () => void;
}) {
  const [showSubs, setShowSubs] = useState(true);
  const attackUrl = `https://attack.mitre.org/techniques/${dt.id}/`;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      role="dialog"
      aria-modal="true"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel */}
      <div
        className="relative rounded-xl shadow-2xl overflow-hidden"
        style={{
          width: 560,
          maxWidth: "95vw",
          maxHeight: "85vh",
          display: "flex",
          flexDirection: "column",
          background: "var(--bg-surface)",
          border: "1px solid var(--border)",
        }}
      >
        {/* Header */}
        <div
          style={{
            flexShrink: 0,
            padding: "16px 20px",
            borderBottom: "1px solid var(--border-subtle)",
            display: "flex",
            alignItems: "flex-start",
            gap: 12,
          }}
        >
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <span
                style={{
                  fontSize: "var(--font-size-xs)",
                  fontFamily: "var(--font-mono)",
                  fontWeight: 700,
                  padding: "2px 7px",
                  borderRadius: 4,
                  background: "rgba(251,191,36,0.12)",
                  color: "rgb(251,191,36)",
                  border: "1px solid rgba(251,191,36,0.25)",
                  flexShrink: 0,
                }}
              >
                {dt.id}
              </span>
              <span
                style={{
                  fontSize: 10,
                  padding: "1px 6px",
                  borderRadius: 999,
                  background: "var(--bg-elevated)",
                  color: "var(--text-muted)",
                  border: "1px solid var(--border)",
                }}
              >
                {dt.tactic}
              </span>
              <a
                href={attackUrl}
                target="_blank"
                rel="noopener noreferrer"
                title="View on MITRE ATT&CK"
                onClick={(e) => e.stopPropagation()}
                style={{ color: "var(--text-muted)", display: "flex", alignItems: "center" }}
              >
                <ExternalLink size={13} />
              </a>
            </div>
            <h2
              style={{
                margin: 0,
                fontSize: "var(--font-size-base)",
                fontWeight: 600,
                color: "var(--text-primary)",
              }}
            >
              {dt.name}
            </h2>
          </div>
          <button
            onClick={onClose}
            style={{
              flexShrink: 0,
              background: "none",
              border: "none",
              cursor: "pointer",
              color: "var(--text-muted)",
              padding: 4,
              display: "flex",
              alignItems: "center",
              borderRadius: "var(--radius-sm)",
            }}
          >
            <X size={15} />
          </button>
        </div>

        {/* Scrollable body */}
        <div style={{ flex: 1, overflowY: "auto", padding: "20px" }}>
          {/* Description */}
          {dt.description && (
            <div style={{ marginBottom: 20 }}>
              <p
                style={{
                  margin: "0 0 8px",
                  fontSize: "var(--font-size-xs)",
                  fontWeight: 600,
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                What it does
              </p>
              <p
                className="selectable"
                style={{
                  margin: 0,
                  fontSize: "var(--font-size-xs)",
                  color: "var(--text-secondary)",
                  lineHeight: 1.7,
                }}
              >
                {dt.description}
              </p>
            </div>
          )}

          {/* Subtechniques detected */}
          {dt.detectedSubs.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <button
                onClick={() => setShowSubs((v) => !v)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  padding: "0 0 8px",
                  fontSize: "var(--font-size-xs)",
                  fontWeight: 600,
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                Subtechniques detected ({dt.detectedSubs.length})
                {showSubs ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              </button>
              {showSubs && (
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {dt.detectedSubs.map((sub) => (
                    <div
                      key={sub.id}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "8px 12px",
                        borderRadius: "var(--radius)",
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--border-subtle)",
                      }}
                    >
                      <span
                        style={{
                          fontSize: 10,
                          fontFamily: "var(--font-mono)",
                          fontWeight: 700,
                          padding: "1px 5px",
                          borderRadius: 3,
                          background: "rgba(251,191,36,0.1)",
                          color: "rgb(251,191,36)",
                          border: "1px solid rgba(251,191,36,0.2)",
                          flexShrink: 0,
                        }}
                      >
                        {sub.id}
                      </span>
                      <span
                        style={{
                          fontSize: "var(--font-size-xs)",
                          color: "var(--text-secondary)",
                        }}
                      >
                        {sub.name}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Indicators */}
          <div style={{ marginBottom: 0 }}>
            <p
              style={{
                margin: "0 0 8px",
                fontSize: "var(--font-size-xs)",
                fontWeight: 600,
                color: "var(--text-muted)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              Detected via
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {dt.indicators.map((ind, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    padding: "6px 10px",
                    borderRadius: "var(--radius-sm)",
                    background: "var(--bg-elevated)",
                  }}
                >
                  <span
                    style={{
                      fontSize: "var(--font-size-xs)",
                      fontFamily: "var(--font-mono)",
                      color: "var(--text-secondary)",
                      flex: 1,
                    }}
                  >
                    {ind.source_indicator}
                  </span>
                  <ConfidenceDot level={ind.confidence} />
                  <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
                    {ind.confidence}
                  </span>
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function MitreTab({ result, highlightId, onPin }: Props) {
  const { enabled: teacherEnabled, focus, blur } = useTeacherMode();
  const [selectedTech, setSelectedTech] = useState<DetectedTechnique | null>(null);
  const [localHighlight, setLocalHighlight] = useState<string | null>(highlightId ?? null);

  const mitre = result.mitre_techniques ?? [];
  const groups = groupTechniques(mitre);

  // Clear highlight after animation completes
  useEffect(() => {
    if (!localHighlight) return;
    const t = setTimeout(() => setLocalHighlight(null), 1800);
    return () => clearTimeout(t);
  }, [localHighlight]);

  // Sync highlight from parent
  useEffect(() => {
    if (highlightId) setLocalHighlight(highlightId);
  }, [highlightId]);

  if (mitre.length === 0) {
    return <AnimatedEmptyState icon="crosshair" title="No MITRE ATT&CK techniques detected" subtitle="No suspicious API combinations or indicators were mapped to ATT&CK techniques." />;
  }

  return (
    <div style={{ height: "100%", overflow: "hidden", display: "flex", flexDirection: "column" }}>
      {/* Header bar */}
      <div
        style={{
          flexShrink: 0,
          padding: "14px 24px 12px",
          background: "var(--bg-base)",
          borderBottom: "1px solid var(--border-subtle)",
          display: "flex",
          alignItems: "center",
          gap: 12,
        }}
      >
        <p style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)" }}>
          <span style={{ fontWeight: 500, color: "var(--text-primary)" }}>{new Set(mitre.map((m) => m.technique_id)).size}</span>
          {" "}technique{new Set(mitre.map((m) => m.technique_id)).size !== 1 ? "s" : ""} detected across{" "}
          <span style={{ fontWeight: 500, color: "var(--text-primary)" }}>{groups.length}</span>
          {" "}tactic{groups.length !== 1 ? "s" : ""}
        </p>
      </div>

      {/* Tactic columns */}
      <div
        style={{
          flex: 1,
          overflowX: "auto",
          overflowY: "hidden",
          padding: "20px 24px",
        }}
      >
        <div
          style={{
            display: "flex",
            gap: 16,
            height: "100%",
            alignItems: "flex-start",
          }}
        >
          {groups.map((group) => (
            <div
              key={group.tactic}
              style={{
                width: 200,
                flexShrink: 0,
                display: "flex",
                flexDirection: "column",
                gap: 8,
                height: "100%",
              }}
            >
              {/* Tactic header */}
              <div
                style={{
                  padding: "6px 10px",
                  borderRadius: "var(--radius-sm)",
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--border-subtle)",
                }}
              >
                <p
                  style={{
                    margin: 0,
                    fontSize: 10,
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    color: "var(--text-muted)",
                  }}
                >
                  {group.tactic}
                </p>
                <p style={{ margin: "1px 0 0", fontSize: 10, color: "var(--text-muted)" }}>
                  {group.techniques.length} technique{group.techniques.length !== 1 ? "s" : ""}
                </p>
              </div>

              {/* Technique cards */}
              <div
                style={{
                  flex: 1,
                  overflowY: "auto",
                  display: "flex",
                  flexDirection: "column",
                  gap: 8,
                }}
              >
                {group.techniques.map((dt) => (
                  <TechniqueCard
                    key={dt.id}
                    dt={dt}
                    highlighted={localHighlight === dt.id || localHighlight?.startsWith(dt.id + ".") === true}
                    onPin={onPin}
                    onClick={() => {
                      if (teacherEnabled) {
                        focus({
                          type: "mitre",
                          techniqueId: dt.id,
                          techniqueName: dt.name,
                          tactic: dt.tactic,
                          detectedSubs: dt.detectedSubs,
                          indicators: dt.indicators.map((i) => ({
                            source: i.source_indicator,
                            confidence: i.confidence,
                          })),
                        });
                      } else {
                        setSelectedTech(dt);
                      }
                    }}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technique modal */}
      {selectedTech && (
        <TechniqueModal
          dt={selectedTech}
          onClose={() => {
            setSelectedTech(null);
            blur();
          }}
        />
      )}
    </div>
  );
}
