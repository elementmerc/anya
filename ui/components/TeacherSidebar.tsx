/**
 * TeacherSidebar — contextual explanation panel for Teacher Mode.
 *
 * Rendered as a flex sibling to the main tab content area. It transitions
 * its width between 0 (hidden) and 280px (visible) so the rest of the layout
 * shrinks/grows — it never overlaps content.
 *
 * The X button disables teacher mode entirely (synced with Settings toggle).
 */
import { GraduationCap, X, ExternalLink, BookOpen } from "lucide-react";
import { useTeacherMode, type TeacherFocusItem } from "@/hooks/useTeacherMode";
import mitreData from "@/data/mitre_attack.json";
import explanations from "@/data/technique_explanations.json";
import { getApiDescription } from "@/lib/apiDescriptions";

// ── Data look-up helpers ─────────────────────────────────────────────────────

interface MitreTechniqueEntry {
  id: string;
  name: string;
  tactic: string;
  description: string;
  subtechniques: { id: string; name: string; description: string }[];
}

const techniqueMap = new Map<string, MitreTechniqueEntry>();
for (const t of (mitreData as { techniques: MitreTechniqueEntry[] }).techniques) {
  techniqueMap.set(t.id, t);
  for (const sub of t.subtechniques) {
    techniqueMap.set(sub.id, { ...sub, tactic: t.tactic, subtechniques: [] });
  }
}

const explanationMap = explanations as Record<string, { simple: string }>;

function getSimpleExplanation(techniqueId: string): string | null {
  const exact = explanationMap[techniqueId]?.simple;
  if (exact) return exact;
  return explanationMap[techniqueId.split(".")[0]]?.simple ?? null;
}

function getTechniqueDescription(techniqueId: string): string | null {
  return techniqueMap.get(techniqueId)?.description ?? null;
}

// ── Empty state ───────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "32px 20px",
        gap: 12,
        textAlign: "center",
      }}
    >
      <div
        style={{
          width: 40,
          height: 40,
          borderRadius: "50%",
          background: "rgba(99,102,241,0.1)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        <BookOpen size={18} style={{ color: "rgb(129,140,248)" }} />
      </div>
      <p style={{ margin: 0, fontSize: "var(--font-size-sm)", fontWeight: 500, color: "var(--text-primary)" }}>
        Teacher Mode
      </p>
      <p style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.6 }}>
        Click or hover any flagged item — a MITRE badge, suspicious API, or
        detection card — to get an explanation here.
      </p>
    </div>
  );
}

// ── MITRE focus content ───────────────────────────────────────────────────────

function MitreFocusContent({ item }: { item: Extract<TeacherFocusItem, { type: "mitre" }> }) {
  const techDescription = getTechniqueDescription(item.techniqueId);
  const simpleExplanation = getSimpleExplanation(item.techniqueId);
  const attackUrl = `https://attack.mitre.org/techniques/${item.techniqueId.replace(".", "/")}/`;

  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
      {/* Technique ID + external link */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <span
          style={{
            fontSize: "var(--font-size-xs)",
            fontFamily: "var(--font-mono)",
            fontWeight: 700,
            padding: "2px 7px",
            borderRadius: 4,
            background: "rgba(99,102,241,0.15)",
            color: "rgb(129,140,248)",
            border: "1px solid rgba(99,102,241,0.3)",
            flexShrink: 0,
          }}
        >
          {item.techniqueId}
        </span>
        <a
          href={attackUrl}
          target="_blank"
          rel="noopener noreferrer"
          title="View on MITRE ATT&CK"
          style={{ color: "var(--text-muted)", display: "flex", alignItems: "center", flexShrink: 0 }}
          onClick={(e) => e.stopPropagation()}
        >
          <ExternalLink size={11} />
        </a>
      </div>

      {/* Name + tactic */}
      <h3
        style={{
          margin: "0 0 6px",
          fontSize: "var(--font-size-sm)",
          fontWeight: 600,
          color: "var(--text-primary)",
          lineHeight: 1.3,
        }}
      >
        {item.techniqueName}
      </h3>
      <span
        style={{
          display: "inline-block",
          marginBottom: 14,
          fontSize: 10,
          padding: "1px 6px",
          borderRadius: 999,
          background: "var(--bg-elevated)",
          color: "var(--text-muted)",
          border: "1px solid var(--border)",
        }}
      >
        {item.tactic}
      </span>

      {/* What it does */}
      {techDescription && (
        <div style={{ marginBottom: 14 }}>
          <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            What it does
          </p>
          <p style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.6 }}>
            {techDescription}
          </p>
        </div>
      )}

      {/* Subtechniques detected (only when focused from MITRE tab) */}
      {item.detectedSubs && item.detectedSubs.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Subtechniques detected
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {item.detectedSubs.map((sub) => (
              <div
                key={sub.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "5px 8px",
                  borderRadius: "var(--radius-sm)",
                  background: "var(--bg-elevated)",
                }}
              >
                <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", fontWeight: 700, color: "rgb(251,191,36)", flexShrink: 0 }}>
                  {sub.id}
                </span>
                <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-secondary)" }}>
                  {sub.name}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detected via (only when focused from MITRE tab) */}
      {item.indicators && item.indicators.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Detected via
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
            {item.indicators.map((ind, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "4px 8px",
                  borderRadius: "var(--radius-sm)",
                  background: "var(--bg-elevated)",
                }}
              >
                <span style={{ flex: 1, fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                  {ind.source}
                </span>
                <span style={{ fontSize: 10, color: "var(--text-muted)", flexShrink: 0 }}>
                  {ind.confidence}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Divider + Simple explanation */}
      {simpleExplanation && (
        <>
          <div
            style={{
              margin: "14px 0 10px",
              paddingTop: 14,
              borderTop: "1px solid var(--border-subtle)",
              display: "flex",
              alignItems: "center",
              gap: 5,
            }}
          >
            <GraduationCap size={11} style={{ color: "var(--text-muted)" }} />
            <span
              style={{
                fontSize: 10,
                color: "var(--text-muted)",
                fontWeight: 600,
                letterSpacing: "0.04em",
                textTransform: "uppercase",
              }}
            >
              Simple explanation
            </span>
          </div>
          <div
            style={{
              background: "rgba(99,102,241,0.06)",
              border: "1px solid rgba(99,102,241,0.2)",
              borderRadius: "var(--radius)",
              padding: "12px 14px",
            }}
          >
            <p style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-primary)", lineHeight: 1.7 }}>
              {simpleExplanation}
            </p>
          </div>
        </>
      )}
    </div>
  );
}

// ── API focus content ─────────────────────────────────────────────────────────

function ApiFocusContent({ item }: { item: Extract<TeacherFocusItem, { type: "api" }> }) {
  const techDesc = getApiDescription(item.name);
  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
      <h3
        style={{
          margin: "0 0 6px",
          fontSize: "var(--font-size-sm)",
          fontWeight: 600,
          fontFamily: "var(--font-mono)",
          color: "var(--text-primary)",
          wordBreak: "break-all",
        }}
      >
        {item.name}
      </h3>
      {item.category && (
        <span
          style={{
            display: "inline-block",
            marginBottom: 14,
            fontSize: 10,
            padding: "1px 6px",
            borderRadius: 999,
            background: "rgba(249,115,22,0.12)",
            color: "var(--risk-high)",
            border: "1px solid rgba(249,115,22,0.2)",
          }}
        >
          {item.category}
        </span>
      )}
      {techDesc ? (
        <div>
          <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Why it&apos;s suspicious
          </p>
          <p style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.6 }}>
            {techDesc}
          </p>
        </div>
      ) : (
        <p style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-muted)", lineHeight: 1.6 }}>
          This API is flagged as suspicious based on its category. Hover a MITRE badge for full technique context.
        </p>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function TeacherSidebar() {
  const { enabled, setEnabled, focusedItem } = useTeacherMode();

  return (
    <div
      style={{
        // Push layout: flex child that smoothly transitions between 0 and 280px.
        // `overflow: hidden` clips content during the transition so nothing leaks
        // into the main area.
        width: enabled ? 280 : 0,
        minWidth: enabled ? 280 : 0,
        flexShrink: 0,
        overflow: "hidden",
        transition: "width 250ms ease-out, min-width 250ms ease-out",
      }}
    >
      {/* Inner container always 280px wide so content doesn't wrap during animation */}
      <div
        style={{
          width: 280,
          height: "100%",
          background: "var(--bg-surface)",
          borderLeft: "1px solid var(--border)",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Header */}
        <div
          style={{
            flexShrink: 0,
            padding: "10px 14px",
            borderBottom: "1px solid var(--border-subtle)",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <GraduationCap size={14} style={{ color: "rgb(129,140,248)", flexShrink: 0 }} />
          <span style={{ flex: 1, fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-primary)", whiteSpace: "nowrap" }}>
            Teacher Mode
          </span>
          <button
            onClick={() => setEnabled(false)}
            title="Disable Teacher Mode"
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              color: "var(--text-muted)",
              padding: 2,
              display: "flex",
              alignItems: "center",
              borderRadius: "var(--radius-sm)",
              flexShrink: 0,
            }}
          >
            <X size={13} />
          </button>
        </div>

        {/* Content area */}
        {!focusedItem && <EmptyState />}
        {focusedItem?.type === "mitre" && <MitreFocusContent item={focusedItem} />}
        {focusedItem?.type === "api" && <ApiFocusContent item={focusedItem} />}
      </div>
    </div>
  );
}
