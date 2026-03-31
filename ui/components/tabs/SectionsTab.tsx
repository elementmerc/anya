import { useState, useMemo } from "react";
import { AlertTriangle, ArrowUpDown, ArrowUp, ArrowDown, Pin } from "lucide-react";
import AnimatedEmptyState from "@/components/AnimatedEmptyState";
import { formatBytes } from "@/lib/utils";
import CopyButton from "@/components/CopyButton";
import type { AnalysisResult, SectionInfo } from "@/types/analysis";

interface PinnedFinding {
  type: string;
  label: string;
  detail: string;
}

interface Props {
  result: AnalysisResult;
  suspiciousEntropy?: number;
  packedEntropy?: number;
  onPin?: (finding: PinnedFinding) => void;
}

type SortKey = "name" | "virtual_size" | "raw_size" | "entropy";
type SortDir = "asc" | "desc" | null;

function entropyColor(e: number, suspicious = 5.0, packed = 7.0): string {
  if (e >= packed) return "var(--risk-critical)";
  if (e >= suspicious) return "var(--risk-medium)";
  return "var(--text-secondary)";
}

function SortIcon({ col, sortKey, sortDir }: { col: SortKey; sortKey: SortKey; sortDir: SortDir }) {
  if (col !== sortKey) return <ArrowUpDown size={12} style={{ opacity: 0.4 }} />;
  if (sortDir === "asc")  return <ArrowUp   size={12} style={{ color: "var(--accent)" }} />;
  if (sortDir === "desc") return <ArrowDown  size={12} style={{ color: "var(--accent)" }} />;
  return <ArrowUpDown size={12} style={{ opacity: 0.4 }} />;
}

function PermBadge({ label, color, bg }: { label: string; color: string; bg: string }) {
  return (
    <span
      style={{
        fontSize: "var(--font-size-xs)",
        padding: "1px 6px",
        borderRadius: 4,
        background: bg,
        color,
        fontFamily: "var(--font-mono)",
        fontWeight: 600,
      }}
    >
      {label}
    </span>
  );
}

export default function SectionsTab({ result, suspiciousEntropy = 5.0, packedEntropy = 7.0, onPin }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<SortDir>(null);

  const sections: SectionInfo[] =
    result.pe_analysis?.sections ?? [];

  function handleSort(key: SortKey) {
    if (sortKey !== key) {
      setSortKey(key);
      setSortDir("asc");
    } else {
      setSortDir((prev) => (prev === "asc" ? "desc" : prev === "desc" ? null : "asc"));
    }
  }

  const sorted = useMemo(() => {
    if (!sortDir) return [...sections];
    return [...sections].sort((a, b) => {
      let av: string | number = a[sortKey] ?? 0;
      let bv: string | number = b[sortKey] ?? 0;
      if (typeof av === "string" && typeof bv === "string") {
        av = av.toLowerCase();
        bv = bv.toLowerCase();
      }
      const cmp = av < bv ? -1 : av > bv ? 1 : 0;
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [sections, sortKey, sortDir]);

  if (sections.length === 0) {
    return <AnimatedEmptyState icon="layers" title="No section data available" subtitle="This file doesn't contain parseable PE or ELF sections." />;
  }

  const HEADER_STYLE: React.CSSProperties = {
    padding: "10px 12px",
    fontSize: "var(--font-size-xs)",
    fontWeight: 600,
    textTransform: "uppercase" as const,
    letterSpacing: "0.06em",
    color: "var(--text-muted)",
    textAlign: "left" as const,
    userSelect: "none" as const,
    whiteSpace: "nowrap" as const,
    borderBottom: "1px solid var(--border-subtle)",
    background: "var(--bg-surface)",
  };

  const cols: { key: SortKey; label: string; sortable: boolean }[] = [
    { key: "name",         label: "Name",        sortable: true },
    { key: "virtual_size", label: "Virtual Size", sortable: true },
    { key: "raw_size",     label: "Raw Size",     sortable: true },
    { key: "entropy",      label: "Entropy",      sortable: true },
  ];

  return (
    <div style={{ height: "100%", overflow: "auto", padding: 24 }}>
      <div style={{ maxWidth: 1600, margin: "0 auto" }}>
        {/* Horizontally scrollable table wrapper */}
        <div style={{ overflowX: "auto" }}>
          <table
            style={{
              minWidth: 700,
              width: "100%",
              borderCollapse: "collapse",
              tableLayout: "auto",
            }}
          >
            <thead>
              <tr>
                {cols.map(({ key, label, sortable }) => (
                  <th
                    key={key}
                    style={{
                      ...HEADER_STYLE,
                      cursor: sortable ? "pointer" : "default",
                      color: sortKey === key && sortDir ? "var(--text-primary)" : "var(--text-muted)",
                    }}
                    onClick={sortable ? () => handleSort(key) : undefined}
                  >
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                      {label}
                      {sortable && <SortIcon col={key} sortKey={sortKey} sortDir={sortDir} />}
                    </span>
                  </th>
                ))}
                <th style={{ ...HEADER_STYLE }}>Anomaly</th>
                <th style={{ ...HEADER_STYLE }}>Permissions</th>
                <th style={{ ...HEADER_STYLE }}>Flags</th>
                <th style={{ ...HEADER_STYLE, width: 40 }}></th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((sec, i) => {
                const isWX = sec.is_wx;
                return (
                  <tr
                    key={sec.name || i}
                    className="stagger-row"
                    style={{
                      "--index": i,
                      background: isWX ? "var(--suspicious-bg)" : "transparent",
                      transition: "background 150ms ease-out",
                    } as React.CSSProperties}
                    onMouseEnter={(e) => {
                      if (!isWX) (e.currentTarget as HTMLTableRowElement).style.background = "var(--bg-elevated)";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLTableRowElement).style.background = isWX ? "var(--suspicious-bg)" : "transparent";
                    }}
                  >
                    <td
                      className="selectable"
                      style={{
                        padding: "10px 12px",
                        fontSize: "var(--font-size-sm)",
                        fontFamily: "var(--font-mono)",
                        color: "var(--text-primary)",
                        borderBottom: "1px solid var(--border-subtle)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {sec.name || "<unnamed>"}
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        fontSize: "var(--font-size-sm)",
                        color: "var(--text-secondary)",
                        borderBottom: "1px solid var(--border-subtle)",
                        textAlign: "right",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {formatBytes(sec.virtual_size)}
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        fontSize: "var(--font-size-sm)",
                        color: "var(--text-secondary)",
                        borderBottom: "1px solid var(--border-subtle)",
                        textAlign: "right",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {formatBytes(sec.raw_size)}
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        fontSize: "var(--font-size-sm)",
                        fontFamily: "var(--font-mono)",
                        color: entropyColor(sec.entropy, suspiciousEntropy, packedEntropy),
                        borderBottom: "1px solid var(--border-subtle)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {sec.entropy.toFixed(4)}
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        fontSize: "var(--font-size-xs)",
                        color: sec.name_anomaly ? "var(--risk-medium)" : "var(--text-muted)",
                        borderBottom: "1px solid var(--border-subtle)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {sec.name_anomaly ?? "—"}
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        borderBottom: "1px solid var(--border-subtle)",
                      }}
                    >
                      <div style={{ display: "flex", gap: 4, flexWrap: "nowrap" }}>
                        <PermBadge
                          label="R"
                          color="var(--text-secondary)"
                          bg="var(--bg-elevated)"
                        />
                        {isWX && (
                          <>
                            <PermBadge label="W" color="var(--risk-medium)" bg="rgba(250,204,21,0.12)" />
                            <PermBadge label="X" color="var(--risk-critical)" bg="rgba(239,68,68,0.12)" />
                          </>
                        )}
                      </div>
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        fontSize: "var(--font-size-xs)",
                        borderBottom: "1px solid var(--border-subtle)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {isWX ? (
                        <span
                          title="Section is both writable and executable — common in shellcode loaders and injectors."
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 5,
                            color: "var(--risk-critical)",
                            cursor: "help",
                          }}
                        >
                          <AlertTriangle size={13} />
                          W+X
                        </span>
                      ) : (
                        <span style={{ color: "var(--text-muted)" }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: "10px 4px", borderBottom: "1px solid var(--border-subtle)", display: "flex", gap: 2, alignItems: "center" }}>
                      <CopyButton text={`${sec.name}: VSize=${formatBytes(sec.virtual_size)} Raw=${formatBytes(sec.raw_size)} Entropy=${sec.entropy.toFixed(4)}${isWX ? " [W+X]" : ""}`} label="Copy section summary" />
                      {isWX && onPin && (
                        <button
                          onClick={() => onPin({ type: "section", label: sec.name || "<unnamed>", detail: `W+X section — entropy ${sec.entropy.toFixed(2)}` })}
                          style={{ opacity: 0.4, cursor: "pointer", background: "transparent", border: "none", color: "var(--text-muted)", padding: 2 }}
                          title="Pin to Overview"
                        >
                          <Pin size={11} />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <p style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", paddingTop: 12 }}>
          {sections.length} section{sections.length !== 1 ? "s" : ""} total
        </p>
      </div>
    </div>
  );
}
