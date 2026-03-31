/**
 * BatchSidebar — collapsible left sidebar shown during batch analysis.
 *
 * Lists analysed files with colour-coded verdict pills and risk scores.
 * Width transitions between 0 (collapsed) and 280px (expanded) so the
 * main content area grows/shrinks accordingly — it never overlaps.
 */
import { useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, FolderOpen, Search } from "lucide-react";
import type { BatchState, Verdict } from "@/types/analysis";

// ── Verdict styling ────────────────────────────────────────────────────────────

const VERDICT_STYLES: Record<Verdict, { bg: string; color: string }> = {
  clean: { bg: "rgba(34,197,94,0.12)", color: "var(--risk-low)" },
  suspicious: { bg: "rgba(234,179,8,0.12)", color: "var(--risk-medium)" },
  malicious: { bg: "rgba(239,68,68,0.12)", color: "var(--risk-critical)" },
  error: { bg: "rgba(128,128,128,0.12)", color: "var(--text-muted)" },
};

// ── Props ──────────────────────────────────────────────────────────────────────

interface Props {
  state: BatchState;
  onSelectFile: (index: number) => void;
  onDeselectFile: () => void;
  onToggleRecursive: () => void;
  onToggleCollapse: () => void;
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function BatchSidebar({
  state,
  onSelectFile,
  onDeselectFile,
  onToggleRecursive,
  onToggleCollapse,
}: Props) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  // Extract folder name from directory path
  const folderName = useMemo(() => {
    if (!state.directoryPath) return "Batch";
    const segments = state.directoryPath.replace(/[\\/]+$/, "").split(/[\\/]/);
    return segments[segments.length - 1] || "Batch";
  }, [state.directoryPath]);

  // Sort results by discovery order (index)
  const sortedResults = useMemo(
    () => [...state.results].sort((a, b) => a.index - b.index),
    [state.results],
  );

  // Filter results by search query (matches filename)
  const filteredResults = useMemo(() => {
    if (!searchQuery.trim()) return sortedResults;
    const q = searchQuery.toLowerCase();
    return sortedResults.filter((r) => {
      const name = r.filePath.split(/[\\/]/).pop() ?? r.filePath;
      return name.toLowerCase().includes(q);
    });
  }, [sortedResults, searchQuery]);

  // Progress percentage
  const progressPct =
    state.totalFiles > 0
      ? (state.results.length / state.totalFiles) * 100
      : 0;

  return (
    <>
      {/* Collapsed toggle strip */}
      {state.sidebarCollapsed && (
        <div
          onClick={onToggleCollapse}
          title="Expand batch sidebar"
          style={{
            width: 20,
            height: "100%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "var(--bg-base)",
            borderRight: "1px solid var(--border-subtle)",
            cursor: "pointer",
            color: "var(--text-muted)",
            flexShrink: 0,
          }}
        >
          <ChevronRight size={14} />
        </div>
      )}

      <aside
        data-testid="batch-sidebar"
        style={{
          width: state.sidebarCollapsed ? 0 : 280,
          transition: "width 200ms ease-out",
          overflow: "hidden",
          borderRight: "1px solid var(--border-subtle)",
          background: "var(--bg-base)",
          display: "flex",
          flexDirection: "column",
          flexShrink: 0,
          height: "100%",
        }}
      >
        {/* Inner wrapper — fixed minWidth so content doesn't squish */}
        <div
          style={{
            minWidth: 280,
            display: "flex",
            flexDirection: "column",
            height: "100%",
          }}
        >
          {/* ── Header ──────────────────────────────────────────────────── */}
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
            <FolderOpen
              size={14}
              style={{ color: "var(--accent)", flexShrink: 0 }}
            />
            <span
              onClick={onDeselectFile}
              style={{
                flex: 1,
                fontSize: "var(--font-size-xs)",
                fontWeight: 600,
                color: state.selectedIndex !== null ? "var(--text-secondary)" : "var(--text-primary)",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
                cursor: "pointer",
                transition: "color 150ms ease-out",
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLSpanElement).style.color = "var(--text-primary)"; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLSpanElement).style.color = state.selectedIndex !== null ? "var(--text-secondary)" : "var(--text-primary)"; }}
              title={state.selectedIndex !== null ? "Click to return to batch summary" : (state.directoryPath ?? undefined)}
            >
              {folderName}
            </span>
            <span
              style={{
                fontSize: 10,
                fontFamily: "var(--font-mono)",
                color: "var(--text-muted)",
                flexShrink: 0,
                whiteSpace: "nowrap",
              }}
            >
              {state.results.length} / {state.isRunning && state.totalFiles === 0 ? "\u2026" : state.totalFiles} file{(state.totalFiles || state.results.length) !== 1 ? "s" : ""}
            </span>
            <button
              onClick={onToggleCollapse}
              title="Collapse sidebar"
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
              <ChevronLeft size={13} />
            </button>
          </div>

          {/* ── Search bar ───────────────────────────────────────────────── */}
          <div
            style={{
              flexShrink: 0,
              padding: "6px 10px",
              borderBottom: "1px solid var(--border-subtle)",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                padding: "5px 8px",
                borderRadius: "var(--radius-sm)",
                background: "var(--bg-elevated)",
                border: "1px solid var(--border-subtle)",
              }}
            >
              <Search size={12} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
              <input
                type="text"
                placeholder="Search files..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  flex: 1,
                  border: "none",
                  outline: "none",
                  background: "transparent",
                  color: "var(--text-primary)",
                  fontSize: "var(--font-size-xs)",
                  fontFamily: "var(--font-ui)",
                  padding: 0,
                  minWidth: 0,
                }}
              />
            </div>
          </div>

          {/* ── Recursive toggle ────────────────────────────────────────── */}
          <div
            style={{
              flexShrink: 0,
              padding: "8px 14px",
              borderBottom: "1px solid var(--border-subtle)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
            }}
          >
            <span
              style={{
                fontSize: "var(--font-size-xs)",
                color: "var(--text-secondary)",
              }}
            >
              Recursive
            </span>
            <button
              role="switch"
              aria-checked={state.recursive}
              onClick={onToggleRecursive}
              style={{
                width: 36,
                height: 20,
                borderRadius: 999,
                border: "none",
                background: state.recursive
                  ? "rgb(99,102,241)"
                  : "var(--bg-elevated)",
                position: "relative",
                cursor: "pointer",
                transition: "background 200ms ease-out",
                flexShrink: 0,
                outline: "1px solid var(--border)",
              }}
            >
              <span
                style={{
                  position: "absolute",
                  top: 3,
                  left: state.recursive ? 19 : 3,
                  width: 14,
                  height: 14,
                  borderRadius: "50%",
                  background: "white",
                  transition: "left 200ms ease-out",
                }}
              />
            </button>
          </div>

          {/* ── Progress bar (only while running) ───────────────────────── */}
          {state.isRunning && (
            <div
              style={{
                flexShrink: 0,
                height: 3,
                background: "var(--border-subtle)",
                borderRadius: 2,
              }}
            >
              <div
                style={{
                  height: 3,
                  background: "var(--accent)",
                  borderRadius: 2,
                  width: `${progressPct}%`,
                  transition: "width 300ms ease-out",
                }}
              />
            </div>
          )}

          {/* ── File list (scrollable) ──────────────────────────────────── */}
          <div style={{ flex: 1, overflowY: "auto" }}>
            {/* Completed results */}
            {filteredResults.map((file) => {
              const isActive = file.index === state.selectedIndex;
              const isHovered = file.index === hoveredIndex;
              const verdictStyle = VERDICT_STYLES[file.verdict];

              return (
                <div
                  key={file.index}
                  onClick={() => onSelectFile(file.index)}
                  onMouseEnter={() => setHoveredIndex(file.index)}
                  onMouseLeave={() => setHoveredIndex(null)}
                  style={{
                    padding: "8px 12px",
                    cursor: "pointer",
                    background: isActive
                      ? "var(--bg-elevated)"
                      : isHovered
                        ? "var(--bg-surface)"
                        : "transparent",
                    transition: "background 150ms ease",
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    animation: "batch-row-enter 200ms ease-out",
                  }}
                >
                  {/* File name */}
                  <span
                    style={{
                      flex: 1,
                      fontSize: "var(--font-size-xs)",
                      color: "var(--text-primary)",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      minWidth: 0,
                    }}
                    title={file.fileName}
                  >
                    {file.fileName}
                  </span>

                  {/* Verdict pill */}
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 600,
                      padding: "1px 7px",
                      borderRadius: 999,
                      background: verdictStyle.bg,
                      color: verdictStyle.color,
                      whiteSpace: "nowrap",
                      flexShrink: 0,
                      textTransform: "capitalize",
                    }}
                  >
                    {file.verdict}
                  </span>

                  {/* Risk score */}
                  <span
                    style={{
                      fontSize: 10,
                      fontFamily: "var(--font-mono)",
                      color: "var(--text-muted)",
                      flexShrink: 0,
                      minWidth: 24,
                      textAlign: "right",
                    }}
                  >
                    {file.verdict === "error" ? "—" : file.riskScore}
                  </span>
                </div>
              );
            })}

            {/* Pending files — shimmer skeleton rows */}
            {state.isRunning &&
              Array.from({ length: Math.min(state.totalFiles - state.results.length, 8) }, (_, i) => (
                <div
                  key={`pending-${i}`}
                  style={{
                    padding: "8px 12px",
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                  }}
                >
                  <div className="skeleton-row" style={{ flex: 1, height: 12, borderRadius: 4, animationDelay: `${i * 100}ms` }} />
                  <div className="skeleton-row" style={{ width: 48, height: 12, borderRadius: 4, animationDelay: `${i * 100 + 50}ms` }} />
                </div>
              ))}
          </div>
        </div>
      </aside>
    </>
  );
}
