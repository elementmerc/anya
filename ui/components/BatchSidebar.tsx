/**
 * BatchSidebar — collapsible left sidebar shown during batch analysis.
 *
 * Lists analysed files with colour-coded verdict pills and risk scores.
 * Width transitions between 0 (collapsed) and 280px (expanded) so the
 * main content area grows/shrinks accordingly — it never overlaps.
 */
import { useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, FolderOpen } from "lucide-react";
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
  onToggleRecursive: () => void;
  onToggleCollapse: () => void;
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function BatchSidebar({
  state,
  onSelectFile,
  onToggleRecursive,
  onToggleCollapse,
}: Props) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

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

  // Set of indices that already have results
  const completedIndices = useMemo(
    () => new Set(state.results.map((r) => r.index)),
    [state.results],
  );

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
              style={{
                flex: 1,
                fontSize: "var(--font-size-xs)",
                fontWeight: 600,
                color: "var(--text-primary)",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
              title={state.directoryPath ?? undefined}
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
            {sortedResults.map((file) => {
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

            {/* Pending files (not yet analysed) */}
            {state.isRunning &&
              Array.from({ length: state.totalFiles }, (_, i) => i)
                .filter((i) => !completedIndices.has(i))
                .map((i) => (
                  <div
                    key={`pending-${i}`}
                    style={{
                      padding: "8px 12px",
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      animation: "pulse 1.5s ease-in-out infinite",
                    }}
                  >
                    <span
                      style={{
                        flex: 1,
                        fontSize: "var(--font-size-xs)",
                        color: "var(--text-muted)",
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        minWidth: 0,
                        opacity: 0.5,
                      }}
                    >
                      Analysing...
                    </span>
                    <span
                      style={{
                        width: 48,
                        height: 8,
                        borderRadius: 4,
                        background: "var(--border-subtle)",
                        flexShrink: 0,
                        opacity: 0.5,
                      }}
                    />
                  </div>
                ))}
          </div>
        </div>
      </aside>
    </>
  );
}
