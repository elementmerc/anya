import { useEffect, useState } from "react";
import { Upload, AlertCircle } from "lucide-react";
import { openFilePicker } from "@/lib/tauri-bridge";
import { getRecentAnalysisSummaries } from "@/lib/db";
import CaseBrowser from "@/components/CaseBrowser";

interface Props {
  isLoading: boolean;
  error: string | null;
  onFileDrop: (path: string) => void;
  onPickFile: (path: string) => void;
}

export default function DropZone({ isLoading, error, onFileDrop: handleDrop, onPickFile }: Props) {
  const [dragOver, setDragOver] = useState(false);
  const [recent, setRecent] = useState<Array<{ file_path: string; file_name: string; risk_score: number; timestamp: string }>>([]);

  useEffect(() => {
    getRecentAnalysisSummaries(5).then(setRecent).catch(() => {});
  }, []);

  // Drag-drop is handled globally in App.tsx — no listener here to avoid double-fire

  function onDragOver(e: React.DragEvent) { e.preventDefault(); setDragOver(true); }
  function onDragLeave(e: React.DragEvent) { e.preventDefault(); setDragOver(false); }

  async function handleBrowse() {
    const res = await openFilePicker();
    const path = Array.isArray(res) ? res[0] : res;
    if (path) onPickFile(path);
  }

  const borderColor = error
    ? "var(--risk-critical)"
    : dragOver
    ? "var(--accent)"
    : "var(--border)";

  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 32,
      }}
    >
      <div
        role="region"
        aria-label="Drop zone"
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={isLoading ? undefined : handleBrowse}
        style={{
          width: "100%",
          maxWidth: 480,
          minHeight: 280,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 12,
          border: `2px dashed ${borderColor}`,
          borderRadius: 12,
          background: dragOver ? "var(--bg-elevated)" : "transparent",
          transform: dragOver ? "scale(1.01)" : "scale(1)",
          transition: "all 150ms ease-out",
          padding: "40px 32px",
          cursor: isLoading ? "default" : "pointer",
        }}
      >
        {isLoading ? (
          <>
            <div
              style={{
                width: 32,
                height: 32,
                borderRadius: "50%",
                border: "3px solid var(--border)",
                borderTopColor: "var(--accent)",
              }}
              className="animate-spin"
            />
            <p style={{ fontSize: "var(--font-size-base)", color: "var(--text-secondary)", margin: 0 }}>
              Analysing…
            </p>
          </>
        ) : error ? (
          <>
            <AlertCircle size={32} style={{ color: "var(--risk-critical)" }} />
            <p
              style={{
                fontSize: "var(--font-size-base)",
                color: "var(--risk-critical)",
                margin: 0,
                textAlign: "center",
                maxWidth: 320,
              }}
            >
              {error}
            </p>
            <button
              onClick={(e) => { e.stopPropagation(); void handleBrowse(); }}
              style={{
                marginTop: 4,
                padding: "6px 16px",
                fontSize: "var(--font-size-sm)",
                borderRadius: "var(--radius)",
                border: "1px solid var(--border)",
                background: "var(--bg-elevated)",
                color: "var(--text-secondary)",
                cursor: "pointer",
                transition: "all 150ms ease-out",
              }}
            >
              Try another file
            </button>
          </>
        ) : (
          <>
            <Upload size={32} style={{ color: "var(--text-muted)" }} />
            <p style={{ fontSize: "var(--font-size-lg)", color: "var(--text-secondary)", margin: 0 }}>
              Drop a file to analyse
            </p>
            <p style={{ fontSize: "var(--font-size-sm)", color: "var(--text-muted)", margin: 0 }}>
              or click to browse
            </p>
            <p
              style={{
                fontSize: "var(--font-size-xs)",
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
                margin: 0,
                letterSpacing: "0.04em",
              }}
            >
              .exe · .elf · .macho · anything really
            </p>
            {recent.length > 0 && (
              <div style={{
                marginTop: 20, width: "100%", maxWidth: 360,
                animation: "batch-fade-in 300ms ease-out",
              }}>
                <p style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", margin: "0 0 8px", textAlign: "center" }}>
                  Recent
                </p>
                {recent.map((r, i) => (
                  <button
                    key={i}
                    onClick={(e) => { e.stopPropagation(); onPickFile(r.file_path); }}
                    style={{
                      display: "flex", alignItems: "center", justifyContent: "space-between",
                      width: "100%", padding: "6px 10px", border: "none",
                      background: "transparent", borderRadius: 4,
                      color: "var(--text-secondary)", fontSize: "var(--font-size-sm)",
                      cursor: "pointer", transition: "background 100ms ease",
                      textAlign: "left",
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                  >
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 220 }}>
                      {r.file_name}
                    </span>
                    <span style={{
                      fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)",
                      color: r.risk_score >= 70 ? "var(--risk-critical)" : r.risk_score >= 40 ? "var(--risk-medium)" : "var(--text-muted)",
                    }}>
                      {r.risk_score}
                    </span>
                  </button>
                ))}
              </div>
            )}
            <CaseBrowser onPickFile={onPickFile} />
          </>
        )}
      </div>
    </div>
  );
}
