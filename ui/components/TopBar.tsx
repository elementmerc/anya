import { useState } from "react";
import { Sun, Moon, Download, Settings, Plus, FileCode } from "lucide-react";
import { exportJson, saveJsonPicker } from "@/lib/tauri-bridge";
import { formatBytes } from "@/lib/utils";
import type { AnalysisResult } from "@/types/analysis";

interface Props {
  fileName: string;
  fileSize: number | null;
  theme: "dark" | "light";
  onToggleTheme: () => void;
  onNewFile: () => void;
  /** Pass the full result to enable export; null = disabled */
  onExport: AnalysisResult | null;
  onSettings: () => void;
}

function GhostButton({
  onClick,
  disabled,
  title,
  "data-testid": dataTestId,
  children,
}: {
  onClick?: () => void;
  disabled?: boolean;
  title?: string;
  "data-testid"?: string;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      data-testid={dataTestId}
      style={{
        height: 32,
        padding: "0 10px",
        display: "flex",
        alignItems: "center",
        gap: 6,
        fontSize: "var(--font-size-sm)",
        borderRadius: "var(--radius-sm)",
        border: "1px solid transparent",
        background: "transparent",
        color: disabled ? "var(--text-muted)" : "var(--text-secondary)",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
        transition: "all 150ms ease-out",
        flexShrink: 0,
      }}
      onMouseEnter={(e) => {
        if (disabled) return;
        const el = e.currentTarget as HTMLButtonElement;
        el.style.background = "var(--bg-elevated)";
        el.style.borderColor = "var(--border)";
        el.style.color = "var(--text-primary)";
      }}
      onMouseLeave={(e) => {
        const el = e.currentTarget as HTMLButtonElement;
        el.style.background = "transparent";
        el.style.borderColor = "transparent";
        el.style.color = disabled ? "var(--text-muted)" : "var(--text-secondary)";
      }}
      onMouseDown={(e) => {
        if (disabled) return;
        (e.currentTarget as HTMLButtonElement).style.transform = "scale(0.97)";
      }}
      onMouseUp={(e) => {
        (e.currentTarget as HTMLButtonElement).style.transform = "scale(1)";
      }}
    >
      {children}
    </button>
  );
}

export default function TopBar({
  fileName,
  fileSize,
  theme,
  onToggleTheme,
  onNewFile,
  onExport,
  onSettings,
}: Props) {
  const [exporting, setExporting] = useState(false);

  async function handleExport() {
    if (!onExport || exporting) return;
    const outputPath = await saveJsonPicker();
    if (!outputPath) return;
    setExporting(true);
    try {
      await exportJson(onExport, outputPath);
    } finally {
      setExporting(false);
    }
  }

  return (
    <header
      style={{
        height: 48,
        flexShrink: 0,
        display: "flex",
        alignItems: "center",
        padding: "0 16px",
        gap: 12,
        background: "var(--bg-surface)",
        borderBottom: "1px solid var(--border-subtle)",
      }}
    >
      {/* Left: wordmark */}
      <span
        style={{
          fontSize: "var(--font-size-sm)",
          fontWeight: 500,
          letterSpacing: "0.05em",
          color: "var(--text-muted)",
          flexShrink: 0,
        }}
      >
        anya
      </span>

      {/* Centre: file info */}
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          gap: 8,
          minWidth: 0,
          overflow: "hidden",
        }}
      >
        {fileName && (
          <>
            <FileCode size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
            <span
              style={{
                fontSize: "var(--font-size-base)",
                color: "var(--text-primary)",
                fontFamily: "var(--font-mono)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                minWidth: 0,
              }}
            >
              {fileName}
            </span>
            {fileSize !== null && (
              <>
                <span style={{ color: "var(--border)", flexShrink: 0 }}>·</span>
                <span
                  style={{
                    fontSize: "var(--font-size-xs)",
                    color: "var(--text-muted)",
                    flexShrink: 0,
                    whiteSpace: "nowrap",
                  }}
                >
                  {formatBytes(fileSize)}
                </span>
              </>
            )}
          </>
        )}
      </div>

      {/* Right: actions */}
      <div style={{ display: "flex", alignItems: "center", gap: 4, flexShrink: 0 }}>
        <GhostButton onClick={onToggleTheme} title="Toggle theme">
          {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
        </GhostButton>

        <GhostButton
          onClick={onExport ? () => void handleExport() : undefined}
          disabled={!onExport || exporting}
          title="Export JSON"
        >
          <Download size={14} />
          <span className="hidden sm:inline">{exporting ? "Exporting…" : "Export"}</span>
        </GhostButton>

        <GhostButton onClick={onSettings} title="Settings" data-testid="settings-button">
          <Settings size={15} />
        </GhostButton>

        <GhostButton onClick={onNewFile} title="Analyse another file">
          <Plus size={15} />
        </GhostButton>
      </div>
    </header>
  );
}
