import { useState, useEffect, forwardRef } from "react";
import { Sun, Moon, Download, Settings, Plus, FileCode, File, FolderSearch, Briefcase, GitCompare } from "lucide-react";
import * as Popover from "@radix-ui/react-popover";
import { exportJson, saveJsonPicker, exportHtmlReport, saveHtmlPicker, saveToCase, listCases, pickNewCaseFolder, pickExistingCaseFolder } from "@/lib/tauri-bridge";
import { formatBytes } from "@/lib/utils";
import { useToast } from "@/components/Toast";
import type { AnalysisResult, CaseSummary } from "@/types/analysis";

interface Props {
  fileName: string;
  fileSize: number | null;
  theme: "dark" | "light";
  onToggleTheme: () => void;
  onNewFile: () => void;
  /** Pass the full result to enable export; null = disabled */
  onExport: AnalysisResult | null;
  onSettings: () => void;
  onBatchAnalysis: () => void;
  onCompare?: () => void;
  /** Pass the full result to enable Save to Case; null = disabled */
  onSaveToCase?: AnalysisResult | null;
}

const GhostButton = forwardRef<
  HTMLButtonElement,
  {
    onClick?: () => void;
    disabled?: boolean;
    title?: string;
    "data-testid"?: string;
    children: React.ReactNode;
  }
>(function GhostButton({ onClick, disabled, title, "data-testid": dataTestId, children }, ref) {
  return (
    <button
      ref={ref}
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
});

export default function TopBar({
  fileName,
  fileSize,
  theme,
  onToggleTheme,
  onNewFile,
  onExport,
  onSettings,
  onBatchAnalysis,
  onSaveToCase,
  onCompare,
}: Props) {
  const [exporting, setExporting] = useState(false);
  const [caseMenuOpen, setCaseMenuOpen] = useState(false);
  const [recentCases, setRecentCases] = useState<CaseSummary[]>([]);
  const [savingCase, setSavingCase] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    if (caseMenuOpen) {
      listCases().then((all) => setRecentCases(all.slice(0, 5))).catch(() => setRecentCases([]));
    }
  }, [caseMenuOpen]);

  async function handleNewCase() {
    if (savingCase) return;
    setCaseMenuOpen(false);
    const folder = await pickNewCaseFolder();
    if (!folder) return;
    const name = folder.split(/[\\/]/).filter(Boolean).pop() ?? "untitled";
    if (!onSaveToCase) {
      toast(`Case "${name}" created`, "success");
      return;
    }
    setSavingCase(true);
    try {
      await saveToCase(onSaveToCase, name);
      toast(`Saved to new case "${name}"`, "success");
    } catch (e) {
      toast(`Failed to create case: ${e}`, "error");
    } finally {
      setSavingCase(false);
    }
  }

  async function handleOpenCase() {
    setCaseMenuOpen(false);
    const folder = await pickExistingCaseFolder();
    if (!folder) return;
    const name = folder.split(/[\\/]/).filter(Boolean).pop() ?? "";
    if (!onSaveToCase) {
      toast(`Opened case "${name}"`, "success");
      return;
    }
    setSavingCase(true);
    try {
      await saveToCase(onSaveToCase, name);
      toast(`Saved to case "${name}"`, "success");
    } catch (e) {
      toast(`Failed to save to case: ${e}`, "error");
    } finally {
      setSavingCase(false);
    }
  }

  async function handleRecentCase(name: string) {
    if (savingCase) return;
    setCaseMenuOpen(false);
    if (!onSaveToCase) {
      toast(`Opened case "${name}"`, "success");
      return;
    }
    setSavingCase(true);
    try {
      await saveToCase(onSaveToCase, name);
      toast(`Saved to case "${name}"`, "success");
    } catch (e) {
      toast(`Failed to save: ${e}`, "error");
    } finally {
      setSavingCase(false);
    }
  }

  async function handleExportJson() {
    if (!onExport || exporting) return;
    const outputPath = await saveJsonPicker();
    if (!outputPath) return;
    setExporting(true);
    try {
      await exportJson(onExport, outputPath);
      toast("JSON exported", "success");
    } finally {
      setExporting(false);
    }
  }

  async function handleExportHtml() {
    if (!onExport || exporting) return;
    const outputPath = await saveHtmlPicker();
    if (!outputPath) return;
    setExporting(true);
    try {
      await exportHtmlReport(onExport, outputPath);
      toast("HTML report exported", "success");
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

        <Popover.Root>
          <Popover.Trigger asChild>
            <GhostButton
              disabled={!onExport || exporting}
              title="Export"
            >
              <Download size={14} />
              <span className="hidden sm:inline">{exporting ? "Exporting..." : "Export"}</span>
            </GhostButton>
          </Popover.Trigger>
          <Popover.Portal>
            <Popover.Content
              side="bottom"
              align="end"
              sideOffset={6}
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius)",
                padding: 4,
                minWidth: 180,
                boxShadow: "0 8px 24px rgba(0,0,0,0.25)",
                zIndex: 100,
                animation: "popover-in 150ms ease-out",
              }}
            >
              <button
                onClick={() => void handleExportJson()}
                style={{
                  display: "flex", alignItems: "center", gap: 10, width: "100%",
                  padding: "8px 12px", border: "none", background: "transparent",
                  borderRadius: 4, color: "var(--text-primary)", fontSize: "var(--font-size-sm)",
                  cursor: "pointer", transition: "background 100ms ease",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <Download size={14} style={{ color: "var(--text-muted)" }} />
                Export JSON
              </button>
              <button
                onClick={() => void handleExportHtml()}
                style={{
                  display: "flex", alignItems: "center", gap: 10, width: "100%",
                  padding: "8px 12px", border: "none", background: "transparent",
                  borderRadius: 4, color: "var(--text-primary)", fontSize: "var(--font-size-sm)",
                  cursor: "pointer", transition: "background 100ms ease",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <FileCode size={14} style={{ color: "var(--text-muted)" }} />
                Export HTML Report
              </button>
            </Popover.Content>
          </Popover.Portal>
        </Popover.Root>

        <Popover.Root open={caseMenuOpen} onOpenChange={setCaseMenuOpen}>
          <Popover.Trigger asChild>
            <GhostButton title="Cases" disabled={false}>
              <Briefcase size={14} />
            </GhostButton>
          </Popover.Trigger>
          <Popover.Portal>
            <Popover.Content
              side="bottom"
              align="end"
              sideOffset={6}
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius)",
                padding: 4,
                minWidth: 200,
                boxShadow: "0 8px 24px rgba(0,0,0,0.25)",
                zIndex: 100,
                animation: "popover-in 150ms ease-out",
              }}
            >
              {/* New */}
              <button
                onClick={() => void handleNewCase()}
                disabled={savingCase}
                style={{
                  display: "flex", alignItems: "center", gap: 8,
                  width: "100%", padding: "8px 12px", border: "none",
                  background: "transparent", borderRadius: 4,
                  color: "var(--text-primary)", fontSize: "var(--font-size-sm)",
                  cursor: savingCase ? "not-allowed" : "pointer",
                  textAlign: "left",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <Plus size={14} style={{ color: "var(--text-muted)" }} />
                New Case
              </button>
              {/* Open */}
              <button
                onClick={() => void handleOpenCase()}
                disabled={savingCase}
                style={{
                  display: "flex", alignItems: "center", gap: 8,
                  width: "100%", padding: "8px 12px", border: "none",
                  background: "transparent", borderRadius: 4,
                  color: "var(--text-primary)", fontSize: "var(--font-size-sm)",
                  cursor: savingCase ? "not-allowed" : "pointer",
                  textAlign: "left",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <FolderSearch size={14} style={{ color: "var(--text-muted)" }} />
                Open Case...
              </button>
              {/* Recent */}
              {recentCases.length > 0 && (
                <>
                  <div style={{ height: 1, background: "var(--border-subtle)", margin: "4px 8px" }} />
                  <p style={{
                    fontSize: "var(--font-size-xs)", color: "var(--text-muted)",
                    textTransform: "uppercase", letterSpacing: "0.05em",
                    margin: "6px 12px 2px", userSelect: "none",
                  }}>
                    Recent
                  </p>
                  {recentCases.map((c) => (
                    <button
                      key={c.name}
                      onClick={() => void handleRecentCase(c.name)}
                      disabled={savingCase}
                      style={{
                        display: "flex", alignItems: "center", justifyContent: "space-between",
                        width: "100%", padding: "6px 12px", border: "none",
                        background: "transparent", borderRadius: 4,
                        color: "var(--text-secondary)", fontSize: "var(--font-size-sm)",
                        cursor: savingCase ? "not-allowed" : "pointer",
                        textAlign: "left",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {c.name}
                      </span>
                      <span style={{
                        fontSize: "var(--font-size-xs)", color: "var(--text-muted)",
                        fontFamily: "var(--font-mono)", flexShrink: 0, marginLeft: 8,
                      }}>
                        {c.file_count} files
                      </span>
                    </button>
                  ))}
                </>
              )}
            </Popover.Content>
          </Popover.Portal>
        </Popover.Root>

        <span data-tour="teacher-toggle">
          <GhostButton onClick={onSettings} title="Settings" data-testid="settings-button">
            <Settings size={15} />
          </GhostButton>
        </span>

        <Popover.Root>
          <Popover.Trigger asChild>
            <span data-tour="new-analysis" style={{ display: "inline-flex" }}>
              <GhostButton title="New analysis" data-testid="new-analysis">
                <Plus size={15} />
              </GhostButton>
            </span>
          </Popover.Trigger>
          <Popover.Portal>
            <Popover.Content
              side="bottom"
              align="end"
              sideOffset={6}
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius)",
                padding: 4,
                minWidth: 180,
                boxShadow: "0 8px 24px rgba(0,0,0,0.25)",
                zIndex: 100,
                animation: "popover-in 150ms ease-out",
              }}
            >
              <button
                onClick={() => { onNewFile(); }}
                style={{
                  display: "flex", alignItems: "center", gap: 10, width: "100%",
                  padding: "8px 12px", border: "none", background: "transparent",
                  borderRadius: 4, color: "var(--text-primary)", fontSize: "var(--font-size-sm)",
                  cursor: "pointer", transition: "background 100ms ease",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <File size={15} style={{ color: "var(--text-muted)" }} />
                Single File
              </button>
              <button
                onClick={() => { onBatchAnalysis(); }}
                style={{
                  display: "flex", alignItems: "center", gap: 10, width: "100%",
                  padding: "8px 12px", border: "none", background: "transparent",
                  borderRadius: 4, color: "var(--text-primary)", fontSize: "var(--font-size-sm)",
                  cursor: "pointer", transition: "background 100ms ease",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <FolderSearch size={15} style={{ color: "var(--text-muted)" }} />
                Batch Analysis
              </button>
              {onCompare && (
                <button
                  onClick={() => { onCompare(); }}
                  style={{
                    display: "flex", alignItems: "center", gap: 10, width: "100%",
                    padding: "8px 12px", border: "none", background: "transparent",
                    borderRadius: 4, color: "var(--text-primary)", fontSize: "var(--font-size-sm)",
                    cursor: "pointer", transition: "background 100ms ease",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <GitCompare size={15} style={{ color: "var(--text-muted)" }} />
                  Compare Two Files
                </button>
              )}
            </Popover.Content>
          </Popover.Portal>
        </Popover.Root>
      </div>
    </header>
  );
}
