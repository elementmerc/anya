import { useState, useEffect } from "react";
import { X, Lock, Database, Sun, Moon, FolderOpen, GraduationCap, BookOpen } from "lucide-react";
import { getSettings } from "@/lib/tauri-bridge";
import { open as dialogOpen } from "@tauri-apps/plugin-dialog";
import { saveSettingsToDb } from "@/lib/db";
import { useTeacherMode } from "@/hooks/useTeacherMode";
import type { FontSize } from "@/hooks/useFontSize";

const FONT_SIZE_OPTIONS: { value: FontSize; label: string; px: string }[] = [
  { value: "small",   label: "Small",       px: "13px" },
  { value: "default", label: "Default",     px: "14px" },
  { value: "large",   label: "Large",       px: "15px" },
  { value: "xl",      label: "Extra Large", px: "16px" },
];

interface SettingsModalProps {
  theme: "dark" | "light";
  onToggleTheme: () => void;
  fontSize: FontSize;
  onSetFontSize: (size: FontSize) => void;
  bibleVersesEnabled: boolean;
  onSetBibleVerses: (v: boolean) => void;
  onClose: () => void;
}

export default function SettingsModal({
  theme,
  onToggleTheme,
  fontSize,
  onSetFontSize,
  bibleVersesEnabled,
  onSetBibleVerses,
  onClose,
}: SettingsModalProps) {
  const { enabled: teacherEnabled, setEnabled: setTeacherEnabled } = useTeacherMode();
  const [dbPath, setDbPath] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void getSettings().then((s) => setDbPath(s.db_path)).finally(() => setLoading(false));
  }, []);

  async function handleBrowseDb() {
    const result = await dialogOpen({
      title: "Choose database directory",
      directory: true,
    });
    if (typeof result === "string") {
      const newPath = `${result}/anya.db`;
      setDbPath(newPath);
      await saveSettingsToDb({ theme });
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      role="dialog"
      aria-modal="true"
      aria-label="Settings"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel */}
      <div
        className="relative w-[520px] max-w-[95vw] rounded-xl shadow-2xl overflow-hidden"
        style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-6 py-4 border-b"
          style={{ borderColor: "var(--border)" }}
        >
          <h2 className="font-semibold text-base" style={{ color: "var(--text-primary)" }}>
            Settings
          </h2>
          <button
            onClick={onClose}
            className="p-1 rounded transition-colors hover:bg-[var(--bg-elevated)] active:scale-[0.97]"
            aria-label="Close settings"
          >
            <X size={16} style={{ color: "var(--text-secondary)" }} />
          </button>
        </div>

        <div className="px-6 py-5 space-y-7">
          {/* ── Storage ──────────────────────────────────────────── */}
          <section>
            <h3
              className="text-xs font-semibold uppercase tracking-wider mb-3"
              style={{ color: "var(--text-muted)" }}
            >
              Storage
            </h3>
            <div className="space-y-3">
              <div>
                <label
                  className="block text-xs mb-1.5"
                  style={{ color: "var(--text-secondary)" }}
                >
                  Database path
                </label>
                <div className="flex gap-2">
                  <div
                    className="flex-1 flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-mono truncate"
                    style={{
                      background: "var(--bg-elevated)",
                      color: "var(--text-primary)",
                      border: "1px solid var(--border)",
                    }}
                    title={dbPath}
                  >
                    <Database size={12} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
                    {loading ? "Loading…" : dbPath || "Default"}
                  </div>
                  <button
                    onClick={() => void handleBrowseDb()}
                    className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs transition-colors hover:bg-[var(--bg-elevated)] active:scale-[0.97]"
                    style={{
                      background: "var(--bg-elevated)",
                      color: "var(--text-secondary)",
                      border: "1px solid var(--border)",
                    }}
                    aria-label="Browse for database location"
                  >
                    <FolderOpen size={13} />
                    Browse
                  </button>
                </div>
                <p className="text-xs mt-1.5" style={{ color: "var(--text-muted)" }}>
                  Database is auto-created if it doesn&apos;t exist.
                </p>
              </div>
            </div>
          </section>

          {/* ── Appearance ───────────────────────────────────────── */}
          <section>
            <h3
              className="text-xs font-semibold uppercase tracking-wider mb-3"
              style={{ color: "var(--text-muted)" }}
            >
              Appearance
            </h3>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                  Theme
                </p>
                <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
                  {theme === "dark" ? "Dark mode" : "Light mode"}
                </p>
              </div>
              <button
                onClick={onToggleTheme}
                className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors hover:bg-[var(--bg-elevated)] active:scale-[0.97]"
                style={{
                  background: "var(--bg-elevated)",
                  color: "var(--text-secondary)",
                  border: "1px solid var(--border)",
                }}
                aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
              >
                {theme === "dark" ? <Sun size={14} /> : <Moon size={14} />}
                {theme === "dark" ? "Switch to light" : "Switch to dark"}
              </button>
            </div>
          </section>

          {/* ── Interface Size ───────────────────────────────────── */}
          <section>
            <h3
              className="text-xs font-semibold uppercase tracking-wider mb-3"
              style={{ color: "var(--text-muted)" }}
            >
              Interface Size
            </h3>
            <div className="space-y-3">
              {/* Segmented control */}
              <div
                style={{
                  display: "flex",
                  gap: 4,
                  padding: 4,
                  borderRadius: "var(--radius)",
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--border)",
                }}
              >
                {FONT_SIZE_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => onSetFontSize(opt.value)}
                    style={{
                      flex: 1,
                      padding: "5px 0",
                      fontSize: "var(--font-size-xs)",
                      fontWeight: fontSize === opt.value ? 600 : 400,
                      borderRadius: 4,
                      border: "none",
                      background: fontSize === opt.value ? "var(--bg-surface)" : "transparent",
                      color: fontSize === opt.value ? "var(--text-primary)" : "var(--text-secondary)",
                      cursor: "pointer",
                      transition: "all 150ms ease-out",
                      boxShadow: fontSize === opt.value ? "0 1px 3px rgba(0,0,0,0.15)" : "none",
                    }}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              {/* Live preview */}
              <p
                style={{
                  margin: 0,
                  fontSize: FONT_SIZE_OPTIONS.find((o) => o.value === fontSize)?.px,
                  color: "var(--text-secondary)",
                  fontFamily: "var(--font-ui)",
                  transition: "font-size 150ms ease-out",
                }}
              >
                The quick brown fox jumps over the lazy dog
              </p>
            </div>
          </section>

          {/* ── Learning / Teacher Mode ──────────────────────────── */}
          <section>
            <h3
              className="text-xs font-semibold uppercase tracking-wider mb-3"
              style={{ color: "var(--text-muted)" }}
            >
              Learning
            </h3>
            <div className="space-y-3">
              <div className="flex items-start gap-3">
                <div className="mt-0.5 p-1.5 rounded" style={{ background: "var(--bg-elevated)" }}>
                  <GraduationCap size={13} style={{ color: "var(--text-muted)" }} />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                      Teacher Mode
                    </p>
                    <button
                      role="switch"
                      aria-checked={teacherEnabled}
                      onClick={() => setTeacherEnabled(!teacherEnabled)}
                      style={{
                        width: 36,
                        height: 20,
                        borderRadius: 999,
                        border: "none",
                        background: teacherEnabled ? "rgb(99,102,241)" : "var(--bg-elevated)",
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
                          left: teacherEnabled ? 19 : 3,
                          width: 14,
                          height: 14,
                          borderRadius: "50%",
                          background: "white",
                          transition: "left 200ms ease-out",
                        }}
                      />
                    </button>
                  </div>
                  <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
                    Show contextual lessons as you analyse files. Great for learning malware analysis.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <div className="mt-0.5 p-1.5 rounded" style={{ background: "var(--bg-elevated)" }}>
                  <BookOpen size={13} style={{ color: "var(--text-muted)" }} />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                      Bible Verses
                    </p>
                    <button
                      role="switch"
                      aria-checked={bibleVersesEnabled}
                      onClick={() => onSetBibleVerses(!bibleVersesEnabled)}
                      style={{
                        width: 36,
                        height: 20,
                        borderRadius: 999,
                        border: "none",
                        background: bibleVersesEnabled ? "rgb(99,102,241)" : "var(--bg-elevated)",
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
                          left: bibleVersesEnabled ? 19 : 3,
                          width: 14,
                          height: 14,
                          borderRadius: "50%",
                          background: "white",
                          transition: "left 200ms ease-out",
                        }}
                      />
                    </button>
                  </div>
                  <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
                    Show a rotating NLT Bible verse in the status bar. Cycles every 10 minutes.
                  </p>
                </div>
              </div>

            </div>
          </section>

          {/* ── Privacy (non-negotiable) ─────────────────────────── */}
          <section
            className="rounded-lg p-4"
            style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
            }}
          >
            <h3
              className="text-xs font-semibold uppercase tracking-wider mb-3"
              style={{ color: "var(--text-muted)" }}
            >
              Privacy
            </h3>
            <div className="space-y-3">
              {/* Telemetry */}
              <div className="flex items-start gap-3">
                <div
                  className="mt-0.5 p-1.5 rounded"
                  style={{ background: "var(--bg-surface)" }}
                >
                  <Lock size={13} style={{ color: "var(--text-muted)" }} />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                      Telemetry
                    </p>
                    <span
                      className="text-xs px-2 py-0.5 rounded"
                      style={{
                        background: "rgba(74, 222, 128, 0.1)",
                        color: "var(--risk-low)",
                      }}
                    >
                      OFF
                    </span>
                  </div>
                  <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
                    Anya never phones home. No analytics. No crash reports. Ever.
                  </p>
                </div>
              </div>

              {/* Network */}
              <div className="flex items-start gap-3">
                <div
                  className="mt-0.5 p-1.5 rounded"
                  style={{ background: "var(--bg-surface)" }}
                >
                  <Lock size={13} style={{ color: "var(--text-muted)" }} />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                      Network access
                    </p>
                    <span
                      className="text-xs px-2 py-0.5 rounded"
                      style={{
                        background: "rgba(74, 222, 128, 0.1)",
                        color: "var(--risk-low)",
                      }}
                    >
                      OFF
                    </span>
                  </div>
                  <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
                    Zero outbound connections. Enforced at the OS permission level.
                  </p>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
