import { useEffect } from "react";

interface Props {
  open: boolean;
  onClose: () => void;
}

const SHORTCUTS: [string, string][] = [
  ["Ctrl/Cmd + O", "Open file"],
  ["Ctrl/Cmd + B", "Batch analysis"],
  ["Ctrl/Cmd + E", "Export JSON"],
  ["1 – 7", "Switch tab"],
  ["T", "Toggle teacher mode"],
  ["?", "Show shortcuts"],
  ["Escape", "Close modal / overlay"],
];

export default function KeyboardShortcutsOverlay({ open, onClose }: Props) {
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.stopPropagation(); onClose(); }
    };
    window.addEventListener("keydown", handler, true);
    return () => window.removeEventListener("keydown", handler, true);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 9000,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: "absolute",
          inset: 0,
          background: "rgba(0,0,0,0.5)",
        }}
      />

      {/* Panel */}
      <div
        style={{
          position: "relative",
          width: 420,
          maxWidth: "90vw",
          background: "var(--bg-surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          padding: "24px 28px",
          boxShadow: "0 16px 48px rgba(0,0,0,0.3)",
          animation: "popover-in 150ms ease-out",
        }}
      >
        <h2
          style={{
            margin: "0 0 20px",
            fontSize: "var(--font-size-base)",
            fontWeight: 600,
            color: "var(--text-primary)",
          }}
        >
          Keyboard Shortcuts
        </h2>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "auto 1fr",
            gap: "10px 20px",
            alignItems: "center",
          }}
        >
          {SHORTCUTS.map(([key, desc]) => (
            <div key={key} style={{ display: "contents" }}>
              <kbd
                style={{
                  display: "inline-block",
                  padding: "3px 8px",
                  borderRadius: 4,
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--border)",
                  fontSize: "var(--font-size-xs)",
                  fontFamily: "var(--font-mono)",
                  color: "var(--text-primary)",
                  whiteSpace: "nowrap",
                }}
              >
                {key}
              </kbd>
              <span
                style={{
                  fontSize: "var(--font-size-sm)",
                  color: "var(--text-secondary)",
                }}
              >
                {desc}
              </span>
            </div>
          ))}
        </div>

        <p
          style={{
            margin: "16px 0 0",
            fontSize: "var(--font-size-xs)",
            color: "var(--text-muted)",
          }}
        >
          Press <strong>Escape</strong> to close
        </p>
      </div>
    </div>
  );
}
