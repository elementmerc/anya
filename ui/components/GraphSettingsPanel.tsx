/**
 * GraphSettingsPanel — draggable, collapsible settings card for graph customisation.
 *
 * Defaults to bottom-left corner, above the legend. Draggable by header.
 * Controls: repulsion, node size, link thickness, label visibility, freeze.
 */

import { useState, useRef, useCallback } from "react";
import { SlidersHorizontal, X } from "lucide-react";

export interface GraphSettings {
  repulsion: number;       // -50 to -400, default -150
  nodeSize: number;        // 0.5 to 3, default 1
  linkThickness: number;   // 0.2 to 4, default 1
  showLabels: boolean;     // default true
  frozen: boolean;         // default false
}

export const DEFAULT_SETTINGS: GraphSettings = {
  repulsion: -150,
  nodeSize: 1,
  linkThickness: 1,
  showLabels: true,
  frozen: false,
};

interface Props {
  settings: GraphSettings;
  onChange: (settings: GraphSettings) => void;
  theme: "dark" | "light";
}

function SliderRow({ label, value, min, max, step, format, onChange }: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  format?: (v: number) => string;
  onChange: (v: number) => void;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>{label}</span>
        <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
          {format ? format(value) : value}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        style={{
          width: "100%",
          height: 4,
          appearance: "none",
          background: "var(--border)",
          borderRadius: 2,
          outline: "none",
          cursor: "pointer",
          accentColor: "var(--accent)",
        }}
      />
    </div>
  );
}

export default function GraphSettingsPanel({ settings, onChange, theme }: Props) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ x: 12, y: -56 }); // bottom-left, 56px above bottom
  const dragRef = useRef<{ startX: number; startY: number; origX: number; origY: number } | null>(null);

  const update = (partial: Partial<GraphSettings>) => onChange({ ...settings, ...partial });

  const onDragStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    dragRef.current = { startX: e.clientX, startY: e.clientY, origX: pos.x, origY: pos.y };
    const onMove = (ev: MouseEvent) => {
      if (!dragRef.current) return;
      setPos({
        x: dragRef.current.origX + (ev.clientX - dragRef.current.startX),
        y: dragRef.current.origY + (ev.clientY - dragRef.current.startY),
      });
    };
    const onUp = () => {
      dragRef.current = null;
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }, [pos]);

  const bg = theme === "dark" ? "rgba(26,26,26,0.92)" : "rgba(255,255,255,0.92)";
  const border = theme === "dark" ? "#3a3a3a" : "#d4d4d4";

  // Position: use bottom-left by default (negative y = from bottom)
  const style: React.CSSProperties = pos.y < 0
    ? { position: "absolute", bottom: Math.abs(pos.y), left: pos.x, zIndex: 10 }
    : { position: "absolute", top: pos.y, left: pos.x, zIndex: 10 };

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        title="Graph settings"
        className="ghost-btn"
        style={{
          ...style,
          width: 32,
          height: 32,
          padding: 0,
          justifyContent: "center",
          background: bg,
          backdropFilter: "blur(8px)",
          border: `1px solid ${border}`,
          borderRadius: 6,
        }}
      >
        <SlidersHorizontal size={14} />
      </button>
    );
  }

  return (
    <div
      style={{
        ...style,
        width: 220,
        background: bg,
        border: `1px solid ${border}`,
        borderRadius: 8,
        backdropFilter: "blur(12px)",
        boxShadow: theme === "dark" ? "0 8px 24px rgba(0,0,0,0.4)" : "0 8px 24px rgba(0,0,0,0.1)",
        padding: "0 14px 12px",
        display: "flex",
        flexDirection: "column",
        gap: 12,
        animation: "popover-in 150ms ease-out",
      }}
    >
      {/* Draggable header */}
      <div
        onMouseDown={onDragStart}
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "10px 0 0",
          cursor: "grab",
          userSelect: "none",
        }}
      >
        <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-primary)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          Graph Settings
        </span>
        <button
          onClick={() => setOpen(false)}
          style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: 2, display: "flex" }}
        >
          <X size={13} />
        </button>
      </div>

      {/* Repulsion */}
      <SliderRow
        label="Repulsion"
        value={Math.abs(settings.repulsion)}
        min={50}
        max={400}
        step={10}
        format={(v) => `${v}`}
        onChange={(v) => update({ repulsion: -v })}
      />

      {/* Node size */}
      <SliderRow
        label="Node Size"
        value={settings.nodeSize}
        min={0.5}
        max={3}
        step={0.1}
        format={(v) => `${v.toFixed(1)}x`}
        onChange={(v) => update({ nodeSize: v })}
      />

      {/* Link thickness */}
      <SliderRow
        label="Link Thickness"
        value={settings.linkThickness}
        min={0.2}
        max={4}
        step={0.1}
        format={(v) => `${v.toFixed(1)}x`}
        onChange={(v) => update({ linkThickness: v })}
      />

      {/* Label visibility */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>Labels</span>
        <button
          role="switch"
          aria-checked={settings.showLabels}
          onClick={() => update({ showLabels: !settings.showLabels })}
          style={{
            width: 32, height: 18, borderRadius: 999, border: "none",
            background: settings.showLabels ? "rgb(99,102,241)" : "var(--bg-elevated)",
            position: "relative", cursor: "pointer", transition: "background 150ms ease-out",
            outline: "1px solid var(--border)",
          }}
        >
          <span style={{ position: "absolute", top: 2, left: settings.showLabels ? 16 : 2, width: 14, height: 14, borderRadius: "50%", background: "white", transition: "left 150ms ease-out" }} />
        </button>
      </div>

      {/* Freeze */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>Freeze Layout</span>
        <button
          role="switch"
          aria-checked={settings.frozen}
          onClick={() => update({ frozen: !settings.frozen })}
          style={{
            width: 32, height: 18, borderRadius: 999, border: "none",
            background: settings.frozen ? "rgb(99,102,241)" : "var(--bg-elevated)",
            position: "relative", cursor: "pointer", transition: "background 150ms ease-out",
            outline: "1px solid var(--border)",
          }}
        >
          <span style={{ position: "absolute", top: 2, left: settings.frozen ? 16 : 2, width: 14, height: 14, borderRadius: "50%", background: "white", transition: "left 150ms ease-out" }} />
        </button>
      </div>

      {/* Reset */}
      <button
        onClick={() => onChange({ ...DEFAULT_SETTINGS })}
        style={{
          marginTop: 2, padding: "5px 0", border: `1px solid ${border}`, borderRadius: 4,
          background: "transparent", color: "var(--text-muted)", fontSize: 10, cursor: "pointer",
          transition: "color 100ms ease",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.color = "var(--text-primary)")}
        onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-muted)")}
      >
        Reset to defaults
      </button>
    </div>
  );
}
