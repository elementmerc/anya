/**
 * AnimatedEmptyState — cinematic empty state with SVG line-draw animation.
 *
 * Uses the exact lucide icon SVG elements (paths, circles, lines) with
 * runtime-measured stroke lengths via getTotalLength() for pixel-perfect
 * draw/undraw animation. Decorative accent strokes orbit outside the icon.
 */

import { useRef, useEffect, useState, useCallback } from "react";

interface Props {
  icon: "shield" | "branch" | "activity" | "layers" | "align" | "crosshair" | "file-search";
  title: string;
  subtitle?: string;
}

// Each SVG element from the lucide source, verbatim.
// "type" maps to the SVG element tag (path, circle, line).
type SvgEl =
  | { type: "path"; d: string }
  | { type: "circle"; cx: number; cy: number; r: number }
  | { type: "line"; x1: number; y1: number; x2: number; y2: number };

// Decorative accent strokes drawn outside the icon bounds
type AccentEl = { d: string; approxLen: number; delay: number };

interface IconDef {
  color: string;
  els: SvgEl[];
  accents: AccentEl[];
}

// ── Icon definitions (exact lucide element data + decorative accents) ────────

const ICONS: Record<Props["icon"], IconDef> = {

  shield: {
    color: "#4ade80",
    els: [
      { type: "path", d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" },
    ],
    accents: [
      { d: "M1.5 9 A12 12 0 0 0 1.5 17.5", approxLen: 12, delay: 0.6 },
      { d: "M22.5 9 A12 12 0 0 1 22.5 17.5", approxLen: 12, delay: 0.65 },
      { d: "M12 -0.5 L12 1", approxLen: 1.5, delay: 0.7 },
      { d: "M7.5 0.5 L8.5 1.8", approxLen: 1.8, delay: 0.75 },
      { d: "M16.5 0.5 L15.5 1.8", approxLen: 1.8, delay: 0.8 },
    ],
  },

  activity: {
    color: "#fbbf24",
    els: [
      { type: "path", d: "M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2" },
    ],
    accents: [
      { d: "M0 12 L24 12", approxLen: 24, delay: 0.15 },
      { d: "M3.5 8 A5 5 0 0 1 3.5 16", approxLen: 11, delay: 0.4 },
      { d: "M20.5 8 A5 5 0 0 0 20.5 16", approxLen: 11, delay: 0.45 },
      { d: "M-0.5 10 L0.5 10", approxLen: 1, delay: 0.6 },
      { d: "M-0.5 14 L0.5 14", approxLen: 1, delay: 0.65 },
      { d: "M23.5 10 L24.5 10", approxLen: 1, delay: 0.7 },
      { d: "M23.5 14 L24.5 14", approxLen: 1, delay: 0.75 },
    ],
  },

  branch: {
    color: "#a78bfa",
    els: [
      { type: "line", x1: 6, y1: 3, x2: 6, y2: 15 },
      { type: "circle", cx: 18, cy: 6, r: 3 },
      { type: "circle", cx: 6, cy: 18, r: 3 },
      { type: "path", d: "M18 9a9 9 0 0 1-9 9" },
    ],
    accents: [
      { d: "M16.5 10.5 L15 12", approxLen: 2.2, delay: 0.55 },
      { d: "M13.5 13.5 L12 15", approxLen: 2.2, delay: 0.6 },
      { d: "M10.5 16 L9.5 17", approxLen: 1.5, delay: 0.65 },
      { d: "M2.5 6 L4 6", approxLen: 1.5, delay: 0.7 },
      { d: "M2.5 10 L4 10", approxLen: 1.5, delay: 0.75 },
      { d: "M22 4 L23.5 4", approxLen: 1.5, delay: 0.8 },
      { d: "M22 8 L23.5 8", approxLen: 1.5, delay: 0.85 },
    ],
  },

  layers: {
    color: "#22d3ee",
    els: [
      { type: "path", d: "M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83z" },
      { type: "path", d: "M2 12a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 12" },
      { type: "path", d: "M2 17a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 17" },
    ],
    accents: [
      { d: "M12 12 L12 22", approxLen: 10, delay: 0.5 },
      { d: "M0.5 5.5 L2.5 6.5", approxLen: 2.3, delay: 0.6 },
      { d: "M23.5 5.5 L21.5 6.5", approxLen: 2.3, delay: 0.65 },
      { d: "M2 7 L2 17", approxLen: 10, delay: 0.55 },
      { d: "M22 7 L22 17", approxLen: 10, delay: 0.6 },
    ],
  },

  align: {
    color: "#fb7185",
    els: [
      { type: "path", d: "M21 6H3" },
      { type: "path", d: "M15 12H3" },
      { type: "path", d: "M17 18H3" },
    ],
    accents: [
      { d: "M1 2.5 L1 21.5", approxLen: 19, delay: 0.25 },
      { d: "M22 5 L22 7", approxLen: 2, delay: 0.5 },
      { d: "M16 11 L16 13", approxLen: 2, delay: 0.55 },
      { d: "M18 17 L18 19", approxLen: 2, delay: 0.6 },
      { d: "M-0.5 6 L0.5 6", approxLen: 1, delay: 0.7 },
      { d: "M-0.5 12 L0.5 12", approxLen: 1, delay: 0.75 },
      { d: "M-0.5 18 L0.5 18", approxLen: 1, delay: 0.8 },
    ],
  },

  crosshair: {
    color: "#818cf8",
    els: [
      { type: "circle", cx: 12, cy: 12, r: 10 },
      { type: "line", x1: 22, y1: 12, x2: 18, y2: 12 },
      { type: "line", x1: 6, y1: 12, x2: 2, y2: 12 },
      { type: "line", x1: 12, y1: 6, x2: 12, y2: 2 },
      { type: "line", x1: 12, y1: 22, x2: 12, y2: 18 },
    ],
    accents: [
      { d: "M12 9a3 3 0 1 0 0 6 3 3 0 1 0 0-6z", approxLen: 19, delay: 0.45 },
      { d: "M5.64 5.64 L6.7 6.7", approxLen: 1.5, delay: 0.6 },
      { d: "M17.3 17.3 L18.36 18.36", approxLen: 1.5, delay: 0.65 },
      { d: "M5.64 18.36 L6.7 17.3", approxLen: 1.5, delay: 0.7 },
      { d: "M17.3 6.7 L18.36 5.64", approxLen: 1.5, delay: 0.75 },
      { d: "M3 3.5 A13.5 13.5 0 0 1 12 -1.5", approxLen: 15, delay: 0.55 },
      { d: "M21 20.5 A13.5 13.5 0 0 1 12 25.5", approxLen: 15, delay: 0.6 },
    ],
  },

  "file-search": {
    color: "#38bdf8",
    els: [
      { type: "path", d: "M14 2v4a2 2 0 0 0 2 2h4" },
      { type: "path", d: "M4.268 21a2 2 0 0 0 1.727 1H18a2 2 0 0 0 2-2V7l-5-5H6a2 2 0 0 0-2 2v3" },
      { type: "path", d: "M9 18l-1.5-1.5" },
      { type: "circle", cx: 5, cy: 14, r: 3 },
    ],
    accents: [
      { d: "M11 10 L17 10", approxLen: 6, delay: 0.55 },
      { d: "M11 13 L17 13", approxLen: 6, delay: 0.6 },
      { d: "M11 16 L17 16", approxLen: 6, delay: 0.65 },
      { d: "M14 19 L17 19", approxLen: 3, delay: 0.7 },
      { d: "M4 7 L20 7", approxLen: 16, delay: 0.45 },
    ],
  },
};

// ── Animated SVG element — measures its own stroke length on mount ───────────

function AnimatedEl({ el, color, delay }: { el: SvgEl; color: string; delay: number }) {
  const ref = useRef<SVGPathElement | SVGCircleElement | SVGLineElement>(null);
  const [len, setLen] = useState<number | null>(null);

  useEffect(() => {
    if (ref.current && typeof (ref.current as SVGGeometryElement).getTotalLength === "function") {
      setLen((ref.current as SVGGeometryElement).getTotalLength());
    }
  }, []);

  const style = len != null ? {
    stroke: color,
    strokeWidth: 1.8,
    fill: "none",
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    strokeDasharray: len,
    strokeDashoffset: len,
    "--path-len": len,
    animationDelay: `${delay}s`,
  } : {
    stroke: "transparent",
    fill: "none",
  };

  const common = { ref: ref as React.Ref<never>, className: len != null ? "empty-icon-path" : undefined, style: style as React.CSSProperties };

  switch (el.type) {
    case "path":
      return <path d={el.d} {...common} />;
    case "circle":
      return <circle cx={el.cx} cy={el.cy} r={el.r} {...common} />;
    case "line":
      return <line x1={el.x1} y1={el.y1} x2={el.x2} y2={el.y2} {...common} />;
  }
}

// ── Main component ──────────────────────────────────────────────────────────

export default function AnimatedEmptyState({ icon, title, subtitle }: Props) {
  const { color, els, accents } = ICONS[icon];

  // Stagger primary elements evenly across the first half of the animation
  const elDelay = useCallback((i: number) => i * (0.12), []);

  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 22,
        padding: 40,
      }}
    >
      <svg
        width={80}
        height={80}
        viewBox="-2 -3 28 30"
        fill="none"
        style={{ overflow: "visible" }}
      >
        {/* Primary icon elements (exact lucide data, runtime-measured) */}
        {els.map((el, i) => (
          <AnimatedEl key={`el-${i}`} el={el} color={color} delay={elDelay(i)} />
        ))}

        {/* Decorative accent strokes (orbits, particles, ticks) */}
        {accents.map((a, i) => (
          <path
            key={`acc-${i}`}
            d={a.d}
            className="empty-icon-accent"
            style={{
              "--path-len": a.approxLen,
              "--icon-color": color,
              animationDelay: `${a.delay}s`,
            } as React.CSSProperties}
          />
        ))}
      </svg>

      <div style={{ textAlign: "center" }}>
        <p
          style={{
            margin: "0 0 6px",
            fontSize: "var(--font-size-base)",
            fontWeight: 500,
            color: "var(--text-primary)",
          }}
        >
          {title}
        </p>
        {subtitle && (
          <p
            style={{
              margin: 0,
              fontSize: "var(--font-size-xs)",
              color: "var(--text-muted)",
              maxWidth: 340,
              lineHeight: 1.6,
            }}
          >
            {subtitle}
          </p>
        )}
      </div>
    </div>
  );
}
