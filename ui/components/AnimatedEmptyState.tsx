/**
 * AnimatedEmptyState — cinematic empty state with SVG line-draw animation.
 *
 * Each icon is a detailed, multi-layered illustration that draws and undraws
 * infinitely (same technique as the Anya splash screen). Icons match their
 * tab counterparts but with extra detail — decorative orbits, data particles,
 * scan lines — for a production-quality look.
 *
 * Falls back to a static icon when prefers-reduced-motion is active.
 */

interface Props {
  icon: "shield" | "branch" | "activity" | "layers" | "align" | "crosshair" | "file-search";
  title: string;
  subtitle?: string;
}

// SVG elements: path d-strings with approximate stroke length and stagger delay.
// Each icon combines the real lucide shape with decorative detail strokes.
const ICONS: Record<Props["icon"], { els: { d: string; len: number; delay?: number; thin?: boolean }[] }> = {

  // Shield (Security tab) — shield body + inner check + decorative arcs
  shield: { els: [
    { d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z", len: 62 },
    { d: "M9 12l2 2 4-4", len: 9, delay: 0.5 },
    { d: "M12 1.5 L12 0.5", len: 1, delay: 0.7, thin: true },
    { d: "M5.5 3 L4.5 2", len: 1.5, delay: 0.8, thin: true },
    { d: "M18.5 3 L19.5 2", len: 1.5, delay: 0.9, thin: true },
    { d: "M2 10 A10 10 0 0 1 2 16", len: 8, delay: 0.6, thin: true },
    { d: "M22 10 A10 10 0 0 0 22 16", len: 8, delay: 0.65, thin: true },
  ]},

  // Activity (Entropy tab) — heartbeat line + pulse rings + baseline
  activity: { els: [
    { d: "M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2", len: 58 },
    { d: "M1 12 L3 12", len: 2, delay: 0.3, thin: true },
    { d: "M21 12 L23 12", len: 2, delay: 0.35, thin: true },
    { d: "M12 0.5 L12 2", len: 1.5, delay: 0.6, thin: true },
    { d: "M12 22 L12 23.5", len: 1.5, delay: 0.65, thin: true },
    { d: "M7 22.5 A11 11 0 0 1 1 12.5", len: 16, delay: 0.4, thin: true },
    { d: "M17 22.5 A11 11 0 0 0 23 12.5", len: 16, delay: 0.45, thin: true },
  ]},

  // GitBranch (Imports tab) — trunk + branch arc + circles + connection dots
  branch: { els: [
    { d: "M6 3 L6 15", len: 12 },
    { d: "M18 9 A9 9 0 0 1 9 18", len: 18, delay: 0.2 },
    { d: "M18 3 A3 3 0 1 1 18 9 A3 3 0 1 1 18 3", len: 19, delay: 0.35 },
    { d: "M6 15 A3 3 0 1 0 6 21 A3 3 0 1 0 6 15", len: 19, delay: 0.5 },
    { d: "M1 6 L3 6", len: 2, delay: 0.6, thin: true },
    { d: "M1 10 L2.5 10", len: 1.5, delay: 0.65, thin: true },
    { d: "M21.5 14 L23 14", len: 1.5, delay: 0.7, thin: true },
    { d: "M21 18 L23 18", len: 2, delay: 0.75, thin: true },
  ]},

  // Layers (Sections tab) — three stacked diamond planes + depth lines
  layers: { els: [
    { d: "M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83z", len: 48 },
    { d: "M2 12a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 12", len: 30, delay: 0.25 },
    { d: "M2 17a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 17", len: 30, delay: 0.5 },
    { d: "M0.5 7 L2.6 6", len: 2.5, delay: 0.6, thin: true },
    { d: "M23.5 7 L21.4 6", len: 2.5, delay: 0.65, thin: true },
    { d: "M12 12 L12 14", len: 2, delay: 0.7, thin: true },
  ]},

  // AlignLeft (Strings tab) — text lines + scan cursor + dots
  align: { els: [
    { d: "M21 6H3", len: 18 },
    { d: "M15 12H3", len: 12, delay: 0.2 },
    { d: "M17 18H3", len: 14, delay: 0.4 },
    { d: "M21 10 L23 10", len: 2, delay: 0.5, thin: true },
    { d: "M19 14 L23 14", len: 4, delay: 0.55, thin: true },
    { d: "M21 22 L23 22", len: 2, delay: 0.6, thin: true },
    { d: "M1 4 L1 20", len: 16, delay: 0.3, thin: true },
  ]},

  // Crosshair (MITRE tab) — outer circle + crosshair lines + inner ring + corner ticks
  crosshair: { els: [
    { d: "M12 2 A10 10 0 1 0 12 22 A10 10 0 1 0 12 2", len: 63 },
    { d: "M22 12 L18 12", len: 4, delay: 0.2 },
    { d: "M6 12 L2 12", len: 4, delay: 0.25 },
    { d: "M12 6 L12 2", len: 4, delay: 0.3 },
    { d: "M12 22 L12 18", len: 4, delay: 0.35 },
    { d: "M12 9 A3 3 0 1 0 12 15 A3 3 0 1 0 12 9", len: 19, delay: 0.5 },
    { d: "M4.93 4.93 L6.34 6.34", len: 2, delay: 0.6, thin: true },
    { d: "M17.66 17.66 L19.07 19.07", len: 2, delay: 0.65, thin: true },
    { d: "M4.93 19.07 L6.34 17.66", len: 2, delay: 0.7, thin: true },
    { d: "M17.66 6.34 L19.07 4.93", len: 2, delay: 0.75, thin: true },
  ]},

  // FileSearch (Format tab) — document outline + corner fold + magnifier + detail lines
  "file-search": { els: [
    { d: "M4.268 21a2 2 0 0 0 1.727 1H18a2 2 0 0 0 2-2V7l-5-5H6a2 2 0 0 0-2 2v3", len: 52 },
    { d: "M14 2v4a2 2 0 0 0 2 2h4", len: 12, delay: 0.2 },
    { d: "M5 11 A3 3 0 1 0 5 17 A3 3 0 1 0 5 11", len: 19, delay: 0.4 },
    { d: "M7.5 16.5 L9 18", len: 2.5, delay: 0.55 },
    { d: "M10 10 L17 10", len: 7, delay: 0.6, thin: true },
    { d: "M13 13 L17 13", len: 4, delay: 0.65, thin: true },
    { d: "M11 16 L17 16", len: 6, delay: 0.7, thin: true },
  ]},
};

export default function AnimatedEmptyState({ icon, title, subtitle }: Props) {
  const { els } = ICONS[icon];

  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 18,
        padding: 40,
      }}
    >
      <svg
        width={56}
        height={56}
        viewBox="0 0 24 24"
        fill="none"
        style={{ overflow: "visible" }}
      >
        {els.map((el, i) => (
          <path
            key={i}
            d={el.d}
            className="empty-icon-path"
            style={{
              "--path-len": el.len,
              animationDelay: `${el.delay ?? 0}s`,
              strokeWidth: el.thin ? 0.75 : 1.5,
              opacity: el.thin ? 0.4 : undefined,
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
              maxWidth: 320,
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
