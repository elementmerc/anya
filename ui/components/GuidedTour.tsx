import { useState, useEffect, useCallback } from "react";

interface TourStep {
  target: string; // CSS selector or data-tour attribute
  title: string;
  body: string;
  position: "bottom" | "top" | "left" | "right";
}

const STEPS: TourStep[] = [
  { target: "[data-tour='risk-ring']", title: "Your Verdict", body: "This is the risk score \u2014 the higher the number, the more suspicious the file. Green means clean, red means danger.", position: "right" },
  { target: "[data-tour='tab-nav']", title: "Explore the Tabs", body: "Each tab shows a different angle of the analysis. Start with Overview, then explore Entropy, Imports, and more.", position: "bottom" },
  { target: "[data-tour='tab-imports']", title: "Imports Matter", body: "Imports show what Windows features the file uses. Red flags here \u2014 like process injection APIs \u2014 are the biggest clues.", position: "bottom" },
  { target: "[data-tour='teacher-toggle']", title: "Teacher Mode", body: "Turn this on anytime for plain-English explanations of everything you see. Perfect for learning.", position: "left" },
  { target: "[data-tour='new-analysis']", title: "Analyse More", body: "Click here to analyse another file, or use Batch Analysis to scan a whole folder at once.", position: "bottom" },
];

interface Props {
  active: boolean;
  onComplete: () => void;
}

export default function GuidedTour({ active, onComplete }: Props) {
  const [step, setStep] = useState(0);
  const [rect, setRect] = useState<DOMRect | null>(null);

  const updatePosition = useCallback(() => {
    if (!active || step >= STEPS.length) return;
    const el = document.querySelector(STEPS[step].target);
    if (el) setRect(el.getBoundingClientRect());
  }, [active, step]);

  useEffect(() => {
    if (!active) return;
    updatePosition();
    const onResize = () => updatePosition();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [active, step, updatePosition]);

  if (!active || step >= STEPS.length || !rect) return null;

  const s = STEPS[step];
  const isLast = step === STEPS.length - 1;

  // Position tooltip relative to target
  let tooltipStyle: React.CSSProperties = {
    position: "fixed", zIndex: 10001, width: 300, padding: "16px 20px",
    background: "var(--bg-elevated)", border: "1px solid var(--border)",
    borderRadius: "var(--radius)", boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
    animation: "batch-fade-in 200ms ease-out",
  };

  if (s.position === "bottom") {
    tooltipStyle.top = rect.bottom + 12;
    tooltipStyle.left = rect.left + rect.width / 2 - 150;
  } else if (s.position === "right") {
    tooltipStyle.top = rect.top + rect.height / 2 - 40;
    tooltipStyle.left = rect.right + 12;
  } else if (s.position === "left") {
    tooltipStyle.top = rect.top + rect.height / 2 - 40;
    tooltipStyle.left = rect.left - 312;
  } else {
    tooltipStyle.top = rect.top - 100;
    tooltipStyle.left = rect.left + rect.width / 2 - 150;
  }

  return (
    <>
      {/* Backdrop with cutout */}
      <div style={{
        position: "fixed", inset: 0, zIndex: 10000,
        background: "rgba(0,0,0,0.5)",
      }} onClick={() => onComplete()} />
      {/* Highlight ring around target */}
      <div style={{
        position: "fixed", zIndex: 10000,
        top: rect.top - 4, left: rect.left - 4,
        width: rect.width + 8, height: rect.height + 8,
        border: "2px solid var(--accent)", borderRadius: 8,
        pointerEvents: "none",
        boxShadow: "0 0 0 9999px rgba(0,0,0,0.45)",
      }} />
      {/* Tooltip */}
      <div style={tooltipStyle}>
        <div style={{ fontSize: "var(--font-size-sm)", fontWeight: 600, color: "var(--text-primary)", marginBottom: 6 }}>
          {s.title}
        </div>
        <div style={{ fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: 12 }}>
          {s.body}
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>
            {step + 1} / {STEPS.length}
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={() => onComplete()} style={{
              padding: "4px 12px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)",
              background: "transparent", color: "var(--text-muted)", fontSize: "var(--font-size-xs)", cursor: "pointer",
            }}>Skip</button>
            <button onClick={() => isLast ? onComplete() : setStep(step + 1)} style={{
              padding: "4px 12px", border: "none", borderRadius: "var(--radius-sm)",
              background: "var(--accent)", color: "#fff", fontSize: "var(--font-size-xs)", cursor: "pointer",
            }}>{isLast ? "Done" : "Next"}</button>
          </div>
        </div>
      </div>
    </>
  );
}
