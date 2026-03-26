import { useMemo, useState, useEffect, useRef } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { FolderOpen, Shield, AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import type { BatchState } from "@/types/analysis";

// ── Animated counter hook ────────────────────────────────────────────────────

function useAnimatedCount(target: number, duration = 400): number {
  const [count, setCount] = useState(0);
  const frameRef = useRef<number>();
  useEffect(() => {
    const start = performance.now();
    const animate = (now: number) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      setCount(Math.round(target * eased));
      if (progress < 1) frameRef.current = requestAnimationFrame(animate);
    };
    frameRef.current = requestAnimationFrame(animate);
    return () => {
      if (frameRef.current) cancelAnimationFrame(frameRef.current);
    };
  }, [target, duration]);
  return count;
}

// ── Verdict colours ──────────────────────────────────────────────────────────

const VERDICT_COLORS: Record<string, string> = {
  malicious: "#ef4444",
  suspicious: "#eab308",
  clean: "#22c55e",
  error: "#888888",
};

const VERDICT_LABELS: Record<string, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  clean: "Clean",
  error: "Error",
};

const VERDICT_ICONS: Record<string, typeof Shield> = {
  malicious: XCircle,
  suspicious: AlertTriangle,
  clean: CheckCircle,
  error: Shield,
};

// ── Keyframes (injected once) ────────────────────────────────────────────────

let stylesInjected = false;
function injectKeyframes() {
  if (stylesInjected) return;
  stylesInjected = true;
  const style = document.createElement("style");
  style.textContent = `
    @keyframes batch-card-enter {
      from { opacity: 0; transform: translateY(12px) scale(0.95); }
      to   { opacity: 1; transform: translateY(0) scale(1); }
    }
    @keyframes batch-fade-in {
      from { opacity: 0; }
      to   { opacity: 1; }
    }
    @keyframes batch-fade-out {
      from { opacity: 1; }
      to   { opacity: 0; }
    }
  `;
  document.head.appendChild(style);
}

// ── Verdict pill for running state ───────────────────────────────────────────

function VerdictPill({ verdict }: { verdict: string }) {
  const color = VERDICT_COLORS[verdict] ?? "#888";
  return (
    <span
      style={{
        fontSize: "var(--font-size-xs)",
        padding: "2px 8px",
        borderRadius: 999,
        background: `${color}1a`,
        color,
        border: `1px solid ${color}44`,
        fontWeight: 600,
        textTransform: "uppercase",
        letterSpacing: "0.04em",
      }}
    >
      {VERDICT_LABELS[verdict] ?? verdict}
    </span>
  );
}

// ── Verdict card (summary state) ─────────────────────────────────────────────

function VerdictCard({
  verdict,
  count,
  delay,
}: {
  verdict: string;
  count: number;
  delay: number;
}) {
  const color = VERDICT_COLORS[verdict] ?? "#888";
  const Icon = VERDICT_ICONS[verdict] ?? Shield;
  const animatedCount = useAnimatedCount(count);

  return (
    <div
      style={{
        width: 140,
        padding: 16,
        borderRadius: "var(--radius)",
        border: "1px solid var(--border-subtle)",
        background: `${color}0f`, // ~0.06 alpha
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 6,
        animation: `batch-card-enter 250ms ease-out ${delay}ms both`,
      }}
    >
      <Icon size={18} style={{ color, opacity: 0.7, marginBottom: 2 }} />
      <span
        style={{
          fontSize: 28,
          fontWeight: 700,
          fontFamily: "var(--font-mono)",
          color,
          lineHeight: 1,
        }}
      >
        {animatedCount}
      </span>
      <span
        style={{
          fontSize: "var(--font-size-xs)",
          textTransform: "uppercase",
          color: "var(--text-muted)",
          letterSpacing: "0.08em",
          fontWeight: 600,
        }}
      >
        {VERDICT_LABELS[verdict] ?? verdict}
      </span>
    </div>
  );
}

// ── Props ────────────────────────────────────────────────────────────────────

interface Props {
  state: BatchState;
}

// ── Main component ───────────────────────────────────────────────────────────

export default function BatchDashboard({ state }: Props) {
  injectKeyframes();

  const [showSummary, setShowSummary] = useState(!state.isRunning);
  const [fading, setFading] = useState(false);
  const prevRunning = useRef(state.isRunning);

  // Cross-fade transition from running → complete
  useEffect(() => {
    if (prevRunning.current && !state.isRunning) {
      setFading(true);
      const timer = setTimeout(() => {
        setShowSummary(true);
        setFading(false);
      }, 300);
      return () => clearTimeout(timer);
    }
    if (state.isRunning) {
      setShowSummary(false);
      setFading(false);
    }
    prevRunning.current = state.isRunning;
  }, [state.isRunning]);

  // Verdict counts
  const counts = useMemo(() => {
    const c = { malicious: 0, suspicious: 0, clean: 0, error: 0 };
    for (const r of state.results) c[r.verdict]++;
    return c;
  }, [state.results]);

  const totalAnalysed = state.results.length;
  const percent =
    state.totalFiles > 0
      ? Math.round((totalAnalysed / state.totalFiles) * 100)
      : 0;

  const dirName = state.directoryPath ?? "Unknown directory";

  // ── Running view ─────────────────────────────────────────────────────────

  if (!showSummary) {
    const recentResults = state.results.slice(-4).reverse();

    return (
      <div
        style={{
          height: "100%",
          overflow: "auto",
          padding: 24,
          animation: fading ? "batch-fade-out 300ms ease-out forwards" : undefined,
        }}
      >
        <div style={{ maxWidth: 640, margin: "0 auto" }}>
          {/* Directory heading */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              marginBottom: 8,
            }}
          >
            <FolderOpen size={20} style={{ color: "var(--accent)", flexShrink: 0 }} />
            <h2
              style={{
                margin: 0,
                fontSize: "var(--font-size-base)",
                fontWeight: 600,
                color: "var(--text-primary)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {dirName}
            </h2>
          </div>

          {/* Progress text */}
          <p
            style={{
              margin: "0 0 16px",
              fontSize: "var(--font-size-sm)",
              color: "var(--text-secondary)",
            }}
          >
            Analysing {totalAnalysed} of {state.totalFiles} file{state.totalFiles !== 1 ? "s" : ""}&hellip;
          </p>

          {/* Progress bar */}
          <div
            style={{
              height: 4,
              borderRadius: 2,
              background: "var(--border)",
              overflow: "hidden",
              marginBottom: 24,
            }}
          >
            <div
              style={{
                height: "100%",
                width: `${percent}%`,
                background: "var(--accent)",
                borderRadius: 2,
                transition: "width 300ms ease-out",
              }}
            />
          </div>

          {/* Recent results */}
          {recentResults.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {recentResults.map((r) => (
                <div
                  key={r.index}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "8px 12px",
                    background: "var(--bg-surface)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "var(--radius)",
                    animation: "batch-fade-in 200ms ease-out",
                  }}
                >
                  <span
                    style={{
                      flex: 1,
                      fontSize: "var(--font-size-sm)",
                      color: "var(--text-primary)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    {r.fileName}
                  </span>
                  <VerdictPill verdict={r.verdict} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  // ── Complete / summary view ──────────────────────────────────────────────

  const total = counts.malicious + counts.suspicious + counts.clean + counts.error;

  const chartData = [
    { name: "Malicious", value: counts.malicious, color: VERDICT_COLORS.malicious },
    { name: "Suspicious", value: counts.suspicious, color: VERDICT_COLORS.suspicious },
    { name: "Clean", value: counts.clean, color: VERDICT_COLORS.clean },
    { name: "Error", value: counts.error, color: VERDICT_COLORS.error },
  ].filter((d) => d.value > 0);

  return (
    <div
      style={{
        height: "100%",
        overflow: "auto",
        padding: 24,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        animation: "batch-fade-in 350ms ease-out",
      }}
    >
      <div style={{ maxWidth: 720, margin: "0 auto" }}>
        {/* Heading */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            marginBottom: 24,
          }}
        >
          <FolderOpen size={20} style={{ color: "var(--accent)", flexShrink: 0 }} />
          <h2
            style={{
              margin: 0,
              fontSize: "var(--font-size-base)",
              fontWeight: 600,
              color: "var(--text-primary)",
            }}
          >
            Batch Summary &mdash; {total} file{total !== 1 ? "s" : ""}
          </h2>
        </div>

        {/* Verdict cards row */}
        <div
          style={{
            display: "flex",
            gap: 12,
            flexWrap: "wrap",
            marginBottom: 32,
          }}
        >
          <VerdictCard verdict="malicious" count={counts.malicious} delay={0} />
          <VerdictCard verdict="suspicious" count={counts.suspicious} delay={60} />
          <VerdictCard verdict="clean" count={counts.clean} delay={120} />
          <VerdictCard verdict="error" count={counts.error} delay={180} />
        </div>

        {/* Donut chart */}
        {total > 0 && (
          <div
            style={{
              display: "flex",
              justifyContent: "center",
              marginBottom: 24,
              position: "relative",
            }}
          >
            <div style={{ width: 200, height: 200, position: "relative" }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={chartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    animationBegin={200}
                    animationDuration={600}
                    strokeWidth={0}
                  >
                    {chartData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "var(--bg-surface)",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                      fontSize: "var(--font-size-xs)",
                      color: "var(--text-primary)",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>

              {/* Centre total */}
              <div
                style={{
                  position: "absolute",
                  inset: 0,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  pointerEvents: "none",
                }}
              >
                <span
                  style={{
                    fontSize: 24,
                    fontWeight: 700,
                    fontFamily: "var(--font-mono)",
                    color: "var(--text-primary)",
                    lineHeight: 1,
                  }}
                >
                  {total}
                </span>
                <span
                  style={{
                    fontSize: "var(--font-size-xs)",
                    color: "var(--text-muted)",
                    marginTop: 2,
                  }}
                >
                  file{total !== 1 ? "s" : ""}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Stats line */}
        <p
          style={{
            textAlign: "center",
            fontSize: "var(--font-size-sm)",
            color: "var(--text-muted)",
            margin: 0,
          }}
        >
          {total} file{total !== 1 ? "s" : ""} analysed
        </p>
      </div>
    </div>
  );
}
