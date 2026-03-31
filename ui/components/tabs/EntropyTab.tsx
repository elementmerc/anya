import { useState, useEffect, useRef } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  type TooltipProps,
} from "recharts";
import { formatBytes } from "@/lib/utils";
import type { AnalysisResult, SectionInfo, ElfSectionInfo } from "@/types/analysis";

interface Props {
  result: AnalysisResult;
  suspiciousEntropy?: number;
  packedEntropy?: number;
}

type AnySection = SectionInfo | ElfSectionInfo;

function entropyColor(e: number, suspicious: number, packed: number): string {
  if (e >= packed) return "var(--entropy-encrypted)";
  if (e >= suspicious) return "var(--entropy-packed)";
  return "var(--entropy-safe)";
}

function entropyLabel(e: number, suspicious: number, packed: number): string {
  if (e >= packed) return "Likely packed/encrypted";
  if (e >= suspicious) return "Suspicious — may be compressed";
  return "Normal";
}

function HistogramAnalysis({ data, fileEntropy }: { data: number[]; fileEntropy: number }) {
  // Coefficient of variation: stddev / mean — low CV = flat distribution = likely encrypted/packed
  const total = data.reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  const mean = total / 256;
  const variance = data.reduce((sum, v) => sum + (v - mean) ** 2, 0) / 256;
  const stddev = Math.sqrt(variance);
  const cv = mean > 0 ? stddev / mean : 0;

  // Classify: CV < 0.15 with high entropy = very flat (encrypted/compressed)
  // CV < 0.3 = moderately flat, CV >= 0.3 = normal variation
  const isVeryFlat = cv < 0.15 && fileEntropy >= 7.0;
  const isModeratelyFlat = cv < 0.3 && cv >= 0.15 && fileEntropy >= 6.0;

  const flatnessLabel = isVeryFlat
    ? "Very flat — consistent with encryption or compression"
    : isModeratelyFlat
      ? "Moderately flat — may indicate packed or compressed content"
      : "Normal variation — typical of standard executables";

  const flatnessColor = isVeryFlat
    ? "var(--entropy-encrypted)"
    : isModeratelyFlat
      ? "var(--entropy-packed)"
      : "var(--entropy-safe)";

  return (
    <div
      style={{
        marginTop: 16,
        display: "inline-flex",
        alignItems: "center",
        gap: 10,
        padding: "8px 14px",
        borderRadius: "var(--radius)",
        background: "var(--bg-surface)",
        border: "1px solid var(--border)",
        fontSize: "var(--font-size-sm)",
      }}
    >
      <span style={{ color: "var(--text-muted)" }}>Distribution flatness:</span>
      <strong style={{ color: flatnessColor, fontFamily: "var(--font-mono)" }}>
        {cv.toFixed(3)}
      </strong>
      <span style={{ color: "var(--text-muted)", fontSize: "var(--font-size-xs)" }}>
        CV — {flatnessLabel}
      </span>
    </div>
  );
}

function ByteHistogram({ data }: { data: number[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);
  const immediateRef = useRef<boolean | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          // First observation: if already in view, mark as immediate (no animation)
          if (immediateRef.current === null) {
            immediateRef.current = true;
          }
          setVisible(true);
          observer.disconnect();
        } else if (immediateRef.current === null) {
          // First observation and NOT visible — will animate when scrolled into view
          immediateRef.current = false;
        }
      },
      { threshold: 0.1 },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const shouldAnimate = visible && immediateRef.current === false;

  return (
    <div ref={ref} style={{ marginTop: 24 }}>
      <h3 style={{ margin: "0 0 4px", fontSize: "var(--font-size-sm)", fontWeight: 600, color: "var(--text-primary)" }}>
        Byte Histogram
      </h3>
      <p style={{ margin: "0 0 12px", fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>
        Distribution of all 256 byte values — flat distributions suggest encryption
      </p>
      <div style={{ width: "100%", height: 180 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data.map((count, byte) => ({ byte, count }))}
            margin={{ top: 4, right: 8, bottom: 4, left: 8 }}
          >
            <XAxis
              dataKey="byte"
              tick={{ fill: "var(--text-muted)", fontSize: 9 }}
              tickLine={false}
              axisLine={{ stroke: "var(--border)" }}
              interval={31}
              tickFormatter={(v: number) => `0x${v.toString(16).toUpperCase()}`}
            />
            <YAxis hide />
            <Tooltip
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const d = payload[0].payload as { byte: number; count: number };
                return (
                  <div style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "6px 10px", fontSize: "var(--font-size-xs)" }}>
                    <p style={{ margin: 0, color: "var(--text-primary)" }}>Byte 0x{d.byte.toString(16).toUpperCase().padStart(2, "0")}</p>
                    <p style={{ margin: 0, color: "var(--text-secondary)" }}>Count: {d.count.toLocaleString()}</p>
                  </div>
                );
              }}
            />
            <Bar
              dataKey="count"
              radius={[1, 1, 0, 0]}
              maxBarSize={4}
              isAnimationActive={shouldAnimate}
              animationDuration={800}
              animationBegin={0}
            >
              {data.map((_, i) => (
                <Cell key={i} fill="var(--accent)" fillOpacity={0.7} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export default function EntropyTab({ result, suspiciousEntropy = 5.0, packedEntropy = 7.0 }: Props) {
  const CustomTooltip = ({ active, payload }: TooltipProps<number, string>) => {
    if (!active || !payload?.length) return null;
    const d = payload[0].payload as AnySection & { displayName: string };
    const e = d.entropy;
    return (
      <div
        style={{
          background: "var(--bg-elevated)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          padding: "10px 14px",
          fontSize: "var(--font-size-xs)",
        }}
      >
        <p style={{ margin: "0 0 6px", fontWeight: 600, color: "var(--text-primary)" }}>
          {d.displayName || d.name}
        </p>
        <p style={{ margin: "0 0 2px", color: entropyColor(e, suspiciousEntropy, packedEntropy) }}>
          Entropy: <strong>{e.toFixed(4)}</strong>
        </p>
        <p style={{ margin: "0 0 2px", color: "var(--text-secondary)" }}>
          {"raw_size" in d ? `Size: ${formatBytes(d.raw_size || 0)}` : `Size: ${formatBytes(("size" in d ? d.size : 0) || 0)}`}
        </p>
        <p style={{ margin: 0, color: "var(--text-muted)" }}>{entropyLabel(e, suspiciousEntropy, packedEntropy)}</p>
      </div>
    );
  };

  const rawSections: AnySection[] =
    result.pe_analysis?.sections ?? result.elf_analysis?.sections ?? [];

  const sections = rawSections
    .filter((s) => (("raw_size" in s ? s.raw_size : ("size" in s ? (s as ElfSectionInfo).size : 0)) ?? 0) > 0)
    .map((s) => ({
      ...s,
      displayName: s.name || "<unnamed>",
    }));

  if (sections.length < 1) {
    return (
      <div
        style={{
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <p style={{ color: "var(--text-muted)" }}>No section entropy data available.</p>
      </div>
    );
  }

  const fileEntropy = result.entropy.value;

  return (
    <div style={{ height: "100%", overflow: "auto", padding: 24 }}>
      <div style={{ maxWidth: 1600, margin: "0 auto" }}>
        {/* Header */}
        <div style={{ marginBottom: 16 }}>
          <h2 style={{ margin: 0, fontSize: "var(--font-size-lg)", fontWeight: 600, color: "var(--text-primary)" }}>
            Section Entropy
          </h2>
          <p style={{ margin: "4px 0 0", fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>
            Higher entropy may indicate packing or encryption
          </p>
        </div>

        {/* Full-file entropy card */}
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 10,
            padding: "8px 14px",
            marginBottom: 24,
            borderRadius: "var(--radius)",
            background: "var(--bg-surface)",
            border: "1px solid var(--border)",
            fontSize: "var(--font-size-sm)",
          }}
        >
          <span style={{ color: "var(--text-muted)" }}>Full-file entropy:</span>
          <strong style={{ color: entropyColor(fileEntropy, suspiciousEntropy, packedEntropy), fontFamily: "var(--font-mono)" }}>
            {fileEntropy.toFixed(4)}
          </strong>
          <span style={{ color: "var(--text-muted)", fontSize: "var(--font-size-xs)" }}>
            — {entropyLabel(fileEntropy, suspiciousEntropy, packedEntropy)}
          </span>
        </div>

        {/* Chart */}
        <div style={{ width: "100%", height: "clamp(300px, 50vh, 500px)" }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={sections}
              layout="vertical"
              margin={{ top: 24, right: 60, bottom: 8, left: 8 }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                horizontal={false}
                stroke="var(--border-subtle)"
              />
              <XAxis
                type="number"
                domain={[0, 8]}
                tick={{ fill: "var(--text-muted)", fontSize: 11 }}
                tickLine={false}
                axisLine={{ stroke: "var(--border)" }}
                tickCount={9}
              />
              <YAxis
                type="category"
                dataKey="displayName"
                width={90}
                tick={{ fill: "var(--text-secondary)", fontSize: 12, fontFamily: "var(--font-mono)" }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
              <ReferenceLine
                x={suspiciousEntropy}
                stroke="var(--risk-medium)"
                strokeDasharray="4 3"
                label={{ value: "Suspicious", position: "top", fill: "var(--risk-medium)", fontSize: 11 }}
              />
              <ReferenceLine
                x={packedEntropy}
                stroke="var(--risk-critical)"
                strokeDasharray="4 3"
                label={{ value: "Encrypted", position: "top", fill: "var(--risk-critical)", fontSize: 11 }}
              />
              <Bar dataKey="entropy" radius={[0, 3, 3, 0]} maxBarSize={24}>
                {sections.map((s, i) => (
                  <Cell key={i} fill={entropyColor(s.entropy, suspiciousEntropy, packedEntropy)} fillOpacity={0.85} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Byte histogram */}
        {result.byte_histogram && result.byte_histogram.length === 256 && (
          <>
            <HistogramAnalysis data={result.byte_histogram} fileEntropy={fileEntropy} />
            <ByteHistogram data={result.byte_histogram} />
          </>
        )}

        {/* Legend */}
        <div
          style={{
            display: "flex",
            gap: 20,
            marginTop: 16,
            fontSize: "var(--font-size-xs)",
            color: "var(--text-muted)",
            flexWrap: "wrap",
          }}
        >
          {[
            { color: "var(--entropy-safe)",      label: `Low entropy (≤ ${suspiciousEntropy.toFixed(1)})` },
            { color: "var(--entropy-packed)",     label: `Suspicious (${suspiciousEntropy.toFixed(1)}–${packedEntropy.toFixed(1)})` },
            { color: "var(--entropy-encrypted)",  label: `Likely packed (> ${packedEntropy.toFixed(1)})` },
          ].map(({ color, label }) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: "50%",
                  background: color,
                  flexShrink: 0,
                }}
              />
              {label}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
