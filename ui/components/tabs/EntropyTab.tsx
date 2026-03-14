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
}

type AnySection = SectionInfo | ElfSectionInfo;

function entropyColor(e: number): string {
  if (e >= 7.0) return "var(--entropy-encrypted)";
  if (e >= 5.0) return "var(--entropy-packed)";
  return "var(--entropy-safe)";
}

function entropyLabel(e: number): string {
  if (e >= 7.0) return "Likely packed/encrypted";
  if (e >= 5.0) return "Suspicious — may be compressed";
  return "Normal";
}

function CustomTooltip({ active, payload }: TooltipProps<number, string>) {
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
      <p style={{ margin: "0 0 2px", color: entropyColor(e) }}>
        Entropy: <strong>{e.toFixed(4)}</strong>
      </p>
      <p style={{ margin: "0 0 2px", color: "var(--text-secondary)" }}>
        {"raw_size" in d ? `Size: ${formatBytes(d.raw_size || 0)}` : `Size: ${formatBytes(("size" in d ? d.size : 0) || 0)}`}
      </p>
      <p style={{ margin: 0, color: "var(--text-muted)" }}>{entropyLabel(e)}</p>
    </div>
  );
}

export default function EntropyTab({ result }: Props) {
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
          <strong style={{ color: entropyColor(fileEntropy), fontFamily: "var(--font-mono)" }}>
            {fileEntropy.toFixed(4)}
          </strong>
          <span style={{ color: "var(--text-muted)", fontSize: "var(--font-size-xs)" }}>
            — {entropyLabel(fileEntropy)}
          </span>
        </div>

        {/* Chart */}
        <div style={{ width: "100%", height: "clamp(300px, 50vh, 500px)" }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={sections}
              layout="vertical"
              margin={{ top: 8, right: 60, bottom: 8, left: 8 }}
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
                x={5.0}
                stroke="var(--risk-medium)"
                strokeDasharray="4 3"
                label={{ value: "Suspicious", position: "insideTopRight", fill: "var(--risk-medium)", fontSize: 11 }}
              />
              <ReferenceLine
                x={7.0}
                stroke="var(--risk-critical)"
                strokeDasharray="4 3"
                label={{ value: "Encrypted", position: "insideTopRight", fill: "var(--risk-critical)", fontSize: 11 }}
              />
              <Bar dataKey="entropy" radius={[0, 3, 3, 0]} maxBarSize={24}>
                {sections.map((s, i) => (
                  <Cell key={i} fill={entropyColor(s.entropy)} fillOpacity={0.85} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

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
            { color: "var(--entropy-safe)",      label: "Low entropy (≤ 5.0)" },
            { color: "var(--entropy-packed)",     label: "Suspicious (5.0–7.0)" },
            { color: "var(--entropy-encrypted)",  label: "Likely packed (> 7.0)" },
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
