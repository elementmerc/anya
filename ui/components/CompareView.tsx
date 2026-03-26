import { useState } from "react";
import { ArrowLeft, FileCode, Shield, Activity, GitBranch } from "lucide-react";
import { openFilePicker, analyzeFile } from "@/lib/tauri-bridge";
import { formatBytes } from "@/lib/utils";
import { getRiskLabel, getRiskColor } from "@/lib/risk";
import type { AnalysisResult } from "@/types/analysis";

interface Props {
  onClose: () => void;
}

interface FileAnalysis {
  path: string;
  name: string;
  result: AnalysisResult;
  riskScore: number;
}

type CompareStage = "pick-a" | "analyzing-a" | "pick-b" | "analyzing-b" | "compare";

export default function CompareView({ onClose }: Props) {
  const [stage, setStage] = useState<CompareStage>("pick-a");
  const [fileA, setFileA] = useState<FileAnalysis | null>(null);
  const [fileB, setFileB] = useState<FileAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function pickAndAnalyze(target: "a" | "b") {
    setError(null);
    const picked = await openFilePicker();
    if (!picked) return;
    const path = Array.isArray(picked) ? picked[0] : picked;
    if (!path) return;

    setStage(target === "a" ? "analyzing-a" : "analyzing-b");
    try {
      const response = await analyzeFile(path);
      const name = path.split(/[\\/]/).pop() ?? path;
      const analysis: FileAnalysis = {
        path,
        name,
        result: response.result,
        riskScore: response.risk_score,
      };
      if (target === "a") {
        setFileA(analysis);
        setStage("pick-b");
      } else {
        setFileB(analysis);
        setStage("compare");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setStage(target === "a" ? "pick-a" : "pick-b");
    }
  }

  // Picker stages
  if (stage !== "compare") {
    const isAnalyzing = stage === "analyzing-a" || stage === "analyzing-b";
    const label = stage === "pick-a" ? "Select first file (A)" : stage === "pick-b" ? "Select second file (B)" : "Analyzing...";

    return (
      <div style={{ height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, padding: 40 }}>
        <button onClick={onClose} style={{ position: "absolute", top: 16, left: 16, display: "flex", alignItems: "center", gap: 6, background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: "var(--font-size-sm)" }}>
          <ArrowLeft size={14} /> Back
        </button>

        <FileCode size={32} style={{ color: "var(--text-muted)" }} />
        <p style={{ fontSize: "var(--font-size-base)", color: "var(--text-primary)", fontWeight: 500 }}>{label}</p>

        {fileA && (
          <p style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>
            File A: <strong style={{ color: "var(--text-secondary)" }}>{fileA.name}</strong>
          </p>
        )}

        {error && <p style={{ fontSize: "var(--font-size-xs)", color: "var(--risk-critical)" }}>{error}</p>}

        {isAnalyzing ? (
          <div className="w-5 h-5 border-2 rounded-full animate-spin" style={{ borderColor: "var(--border)", borderTopColor: "var(--accent)" }} />
        ) : (
          <button
            onClick={() => pickAndAnalyze(stage === "pick-a" ? "a" : "b")}
            style={{
              padding: "10px 24px", borderRadius: "var(--radius)", background: "var(--accent)", color: "#fff",
              border: "none", cursor: "pointer", fontSize: "var(--font-size-sm)", fontWeight: 500,
            }}
          >
            Choose File
          </button>
        )}
      </div>
    );
  }

  if (!fileA || !fileB) return null;

  // Comparison helpers
  const peA = fileA.result.pe_analysis;
  const peB = fileB.result.pe_analysis;

  const importsA = new Set(peA?.imports?.libraries ?? []);
  const importsB = new Set(peB?.imports?.libraries ?? []);
  const addedImports = [...importsB].filter((i) => !importsA.has(i));
  const removedImports = [...importsA].filter((i) => !importsB.has(i));
  const commonImports = [...importsA].filter((i) => importsB.has(i));

  const sectionsA = peA?.sections ?? [];
  const sectionsB = peB?.sections ?? [];

  const strCountA = fileA.result.strings?.samples?.length ?? 0;
  const strCountB = fileB.result.strings?.samples?.length ?? 0;

  return (
    <div style={{ height: "100%", overflow: "auto", padding: 24 }}>
      <div style={{ maxWidth: 1600, margin: "0 auto" }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24 }}>
          <button onClick={onClose} style={{ display: "flex", alignItems: "center", gap: 6, background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: "var(--font-size-sm)" }}>
            <ArrowLeft size={14} /> Back
          </button>
          <h2 style={{ margin: 0, fontSize: "var(--font-size-base)", fontWeight: 600, color: "var(--text-primary)" }}>
            Comparison: {fileA.name} vs {fileB.name}
          </h2>
        </div>

        {/* Side-by-side risk summary */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
          {[fileA, fileB].map((f, idx) => {
            const color = getRiskColor(f.riskScore);
            const label = getRiskLabel(f.riskScore);
            return (
              <div key={idx} style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 16 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <FileCode size={14} style={{ color: "var(--text-muted)" }} />
                  <span style={{ fontSize: "var(--font-size-sm)", fontFamily: "var(--font-mono)", color: "var(--text-primary)", fontWeight: 500 }}>
                    {f.name}
                  </span>
                  <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>
                    {formatBytes(f.result.file_info.size_bytes)}
                  </span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <span style={{ fontSize: "calc(var(--font-size-base) * 1.5)", fontWeight: 700, color }}>{f.riskScore}</span>
                  <span style={{ fontSize: "var(--font-size-sm)", color: "var(--text-secondary)" }}>{label}</span>
                </div>
                <div style={{ marginTop: 8, fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>
                  {f.result.file_format} &middot; {f.result.pe_analysis?.architecture ?? f.result.elf_analysis?.architecture ?? "Unknown"}
                </div>
              </div>
            );
          })}
        </div>

        {/* Imports diff */}
        <div style={{ marginBottom: 24 }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 12 }}>
            <GitBranch size={13} /> Import Libraries
          </h3>
          <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 12 }}>
            {addedImports.length > 0 && (
              <div style={{ marginBottom: 8 }}>
                <span style={{ fontSize: "var(--font-size-xs)", color: "var(--risk-low)", fontWeight: 600 }}>+ Added in B ({addedImports.length})</span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 4 }}>
                  {addedImports.map((lib) => (
                    <span key={lib} style={{ fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", padding: "2px 8px", borderRadius: 4, background: "rgba(34,197,94,0.12)", color: "var(--risk-low)" }}>{lib}</span>
                  ))}
                </div>
              </div>
            )}
            {removedImports.length > 0 && (
              <div style={{ marginBottom: 8 }}>
                <span style={{ fontSize: "var(--font-size-xs)", color: "var(--risk-critical)", fontWeight: 600 }}>- Removed in B ({removedImports.length})</span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 4 }}>
                  {removedImports.map((lib) => (
                    <span key={lib} style={{ fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", padding: "2px 8px", borderRadius: 4, background: "rgba(239,68,68,0.12)", color: "var(--risk-critical)" }}>{lib}</span>
                  ))}
                </div>
              </div>
            )}
            {commonImports.length > 0 && (
              <div>
                <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>{commonImports.length} common libraries</span>
              </div>
            )}
            {addedImports.length === 0 && removedImports.length === 0 && (
              <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>Import libraries are identical</span>
            )}
          </div>
        </div>

        {/* Entropy diff */}
        <div style={{ marginBottom: 24 }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 12 }}>
            <Activity size={13} /> Entropy Comparison
          </h3>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {[{ label: "File A", sections: sectionsA }, { label: "File B", sections: sectionsB }].map(({ label, sections }) => (
              <div key={label} style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 12 }}>
                <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", fontWeight: 600, marginBottom: 8, display: "block" }}>{label}</span>
                {sections.map((s) => {
                  const eColor = s.entropy >= 7.0 ? "var(--risk-critical)" : s.entropy >= 5.0 ? "var(--risk-medium)" : "var(--text-secondary)";
                  return (
                    <div key={s.name} style={{ display: "flex", justifyContent: "space-between", padding: "3px 0", fontSize: "var(--font-size-xs)" }}>
                      <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-primary)" }}>{s.name}</span>
                      <span style={{ fontFamily: "var(--font-mono)", color: eColor }}>{s.entropy.toFixed(4)}</span>
                    </div>
                  );
                })}
                {sections.length === 0 && <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>No sections</span>}
              </div>
            ))}
          </div>
        </div>

        {/* Strings count diff */}
        <div style={{ marginBottom: 24 }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 12 }}>
            Strings
          </h3>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 12, fontSize: "var(--font-size-sm)" }}>
              <span style={{ color: "var(--text-muted)" }}>File A:</span>{" "}
              <strong style={{ color: "var(--text-primary)" }}>{strCountA}</strong> strings
            </div>
            <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 12, fontSize: "var(--font-size-sm)" }}>
              <span style={{ color: "var(--text-muted)" }}>File B:</span>{" "}
              <strong style={{ color: "var(--text-primary)" }}>{strCountB}</strong> strings
              {strCountB !== strCountA && (
                <span style={{ marginLeft: 8, fontSize: "var(--font-size-xs)", color: strCountB > strCountA ? "var(--risk-medium)" : "var(--risk-low)" }}>
                  ({strCountB > strCountA ? "+" : ""}{strCountB - strCountA})
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Security flags diff */}
        <div style={{ marginBottom: 24 }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-muted)", marginBottom: 12 }}>
            <Shield size={13} /> Security Flags
          </h3>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {[{ label: "File A", pe: peA }, { label: "File B", pe: peB }].map(({ label, pe }) => (
              <div key={label} style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 12 }}>
                <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", fontWeight: 600, display: "block", marginBottom: 8 }}>{label}</span>
                {pe?.security ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {[
                      ["ASLR", pe.security.aslr_enabled],
                      ["DEP", pe.security.dep_enabled],
                    ].map(([name, enabled]) => {
                      const ok = enabled as boolean;
                      const color = ok ? "var(--risk-low)" : "var(--risk-critical)";
                      return (
                        <div key={name as string} style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--font-size-xs)" }}>
                          <span style={{ color: "var(--text-secondary)" }}>{name as string}</span>
                          <span style={{ color, fontWeight: 600 }}>{ok ? "Enabled" : "Disabled"}</span>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>No PE security data</span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
