import type { AnalysisResult } from "@/types/analysis";

/**
 * Compute a 0–100 integer risk score from the analysis result.
 * Mirrors the logic in src-tauri/src/lib.rs compute_risk_score().
 * The Rust backend already computes this; this copy exists for
 * client-side recalculation when displaying stored results.
 */
export function computeRiskScore(result: AnalysisResult): number {
  let score = 0;

  if (result.entropy.is_suspicious) score += 20;

  const pe = result.pe_analysis;
  if (pe) {
    score += Math.min(pe.imports.suspicious_api_count, 5) * 5;

    const wxCount = pe.sections.filter((s) => s.is_wx).length;
    score += wxCount * 15;

    if (pe.tls?.callback_count) {
      score += Math.min(pe.tls.callback_count, 3) * 5;
    }

    if (pe.overlay?.high_entropy) score += 15;

    score += Math.min(pe.anti_analysis.length, 4) * 5;

    for (const p of pe.packers) {
      score += p.confidence === "High" ? 20 : p.confidence === "Medium" ? 10 : 5;
    }

    if (pe.authenticode?.present) {
      score -= pe.authenticode.is_microsoft_signed ? 15 : 5;
    }

    if (!pe.security.aslr_enabled) score += 5;
    if (!pe.security.dep_enabled) score += 5;
  }

  return Math.max(0, Math.min(100, score));
}

export type RiskLevel = "clean" | "suspicious" | "likely-malicious" | "critical";

export function getRiskLevel(score: number): RiskLevel {
  if (score < 30) return "clean";
  if (score < 60) return "suspicious";
  if (score < 80) return "likely-malicious";
  return "critical";
}

export function getRiskLabel(score: number): string {
  const level = getRiskLevel(score);
  return {
    clean: "Clean",
    suspicious: "Suspicious",
    "likely-malicious": "Likely Malicious",
    critical: "Critical",
  }[level];
}

export function getRiskColor(score: number): string {
  const level = getRiskLevel(score);
  return {
    clean: "var(--risk-low)",
    suspicious: "var(--risk-medium)",
    "likely-malicious": "var(--risk-high)",
    critical: "var(--risk-critical)",
  }[level];
}

export function getRiskTailwindClass(score: number): string {
  const level = getRiskLevel(score);
  return {
    clean: "text-[var(--risk-low)]",
    suspicious: "text-[var(--risk-medium)]",
    "likely-malicious": "text-[var(--risk-high)]",
    critical: "text-[var(--risk-critical)]",
  }[level];
}

/** Detection tag categories and their associated risk levels */
export function getDetectionTags(result: AnalysisResult): DetectionTag[] {
  const tags: DetectionTag[] = [];
  const pe = result.pe_analysis;
  if (!pe) return tags;

  // Group suspicious APIs by category
  const catMap = new Map<string, string[]>();
  for (const api of pe.imports.suspicious_apis) {
    const list = catMap.get(api.category) ?? [];
    list.push(api.name);
    catMap.set(api.category, list);
  }
  for (const [cat, apis] of catMap) {
    tags.push({ label: cat, apis, severity: "high" });
  }

  // Anti-analysis categories
  const antiCats = new Set(pe.anti_analysis.map((f) => f.category));
  for (const cat of antiCats) {
    const label = {
      VmDetection: "VM Detection",
      DebuggerDetection: "Anti-Debug",
      TimingCheck: "Timing Evasion",
      SandboxDetection: "Sandbox Evasion",
    }[cat] ?? cat;
    tags.push({
      label,
      apis: pe.anti_analysis.filter((f) => f.category === cat).map((f) => f.indicator),
      severity: "high",
    });
  }

  // Packers
  for (const p of pe.packers) {
    tags.push({
      label: p.name,
      apis: [`detected via ${p.detection_method}`],
      severity: p.confidence === "High" ? "high" : "medium",
    });
  }

  // W+X sections
  const wxSections = pe.sections.filter((s) => s.is_wx);
  if (wxSections.length > 0) {
    tags.push({
      label: "W+X Section",
      apis: wxSections.map((s) => s.name),
      severity: "critical",
    });
  }

  return tags;
}

export interface DetectionTag {
  label: string;
  apis: string[];
  severity: "critical" | "high" | "medium" | "low";
}
