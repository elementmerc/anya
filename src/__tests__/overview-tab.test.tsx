import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { TeacherModeContext, type TeacherModeContextValue } from "../../ui/hooks/useTeacherMode";
import OverviewTab from "../../ui/components/tabs/OverviewTab";
import type { AnalysisResult } from "../../ui/types/analysis";

const teacherCtx: TeacherModeContextValue = {
  enabled: false,
  setEnabled: vi.fn(),
  focusedItem: null,
  focus: vi.fn(),
  blur: vi.fn(),
};

function makeResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    file_name: "test.exe",
    file_size: 2048,
    file_info: { path: "/tmp/test.exe", size_bytes: 2048, size_kb: 2, extension: "exe", mime_type: "application/x-dosexec" },
    hashes: { md5: "d41d8cd98f00b204e9800998ecf8427e", sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709", sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    entropy: { overall: 5.5, per_section: [] },
    strings: { min_length: 4, total_count: 0, sample_count: 0, samples: [] },
    file_format: "PE",
    verdict_summary: "CLEAN — no findings",
    top_findings: [],
    mitre_techniques: [],
    confidence_scores: {},
    plain_english_findings: [],
    ...overrides,
  } as unknown as AnalysisResult;
}

function renderTab(result: AnalysisResult, riskScore = 10) {
  return render(
    <TeacherModeContext.Provider value={teacherCtx}>
      <OverviewTab result={result} riskScore={riskScore} pinnedFindings={[]} onPin={vi.fn()} />
    </TeacherModeContext.Provider>
  );
}

describe("OverviewTab", () => {
  it("renders without crashing", () => {
    const { container } = renderTab(makeResult());
    expect(container.querySelector("div")).toBeDefined();
  });

  it("renders hash values", () => {
    renderTab(makeResult());
    // SHA256 should appear in the rendered output
    expect(screen.getByText(/e3b0c44298fc1c14/)).toBeDefined();
  });
});
