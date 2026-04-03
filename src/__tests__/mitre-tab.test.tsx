import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { TeacherModeContext, type TeacherModeContextValue } from "../../ui/hooks/useTeacherMode";
import MitreTab from "../../ui/components/tabs/MitreTab";

// Suppress expected console.warn from MitreTab when MITRE data isn't loaded via IPC in test env
const originalWarn = console.warn;
beforeAll(() => { console.warn = (...args: unknown[]) => { if (typeof args[0] === "string" && args[0].includes("[MitreTab]")) return; originalWarn(...args); }; });
afterAll(() => { console.warn = originalWarn; });
import type { AnalysisResult } from "../../ui/types/analysis";

const teacherCtx: TeacherModeContextValue = {
  enabled: false,
  setEnabled: vi.fn(),
  focusedItem: null,
  focus: vi.fn(),
  blur: vi.fn(),
};

function emptyResult(): AnalysisResult {
  return {
    file_name: "test.exe",
    file_size: 1024,
    file_type: "PE",
    md5: "abc",
    sha1: "abc",
    sha256: "abc",
    is_suspicious: false,
    analysis_timestamp: "2026-01-01T00:00:00Z",
    mitre_techniques: [],
  } as unknown as AnalysisResult;
}

function resultWithTechnique(): AnalysisResult {
  return {
    ...emptyResult(),
    mitre_techniques: [
      {
        technique_id: "T1055",
        sub_technique_id: null,
        technique_name: "Process Injection",
        tactic: "Defense Evasion",
        confidence: "High",
        source_indicator: "VirtualAllocEx",
      },
    ],
  } as unknown as AnalysisResult;
}

function resultWithTwoTactics(): AnalysisResult {
  return {
    ...emptyResult(),
    mitre_techniques: [
      {
        technique_id: "T1055",
        sub_technique_id: null,
        technique_name: "Process Injection",
        tactic: "Defense Evasion",
        confidence: "High",
        source_indicator: "VirtualAllocEx",
      },
      {
        technique_id: "T1082",
        sub_technique_id: null,
        technique_name: "System Information Discovery",
        tactic: "Discovery",
        confidence: "Medium",
        source_indicator: "GetSystemInfo",
      },
    ],
  } as unknown as AnalysisResult;
}

function renderMitreTab(result: AnalysisResult) {
  return render(
    <TeacherModeContext.Provider value={teacherCtx}>
      <MitreTab result={result} />
    </TeacherModeContext.Provider>
  );
}

describe("MitreTab", () => {
  it("shows empty state when there are no MITRE techniques", () => {
    renderMitreTab(emptyResult());
    expect(
      screen.getByText(/No MITRE ATT&CK techniques detected/i)
    ).toBeInTheDocument();
  });

  it("empty state contains a shield icon (SVG rendered by lucide)", () => {
    const { container } = renderMitreTab(emptyResult());
    // lucide Shield renders an <svg> element
    expect(container.querySelector("svg")).toBeInTheDocument();
  });

  it("renders a technique card when techniques are present", () => {
    renderMitreTab(resultWithTechnique());
    expect(screen.getByText("T1055")).toBeInTheDocument();
  });

  it("card displays technique ID and name", () => {
    renderMitreTab(resultWithTechnique());
    expect(screen.getByText("T1055")).toBeInTheDocument();
    expect(screen.getByText("Process Injection")).toBeInTheDocument();
  });

  it("techniques are grouped by tactic — tactic header is rendered", () => {
    renderMitreTab(resultWithTechnique());
    expect(screen.getByText("Defense Evasion")).toBeInTheDocument();
  });

  it("renders separate tactic columns for different tactics", () => {
    renderMitreTab(resultWithTwoTactics());
    expect(screen.getByText("Defense Evasion")).toBeInTheDocument();
    expect(screen.getByText("Discovery")).toBeInTheDocument();
  });
});
