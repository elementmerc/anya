import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { TeacherModeContext, type TeacherModeContextValue } from "../../ui/hooks/useTeacherMode";
import StringsTab from "../../ui/components/tabs/StringsTab";
import type { AnalysisResult } from "../../ui/types/analysis";

const teacherCtx: TeacherModeContextValue = {
  enabled: false,
  setEnabled: vi.fn(),
  focusedItem: null,
  focus: vi.fn(),
  blur: vi.fn(),
};

function makeResult(strings: string[]): AnalysisResult {
  return {
    file_name: "test.exe",
    file_size: 1024,
    strings: {
      min_length: 4,
      total_count: strings.length,
      sample_count: strings.length,
      samples: strings,
    },
    mitre_techniques: [],
  } as unknown as AnalysisResult;
}

function renderTab(result: AnalysisResult) {
  return render(
    <TeacherModeContext.Provider value={teacherCtx}>
      <div style={{ height: 600 }}>
        <StringsTab result={result} onPin={vi.fn()} />
      </div>
    </TeacherModeContext.Provider>
  );
}

describe("StringsTab", () => {
  it("renders without crashing", () => {
    const { container } = renderTab(makeResult(["hello", "world"]));
    expect(container.querySelector("div")).toBeDefined();
  });

  it("renders search input", () => {
    renderTab(makeResult(["hello"]));
    const input = screen.getByPlaceholderText(/search/i);
    expect(input).toBeDefined();
  });

  it("shows empty state when no strings", () => {
    renderTab(makeResult([]));
    // Should show some empty/no-strings message
    expect(screen.getByText(/no strings/i)).toBeDefined();
  });
});
