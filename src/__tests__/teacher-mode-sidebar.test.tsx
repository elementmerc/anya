import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { TeacherModeContext, type TeacherModeContextValue } from "../../ui/hooks/useTeacherMode";
import TeacherSidebar from "../../ui/components/TeacherSidebar";

// TeacherSidebar reads JSON data files at module load — these import fine in
// jsdom because Vitest resolves them as static assets.

function renderWithContext(contextValue: Partial<TeacherModeContextValue>) {
  const defaults: TeacherModeContextValue = {
    enabled: true,
    setEnabled: vi.fn(),
    focusedItem: null,
    focus: vi.fn(),
    blur: vi.fn(),
  };
  const value = { ...defaults, ...contextValue };
  return {
    ...render(
      <TeacherModeContext.Provider value={value}>
        <TeacherSidebar />
      </TeacherModeContext.Provider>
    ),
    value,
  };
}

describe("TeacherSidebar", () => {
  it("renders the 'Teacher Mode' heading in the header", () => {
    renderWithContext({ enabled: true });
    // The heading is the span in the header bar
    const headings = screen.getAllByText("Teacher Mode");
    expect(headings.length).toBeGreaterThan(0);
  });

  it("shows the default prompt text when no technique is selected", () => {
    renderWithContext({ enabled: true, focusedItem: null });
    expect(
      screen.getByText(/Click or hover any flagged item/i)
    ).toBeInTheDocument();
  });

  it("shows technique ID when a MITRE focus item is set", () => {
    renderWithContext({
      enabled: true,
      focusedItem: {
        type: "mitre",
        techniqueId: "T1055",
        techniqueName: "Process Injection",
        tactic: "Defense Evasion",
      },
    });
    expect(screen.getByText("T1055")).toBeInTheDocument();
  });

  it("shows technique name when a MITRE focus item is set", () => {
    renderWithContext({
      enabled: true,
      focusedItem: {
        type: "mitre",
        techniqueId: "T1055",
        techniqueName: "Process Injection",
        tactic: "Defense Evasion",
      },
    });
    expect(screen.getByText("Process Injection")).toBeInTheDocument();
  });

  it("collapses the sidebar (width 0) when enabled is false", () => {
    const { container } = renderWithContext({ enabled: false });
    // The outermost div transitions to width: 0 when disabled
    const outerDiv = container.firstChild as HTMLElement;
    expect(outerDiv.style.width).toMatch(/^0(px)?$/);
  });

  it("shows the 'Simple explanation' section when a technique with explanation is focused", () => {
    // T1055 (Process Injection) has an entry in technique_explanations.json
    renderWithContext({
      enabled: true,
      focusedItem: {
        type: "mitre",
        techniqueId: "T1055",
        techniqueName: "Process Injection",
        tactic: "Defense Evasion",
      },
    });
    expect(screen.getByText(/Simple explanation/i)).toBeInTheDocument();
  });

  it("calls setEnabled(false) when the X button is clicked", () => {
    const setEnabled = vi.fn();
    renderWithContext({ enabled: true, setEnabled });
    const closeBtn = screen.getByTitle("Disable Teacher Mode");
    fireEvent.click(closeBtn);
    expect(setEnabled).toHaveBeenCalledWith(false);
  });
});
