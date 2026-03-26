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

  it("shows DLL name when a dll focus item is set", () => {
    renderWithContext({
      enabled: true,
      focusedItem: {
        type: "dll",
        name: "KERNEL32.dll",
        description: "Core Windows API — file I/O, memory management, process and thread creation.",
      },
    });
    expect(screen.getByText("KERNEL32.dll")).toBeInTheDocument();
  });

  it("shows DLL description in the Simple explanation card", () => {
    renderWithContext({
      enabled: true,
      focusedItem: {
        type: "dll",
        name: "KERNEL32.dll",
        description: "Core Windows API — file I/O, memory management, process and thread creation.",
      },
    });
    expect(screen.getByText(/main toolbox Windows uses/)).toBeInTheDocument();
    expect(screen.getByText(/Simple explanation/i)).toBeInTheDocument();
  });

  it("shows 'Dynamic-Link Library' badge for DLL focus items", () => {
    renderWithContext({
      enabled: true,
      focusedItem: {
        type: "dll",
        name: "USER32.dll",
        description: "Windows UI API.",
      },
    });
    expect(screen.getByText("Dynamic-Link Library")).toBeInTheDocument();
  });

  it("shows API name and category when an api focus item is set", () => {
    renderWithContext({
      enabled: true,
      focusedItem: {
        type: "api",
        name: "CreateRemoteThread",
        category: "Code Injection",
      },
    });
    expect(screen.getByText("CreateRemoteThread")).toBeInTheDocument();
    expect(screen.getByText("Code Injection")).toBeInTheDocument();
  });

  it("renders the drag handle when enabled", () => {
    const { container } = renderWithContext({ enabled: true });
    const outerDiv = container.firstChild as HTMLElement;
    // The drag handle is the first child inside the outer div, with cursor: col-resize
    const dragHandle = outerDiv.querySelector('[style*="col-resize"]');
    expect(dragHandle).toBeTruthy();
  });
});
