import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import DropZone from "../../ui/components/DropZone";

// Stub the Tauri bridge + db modules so the component renders without a backend.
vi.mock("@/lib/tauri-bridge", () => ({
  openFilePicker: vi.fn(),
}));
vi.mock("@/lib/db", () => ({
  getRecentAnalysisSummaries: vi.fn(() => Promise.resolve([])),
}));
vi.mock("@/components/CaseBrowser", () => ({
  default: () => null,
}));

describe("DropZone friendly-error branch", () => {
  const baseProps = {
    isLoading: false,
    onPickFile: () => {},
  };

  it("renders the friendly primary line when the engine reports 'Couldn't read' with a path", () => {
    render(
      <DropZone
        {...baseProps}
        error={
          "Couldn't read '/tmp/whatsapp-xy-sample.exe'. Check that the file exists and you have read permission."
        }
      />,
    );

    expect(
      screen.getByText("This file is no longer available at its original location."),
    ).toBeDefined();
    expect(screen.getByText("It may have been deleted or moved.")).toBeDefined();
  });

  it("displays the original path (muted, wrapped) when the friendly branch fires", () => {
    const path = "/tmp/whatsapp-xy-sample.exe";
    render(
      <DropZone
        {...baseProps}
        error={`Couldn't read '${path}'. Check that the file exists and you have read permission.`}
      />,
    );

    const pathEl = screen.getByText(path);
    expect(pathEl).toBeDefined();
    expect((pathEl as HTMLElement).style.wordBreak).toBe("break-all");
    expect((pathEl as HTMLElement).style.overflowWrap).toBe("anywhere");
  });

  it("falls back to the raw error message when the 'Couldn't read' pattern does not match", () => {
    const raw = "Unsupported file format: Unknown (magic=0xDEADBEEF)";
    render(<DropZone {...baseProps} error={raw} />);

    expect(screen.getByText(raw)).toBeDefined();
    expect(
      screen.queryByText("This file is no longer available at its original location."),
    ).toBeNull();
  });

  it("does not match a superficially similar error that lacks the full engine phrasing", () => {
    // Self-evolving-sweep guard: if the engine's Couldn't-read wording ever
    // drifts (e.g. a refactor changes 'Check that the file exists' to
    // something else), the friendly branch silently stops firing. This test
    // pins the exact engine string the UI regex depends on; the paired Rust
    // integration test `test_couldnt_read_error_matches_ui_regex` asserts the
    // engine still produces this exact phrasing. Either side breaking
    // surfaces as a test failure in the release gate before ship.
    render(
      <DropZone
        {...baseProps}
        error={"Couldn't read '/tmp/sample.exe'. File does not exist."}
      />,
    );

    expect(
      screen.queryByText("This file is no longer available at its original location."),
    ).toBeNull();
    expect(screen.getByText("Couldn't read '/tmp/sample.exe'. File does not exist.")).toBeDefined();
  });
});
