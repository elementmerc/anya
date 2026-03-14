import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, act } from "@testing-library/react";
import { Installer } from "../../ui/components/Installer";

// The Installer imports `invoke` from @tauri-apps/api/core and `open` from
// @tauri-apps/plugin-dialog — both are auto-mocked by Vitest.

// Mock the dialog plugin
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn().mockResolvedValue(null),
}));

// Override the default invoke mock to handle installer-specific commands
const { invoke } = await import("@tauri-apps/api/core");

beforeEach(() => {
  vi.clearAllMocks();
  (invoke as ReturnType<typeof vi.fn>).mockImplementation(
    (cmd: string) => {
      if (cmd === "get_default_install_path") return Promise.resolve("/home/user/.local/share/anya");
      if (cmd === "complete_setup") return Promise.resolve(undefined);
      return Promise.resolve(undefined);
    }
  );
});

describe("Installer", () => {
  it("renders the licence step first", async () => {
    await act(async () => {
      render(<Installer onComplete={vi.fn()} />);
    });
    expect(screen.getByText("AGPL-3.0 Licence")).toBeInTheDocument();
  });

  it("disables Continue until licence is accepted", async () => {
    await act(async () => {
      render(<Installer onComplete={vi.fn()} />);
    });
    const continueBtn = screen.getByText("Continue");
    expect(continueBtn).toBeDisabled();
  });

  it("enables Continue after accepting the licence", async () => {
    await act(async () => {
      render(<Installer onComplete={vi.fn()} />);
    });
    const toggle = screen.getByRole("checkbox");
    fireEvent.click(toggle);
    const continueBtn = screen.getByText("Continue");
    expect(continueBtn).not.toBeDisabled();
  });

  it("navigates to step 2 (Location) after accepting and clicking Continue", async () => {
    await act(async () => {
      render(<Installer onComplete={vi.fn()} />);
    });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByText("Continue"));
    expect(screen.getByText("Install location")).toBeInTheDocument();
  });

  it("shows the default install path from Tauri", async () => {
    await act(async () => {
      render(<Installer onComplete={vi.fn()} />);
    });
    // Navigate to step 2
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByText("Continue"));
    expect(screen.getByText("/home/user/.local/share/anya")).toBeInTheDocument();
  });

  it("navigates to step 3 (Preferences) and shows theme toggle", async () => {
    await act(async () => {
      render(<Installer onComplete={vi.fn()} />);
    });
    // Step 1 → 2 → 3
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByText("Continue"));
    fireEvent.click(screen.getByText("Continue"));
    expect(screen.getByText("Initial preferences")).toBeInTheDocument();
    expect(screen.getByText("Dark theme")).toBeInTheDocument();
    expect(screen.getByText("Teacher Mode")).toBeInTheDocument();
  });

  it("toggles dark theme class on the installer root", async () => {
    let container: HTMLElement;
    await act(async () => {
      const result = render(<Installer onComplete={vi.fn()} />);
      container = result.container;
    });
    // Navigate to preferences step
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByText("Continue"));
    fireEvent.click(screen.getByText("Continue"));

    // Initially light
    const root = container!.firstChild as HTMLElement;
    expect(root.className).toContain("light");

    // Toggle dark
    const darkToggle = screen.getAllByRole("checkbox")[0];
    fireEvent.click(darkToggle);
    expect(root.className).toContain("dark");
  });

  it("allows navigating back from step 2 to step 1", async () => {
    await act(async () => {
      render(<Installer onComplete={vi.fn()} />);
    });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByText("Continue"));
    expect(screen.getByText("Install location")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Back"));
    expect(screen.getByText("AGPL-3.0 Licence")).toBeInTheDocument();
  });

  it("renders five step dots", async () => {
    await act(async () => {
      render(<Installer onComplete={vi.fn()} />);
    });
    const dots = document.querySelectorAll(".dot");
    expect(dots.length).toBe(5);
  });
});
