import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { invoke } from "@tauri-apps/api/core";
import { BibleVerseBar } from "../../ui/components/BibleVerseBar";

const mockVerse = {
  text: "For God so loved the world that he gave his one and only Son.",
  reference: "John 3:16",
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.mocked(invoke).mockResolvedValue(mockVerse);
});

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("BibleVerseBar", () => {
  it("renders verse text and reference after fetch", async () => {
    const { container } = render(<BibleVerseBar />);

    // Allow the async invoke to resolve
    await act(async () => {
      await Promise.resolve();
    });

    expect(container.textContent).toContain(mockVerse.text);
    expect(container.textContent).toContain(mockVerse.reference);
  });

  it("displays verse text in the first span", async () => {
    render(<BibleVerseBar />);
    await act(async () => { await Promise.resolve(); });

    const spans = screen.getAllByText((content) => content.includes("God so loved"));
    expect(spans.length).toBeGreaterThan(0);
  });

  it("displays reference text adjacent to verse", async () => {
    render(<BibleVerseBar />);
    await act(async () => { await Promise.resolve(); });

    expect(screen.getByText(mockVerse.reference)).toBeInTheDocument();
  });

  it("calls invoke to fetch a verse on mount", async () => {
    render(<BibleVerseBar />);
    await act(async () => { await Promise.resolve(); });

    expect(invoke).toHaveBeenCalledWith("get_random_verse");
  });

  it("fetches a new verse after 10 minutes (600000ms)", async () => {
    render(<BibleVerseBar />);
    await act(async () => { await Promise.resolve(); });

    const initialCallCount = vi.mocked(invoke).mock.calls.length;

    // Advance time by exactly 10 minutes
    await act(async () => {
      vi.advanceTimersByTime(600_000);
      await Promise.resolve();
    });

    expect(vi.mocked(invoke).mock.calls.length).toBeGreaterThan(initialCallCount);
  });
});
