import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { TeacherModeContext, type TeacherModeContextValue } from "../../ui/hooks/useTeacherMode";
import SettingsModal from "../../ui/components/SettingsModal";

// Mock Tauri-specific modules used inside SettingsModal
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn().mockResolvedValue(null),
}));

vi.mock("../../ui/lib/tauri-bridge", () => ({
  getSettings: vi.fn().mockResolvedValue({ db_path: "/tmp/anya.db", theme: "dark" }),
  getThresholds: vi.fn().mockResolvedValue({ suspicious_entropy: 5.0, packed_entropy: 7.0, suspicious_score: 40, malicious_score: 70 }),
  saveThresholds: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../ui/lib/db", () => ({
  saveSettingsToDb: vi.fn().mockResolvedValue(undefined),
}));

const defaultProps = {
  theme: "dark" as const,
  onToggleTheme: vi.fn(),
  fontSize: "default" as const,
  onSetFontSize: vi.fn(),
  bibleVersesEnabled: true,
  onSetBibleVerses: vi.fn(),
  onClose: vi.fn(),
};

function renderSettingsModal(
  contextOverrides: Partial<TeacherModeContextValue> = {},
  propOverrides: Partial<typeof defaultProps> = {}
) {
  const contextValue: TeacherModeContextValue = {
    enabled: false,
    setEnabled: vi.fn(),
    focusedItem: null,
    focus: vi.fn(),
    blur: vi.fn(),
    ...contextOverrides,
  };
  const props = { ...defaultProps, ...propOverrides };
  return render(
    <TeacherModeContext.Provider value={contextValue}>
      <SettingsModal {...props} />
    </TeacherModeContext.Provider>
  );
}

describe("SettingsModal toggles", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the Bible Verses label", () => {
    renderSettingsModal();
    expect(screen.getByText("Bible Verses")).toBeInTheDocument();
  });

  it("renders the Teacher Mode label", () => {
    renderSettingsModal();
    expect(screen.getByText("Teacher Mode")).toBeInTheDocument();
  });

  it("Teacher Mode toggle reflects context enabled state via aria-checked", () => {
    renderSettingsModal({ enabled: true });
    const toggles = screen.getAllByRole("switch");
    const teacherToggle = toggles.find(
      (btn) => btn.getAttribute("aria-checked") !== null
    );
    // The Teacher Mode toggle is the first switch; aria-checked should match context
    expect(toggles[0].getAttribute("aria-checked")).toBe("true");
  });

  it("Bible Verses toggle reflects bibleVersesEnabled prop via aria-checked", () => {
    renderSettingsModal({}, { bibleVersesEnabled: false });
    const toggles = screen.getAllByRole("switch");
    // Bible Verses is the second switch in the Learning section
    const bibleToggle = toggles[1];
    expect(bibleToggle.getAttribute("aria-checked")).toBe("false");
  });

  it("clicking the Bible Verses toggle calls onSetBibleVerses", () => {
    const onSetBibleVerses = vi.fn();
    renderSettingsModal({}, { bibleVersesEnabled: true, onSetBibleVerses });
    const toggles = screen.getAllByRole("switch");
    fireEvent.click(toggles[1]);
    expect(onSetBibleVerses).toHaveBeenCalledWith(false);
  });
});
