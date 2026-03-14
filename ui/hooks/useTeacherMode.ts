/**
 * Teacher Mode context — shared state for the contextual explanation sidebar.
 *
 * Any component can call `useTeacherFocus()` to send a focus event;
 * TeacherSidebar reads the same context to show the relevant explanation.
 */
import { createContext, useContext } from "react";
import type { MitreTechnique } from "@/types/analysis";

// ── Focus item union ────────────────────────────────────────────────────────

export type TeacherFocusItem =
  | {
      type: "mitre";
      techniqueId: string;
      techniqueName: string;
      tactic: string;
      /** Optional: detected subtechniques, present when focused from MITRE tab card. */
      detectedSubs?: { id: string; name: string }[];
      /** Optional: API indicators that triggered this technique. */
      indicators?: { source: string; confidence: string }[];
    }
  | { type: "api"; name: string; category?: string }
  | { type: "dll"; name: string; description?: string };

// ── Context shape ───────────────────────────────────────────────────────────

export interface TeacherModeContextValue {
  /** Whether teacher mode is enabled (persisted to DB). Sidebar is visible iff true. */
  enabled: boolean;
  /**
   * Enable or disable teacher mode. Also shows/hides the sidebar and persists
   * the setting to the DB.
   */
  setEnabled: (v: boolean) => void;
  /** The item the user is currently hovering/clicking. */
  focusedItem: TeacherFocusItem | null;
  focus: (item: TeacherFocusItem) => void;
  blur: () => void;
}

export const TeacherModeContext = createContext<TeacherModeContextValue>({
  enabled: false,
  setEnabled: () => {},
  focusedItem: null,
  focus: () => {},
  blur: () => {},
});

// ── Consumer hooks ──────────────────────────────────────────────────────────

export function useTeacherMode(): TeacherModeContextValue {
  return useContext(TeacherModeContext);
}

/**
 * Convenience hook for tab components that only need to send focus events.
 */
export function useTeacherFocus() {
  const { enabled, focus, blur } = useTeacherMode();
  return { teacherEnabled: enabled, focus, blur };
}

// ── Helper: build focus item from a MitreTechnique ──────────────────────────

export function mitreToFocus(t: MitreTechnique): TeacherFocusItem {
  return {
    type: "mitre",
    techniqueId: t.sub_technique_id
      ? `${t.technique_id}.${t.sub_technique_id}`
      : t.technique_id,
    techniqueName: t.technique_name,
    tactic: t.tactic,
  };
}
