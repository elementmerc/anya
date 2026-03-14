/**
 * All Tauri invoke() calls live here.
 * Components MUST call these functions — never invoke() directly.
 */
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import type { AnalyzeResponse, AppSettings, AnalysisResult, TriggeredLesson } from "@/types/analysis";

// ─── File analysis ─────────────────────────────────────────────────────────

export const analyzeFile = (path: string): Promise<AnalyzeResponse> =>
  invoke("analyze_file", { path });

// ─── JSON export ───────────────────────────────────────────────────────────

export const exportJson = (result: AnalysisResult, outputPath: string): Promise<void> =>
  invoke("export_json", { result, outputPath });

// ─── Settings ──────────────────────────────────────────────────────────────

export const getSettings = (): Promise<AppSettings> =>
  invoke("get_settings");

export const saveSettings = (settings: AppSettings): Promise<void> =>
  invoke("save_settings", { settings });

// ─── Teacher Mode ──────────────────────────────────────────────────────────

/** Evaluate lesson triggers for `result` and return matching lessons. */
export const getTriggeredLessons = (
  result: AnalysisResult,
  riskScore?: number
): Promise<TriggeredLesson[]> =>
  invoke("get_triggered_lessons", { result, riskScore: riskScore ?? null });

// ─── File pickers ──────────────────────────────────────────────────────────

export const openFilePicker = (): Promise<string | string[] | null> =>
  open({
    filters: [{ name: "PE Files", extensions: ["exe", "dll", "sys", "drv", "ocx", "so", "elf"] }],
    multiple: false,
  });

export const saveJsonPicker = (): Promise<string | null> =>
  save({ filters: [{ name: "JSON", extensions: ["json"] }], defaultPath: "analysis.json" });

// ─── Drag-drop ─────────────────────────────────────────────────────────────

export const onFileDrop = (handler: (paths: string[]) => void) =>
  listen("tauri://drag-drop", (event: { payload: { paths: string[] } }) =>
    handler(event.payload.paths)
  );
