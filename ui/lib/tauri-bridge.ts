/**
 * All Tauri invoke() calls live here.
 * Components MUST call these functions — never invoke() directly.
 */
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import type { AnalyzeResponse, AppSettings, AnalysisResult, TriggeredLesson, ThresholdConfig, CaseSummary, CaseDetail } from "@/types/analysis";

// ─── Timeout helper ───────────────────────────────────────────────────────

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(
        `${label} took too long (>${Math.round(ms / 1000)}s). The file may be corrupted or too large.`
      )), ms)
    ),
  ]);
}

// ─── File analysis ─────────────────────────────────────────────────────────

export const analyzeFile = (path: string): Promise<AnalyzeResponse> =>
  withTimeout(invoke("analyze_file", { path }), 120_000, "Analysis");

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

// ─── Thresholds ────────────────────────────────────────────────────

export const getThresholds = (): Promise<ThresholdConfig> =>
  invoke("get_thresholds");

export const saveThresholds = (thresholds: ThresholdConfig): Promise<void> =>
  invoke("save_thresholds", { thresholds });

// ─── File pickers ──────────────────────────────────────────────────────────

export const openFilePicker = (): Promise<string | string[] | null> =>
  open({
    multiple: false,
  });

export const saveJsonPicker = (): Promise<string | null> =>
  save({ filters: [{ name: "JSON", extensions: ["json"] }], defaultPath: "analysis.json" });

export const saveHtmlPicker = (): Promise<string | null> =>
  save({ filters: [{ name: "HTML", extensions: ["html"] }], defaultPath: "report.html" });

// ─── HTML report export ─────────────────────────────────────────────────

export const exportHtmlReport = (result: AnalysisResult, outputPath: string): Promise<void> =>
  withTimeout(invoke("export_html_report", { result, outputPath }), 30_000, "HTML export");

// ─── Drag-drop ─────────────────────────────────────────────────────────────

export const onFileDrop = (handler: (paths: string[]) => void) =>
  listen("tauri://drag-drop", (event: { payload: { paths: string[] } }) =>
    handler(event.payload.paths)
  );

// ── Batch analysis ──────────────────────────────────────────────

import type { BatchStartedPayload, BatchFileResultPayload, BatchCompletePayload } from "@/types/analysis";

export const openFolderPicker = (): Promise<string | null> =>
  open({ directory: true, multiple: false }) as Promise<string | null>;

export const analyzeDirectory = (path: string, recursive: boolean, batchId: number): Promise<void> =>
  withTimeout(invoke("analyze_directory", { path, recursive, batchId }), 600_000, "Batch analysis");

export const onBatchStarted = (handler: (payload: BatchStartedPayload) => void) =>
  listen<BatchStartedPayload>("batch-started", (event) => handler(event.payload));

export const onBatchFileResult = (handler: (payload: BatchFileResultPayload) => void) =>
  listen<BatchFileResultPayload>("batch-file-result", (event) => handler(event.payload));

export const onBatchComplete = (handler: (payload: BatchCompletePayload) => void) =>
  listen<BatchCompletePayload>("batch-complete", (event) => handler(event.payload));

export const pollDirectory = (path: string, recursive: boolean): Promise<string[]> =>
  invoke("poll_directory", { path, recursive });

// ── Case management ──────────────────────────────────────────────

export const saveToCase = (result: AnalysisResult, caseName: string): Promise<void> =>
  invoke("save_to_case", { result, caseName });

export const listCases = (): Promise<CaseSummary[]> =>
  invoke("list_cases");

export const getCase = (name: string): Promise<CaseDetail> =>
  invoke("get_case", { name });

export const deleteCase = (name: string): Promise<void> =>
  invoke("delete_case", { name });

/** Get the default cases directory path from the backend */
export const getCasesDir = (): Promise<string> =>
  invoke("get_cases_dir");

/** Open a native folder picker starting at the cases root for creating a new case */
export const pickNewCaseFolder = async (): Promise<string | null> => {
  const casesRoot = await getCasesDir();
  return open({ directory: true, multiple: false, defaultPath: casesRoot }) as Promise<string | null>;
};

/** Open a native folder picker starting at the cases root for opening an existing case */
export const pickExistingCaseFolder = async (): Promise<string | null> => {
  const casesRoot = await getCasesDir();
  return open({ directory: true, multiple: false, defaultPath: casesRoot }) as Promise<string | null>;
};
