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

export const savePdfPicker = (): Promise<string | null> =>
  save({ filters: [{ name: "PDF", extensions: ["pdf"] }], defaultPath: "report.pdf" });

// ─── HTML report export ─────────────────────────────────────────────────

export const exportHtmlReport = (result: AnalysisResult, outputPath: string): Promise<void> =>
  withTimeout(invoke("export_html_report", { result, outputPath }), 30_000, "HTML export");

export const exportPdfReport = (result: AnalysisResult, outputPath: string): Promise<void> =>
  withTimeout(invoke("export_pdf_report", { result, outputPath }), 30_000, "PDF export");

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

// ── Network graph ────────────────────────────────────────────────────────────

/** Compute relationship graph from batch analysis results (server-side TLSH + KSD matching) */
export const getBatchGraphData = (results: unknown[]): Promise<import("../types/analysis").GraphData> =>
  invoke("get_batch_graph_data", { results });

/** Install bundled YARA rules from app resources to user's rules directory */
export const installBundledYaraRules = (): Promise<string> =>
  invoke("install_bundled_yara_rules");

/** Get KSD neighborhood for a single file's TLSH hash (for single-file graph mode) */
export interface KsdNeighbor {
  family: string;
  function: string;
  sha256: string;
  tlsh: string;
  distance: number;
  tags: string[];
}
export const getKsdNeighborhood = (
  tlshHash: string,
  family?: string,
  maxResults?: number,
): Promise<{ neighbors: KsdNeighbor[] }> =>
  invoke("get_ksd_neighborhood", { tlshHash, family: family ?? null, maxResults: maxResults ?? null });

// ── Proprietary data access ──────────────────────────────────────────────────

export const getDllExplanations = (): Promise<string> =>
  invoke("get_dll_explanations");

export const getFunctionExplanations = (): Promise<string> =>
  invoke("get_function_explanations");

export const getTechniqueExplanations = (): Promise<string> =>
  invoke("get_technique_explanations");

export const getMitreAttackData = (): Promise<string> =>
  invoke("get_mitre_attack_data");

export const getCategoryExplanations = (): Promise<string> =>
  invoke("get_category_explanations");

export const yaraScanOnly = (path: string): Promise<unknown> =>
  invoke("yara_scan_only", { path });
