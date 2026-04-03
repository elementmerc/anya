/**
 * Centralised explanation data loaders for APIs, DLLs, and categories.
 * All data loaded from the proprietary data crate via IPC. Single source of truth.
 */
import { getFunctionExplanations, getDllExplanations, getCategoryExplanations } from "@/lib/tauri-bridge";

// ── API descriptions ──────────────────────────────────────────────────────────

let _apiCache: Record<string, string> | null = null;

export async function initApiDescriptions(): Promise<void> {
  if (_apiCache) return;
  try {
    const json = await getFunctionExplanations();
    _apiCache = JSON.parse(json) as Record<string, string>;
  } catch {
    _apiCache = {};
  }
}

export function getApiDescription(name: string): string | undefined {
  if (!_apiCache) return undefined;
  return _apiCache[name] ?? _apiCache[name + "A"] ?? _apiCache[name + "W"];
}

// ── DLL descriptions ──────────────────────────────────────────────────────────

interface DllEntry { summary: string; teacher: string }
let _dllCache: Record<string, DllEntry> | null = null;

export async function initDllExplanations(): Promise<void> {
  if (_dllCache) return;
  try {
    const json = await getDllExplanations();
    _dllCache = JSON.parse(json) as Record<string, DllEntry>;
  } catch {
    _dllCache = {};
  }
}

/** Get the technical summary for inline display (e.g. ImportsTab). */
export function getDllSummary(dll: string): string | undefined {
  if (!_dllCache) return undefined;
  const entry = _dllCache[dll] ?? _dllCache[dll.toUpperCase()] ?? _dllCache[dll.toLowerCase()];
  return entry?.summary;
}

/** Get the teacher explanation for Teacher Mode sidebar. */
export function getDllTeacher(dll: string): string | undefined {
  if (!_dllCache) return undefined;
  const entry = _dllCache[dll] ?? _dllCache[dll.toUpperCase()] ?? _dllCache[dll.toLowerCase()];
  return entry?.teacher;
}

// ── Category descriptions ─────────────────────────────────────────────────────

interface CategoryEntry { summary: string; teacher: string }
let _categoryCache: Record<string, CategoryEntry> | null = null;

export async function initCategoryExplanations(): Promise<void> {
  if (_categoryCache) return;
  try {
    const json = await getCategoryExplanations();
    _categoryCache = JSON.parse(json) as Record<string, CategoryEntry>;
  } catch {
    _categoryCache = {};
  }
}

/** Get the teacher explanation for a category. */
export function getCategoryTeacher(name: string): string | undefined {
  if (!_categoryCache) return undefined;
  return _categoryCache[name]?.teacher;
}

/** Get the technical summary for a category. */
export function getCategorySummary(name: string): string | undefined {
  if (!_categoryCache) return undefined;
  return _categoryCache[name]?.summary;
}

// ── Init all at once ──────────────────────────────────────────────────────────

export async function initAllExplanations(): Promise<void> {
  await Promise.all([initApiDescriptions(), initDllExplanations(), initCategoryExplanations()]);
}
