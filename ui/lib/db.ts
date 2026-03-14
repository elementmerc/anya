/**
 * Local SQLite storage via @tauri-apps/plugin-sql.
 * All DB access goes through this module.
 */
import Database from "@tauri-apps/plugin-sql";
import type { StoredAnalysis, AnalysisResult, AppSettings } from "@/types/analysis";

// ─── Teacher Mode types ───────────────────────────────────────────────────────

export interface TeacherProgress {
  id: number;
  lesson_id: string;
  completed_at: string;
  analysis_hash: string | null;
}

export interface TeacherSettings {
  enabled: boolean;
  auto_show_on_trigger: boolean;
  show_beginner: boolean;
  show_intermediate: boolean;
  show_advanced: boolean;
}

let _db: Database | null = null;

async function getDb(): Promise<Database> {
  if (_db) return _db;
  _db = await Database.load("sqlite:anya.db");
  await initSchema(_db);
  return _db;
}

async function initSchema(db: Database): Promise<void> {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS analyses (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      file_name   TEXT NOT NULL,
      file_path   TEXT NOT NULL,
      file_hash   TEXT NOT NULL,
      analysed_at TEXT NOT NULL,
      risk_score  INTEGER NOT NULL,
      result_json TEXT NOT NULL
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);
  // Teacher Mode tables
  await db.execute(`
    CREATE TABLE IF NOT EXISTS teacher_progress (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      lesson_id     TEXT NOT NULL UNIQUE,
      completed_at  TEXT NOT NULL,
      analysis_hash TEXT
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS teacher_settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);
  // Seed teacher_settings defaults if not present
  await db.execute(`
    INSERT OR IGNORE INTO teacher_settings (key, value) VALUES
      ('enabled',              'false'),
      ('auto_show_on_trigger', 'true'),
      ('show_beginner',        'true'),
      ('show_intermediate',    'true'),
      ('show_advanced',        'false')
  `);
}

// ─── Analysis storage ─────────────────────────────────────────────────────

/**
 * Store an analysis result.
 * If the same file hash has been analysed before, update the existing row.
 */
export async function storeAnalysis(
  result: AnalysisResult,
  riskScore: number
): Promise<void> {
  const db = await getDb();
  const hash = result.hashes.sha256;
  const filePath = result.file_info.path;
  const fileName = filePath.replace(/\\/g, "/").split("/").pop() ?? filePath;
  const now = new Date().toISOString();
  const json = JSON.stringify(result);

  // Check if already exists
  const existing = await db.select<{ id: number }[]>(
    "SELECT id FROM analyses WHERE file_hash = ?",
    [hash]
  );

  if (existing.length > 0) {
    await db.execute(
      `UPDATE analyses
       SET file_path = ?, analysed_at = ?, risk_score = ?, result_json = ?
       WHERE file_hash = ?`,
      [filePath, now, riskScore, json, hash]
    );
  } else {
    await db.execute(
      `INSERT INTO analyses (file_name, file_path, file_hash, analysed_at, risk_score, result_json)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [fileName, filePath, hash, now, riskScore, json]
    );
  }
}

export async function getRecentAnalyses(limit = 20): Promise<StoredAnalysis[]> {
  const db = await getDb();
  return db.select<StoredAnalysis[]>(
    "SELECT * FROM analyses ORDER BY analysed_at DESC LIMIT ?",
    [limit]
  );
}

export async function getAnalysisByHash(
  sha256: string
): Promise<StoredAnalysis | null> {
  const db = await getDb();
  const rows = await db.select<StoredAnalysis[]>(
    "SELECT * FROM analyses WHERE file_hash = ?",
    [sha256]
  );
  return rows[0] ?? null;
}

// ─── Settings ────────────────────────────────────────────────────────────

export async function loadSettings(): Promise<Partial<AppSettings>> {
  const db = await getDb();
  const rows = await db.select<{ key: string; value: string }[]>(
    "SELECT key, value FROM settings"
  );
  const map: Record<string, string> = {};
  for (const row of rows) map[row.key] = row.value;

  const settings: Partial<AppSettings> = {};
  if (map["theme"] === "dark" || map["theme"] === "light") {
    settings.theme = map["theme"];
  }
  if (["small", "default", "large", "xl"].includes(map["font_size"])) {
    settings.font_size = map["font_size"] as AppSettings["font_size"];
  }
  return settings;
}

export async function saveSettingsToDb(
  partial: Partial<AppSettings>
): Promise<void> {
  const db = await getDb();
  for (const [key, value] of Object.entries(partial)) {
    if (value === undefined) continue;
    await db.execute(
      "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
      [key, String(value)]
    );
  }
}

// ─── Teacher Mode: progress ───────────────────────────────────────────────────

export async function markLessonComplete(
  lessonId: string,
  analysisHash?: string
): Promise<void> {
  const db = await getDb();
  await db.execute(
    `INSERT OR REPLACE INTO teacher_progress (lesson_id, completed_at, analysis_hash)
     VALUES (?, ?, ?)`,
    [lessonId, new Date().toISOString(), analysisHash ?? null]
  );
}

export async function getLessonProgress(): Promise<TeacherProgress[]> {
  const db = await getDb();
  return db.select<TeacherProgress[]>(
    "SELECT * FROM teacher_progress ORDER BY completed_at DESC"
  );
}

export async function isLessonComplete(lessonId: string): Promise<boolean> {
  const db = await getDb();
  const rows = await db.select<{ id: number }[]>(
    "SELECT id FROM teacher_progress WHERE lesson_id = ?",
    [lessonId]
  );
  return rows.length > 0;
}

export async function resetLessonProgress(): Promise<void> {
  const db = await getDb();
  await db.execute("DELETE FROM teacher_progress");
}

// ─── Teacher Mode: settings ───────────────────────────────────────────────────

export async function loadTeacherSettings(): Promise<TeacherSettings> {
  const db = await getDb();
  const rows = await db.select<{ key: string; value: string }[]>(
    "SELECT key, value FROM teacher_settings"
  );
  const map: Record<string, string> = {};
  for (const row of rows) map[row.key] = row.value;
  return {
    enabled:              map["enabled"]              === "true",
    auto_show_on_trigger: map["auto_show_on_trigger"] === "true",
    show_beginner:        map["show_beginner"]        !== "false",
    show_intermediate:    map["show_intermediate"]    !== "false",
    show_advanced:        map["show_advanced"]        === "true",
  };
}

export async function saveTeacherSettings(
  settings: Partial<TeacherSettings>
): Promise<void> {
  const db = await getDb();
  for (const [key, value] of Object.entries(settings)) {
    if (value === undefined) continue;
    await db.execute(
      "INSERT OR REPLACE INTO teacher_settings (key, value) VALUES (?, ?)",
      [key, String(value)]
    );
  }
}
