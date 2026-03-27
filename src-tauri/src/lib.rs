use serde::{Deserialize, Serialize};
use tauri::window::Color;
use tauri::Manager;

// ─── Shared types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub db_path: String,
    /// "dark" | "light"
    pub theme: String,
    /// Hard-coded false. Field exists for future tooling compatibility but is
    /// never settable. The UI must render it as a locked-off status display.
    pub telemetry_enabled: bool,
}

impl AppSettings {
    pub fn default_with_db_path(db_path: String) -> Self {
        AppSettings {
            db_path,
            theme: "dark".to_string(),
            telemetry_enabled: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AnalyzeResponse {
    pub result: serde_json::Value,
    pub risk_score: i64,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct BatchStartedPayload {
    directory: String,
    total_files: usize,
    file_paths: Vec<String>,
    batch_id: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct BatchFileResultPayload {
    index: usize,
    file_path: String,
    file_name: String,
    result: Option<serde_json::Value>,
    risk_score: i64,
    verdict: String,
    error: Option<String>,
    batch_id: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct BatchCompletePayload {
    total: usize,
    analysed: usize,
    failed: usize,
    duration_secs: f64,
    batch_id: u64,
}

// ─── Risk score helper ────────────────────────────────────────────────────────
// Delegates to the core crate's scoring engine (which delegates to anya-scoring).

pub fn compute_risk_score(result: &anya_security_core::output::AnalysisResult) -> i64 {
    anya_security_core::confidence::calculate_risk_score(result) as i64
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn calculate_dir_size(path: &std::path::Path) -> std::io::Result<u64> {
    let mut size = 0;
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                size += metadata.len();
            } else if metadata.is_dir() {
                size += calculate_dir_size(&entry.path()).unwrap_or(0);
            }
        }
    }
    Ok(size)
}

// ─── Commands (separate module to avoid __cmd__ macro namespace collision) ────

pub mod commands {
    use super::{compute_risk_score, AnalyzeResponse, AppSettings};
    use anya_security_core::{
        analyse_file as lib_analyse_file, is_suspicious_file as lib_is_suspicious_file,
        to_json_output as lib_to_json_output,
    };
    use std::path::Path;
    use tauri::Emitter;
    use tauri::Manager;

    /// Append a plain-English hint to an error message if one is available.
    fn with_hint(msg: String) -> String {
        if let Some(hint) = anya_security_core::errors::suggest(&msg) {
            format!("{msg}\n{hint}")
        } else {
            msg
        }
    }

    /// Validate an export path: canonicalize, block system directories, require extension.
    fn validate_export_path(
        output_path: &str,
        required_ext: &str,
    ) -> Result<std::path::PathBuf, String> {
        let requested = std::path::Path::new(output_path);

        let parent = requested
            .parent()
            .ok_or_else(|| "Invalid path: no parent directory".to_string())?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|e| format!("Path error: {e}"))?;
        let canonical = canonical_parent.join(
            requested
                .file_name()
                .ok_or_else(|| "Invalid path: no file name".to_string())?,
        );

        let blocked: &[&str] = &[
            "/etc", "/bin", "/sbin", "/usr", "/boot", "/proc", "/sys", "/dev",
        ];
        let canonical_str = canonical.to_string_lossy();
        for prefix in blocked {
            if canonical_str.starts_with(prefix) {
                return Err(format!(
                    "Refused to write to restricted path: {canonical_str}"
                ));
            }
        }

        if canonical
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            != Some(required_ext.to_lowercase())
        {
            return Err(format!("File must have a .{required_ext} extension"));
        }

        Ok(canonical)
    }

    /// Analyse a file at the given absolute path.
    #[tauri::command]
    pub async fn analyze_file(path: String) -> Result<AnalyzeResponse, String> {
        let path_clone = path.clone();
        let result =
            tokio::task::spawn_blocking(move || lib_analyse_file(Path::new(&path_clone), 4))
                .await
                .map_err(|e| with_hint(format!("Task error: {e}")))?
                .map_err(|e| with_hint(format!("Analysis error: {e}")))?;

        let is_suspicious = lib_is_suspicious_file(&result);
        let json_result = lib_to_json_output(&result);
        let risk_score = compute_risk_score(&json_result);

        let json_value =
            serde_json::to_value(&json_result).map_err(|e| format!("Serialise error: {e}"))?;

        Ok(AnalyzeResponse {
            result: json_value,
            risk_score,
            is_suspicious,
        })
    }

    /// Write a previously-computed JSON result to a user-chosen path.
    ///
    /// The path is expected to come from the native save-file dialog, but since
    /// IPC endpoints are callable directly we validate here as defence-in-depth:
    ///   - resolve to an absolute, canonical path (follows symlinks)
    ///   - reject paths that land inside known sensitive directories
    ///   - require a `.json` extension
    #[tauri::command]
    pub async fn export_json(result: serde_json::Value, output_path: String) -> Result<(), String> {
        let canonical = validate_export_path(&output_path, "json")?;

        let json =
            serde_json::to_string_pretty(&result).map_err(|e| format!("Serialise error: {e}"))?;
        std::fs::write(&canonical, json).map_err(|e| format!("Write error: {e}"))
    }

    /// Return current settings (reads from Tauri app-data dir for the DB path).
    #[tauri::command]
    pub async fn get_settings(app: tauri::AppHandle) -> Result<AppSettings, String> {
        let data_dir = app
            .path()
            .app_data_dir()
            .map_err(|e| format!("Path error: {e}"))?;
        let db_path = data_dir.join("anya").join("anya.db");
        Ok(AppSettings::default_with_db_path(
            db_path.to_string_lossy().into_owned(),
        ))
    }

    /// Persist settings — telemetry is always hard-enforced false.
    #[tauri::command]
    pub async fn save_settings(settings: AppSettings) -> Result<(), String> {
        if settings.telemetry_enabled {
            return Err("Telemetry cannot be enabled".to_string());
        }
        Ok(())
    }

    /// Return a random Bible verse (NLT) from the shared verse pool.
    #[tauri::command]
    pub async fn get_random_verse() -> serde_json::Value {
        use anya_security_core::data::verses;
        let idx = verses::verse_index();
        let (text, reference) = verses::VERSES[idx];
        serde_json::json!({ "text": text, "reference": reference })
    }

    /// Given a serialised `AnalysisResult`, evaluate all lesson triggers and
    /// return the lessons that match.  The caller supplies an optional risk
    /// score (0–100) so that `RiskScoreAbove` triggers can be evaluated.
    #[tauri::command]
    pub async fn get_triggered_lessons(
        result: serde_json::Value,
        risk_score: Option<u32>,
    ) -> Result<serde_json::Value, String> {
        use anya_security_core::{
            data::lessons::{
                context_from_analysis, get_triggered_lessons as compute_triggered, TriggerContext,
            },
            output::AnalysisResult,
        };

        let analysis: AnalysisResult =
            serde_json::from_value(result).map_err(|e| format!("Deserialize error: {e}"))?;

        let pe = analysis.pe_analysis.as_ref();
        let elf = analysis.elf_analysis.as_ref();
        let mitre = &analysis.mitre_techniques;

        let (file_format, packer_names, import_names, mitre_ids) =
            context_from_analysis(pe, elf, analysis.mach_analysis.is_some(), mitre);

        // Compute auxiliary booleans
        let has_ordinal_imports = pe.is_some_and(|p| !p.ordinal_imports.is_empty());
        let has_tls_callbacks = pe
            .and_then(|p| p.tls.as_ref())
            .is_some_and(|t| t.callback_count > 0);
        let has_high_entropy_overlay = pe
            .and_then(|p| p.overlay.as_ref())
            .is_some_and(|o| o.high_entropy);
        let max_section_entropy = pe
            .map(|p| p.sections.iter().map(|s| s.entropy).fold(0.0_f64, f64::max))
            .unwrap_or(0.0);

        let empty_iocs: Vec<String> = Vec::new();
        let ctx = TriggerContext {
            file_format,
            max_section_entropy,
            packer_names: &packer_names,
            import_names: &import_names,
            has_ordinal_imports,
            mitre_technique_ids: &mitre_ids,
            has_tls_callbacks,
            has_high_entropy_overlay,
            pe_analysis: pe,
            elf_analysis: elf,
            risk_score,
            ioc_types: &empty_iocs,
            is_batch: false,
            has_mismatch: false,
            thresholds_customised: false,
            max_confidence: None,
        };

        let lessons = compute_triggered(&ctx);
        serde_json::to_value(&lessons).map_err(|e| format!("Serialize error: {e}"))
    }

    // ── Directory analysis command ─────────────────────────────────────────

    #[tauri::command]
    pub async fn analyze_directory(
        app: tauri::AppHandle,
        path: String,
        recursive: bool,
        batch_id: u64,
    ) -> Result<(), String> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        use super::{BatchCompletePayload, BatchFileResultPayload, BatchStartedPayload};

        let files = anya_security_core::find_executable_files(Path::new(&path), recursive)
            .map_err(|e| format!("Directory scan error: {e}"))?;

        let file_paths: Vec<String> = files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();

        app.emit(
            "batch-started",
            BatchStartedPayload {
                directory: path.clone(),
                total_files: files.len(),
                file_paths: file_paths.clone(),
                batch_id,
            },
        )
        .map_err(|e| format!("Emit error: {e}"))?;

        if files.is_empty() {
            app.emit(
                "batch-complete",
                BatchCompletePayload {
                    total: 0,
                    analysed: 0,
                    failed: 0,
                    duration_secs: 0.0,
                    batch_id,
                },
            )
            .map_err(|e| format!("Emit error: {e}"))?;
            return Ok(());
        }

        let total = files.len();
        let app_handle = app.clone();

        tokio::spawn(async move {
            let start = std::time::Instant::now();
            let semaphore = Arc::new(Semaphore::new(4));
            let failed = Arc::new(AtomicUsize::new(0));

            let mut handles = Vec::with_capacity(total);

            for (index, file_path) in file_paths.into_iter().enumerate() {
                let sem = semaphore.clone();
                let app_h = app_handle.clone();
                let failed_c = failed.clone();
                let fp = file_path.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem
                        .acquire()
                        .await
                        .expect("batch semaphore closed unexpectedly");

                    let fp_inner = fp.clone();
                    let analysis = tokio::task::spawn_blocking(move || {
                        anya_security_core::analyse_file(Path::new(&fp_inner), 4)
                    })
                    .await;

                    let file_name = Path::new(&fp)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();

                    match analysis {
                        Ok(Ok(raw_result)) => {
                            let json_result = lib_to_json_output(&raw_result);
                            let risk_score = compute_risk_score(&json_result);
                            let verdict = if risk_score >= 70 {
                                "malicious"
                            } else if risk_score >= 40 {
                                "suspicious"
                            } else {
                                "clean"
                            };

                            let json_value = serde_json::to_value(&json_result).ok();

                            let _ = app_h.emit(
                                "batch-file-result",
                                BatchFileResultPayload {
                                    index,
                                    file_path: fp,
                                    file_name,
                                    result: json_value,
                                    risk_score,
                                    verdict: verdict.to_string(),
                                    error: None,
                                    batch_id,
                                },
                            );
                        }
                        Ok(Err(e)) => {
                            failed_c.fetch_add(1, Ordering::Relaxed);
                            let _ = app_h.emit(
                                "batch-file-result",
                                BatchFileResultPayload {
                                    index,
                                    file_path: fp,
                                    file_name,
                                    result: None,
                                    risk_score: 0,
                                    verdict: "error".to_string(),
                                    error: Some(format!("Analysis error: {e}")),
                                    batch_id,
                                },
                            );
                        }
                        Err(e) => {
                            failed_c.fetch_add(1, Ordering::Relaxed);
                            let _ = app_h.emit(
                                "batch-file-result",
                                BatchFileResultPayload {
                                    index,
                                    file_path: fp,
                                    file_name,
                                    result: None,
                                    risk_score: 0,
                                    verdict: "error".to_string(),
                                    error: Some(format!("Task error: {e}")),
                                    batch_id,
                                },
                            );
                        }
                    }
                });

                handles.push(handle);
            }

            for handle in handles {
                let _ = handle.await;
            }

            let duration = start.elapsed();
            let failed_count = failed.load(Ordering::Relaxed);

            let _ = app_handle.emit(
                "batch-complete",
                BatchCompletePayload {
                    total,
                    analysed: total - failed_count,
                    failed: failed_count,
                    duration_secs: duration.as_secs_f64(),
                    batch_id,
                },
            );
        });

        Ok(())
    }

    // ── Directory polling ─────────────────────────────────────────────────

    #[tauri::command]
    pub async fn poll_directory(path: String, recursive: bool) -> Result<Vec<String>, String> {
        let dir = std::path::Path::new(&path);
        let files = anya_security_core::find_executable_files(dir, recursive)
            .map_err(|e| format!("Directory scan error: {e}"))?;
        Ok(files
            .iter()
            .map(|f| f.to_string_lossy().to_string())
            .collect())
    }

    // ── Threshold commands ──────────────────────────────────────────────────

    /// Return the current analysis thresholds from config (defaults if unavailable).
    #[tauri::command]
    pub async fn get_thresholds() -> anya_security_core::config::ThresholdConfig {
        anya_security_core::config::Config::load_or_default()
            .map(|c| c.thresholds)
            .unwrap_or_default()
    }

    /// Validate and persist new threshold values to the user's config file.
    #[tauri::command]
    pub async fn save_thresholds(
        thresholds: anya_security_core::config::ThresholdConfig,
    ) -> Result<(), String> {
        thresholds.validate().map_err(|e| e)?;

        let mut config = anya_security_core::config::Config::load_or_default()
            .map_err(|e| format!("Failed to load config: {e}"))?;
        config.thresholds = thresholds;

        let path = anya_security_core::config::Config::default_path().ok_or_else(|| {
            "Config state unavailable: could not determine config path".to_string()
        })?;
        config.save_to_file(&path).map_err(|e| format!("{e}"))?;

        Ok(())
    }

    // ── HTML report export ─────────────────────────────────────────────────

    /// Generate a standalone HTML report from a previously-computed analysis
    /// result and write it to `output_path`.
    #[tauri::command]
    pub async fn export_html_report(
        result: serde_json::Value,
        output_path: String,
    ) -> Result<(), String> {
        let canonical = validate_export_path(&output_path, "html")?;

        // Compute risk score the same way the GUI does
        let json_result: anya_security_core::output::AnalysisResult =
            serde_json::from_value(result.clone()).map_err(|e| format!("Parse error: {e}"))?;
        let risk_score = compute_risk_score(&json_result);

        fn esc(s: &str) -> String {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
        }

        let file_name = json_result
            .file_info
            .path
            .split(['/', '\\'])
            .last()
            .unwrap_or("Unknown");
        let file_path = &json_result.file_info.path;
        let file_size_kb = json_result.file_info.size_kb;
        let file_format = &json_result.file_format;
        let entropy_val = json_result.entropy.value;

        // Risk score colour
        let (score_bg, score_color) = if risk_score >= 70 {
            ("rgba(239,68,68,0.15)", "#ef4444") // red
        } else if risk_score >= 40 {
            ("rgba(234,179,8,0.15)", "#eab308") // yellow
        } else {
            ("rgba(74,222,128,0.15)", "#4ade80") // green
        };

        // Verdict
        let verdict = json_result.verdict_summary.as_deref().unwrap_or("Unknown");

        // Hashes
        let md5 = &json_result.hashes.md5;
        let sha1 = &json_result.hashes.sha1;
        let sha256 = &json_result.hashes.sha256;

        // Top findings
        let mut findings_html = String::new();
        for f in &json_result.top_findings {
            let badge_color = match f.confidence {
                anya_security_core::output::ConfidenceLevel::Critical => "#ef4444",
                anya_security_core::output::ConfidenceLevel::High => "#f97316",
                anya_security_core::output::ConfidenceLevel::Medium => "#eab308",
                anya_security_core::output::ConfidenceLevel::Low => "#94a3b8",
            };
            findings_html.push_str(&format!(
                r#"<div class="finding"><span class="badge" style="background:{bc}22;color:{bc};">{conf:?}</span> {label}</div>"#,
                bc = badge_color, conf = f.confidence, label = esc(&f.label),
            ));
        }

        // MITRE techniques
        let mut mitre_html = String::new();
        for t in &json_result.mitre_techniques {
            mitre_html.push_str(&format!(
                r#"<span class="tag">{id} — {name}</span>"#,
                id = esc(&format!(
                    "{}{}",
                    t.technique_id,
                    t.sub_technique_id
                        .as_ref()
                        .map(|s| format!(".{s}"))
                        .unwrap_or_default()
                )),
                name = esc(&t.technique_name),
            ));
        }

        // Security features (PE)
        let mut security_html = String::new();
        if let Some(pe) = &json_result.pe_analysis {
            let features = [
                ("ASLR", pe.security.aslr_enabled),
                ("DEP/NX", pe.security.dep_enabled),
            ];
            for (name, enabled) in features {
                let (icon, color) = if enabled {
                    ("&#10003;", "#4ade80")
                } else {
                    ("&#10007;", "#ef4444")
                };
                security_html.push_str(&format!(
                    r#"<span class="sec-badge" style="color:{color};">{icon} {name}</span>"#,
                ));
            }
        }

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Anya Report — {file_name_esc}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #111118; color: #e8e8ef; line-height: 1.6; }}
  .page {{ max-width: 900px; margin: 0 auto; padding: 40px 24px; }}
  .header {{ display: flex; align-items: center; gap: 20px; margin-bottom: 32px; padding-bottom: 20px; border-bottom: 1px solid #2a2a35; }}
  .score-ring {{ width: 72px; height: 72px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.5em; font-weight: 700; border: 3px solid {score_color}; background: {score_bg}; color: {score_color}; flex-shrink: 0; }}
  .header-text h1 {{ font-size: 1.3em; font-weight: 600; color: #f0f0f8; }}
  .header-text .sub {{ font-size: 0.8em; color: #888; margin-top: 2px; }}
  .verdict {{ font-size: 0.85em; margin-top: 4px; color: {score_color}; font-weight: 600; }}
  .card {{ background: #1a1a24; border: 1px solid #2a2a35; border-radius: 10px; padding: 20px; margin-bottom: 16px; }}
  .card h2 {{ font-size: 0.7em; text-transform: uppercase; letter-spacing: 0.08em; color: #666; margin-bottom: 12px; }}
  .hash-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #222230; font-family: 'SF Mono', 'Cascadia Code', monospace; font-size: 0.78em; }}
  .hash-row:last-child {{ border-bottom: none; }}
  .hash-label {{ color: #888; width: 60px; flex-shrink: 0; }}
  .hash-value {{ color: #c8c8d8; word-break: break-all; }}
  .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }}
  .info-item {{ display: flex; justify-content: space-between; padding: 6px 0; font-size: 0.85em; }}
  .info-label {{ color: #888; }}
  .info-value {{ color: #d0d0dd; font-weight: 500; }}
  .finding {{ padding: 10px 14px; background: #15151e; border-radius: 8px; margin-bottom: 8px; font-size: 0.85em; display: flex; align-items: center; gap: 10px; }}
  .badge {{ padding: 2px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 600; flex-shrink: 0; }}
  .tag {{ display: inline-block; padding: 4px 10px; margin: 3px; border-radius: 6px; font-size: 0.75em; background: #1e1e2e; border: 1px solid #333; color: #a0a0b8; }}
  .sec-badge {{ display: inline-block; padding: 4px 12px; margin: 3px; font-size: 0.8em; font-weight: 500; }}
  .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #2a2a35; color: #555; font-size: 0.72em; text-align: center; }}
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div class="score-ring">{risk_score}</div>
    <div class="header-text">
      <h1>{file_name_esc}</h1>
      <div class="sub">{file_path_esc} &middot; {file_size_kb:.1} KB &middot; {file_format}</div>
      <div class="verdict">{verdict_esc}</div>
    </div>
  </div>

  <div class="card">
    <h2>Hashes</h2>
    <div class="hash-row"><span class="hash-label">MD5</span><span class="hash-value">{md5}</span></div>
    <div class="hash-row"><span class="hash-label">SHA1</span><span class="hash-value">{sha1}</span></div>
    <div class="hash-row"><span class="hash-label">SHA256</span><span class="hash-value">{sha256}</span></div>
  </div>

  <div class="card">
    <h2>File Info</h2>
    <div class="info-grid">
      <div class="info-item"><span class="info-label">Format</span><span class="info-value">{file_format}</span></div>
      <div class="info-item"><span class="info-label">Entropy</span><span class="info-value">{entropy_val:.4} / 8.0</span></div>
      <div class="info-item"><span class="info-label">Risk Score</span><span class="info-value" style="color:{score_color};">{risk_score} / 100</span></div>
    </div>
  </div>

  {findings_section}

  {mitre_section}

  {security_section}

  <div class="footer">Generated by Anya &middot; Static analysis only &middot; No files were executed</div>
</div>
</body>
</html>"#,
            file_name_esc = esc(file_name),
            file_path_esc = esc(file_path),
            file_size_kb = file_size_kb,
            file_format = esc(file_format),
            risk_score = risk_score,
            score_bg = score_bg,
            score_color = score_color,
            verdict_esc = esc(verdict),
            md5 = md5,
            sha1 = sha1,
            sha256 = sha256,
            entropy_val = entropy_val,
            findings_section = if findings_html.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<div class="card"><h2>Key Findings</h2>{}</div>"#,
                    findings_html
                )
            },
            mitre_section = if mitre_html.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<div class="card"><h2>MITRE ATT&amp;CK</h2>{}</div>"#,
                    mitre_html
                )
            },
            security_section = if security_html.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<div class="card"><h2>Security Features</h2>{}</div>"#,
                    security_html
                )
            },
        );

        std::fs::write(&canonical, html).map_err(|e| format!("Write error: {e}"))
    }

    // ── Case management commands ──────────────────────────────────────────────

    #[tauri::command]
    pub async fn save_to_case(result: serde_json::Value, case_name: String) -> Result<(), String> {
        tokio::task::spawn_blocking(move || {
            anya_security_core::case::save_to_case_from_json(&result, &case_name, None)
        })
        .await
        .map_err(|e| format!("{e}"))?
        .map_err(|e| format!("{e}"))
    }

    #[tauri::command]
    pub async fn list_cases() -> Result<serde_json::Value, String> {
        tokio::task::spawn_blocking(|| anya_security_core::case::list_cases_json(None))
            .await
            .map_err(|e| format!("{e}"))?
            .map_err(|e| format!("{e}"))
    }

    #[tauri::command]
    pub async fn get_case(name: String) -> Result<serde_json::Value, String> {
        tokio::task::spawn_blocking(move || anya_security_core::case::get_case_json(&name, None))
            .await
            .map_err(|e| format!("{e}"))?
            .map_err(|e| format!("{e}"))
    }

    #[tauri::command]
    pub async fn delete_case(name: String) -> Result<(), String> {
        tokio::task::spawn_blocking(move || anya_security_core::case::delete_case(&name, None))
            .await
            .map_err(|e| format!("{e}"))?
            .map_err(|e| format!("{e}"))
    }

    #[tauri::command]
    pub async fn get_cases_dir() -> Result<String, String> {
        tokio::task::spawn_blocking(|| {
            anya_security_core::case::cases_dir(None).map(|p| p.to_string_lossy().to_string())
        })
        .await
        .map_err(|e| format!("{e}"))?
        .map_err(|e| format!("{e}"))
    }

    // ── Installer / first-run commands ────────────────────────────────────────

    /// Check whether this is a first run by looking for the `.anya_configured`
    /// marker file in the app config directory.
    // TODO v1.1.0: Compare stored version in .anya_configured against
    // current app version to show the shorter update installer flow.
    #[tauri::command]
    pub async fn is_first_run(app: tauri::AppHandle) -> bool {
        let config_dir = app
            .path()
            .app_config_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        let marker = config_dir.join(".anya_configured");
        !marker.exists()
    }

    /// Write the first-run marker and persist installer preferences.
    #[tauri::command]
    pub async fn complete_setup(
        app: tauri::AppHandle,
        install_path: String,
        dark_theme: bool,
        teacher_mode: bool,
    ) -> Result<(), String> {
        let _ = install_path;
        let _ = dark_theme;
        let _ = teacher_mode;

        let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;

        let marker = config_dir.join(".anya_configured");
        std::fs::write(&marker, "1").map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Return the platform-appropriate default data directory path.
    #[tauri::command]
    pub async fn get_default_install_path(app: tauri::AppHandle) -> String {
        app.path()
            .app_data_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "~/.local/share/anya".to_string())
    }

    // ── Uninstaller commands ──────────────────────────────────────────────────

    /// Check whether the app was launched with `--uninstall` or `-u`.
    #[tauri::command]
    pub fn get_launch_mode() -> String {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--uninstall" || a == "-u") {
            "uninstall".to_string()
        } else {
            "normal".to_string()
        }
    }

    /// Return info about user data directories and their sizes.
    #[tauri::command]
    pub async fn get_uninstall_info(app: tauri::AppHandle) -> serde_json::Value {
        let config_dir = app.path().app_config_dir().unwrap_or_default();
        let data_dir = app.path().app_data_dir().unwrap_or_default();
        let db_size = super::calculate_dir_size(&data_dir).unwrap_or(0);

        serde_json::json!({
            "config_dir": config_dir.to_string_lossy(),
            "data_dir": data_dir.to_string_lossy(),
            "db_size_mb": db_size / 1_048_576,
        })
    }

    /// Remove user data directories based on user selection.
    /// The app binary itself is removed by the OS installer (msi/deb/dmg).
    #[tauri::command]
    pub async fn perform_uninstall(
        app: tauri::AppHandle,
        remove_database: bool,
        remove_config: bool,
    ) -> Result<(), String> {
        let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
        let data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;

        if remove_database && data_dir.exists() {
            // Reject symlinks to prevent symlink attacks
            if let Ok(meta) = std::fs::symlink_metadata(&data_dir) {
                if !meta.file_type().is_symlink() {
                    std::fs::remove_dir_all(&data_dir)
                        .map_err(|e| format!("Failed to remove database: {e}"))?;
                }
            }
        }

        if remove_config && config_dir.exists() {
            // Reject symlinks to prevent symlink attacks
            if let Ok(meta) = std::fs::symlink_metadata(&config_dir) {
                if !meta.file_type().is_symlink() {
                    std::fs::remove_dir_all(&config_dir)
                        .map_err(|e| format!("Failed to remove config: {e}"))?;
                }
            }
        }

        Ok(())
    }
}

// ─── App entry point ─────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if let Some(main) = app.get_webview_window("main") {
                main.set_background_color(Some(Color(13, 13, 15, 255)))
                    .unwrap_or(());
            }
            Ok(())
        })
        .plugin(tauri_plugin_sql::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            commands::analyze_file,
            commands::analyze_directory,
            commands::export_json,
            commands::export_html_report,
            commands::get_settings,
            commands::save_settings,
            commands::get_triggered_lessons,
            commands::get_random_verse,
            commands::is_first_run,
            commands::complete_setup,
            commands::get_default_install_path,
            commands::get_launch_mode,
            commands::get_uninstall_info,
            commands::perform_uninstall,
            commands::get_thresholds,
            commands::save_thresholds,
            commands::poll_directory,
            commands::save_to_case,
            commands::list_cases,
            commands::get_case,
            commands::delete_case,
            commands::get_cases_dir,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Anya");
}
