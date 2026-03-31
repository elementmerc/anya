use serde::{Deserialize, Serialize};
use tauri::window::Color;
use tauri::Manager;

// ─── Shared types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub db_path: String,
    /// "dark" | "light"
    pub theme: String,
    /// Always false. Anya makes zero network calls. This field exists in the
    /// settings struct for schema completeness but is never settable.
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

/// IPC API version — bump when response shapes change.
/// Frontend can check this to handle version skew gracefully.
pub const API_VERSION: &str = "2.0.0";

#[derive(Debug, Serialize)]
pub struct AnalyzeResponse {
    /// IPC API version for frontend/backend compatibility checking
    pub api_version: &'static str,
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
            api_version: super::API_VERSION,
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
        thresholds.validate()?;

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

    /// Generate a standalone HTML report. Delegates to the shared generator
    /// in anya-security-core::report — single source of truth for all report formats.
    #[tauri::command]
    pub async fn export_html_report(
        result: serde_json::Value,
        output_path: String,
    ) -> Result<(), String> {
        let canonical = validate_export_path(&output_path, "html")?;
        let json_result: anya_security_core::output::AnalysisResult =
            serde_json::from_value(result).map_err(|e| format!("Parse error: {e}"))?;
        tokio::task::spawn_blocking(move || {
            anya_security_core::report::generate_html_report(&json_result, &canonical)
                .map_err(|e| format!("HTML generation error: {e}"))
        })
        .await
        .map_err(|e| format!("{e}"))?
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

    /// Generate a PDF report from analysis results.
    #[tauri::command]
    pub async fn export_pdf_report(
        result: serde_json::Value,
        output_path: String,
    ) -> Result<(), String> {
        let canonical = validate_export_path(&output_path, "pdf")?;
        let json_result: anya_security_core::output::AnalysisResult =
            serde_json::from_value(result).map_err(|e| format!("Parse error: {e}"))?;

        tokio::task::spawn_blocking(move || {
            anya_security_core::report::generate_pdf_report(&json_result, &canonical)
                .map_err(|e| format!("PDF generation error: {e}"))
        })
        .await
        .map_err(|e| format!("{e}"))?
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

    // ── Graph data commands ────────────────────────────────────────────────────

    /// Compute relationship graph data from batch results.
    /// Returns nodes (files) and edges (relationships) for the 3D graph.
    #[tauri::command]
    pub async fn get_batch_graph_data(
        results: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        tokio::task::spawn_blocking(move || {
            let mut nodes = Vec::new();
            let mut edges = Vec::new();

            // Build nodes from results
            for (i, r) in results.iter().enumerate() {
                let file_name = r
                    .get("file_info")
                    .and_then(|fi| fi.get("path"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("unknown");
                let short_name = std::path::Path::new(file_name)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| file_name.to_string());
                let verdict = r
                    .get("verdict_summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");
                let color = if verdict.contains("MALICIOUS") {
                    "#ff4444"
                } else if verdict.contains("SUSPICIOUS") {
                    "#ffaa00"
                } else if verdict.contains("CLEAN") {
                    "#44ff88"
                } else {
                    "#888888"
                };
                let tlsh = r
                    .get("hashes")
                    .and_then(|h| h.get("tlsh"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                let family = r
                    .get("ksd_match")
                    .and_then(|k| k.get("family"))
                    .and_then(|f| f.as_str())
                    .unwrap_or("");

                nodes.push(serde_json::json!({
                    "id": i,
                    "name": short_name,
                    "color": color,
                    "verdict": verdict,
                    "tlsh": tlsh,
                    "family": family,
                    "val": 1,
                }));
            }

            // Build edges from TLSH similarity
            for (i, ri) in results.iter().enumerate() {
                let tlsh_i = ri
                    .get("hashes")
                    .and_then(|h| h.get("tlsh"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                if tlsh_i.is_empty() {
                    continue;
                }
                for (j, rj) in results.iter().enumerate().skip(i + 1) {
                    let tlsh_j = rj
                        .get("hashes")
                        .and_then(|h| h.get("tlsh"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    if tlsh_j.is_empty() {
                        continue;
                    }
                    // Compute TLSH distance using core crate utility
                    if let Some(distance) = anya_security_core::tlsh_distance(tlsh_i, tlsh_j) {
                        if distance <= 150 {
                            let strength = 1.0 - (distance as f64 / 150.0);
                            let label = if distance <= 30 {
                                "near-identical"
                            } else if distance <= 80 {
                                "similar"
                            } else {
                                "related"
                            };
                            edges.push(serde_json::json!({
                                "source": i,
                                "target": j,
                                "distance": distance,
                                "strength": strength,
                                "label": label,
                            }));
                        }
                    }
                }
            }

            // Also connect files that share the same KSD family
            for (i, ri) in results.iter().enumerate() {
                let family_i = ri
                    .get("ksd_match")
                    .and_then(|k| k.get("family"))
                    .and_then(|f| f.as_str())
                    .unwrap_or("");
                if family_i.is_empty() {
                    continue;
                }
                for (j, rj) in results.iter().enumerate().skip(i + 1) {
                    let family_j = rj
                        .get("ksd_match")
                        .and_then(|k| k.get("family"))
                        .and_then(|f| f.as_str())
                        .unwrap_or("");
                    if family_i == family_j {
                        // Check if edge already exists from TLSH
                        let already = edges.iter().any(|e| {
                            (e["source"] == i && e["target"] == j)
                                || (e["source"] == j && e["target"] == i)
                        });
                        if !already {
                            edges.push(serde_json::json!({
                                "source": i,
                                "target": j,
                                "distance": 0,
                                "strength": 0.8,
                                "label": format!("same family: {}", family_i),
                            }));
                        }
                    }
                }
            }

            Ok(serde_json::json!({
                "nodes": nodes,
                "links": edges,
            }))
        })
        .await
        .map_err(|e| format!("{e}"))?
    }

    /// Get KSD neighborhood for a single file — returns nearby known samples
    /// for the 3D relationship graph in single-file mode.
    #[tauri::command]
    pub async fn get_ksd_neighborhood(
        tlsh_hash: String,
        family: Option<String>,
        max_results: Option<usize>,
    ) -> Result<serde_json::Value, String> {
        tokio::task::spawn_blocking(move || {
            let db = anya_security_core::anya_scoring::ksd::KnownSampleDb::load(None);
            let max = max_results.unwrap_or(20);
            let mut neighbors: Vec<serde_json::Value> = Vec::new();

            for sample in db.samples() {
                if let Some(distance) =
                    anya_security_core::tlsh_distance(&tlsh_hash, &sample.tlsh)
                {
                    if distance <= 200 {
                        neighbors.push(serde_json::json!({
                            "family": sample.family,
                            "function": sample.function,
                            "sha256": sample.sha256,
                            "tlsh": sample.tlsh,
                            "distance": distance,
                            "tags": sample.tags,
                        }));
                    }
                }
            }

            // Also include same-family samples even if TLSH distance is large
            if let Some(ref fam) = family {
                for sample in db.samples() {
                    let already = neighbors.iter().any(|n| {
                        n.get("sha256").and_then(|s| s.as_str()) == Some(&sample.sha256)
                    });
                    if !already && sample.family == *fam {
                        neighbors.push(serde_json::json!({
                            "family": sample.family,
                            "function": sample.function,
                            "sha256": sample.sha256,
                            "tlsh": sample.tlsh,
                            "distance": anya_security_core::tlsh_distance(&tlsh_hash, &sample.tlsh).unwrap_or(999),
                            "tags": sample.tags,
                        }));
                    }
                }
            }

            // Sort by distance and limit
            neighbors.sort_by_key(|n| {
                n.get("distance").and_then(|d| d.as_u64()).unwrap_or(999)
            });
            neighbors.truncate(max);

            Ok(serde_json::json!({ "neighbors": neighbors }))
        })
        .await
        .map_err(|e| format!("{e}"))?
    }

    // ── Installer / first-run commands ────────────────────────────────────────

    /// Check whether this is a first run or an upgrade.
    /// Returns "first_run", "upgrade", or "current" as a string.
    #[tauri::command]
    pub async fn is_first_run(app: tauri::AppHandle) -> String {
        let config_dir = app
            .path()
            .app_config_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        let marker = config_dir.join(".anya_configured");
        if !marker.exists() {
            return "first_run".to_string();
        }
        // Compare stored version against current app version
        let stored = std::fs::read_to_string(&marker).unwrap_or_default();
        let current = env!("CARGO_PKG_VERSION");
        if stored.trim() == current {
            "current".to_string()
        } else {
            "upgrade".to_string()
        }
    }

    /// Install bundled YARA rules from the app resources to the user's rules directory.
    /// Called on first run or when user explicitly requests rule installation.
    #[tauri::command]
    pub async fn install_bundled_yara_rules(app: tauri::AppHandle) -> Result<String, String> {
        let rules_dest = anya_security_core::yara::scanner::default_rules_dir();

        // Skip if rules already exist
        if rules_dest.exists() {
            let has_rules = std::fs::read_dir(&rules_dest)
                .map(|entries| {
                    entries.filter_map(|e| e.ok()).any(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        name.ends_with(".yar") || name.ends_with(".yara")
                    })
                })
                .unwrap_or(false);
            if has_rules {
                return Ok("Rules already installed".to_string());
            }
        }

        // Resolve bundled rules from Tauri resources
        let resource_dir = app
            .path()
            .resource_dir()
            .map_err(|e| format!("Resource dir error: {e}"))?
            .join("rules");

        if !resource_dir.exists() {
            return Err("No bundled YARA rules found in installer package. Run prep-yara-rules.sh before building.".to_string());
        }

        // Create destination directory
        std::fs::create_dir_all(&rules_dest)
            .map_err(|e| format!("Failed to create rules directory: {e}"))?;

        // Copy all .yar/.yara files
        let mut copied = 0usize;
        for entry in walkdir::WalkDir::new(&resource_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy();
                e.file_type().is_file() && (name.ends_with(".yar") || name.ends_with(".yara"))
            })
        {
            let rel_path = entry
                .path()
                .strip_prefix(&resource_dir)
                .unwrap_or(entry.path());
            let dest_file = rules_dest.join(rel_path);
            if let Some(parent) = dest_file.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            if std::fs::copy(entry.path(), &dest_file).is_ok() {
                copied += 1;
            }
        }

        // Reload the YARA scanner with the new rules
        let _ = anya_security_core::yara::scanner::reload_rules();

        Ok(format!(
            "Installed {} YARA rule files to {}",
            copied,
            rules_dest.display()
        ))
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

        // Install bundled YARA rules on first run
        let _ = install_bundled_yara_rules(app.clone()).await;

        let config_dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;

        let marker = config_dir.join(".anya_configured");
        std::fs::write(&marker, env!("CARGO_PKG_VERSION")).map_err(|e| e.to_string())?;

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
            commands::export_pdf_report,
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
            commands::get_batch_graph_data,
            commands::get_ksd_neighborhood,
            commands::install_bundled_yara_rules,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Anya");
}
