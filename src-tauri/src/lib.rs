use serde::{Deserialize, Serialize};

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

// ─── Risk score helper ────────────────────────────────────────────────────────

pub fn compute_risk_score(result: &anya_security_core::output::AnalysisResult) -> i64 {
    let mut score: i64 = 0;

    if result.entropy.is_suspicious {
        score += 20;
    }

    if let Some(pe) = &result.pe_analysis {
        score += (pe.imports.suspicious_api_count as i64).min(5) * 5;

        let wx = pe.sections.iter().filter(|s| s.is_wx).count() as i64;
        score += wx * 15;

        if let Some(tls) = &pe.tls {
            score += (tls.callback_count as i64).min(3) * 5;
        }

        if pe.overlay.as_ref().map_or(false, |o| o.high_entropy) {
            score += 15;
        }

        score += (pe.anti_analysis.len() as i64).min(4) * 5;

        for p in &pe.packers {
            score += match p.confidence.as_str() {
                "High" => 20,
                "Medium" => 10,
                _ => 5,
            };
        }

        if let Some(auth) = &pe.authenticode {
            if auth.present {
                score -= if auth.is_microsoft_signed { 15 } else { 5 };
            }
        }

        if !pe.security.aslr_enabled {
            score += 5;
        }
        if !pe.security.dep_enabled {
            score += 5;
        }
    }

    score.clamp(0, 100)
}

// ─── Commands (separate module to avoid __cmd__ macro namespace collision) ────

pub mod commands {
    use super::{compute_risk_score, AnalyzeResponse, AppSettings};
    use anya_security_core::{
        analyse_file as lib_analyse_file, is_suspicious_file as lib_is_suspicious_file,
        to_json_output as lib_to_json_output,
    };
    use std::path::Path;
    use tauri::Manager;

    /// Analyse a file at the given absolute path.
    #[tauri::command]
    pub async fn analyze_file(path: String) -> Result<AnalyzeResponse, String> {
        let path_clone = path.clone();
        let result =
            tokio::task::spawn_blocking(move || lib_analyse_file(Path::new(&path_clone), 4))
                .await
                .map_err(|e| format!("Task error: {e}"))?
                .map_err(|e| format!("Analysis error: {e}"))?;

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
    #[tauri::command]
    pub async fn export_json(
        result: serde_json::Value,
        output_path: String,
    ) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialise error: {e}"))?;
        std::fs::write(&output_path, json).map_err(|e| format!("Write error: {e}"))
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

        let analysis: AnalysisResult = serde_json::from_value(result)
            .map_err(|e| format!("Deserialize error: {e}"))?;

        let pe = analysis.pe_analysis.as_ref();
        let elf = analysis.elf_analysis.as_ref();
        let mitre = &analysis.mitre_techniques;

        let (file_format, packer_names, import_names, mitre_ids) =
            context_from_analysis(pe, elf, mitre);

        // Compute auxiliary booleans
        let has_ordinal_imports = pe.map_or(false, |p| !p.ordinal_imports.is_empty());
        let has_tls_callbacks = pe
            .and_then(|p| p.tls.as_ref())
            .map_or(false, |t| t.callback_count > 0);
        let has_high_entropy_overlay = pe
            .and_then(|p| p.overlay.as_ref())
            .map_or(false, |o| o.high_entropy);
        let max_section_entropy = pe
            .map(|p| {
                p.sections
                    .iter()
                    .map(|s| s.entropy)
                    .fold(0.0_f64, f64::max)
            })
            .unwrap_or(0.0);

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
        };

        let lessons = compute_triggered(&ctx);
        serde_json::to_value(&lessons).map_err(|e| format!("Serialize error: {e}"))
    }
}

// ─── App entry point ─────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_sql::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            commands::analyze_file,
            commands::export_json,
            commands::get_settings,
            commands::save_settings,
            commands::get_triggered_lessons,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Anya");
}
