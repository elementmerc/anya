// Ányá - Malware Analysis Platform
// Copyright (C) 2026 Daniel Iwugo
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// For commercial licensing, contact: daniel@themalwarefiles.com

use anyhow::{Context, Result, bail};
use chrono::Utc;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseFile {
    pub case: CaseMeta,
    pub files: Vec<CaseFileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseMeta {
    pub name: String,
    pub created: String,
    pub updated: String,
    pub status: String,
    pub tags: Vec<String>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseFileEntry {
    pub path: String,
    pub sha256: String,
    pub verdict: String,
    pub analysed_at: String,
    pub report: String,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Returns the `./cases` directory relative to the current working directory.
/// A config-based override can be added later.
pub fn cases_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("./cases"))
}

/// Sanitise a case name for use as a directory name.
///
/// - Lowercase
/// - Replace spaces and special characters with hyphens
/// - Collapse multiple consecutive hyphens
/// - Trim leading/trailing hyphens
/// - Error if the result is shorter than 2 characters
pub fn sanitise_case_name(name: &str) -> Result<String> {
    let lower = name.to_lowercase();

    // Replace anything that isn't alphanumeric with a hyphen
    let replaced: String = lower
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();

    // Collapse multiple consecutive hyphens into one
    let mut collapsed = String::with_capacity(replaced.len());
    let mut prev_hyphen = false;
    for c in replaced.chars() {
        if c == '-' {
            if !prev_hyphen {
                collapsed.push('-');
            }
            prev_hyphen = true;
        } else {
            collapsed.push(c);
            prev_hyphen = false;
        }
    }

    // Trim leading/trailing hyphens
    let trimmed = collapsed.trim_matches('-').to_string();

    if trimmed.len() < 2 {
        bail!(
            "Case name is too short or contains only special characters. \
             Use a simple name like 'my-investigation'."
        );
    }

    Ok(trimmed)
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Save an analysis result into a named case.
///
/// Creates the case directory structure if needed, appends the file entry to
/// the case manifest (`case.yaml`), and writes the JSON report to the
/// `reports/` subdirectory.
pub fn save_to_case(
    case_name: &str,
    file_path: &Path,
    sha256: &str,
    verdict: &str,
    json_report: &str,
) -> Result<()> {
    let sanitised = sanitise_case_name(case_name)?;
    let base = cases_dir()?;
    let case_dir = base.join(&sanitised);
    let reports_dir = case_dir.join("reports");

    // Ensure directories exist
    fs::create_dir_all(&reports_dir)
        .with_context(|| format!("Failed to create case directory: {}", case_dir.display()))?;

    let now = Utc::now().to_rfc3339();
    let case_yaml_path = case_dir.join("case.yaml");

    // Load existing case file or create a new one
    let mut case_file = if case_yaml_path.exists() {
        let contents = fs::read_to_string(&case_yaml_path)
            .with_context(|| format!("Failed to read {}", case_yaml_path.display()))?;
        let mut cf: CaseFile = serde_yaml::from_str(&contents)
            .with_context(|| format!("Failed to parse {}", case_yaml_path.display()))?;
        cf.case.updated = now.clone();
        cf
    } else {
        CaseFile {
            case: CaseMeta {
                name: sanitised.clone(),
                created: now.clone(),
                updated: now.clone(),
                status: "open".to_string(),
                tags: Vec::new(),
                notes: String::new(),
            },
            files: Vec::new(),
        }
    };

    // Build report filename: {original_filename}_{timestamp}.json
    // Replace colons in the timestamp with hyphens for filesystem safety
    let original_filename = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let ts_safe = now.replace(':', "-");
    let report_filename = format!("{}_{}.json", original_filename, ts_safe);
    let report_path = reports_dir.join(&report_filename);

    // Write the JSON report
    fs::write(&report_path, json_report)
        .with_context(|| format!("Failed to write report: {}", report_path.display()))?;

    // Add entry to the case file list
    case_file.files.push(CaseFileEntry {
        path: file_path.to_string_lossy().to_string(),
        sha256: sha256.to_string(),
        verdict: verdict.to_string(),
        analysed_at: now,
        report: format!("reports/{}", report_filename),
    });

    // Write case.yaml
    let yaml =
        serde_yaml::to_string(&case_file).context("Failed to serialise case file to YAML")?;
    fs::write(&case_yaml_path, yaml)
        .with_context(|| format!("Failed to write {}", case_yaml_path.display()))?;

    let n = case_file.files.len();
    println!(
        "Case '{}' updated — {} files",
        sanitised.bold(),
        n.to_string().bold()
    );

    Ok(())
}

/// List all cases found under the cases directory.
pub fn list_cases() -> Result<()> {
    let base = cases_dir()?;

    if !base.exists() {
        println!("No cases found.");
        return Ok(());
    }

    let mut entries: Vec<_> = fs::read_dir(&base)
        .with_context(|| format!("Failed to read cases directory: {}", base.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();

    entries.sort_by_key(|e| e.file_name());

    let mut cases: Vec<CaseFile> = Vec::new();

    for entry in &entries {
        let case_yaml = entry.path().join("case.yaml");
        if !case_yaml.exists() {
            eprintln!(
                "Skipping {} — no case.yaml found",
                entry.file_name().to_string_lossy()
            );
            continue;
        }
        match fs::read_to_string(&case_yaml) {
            Ok(contents) => match serde_yaml::from_str::<CaseFile>(&contents) {
                Ok(cf) => cases.push(cf),
                Err(e) => {
                    eprintln!(
                        "Skipping {} — failed to parse case.yaml: {}",
                        entry.file_name().to_string_lossy(),
                        e
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "Skipping {} — failed to read case.yaml: {}",
                    entry.file_name().to_string_lossy(),
                    e
                );
            }
        }
    }

    if cases.is_empty() {
        println!("No cases found.");
        return Ok(());
    }

    println!("{}", format!("CASES ({})", cases.len()).bold());
    for cf in &cases {
        // Extract just the date portion from the updated timestamp
        let updated_date = if cf.case.updated.len() >= 10 {
            &cf.case.updated[..10]
        } else {
            &cf.case.updated
        };

        println!(
            "  {:<30} {:<10} {} files    updated {}",
            cf.case.name.bold(),
            cf.case.status,
            cf.files.len(),
            updated_date
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitise_case_name() {
        // Spaces become hyphens
        assert_eq!(
            sanitise_case_name("Operation Nightfall").unwrap(),
            "operation-nightfall"
        );

        // Special characters become hyphens and collapse
        assert_eq!(
            sanitise_case_name("my!!!case---name").unwrap(),
            "my-case-name"
        );

        // Leading/trailing special chars are trimmed
        assert_eq!(sanitise_case_name("--hello--").unwrap(), "hello");

        // Too short after sanitisation
        assert!(sanitise_case_name("!").is_err());
        assert!(sanitise_case_name("a").is_err());
        assert!(sanitise_case_name("---").is_err());
        assert!(sanitise_case_name("").is_err());
    }

    #[test]
    fn test_case_name_with_spaces() {
        let result = sanitise_case_name("operation nightfall").unwrap();
        assert_eq!(result, "operation-nightfall");
    }
}
