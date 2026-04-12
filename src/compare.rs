// Anya - Malware Analysis Platform
// Compare module: side-by-side diff of two file analyses
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use std::path::Path;

use anya_security_core::{analyse_file, compute_verdict, confidence, config, to_json_output};
use colored::*;

/// Analyse two files and print a side-by-side comparison of their verdicts,
/// risk scores, imports, sections, strings and security features.
pub fn compare_files(path1: &Path, path2: &Path, min_string_length: usize) -> anyhow::Result<()> {
    let result1 = analyse_file(path1, min_string_length, config::AnalysisDepth::Standard)?;
    let result2 = analyse_file(path2, min_string_length, config::AnalysisDepth::Standard)?;
    let json1 = to_json_output(&result1);
    let json2 = to_json_output(&result2);

    let (verdict1, summary1) = compute_verdict(&json1);
    let (verdict2, summary2) = compute_verdict(&json2);

    // Header
    println!("{}", "=== Anya File Comparison ===".bold().cyan());
    println!("  A: {}", path1.display());
    println!("  B: {}", path2.display());
    println!();

    // Verdicts
    println!("{}", "--- Verdicts ---".bold());
    println!("  A: {}", colour_verdict(&verdict1, &summary1));
    println!("  B: {}", colour_verdict(&verdict2, &summary2));
    println!();

    // Risk scores (top detections count)
    let top_a = confidence::top_detections(&json1, 10);
    let top_b = confidence::top_detections(&json2, 10);
    println!("{}", "--- Top Findings ---".bold());
    println!("  A: {} findings", top_a.len());
    for d in &top_a {
        println!("     [{:?}] {}", d.confidence, d.description);
    }
    println!("  B: {} findings", top_b.len());
    for d in &top_b {
        println!("     [{:?}] {}", d.confidence, d.description);
    }
    println!();

    // File info
    println!("{}", "--- File Info ---".bold());
    println!(
        "  A: {} bytes, format: {}",
        json1.file_info.size_bytes, json1.file_format
    );
    println!(
        "  B: {} bytes, format: {}",
        json2.file_info.size_bytes, json2.file_format
    );
    println!();

    // Hashes
    println!("{}", "--- Hashes ---".bold());
    println!("  SHA256-A: {}", json1.hashes.sha256);
    println!("  SHA256-B: {}", json2.hashes.sha256);
    if json1.hashes.sha256 == json2.hashes.sha256 {
        println!("  {}", "Identical file content".green().bold());
    } else {
        println!("  {}", "Different file content".yellow());
    }
    if let (Some(t1), Some(t2)) = (&json1.hashes.tlsh, &json2.hashes.tlsh) {
        println!("  TLSH-A: {}", t1);
        println!("  TLSH-B: {}", t2);
    }
    println!();

    // Entropy comparison
    println!("{}", "--- Entropy ---".bold());
    println!("  A: {:.4} / 8.0", json1.entropy.value);
    println!("  B: {:.4} / 8.0", json2.entropy.value);
    let diff = (json1.entropy.value - json2.entropy.value).abs();
    if diff > 1.0 {
        println!(
            "  {} Entropy difference of {:.4}",
            "!".yellow().bold(),
            diff
        );
    }
    println!();

    // Strings count
    println!("{}", "--- Strings ---".bold());
    println!("  A: {} strings extracted", json1.strings.total_count);
    println!("  B: {} strings extracted", json2.strings.total_count);
    println!();

    // PE sections comparison (if both are PE)
    if let (Some(pe_a), Some(pe_b)) = (&json1.pe_analysis, &json2.pe_analysis) {
        println!("{}", "--- PE Sections ---".bold());
        let names_a: Vec<&str> = pe_a.sections.iter().map(|s| s.name.as_str()).collect();
        let names_b: Vec<&str> = pe_b.sections.iter().map(|s| s.name.as_str()).collect();
        for name in &names_a {
            if !names_b.contains(name) {
                println!("  {} section {} (only in A)", "-".red(), name);
            }
        }
        for name in &names_b {
            if !names_a.contains(name) {
                println!("  {} section {} (only in B)", "+".green(), name);
            }
        }
        for name in &names_a {
            if names_b.contains(name) {
                println!("  {} section {} (in both)", "=".white().dimmed(), name);
            }
        }

        // Imports comparison
        println!();
        println!("{}", "--- Suspicious Imports ---".bold());
        let imps_a: Vec<&str> = pe_a
            .imports
            .suspicious_apis
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        let imps_b: Vec<&str> = pe_b
            .imports
            .suspicious_apis
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        for api in &imps_a {
            if !imps_b.contains(api) {
                println!("  {} {} (only in A)", "-".red(), api);
            }
        }
        for api in &imps_b {
            if !imps_a.contains(api) {
                println!("  {} {} (only in B)", "+".green(), api);
            }
        }
        let common: Vec<&&str> = imps_a.iter().filter(|a| imps_b.contains(a)).collect();
        if !common.is_empty() {
            println!(
                "  {} {} shared suspicious imports",
                "=".white().dimmed(),
                common.len()
            );
        }
        println!();
    }

    // Security features (PE)
    if let (Some(pe_a), Some(pe_b)) = (&json1.pe_analysis, &json2.pe_analysis) {
        println!("{}", "--- Security Features ---".bold());
        println!(
            "  A: ASLR={}, DEP={}",
            pe_a.security.aslr_enabled, pe_a.security.dep_enabled
        );
        println!(
            "  B: ASLR={}, DEP={}",
            pe_b.security.aslr_enabled, pe_b.security.dep_enabled
        );
        println!();
    }

    Ok(())
}

fn colour_verdict(word: &str, summary: &str) -> String {
    match word {
        "MALICIOUS" => format!("{}", format!("{} -- {}", word, summary).red().bold()),
        "SUSPICIOUS" => format!("{}", format!("{} -- {}", word, summary).yellow().bold()),
        "CLEAN" => format!("{}", format!("{} -- {}", word, summary).green().bold()),
        _ => format!("{} -- {}", word, summary),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_colour_verdict_malicious() {
        let result = colour_verdict("MALICIOUS", "4 critical");
        assert!(result.contains("MALICIOUS"));
        assert!(result.contains("4 critical"));
    }

    #[test]
    fn test_colour_verdict_clean() {
        let result = colour_verdict("CLEAN", "no findings");
        assert!(result.contains("CLEAN"));
    }

    #[test]
    fn test_colour_verdict_unknown() {
        let result = colour_verdict("UNKNOWN", "unrecognised");
        assert!(result.contains("UNKNOWN"));
        assert!(result.contains("unrecognised"));
    }

    #[test]
    fn test_compare_identical_files() {
        // Use the test fixture shipped with the repo
        let fixture = Path::new("tests/fixtures/simple.exe");
        if !fixture.exists() {
            // Skip if fixture not available (e.g. in CI without test assets)
            return;
        }
        let result = compare_files(fixture, fixture, 4);
        assert!(result.is_ok());
    }
}
