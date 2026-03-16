// Anya - Malware Analysis Platform
// YARA rule utilities: combine and from-strings
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use anyhow::{bail, Context, Result};
use chrono::Utc;
use colored::Colorize;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;
use walkdir::WalkDir;

/// Regex to extract YARA rule names from source text.
static RULE_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*rule\s+(\w+)").expect("rule name regex")
});

// ---------------------------------------------------------------------------
// combine
// ---------------------------------------------------------------------------

/// Walk `input_dir`, collect all `.yar` / `.yara` files, concatenate them into
/// a single `output_file`, and print a summary.
pub fn combine(input_dir: &Path, output_file: &Path, recursive: bool) -> Result<()> {
    let max_depth = if recursive { usize::MAX } else { 1 };

    let yara_files: Vec<_> = WalkDir::new(input_dir)
        .max_depth(max_depth)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let name = e.file_name().to_string_lossy();
            name.ends_with(".yar") || name.ends_with(".yara")
        })
        .collect();

    if yara_files.is_empty() {
        bail!(
            "No .yar or .yara files found in '{}'",
            input_dir.display()
        );
    }

    let now = Utc::now();
    let mut seen_rules: HashSet<String> = HashSet::new();
    let mut total_rules: usize = 0;
    let mut duplicates: usize = 0;
    let mut combined = String::new();

    // Header
    combined.push_str(&format!(
        "// Combined by Anya on {}\n",
        now.format("%Y-%m-%dT%H:%M:%SZ")
    ));
    combined.push_str(&format!(
        "// Source directory: {}\n",
        input_dir.display()
    ));
    combined.push_str(&format!(
        "// Files: {}\n\n",
        yara_files.len()
    ));

    for entry in &yara_files {
        let contents = fs::read_to_string(entry.path())
            .with_context(|| format!("Failed to read {}", entry.path().display()))?;

        // Extract rule names for counting
        for cap in RULE_NAME_RE.captures_iter(&contents) {
            let name = cap[1].to_string();
            total_rules += 1;
            if !seen_rules.insert(name) {
                duplicates += 1;
            }
        }

        combined.push_str(&contents);
        if !contents.ends_with('\n') {
            combined.push('\n');
        }
        combined.push('\n');
    }

    fs::write(output_file, &combined)
        .with_context(|| format!("Failed to write {}", output_file.display()))?;

    let size_kb = combined.len() / 1024;
    let dir_display = input_dir.display();
    let out_display = output_file.display();

    println!();
    println!("{}", "YARA COMBINE".bold().cyan());
    println!(
        "  {}   {} ({} files)",
        "Source:".bold(),
        dir_display,
        yara_files.len()
    );
    println!("  {}   {}", "Output:".bold(), out_display);
    println!(
        "  {}    {} total, {} duplicates found",
        "Rules:".bold(),
        total_rules,
        duplicates
    );
    println!(
        "  {}  {} ({} KB)",
        "Written:".bold(),
        out_display,
        size_kb
    );
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// from-strings
// ---------------------------------------------------------------------------

/// Sanitise a user-supplied rule name so it is a valid YARA identifier.
fn sanitise_rule_name(name: &str) -> String {
    let sanitised: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect();

    // Ensure starts with letter or underscore
    if sanitised
        .chars()
        .next()
        .is_none_or(|c| c.is_ascii_digit())
    {
        format!("_{sanitised}")
    } else {
        sanitised
    }
}

/// Returns `true` if every byte in `s` is ASCII printable (0x20..=0x7E).
fn is_ascii_printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// Read a strings file and generate a YARA rule.
///
/// * `strings_file` - path to a text file, one string per line.
/// * `output`       - if `Some`, write the rule to this path; otherwise print to stdout.
/// * `name`         - custom rule name (sanitised automatically).
/// * `overwrite`    - allow overwriting an existing output file.
pub fn from_strings(
    strings_file: &Path,
    output: Option<&Path>,
    name: Option<&str>,
    overwrite: bool,
) -> Result<()> {
    let raw = fs::read_to_string(strings_file)
        .with_context(|| format!("Failed to read {}", strings_file.display()))?;

    let strings: Vec<&str> = raw
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .take(100)
        .collect();

    if strings.is_empty() {
        bail!(
            "No strings found in '{}'",
            strings_file.display()
        );
    }

    let total_available = raw
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count();

    let truncated = total_available > 100;

    let rule_name = match name {
        Some(n) => sanitise_rule_name(n),
        None => format!("anya_generated_{}", Utc::now().format("%Y%m%d")),
    };

    let today = Utc::now().format("%Y-%m-%d").to_string();
    let source_name = strings_file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| strings_file.display().to_string());

    // Build rule text
    let mut rule = String::new();

    // Header comment
    rule.push_str(&format!(
        "/*\n    Rule generated by Anya\n    Date: {today}\n    Source: {source_name} ({} strings)\n*/\n",
        strings.len()
    ));
    rule.push_str("// \u{26A0} Auto-generated. Review all strings and condition before use.\n\n");

    rule.push_str(&format!("rule {rule_name} {{\n"));

    // meta
    rule.push_str("    meta:\n");
    rule.push_str("        description = \"Auto-generated rule \u{2014} review and edit before use\"\n");
    rule.push_str("        author      = \"Anya\"\n");
    rule.push_str(&format!("        date        = \"{today}\"\n"));
    rule.push_str("        confidence  = \"low\"\n");
    if truncated {
        rule.push_str(&format!(
            "        truncation  = \"Input contained {} strings; capped at 100\"\n",
            total_available
        ));
    }

    // strings
    rule.push_str("\n    strings:\n");
    for (i, s) in strings.iter().enumerate() {
        if is_ascii_printable(s) {
            let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
            rule.push_str(&format!("        $s{i} = \"{escaped}\"\n"));
        } else {
            // Hex string
            let hex: Vec<String> = s.bytes().map(|b| format!("{b:02X}")).collect();
            rule.push_str(&format!("        $s{i} = {{ {} }}\n", hex.join(" ")));
        }
    }

    // condition
    rule.push_str("\n    condition:\n");
    rule.push_str("        any of them\n");
    rule.push_str("}\n");

    // Output
    match output {
        Some(path) => {
            if path.exists() && !overwrite {
                bail!(
                    "'{}' already exists. Use --overwrite to replace it.",
                    path.display()
                );
            }
            fs::write(path, &rule)
                .with_context(|| format!("Failed to write {}", path.display()))?;
            println!("{} {}", "Written:".bold().green(), path.display());
        }
        None => {
            print!("{rule}");
        }
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
    fn test_sanitise_rule_name() {
        // Basic pass-through
        assert_eq!(sanitise_rule_name("my_rule"), "my_rule");
        // Spaces and dashes replaced
        assert_eq!(sanitise_rule_name("my-rule name"), "my_rule_name");
        // Leading digit gets underscore prefix
        assert_eq!(sanitise_rule_name("123abc"), "_123abc");
        // Already starts with underscore
        assert_eq!(sanitise_rule_name("_ok"), "_ok");
        // Empty string
        assert_eq!(sanitise_rule_name(""), "_");
        // Special characters
        assert_eq!(sanitise_rule_name("r@t!ng"), "r_t_ng");
    }

    #[test]
    fn test_from_strings_basic() {
        let dir = tempfile::tempdir().unwrap();
        let strings_path = dir.path().join("strings.txt");
        fs::write(
            &strings_path,
            "# comment\nCreateRemoteThread\nVirtualAlloc\n\nWriteProcessMemory\n",
        )
        .unwrap();

        let output_path = dir.path().join("rule.yar");
        from_strings(&strings_path, Some(&output_path), Some("test_rule"), false)
            .expect("from_strings should succeed");

        let content = fs::read_to_string(&output_path).unwrap();

        // Verify rule skeleton
        assert!(content.contains("rule test_rule {"));
        assert!(content.contains("$s0 = \"CreateRemoteThread\""));
        assert!(content.contains("$s1 = \"VirtualAlloc\""));
        assert!(content.contains("$s2 = \"WriteProcessMemory\""));
        assert!(content.contains("any of them"));
        assert!(content.contains("Rule generated by Anya"));
        assert!(content.contains("author      = \"Anya\""));
        assert!(content.contains("confidence  = \"low\""));
    }
}
