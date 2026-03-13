// Ányá - Malware Analysis Platform
// Library interface - All testable business logic
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use anyhow::{Context, Result};
use goblin::Object;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// Re-export modules
pub mod config;
pub mod elf_parser;
pub mod output;
pub mod pe_parser;

// Output verbosity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputLevel {
    Quiet,
    Normal,
    Verbose,
}

impl OutputLevel {
    pub fn from_args(verbose: bool, quiet: bool) -> Self {
        if quiet {
            OutputLevel::Quiet
        } else if verbose {
            OutputLevel::Verbose
        } else {
            OutputLevel::Normal
        }
    }

    pub fn should_print_info(&self) -> bool {
        matches!(self, OutputLevel::Normal | OutputLevel::Verbose)
    }

    pub fn should_print_verbose(&self) -> bool {
        matches!(self, OutputLevel::Verbose)
    }
}

/// File analysis result - contains all analysis data
#[derive(Debug, Clone)]
pub struct FileAnalysisResult {
    pub path: PathBuf,
    pub size_bytes: usize,
    pub hashes: output::Hashes,
    pub entropy: output::EntropyInfo,
    pub strings: output::StringsInfo,
    pub file_format: String,
    pub pe_analysis: Option<output::PEAnalysis>,
    pub elf_analysis: Option<output::ELFAnalysis>,
}

/// Batch analysis summary
#[derive(Debug, Default, Clone)]
pub struct BatchSummary {
    pub total_files: usize,
    pub analysed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub suspicious: usize,
    pub duration: f64,
}

impl BatchSummary {
    pub fn success_rate(&self) -> f64 {
        if self.total_files == 0 {
            0.0
        } else {
            (self.analysed as f64 / self.total_files as f64) * 100.0
        }
    }

    pub fn print_summary(&self) {
        use colored::Colorize;

        println!("\n{}", "═══ Batch Analysis Summary ═══".cyan().bold());
        println!("Total files:     {}", self.total_files);
        println!("Analysed:        {} {}", self.analysed, "✓".green());
        println!(
            "Failed:          {} {}",
            self.failed,
            if self.failed > 0 {
                "✗".red()
            } else {
                "".normal()
            }
        );
        println!("Skipped:         {}", self.skipped);
        println!(
            "Suspicious:      {} {}",
            self.suspicious,
            if self.suspicious > 0 {
                "⚠".yellow()
            } else {
                "".normal()
            }
        );
        println!("Duration:        {:.2}s", self.duration);
        println!("Success rate:    {:.1}%", self.success_rate());
        println!("Analysis rate:   {:.1} files/sec", self.analysis_rate());
    }

    pub fn analysis_rate(&self) -> f64 {
        if self.duration == 0.0 {
            0.0
        } else {
            self.analysed as f64 / self.duration
        }
    }
}

/// Calculate cryptographic hashes for data
pub fn calculate_hashes(data: &[u8]) -> output::Hashes {
    let md5 = Md5::digest(data);
    let sha1 = Sha1::digest(data);
    let sha256 = Sha256::digest(data);

    output::Hashes {
        md5: format!("{:x}", md5),
        sha1: format!("{:x}", sha1),
        sha256: format!("{:x}", sha256),
    }
}

/// Calculate Shannon entropy
pub fn calculate_file_entropy(data: &[u8]) -> output::EntropyInfo {
    let mut frequencies = [0u32; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let entropy: f64 = frequencies
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum();

    let (category, is_suspicious) = categorize_entropy(entropy);

    output::EntropyInfo {
        value: entropy,
        category: category.to_string(),
        is_suspicious,
    }
}

/// Categorize entropy value
pub fn categorize_entropy(entropy: f64) -> (&'static str, bool) {
    if entropy > 7.5 {
        ("Very High", true)
    } else if entropy > 7.0 {
        ("High", true)
    } else if entropy > 6.0 {
        ("Moderate-High", false)
    } else if entropy > 4.0 {
        ("Moderate", false)
    } else {
        ("Low", false)
    }
}

/// Extract printable ASCII strings
pub fn extract_strings_data(data: &[u8], min_length: usize) -> output::StringsInfo {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else if current.len() >= min_length {
            strings.push(String::from_utf8_lossy(&current).to_string());
            current.clear();
        } else {
            current.clear();
        }
    }

    if current.len() >= min_length {
        strings.push(String::from_utf8_lossy(&current).to_string());
    }

    let total_count = strings.len();
    let sample_count = 10.min(total_count);
    let samples: Vec<String> = strings.iter().take(sample_count).cloned().collect();

    output::StringsInfo {
        min_length,
        total_count,
        samples,
        sample_count,
    }
}

/// Check if file is executable based on extension
pub fn is_executable_file(path: &Path) -> bool {
    let extension = match path.extension() {
        Some(ext) => ext.to_string_lossy().to_lowercase(),
        None => return false,
    };

    matches!(
        extension.as_str(),
        "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | // Windows
        "elf" | "so" | "bin" |                          // Linux
        "dylib" | "bundle" | "app" // macOS
    )
}

/// Analyze a single file and return structured result
pub fn analyse_file(path: &Path, min_string_length: usize) -> Result<FileAnalysisResult> {
    // Read file
    let data = fs::read(path).context("Failed to read file")?;
    let size_bytes = data.len();

    // Calculate hashes
    let hashes = calculate_hashes(&data);

    // Calculate entropy
    let entropy = calculate_file_entropy(&data);

    // Extract strings
    let strings = extract_strings_data(&data, min_string_length);

    // Determine file format and analyse
    let (file_format, pe_analysis, elf_analysis) = match Object::parse(&data) {
        Ok(Object::PE(_)) => {
            let pe_data = pe_parser::analyse_pe_data(&data)?;
            ("Windows PE".to_string(), Some(pe_data), None)
        }
        Ok(Object::Elf(_)) => {
            let elf_data = elf_parser::analyse_elf_data(&data)?;
            ("Linux ELF".to_string(), None, Some(elf_data))
        }
        Ok(Object::Mach(_)) => ("macOS Mach-O".to_string(), None, None),
        Ok(_) => ("Unknown".to_string(), None, None),
        Err(_) => ("Unrecognized".to_string(), None, None),
    };

    Ok(FileAnalysisResult {
        path: path.to_path_buf(),
        size_bytes,
        hashes,
        entropy,
        strings,
        file_format,
        pe_analysis,
        elf_analysis,
    })
}

/// Find all executable files in a directory
pub fn find_executable_files(dir_path: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    if !dir_path.exists() {
        anyhow::bail!("Directory does not exist: {:?}", dir_path);
    }

    if !dir_path.is_dir() {
        anyhow::bail!("Path is not a directory: {:?}", dir_path);
    }

    let walker = if recursive {
        WalkDir::new(dir_path)
    } else {
        WalkDir::new(dir_path).max_depth(1)
    };

    let files: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .filter(|path| is_executable_file(path))
        .collect();

    Ok(files)
}

/// Check if a file is suspicious based on analysis
pub fn is_suspicious_file(result: &FileAnalysisResult) -> bool {
    // High entropy
    if result.entropy.is_suspicious {
        return true;
    }

    if let Some(ref pe) = result.pe_analysis {
        // Many suspicious APIs
        if pe.imports.suspicious_api_count > 5 {
            return true;
        }
        // W+X sections
        if pe.sections.iter().any(|s| s.is_wx) {
            return true;
        }
        // TLS callbacks present
        if pe.tls.as_ref().map_or(false, |t| t.callback_count > 0) {
            return true;
        }
        // High-entropy overlay
        if pe.overlay.as_ref().map_or(false, |o| o.high_entropy) {
            return true;
        }
        // Multiple anti-analysis categories
        if pe.anti_analysis.len() >= 2 {
            return true;
        }
        // Packer detected with high confidence
        if pe.packers.iter().any(|p| p.confidence == "High") {
            return true;
        }
        // Ordinal imports from sensitive DLLs
        if pe
            .ordinal_imports
            .iter()
            .any(|o| o.dll.eq_ignore_ascii_case("ntdll.dll") || o.dll.eq_ignore_ascii_case("kernel32.dll"))
        {
            return true;
        }
    }

    if let Some(ref elf) = result.elf_analysis {
        // W+X ELF sections
        if elf.sections.iter().any(|s| s.is_wx) {
            return true;
        }
        // Packer detected
        if !elf.packer_indicators.is_empty() {
            return true;
        }
        // Suspicious function imports
        if !elf.imports.suspicious_functions.is_empty() {
            return true;
        }
    }

    false
}

/// Convert FileAnalysisResult to JSON output format
pub fn to_json_output(result: &FileAnalysisResult) -> output::AnalysisResult {
    output::AnalysisResult {
        file_info: output::FileInfo {
            path: result.path.to_string_lossy().to_string(),
            size_bytes: result.size_bytes as u64,
            size_kb: result.size_bytes as f64 / 1024.0,
            extension: result
                .path
                .extension()
                .map(|e| e.to_string_lossy().to_string()),
        },
        hashes: result.hashes.clone(),
        entropy: result.entropy.clone(),
        strings: result.strings.clone(),
        pe_analysis: result.pe_analysis.clone(),
        elf_analysis: result.elf_analysis.clone(),
        file_format: result.file_format.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_output_level_from_args() {
        assert_eq!(OutputLevel::from_args(false, false), OutputLevel::Normal);
        assert_eq!(OutputLevel::from_args(true, false), OutputLevel::Verbose);
        assert_eq!(OutputLevel::from_args(false, true), OutputLevel::Quiet);
    }

    #[test]
    fn test_output_level_should_print() {
        assert!(OutputLevel::Normal.should_print_info());
        assert!(OutputLevel::Verbose.should_print_info());
        assert!(!OutputLevel::Quiet.should_print_info());

        assert!(OutputLevel::Verbose.should_print_verbose());
        assert!(!OutputLevel::Normal.should_print_verbose());
        assert!(!OutputLevel::Quiet.should_print_verbose());
    }

    #[test]
    fn test_calculate_hashes() {
        let data = b"Hello, World!";
        let hashes = calculate_hashes(data);

        assert_eq!(hashes.md5.len(), 32);
        assert_eq!(hashes.sha1.len(), 40);
        assert_eq!(hashes.sha256.len(), 64);
        assert_eq!(hashes.md5, "65a8e27d8879283831b664bd8b7f0ad4");
    }

    #[test]
    fn test_calculate_entropy_zero() {
        let data = vec![0u8; 100];
        let entropy = calculate_file_entropy(&data);

        assert_eq!(entropy.value, 0.0);
        assert_eq!(entropy.category, "Low");
        assert!(!entropy.is_suspicious);
    }

    #[test]
    fn test_calculate_entropy_high() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = calculate_file_entropy(&data);

        assert!(entropy.value > 7.5);
        assert_eq!(entropy.category, "Very High");
        assert!(entropy.is_suspicious);
    }

    #[test]
    fn test_categorize_entropy() {
        assert_eq!(categorize_entropy(0.0), ("Low", false));
        assert_eq!(categorize_entropy(3.5), ("Low", false));
        assert_eq!(categorize_entropy(5.0), ("Moderate", false));
        assert_eq!(categorize_entropy(6.5), ("Moderate-High", false));
        assert_eq!(categorize_entropy(7.2), ("High", true));
        assert_eq!(categorize_entropy(7.8), ("Very High", true));
    }

    #[test]
    fn test_extract_strings_basic() {
        let data = b"Hello World\x00\x00Test String";
        let strings = extract_strings_data(data, 4);

        assert_eq!(strings.min_length, 4);
        assert_eq!(strings.total_count, 2);
        assert!(strings.samples.contains(&"Hello World".to_string()));
        assert!(strings.samples.contains(&"Test String".to_string()));
    }

    #[test]
    fn test_extract_strings_min_length() {
        let data = b"Hi\x00\x00Hello\x00\x00Greetings";
        let strings = extract_strings_data(data, 5);

        assert_eq!(strings.total_count, 2);
        assert!(strings.samples.contains(&"Hello".to_string()));
        assert!(strings.samples.contains(&"Greetings".to_string()));
    }

    #[test]
    fn test_extract_strings_sample_limit() {
        let mut data = Vec::new();
        for i in 0..20 {
            data.extend_from_slice(format!("String{}", i).as_bytes());
            data.push(0x00);
        }

        let strings = extract_strings_data(&data, 4);
        assert_eq!(strings.total_count, 20);
        assert_eq!(strings.sample_count, 10);
        assert_eq!(strings.samples.len(), 10);
    }

    #[test]
    fn test_is_executable_file() {
        assert!(is_executable_file(&PathBuf::from("test.exe")));
        assert!(is_executable_file(&PathBuf::from("library.dll")));
        assert!(is_executable_file(&PathBuf::from("driver.sys")));
        assert!(is_executable_file(&PathBuf::from("program.elf")));
        assert!(is_executable_file(&PathBuf::from("library.so")));
        assert!(is_executable_file(&PathBuf::from("lib.dylib")));

        assert!(!is_executable_file(&PathBuf::from("document.txt")));
        assert!(!is_executable_file(&PathBuf::from("image.png")));
        assert!(!is_executable_file(&PathBuf::from("data.json")));
        assert!(!is_executable_file(&PathBuf::from("noextension")));
    }

    #[test]
    fn test_is_executable_case_insensitive() {
        assert!(is_executable_file(&PathBuf::from("TEST.EXE")));
        assert!(is_executable_file(&PathBuf::from("Library.DLL")));
        assert!(is_executable_file(&PathBuf::from("PROGRAM.ELF")));
    }

    #[test]
    fn test_analyse_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Test file content").unwrap();

        let result = analyse_file(temp_file.path(), 4).unwrap();

        assert_eq!(result.size_bytes, 17);
        assert_eq!(result.hashes.md5.len(), 32);
        assert!(result.strings.total_count > 0);
    }

    #[test]
    fn test_find_executable_files() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        fs::write(temp_dir.path().join("test.exe"), b"exe").unwrap();
        fs::write(temp_dir.path().join("test.dll"), b"dll").unwrap();
        fs::write(temp_dir.path().join("test.txt"), b"txt").unwrap();

        let files = find_executable_files(temp_dir.path(), false).unwrap();
        assert_eq!(files.len(), 2); // Only .exe and .dll
    }

    #[test]
    fn test_find_executable_files_recursive() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        fs::write(temp_dir.path().join("root.exe"), b"root").unwrap();
        fs::write(subdir.join("nested.exe"), b"nested").unwrap();

        // Non-recursive: should find 1
        let files = find_executable_files(temp_dir.path(), false).unwrap();
        assert_eq!(files.len(), 1);

        // Recursive: should find 2
        let files = find_executable_files(temp_dir.path(), true).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_batch_summary() {
        let mut summary = BatchSummary::default();
        summary.total_files = 10;
        summary.analysed = 8;
        summary.failed = 2;
        summary.duration = 4.0;

        assert_eq!(summary.success_rate(), 80.0);
        assert_eq!(summary.analysis_rate(), 2.0); // 8 files / 4 seconds
    }

    #[test]
    fn test_is_suspicious_file_high_entropy() {
        let result = FileAnalysisResult {
            path: PathBuf::from("test.exe"),
            size_bytes: 1000,
            hashes: calculate_hashes(b"test"),
            entropy: output::EntropyInfo {
                value: 7.8,
                category: "Very High".to_string(),
                is_suspicious: true,
            },
            strings: extract_strings_data(b"test", 4),
            file_format: "PE".to_string(),
            pe_analysis: None,
            elf_analysis: None,
        };

        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_to_json_output() {
        let result = FileAnalysisResult {
            path: PathBuf::from("test.exe"),
            size_bytes: 1024,
            hashes: calculate_hashes(b"test"),
            entropy: calculate_file_entropy(b"test"),
            strings: extract_strings_data(b"test", 4),
            file_format: "PE".to_string(),
            pe_analysis: None,
            elf_analysis: None,
        };

        let json = to_json_output(&result);
        assert_eq!(json.file_info.size_bytes, 1024);
        assert_eq!(json.file_format, "PE");
    }
}
