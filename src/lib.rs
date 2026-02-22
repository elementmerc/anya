// Ányá - Malware Analysis Platform
// Library interface for testing and integration
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::path::Path;

// Re-export modules for testing
pub mod config;
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

/// Calculate cryptographic hashes for a file
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

/// Calculate Shannon entropy for a file
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

    let (category, is_suspicious) = if entropy > 7.5 {
        ("Very High", true)
    } else if entropy > 7.0 {
        ("High", true)
    } else if entropy > 6.0 {
        ("Moderate-High", false)
    } else if entropy > 4.0 {
        ("Moderate", false)
    } else {
        ("Low", false)
    };

    output::EntropyInfo {
        value: entropy,
        category: category.to_string(),
        is_suspicious,
    }
}

/// Extract printable ASCII strings from data
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

/// Check if a file is an executable based on extension
pub fn is_executable_file(path: &Path) -> bool {
    let extension = match path.extension() {
        Some(ext) => ext.to_string_lossy().to_lowercase(),
        None => return false,
    };

    matches!(
        extension.as_str(),
        "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | // Windows
        "elf" | "so" | "bin" |                          // Linux
        "dylib" | "bundle" | "app"                      // macOS
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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

        assert_eq!(hashes.md5.len(), 32); // MD5 is 32 hex chars
        assert_eq!(hashes.sha1.len(), 40); // SHA1 is 40 hex chars
        assert_eq!(hashes.sha256.len(), 64); // SHA256 is 64 hex chars

        // Verify specific hash for known data
        assert_eq!(hashes.md5, "65a8e27d8879283831b664bd8b7f0ad4");
    }

    #[test]
    fn test_calculate_entropy_zero() {
        let data = vec![0u8; 100]; // All zeros
        let entropy = calculate_file_entropy(&data);

        assert_eq!(entropy.value, 0.0);
        assert_eq!(entropy.category, "Low");
        assert!(!entropy.is_suspicious);
    }

    #[test]
    fn test_calculate_entropy_high() {
        // Random-looking data (high entropy)
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = calculate_file_entropy(&data);

        assert!(entropy.value > 7.5);
        assert_eq!(entropy.category, "Very High");
        assert!(entropy.is_suspicious);
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

        // "Hi" (2 chars) should be filtered, "Hello" and "Greetings" kept
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
        assert_eq!(strings.sample_count, 10); // Limited to 10
        assert_eq!(strings.samples.len(), 10);
    }

    #[test]
    fn test_is_executable_file() {
        use std::path::PathBuf;

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
        use std::path::PathBuf;

        assert!(is_executable_file(&PathBuf::from("TEST.EXE")));
        assert!(is_executable_file(&PathBuf::from("Library.DLL")));
        assert!(is_executable_file(&PathBuf::from("PROGRAM.ELF")));
    }
}