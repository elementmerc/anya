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

// PE analysis module (for handling executables)

use crate::OutputLevel;
use crate::output;
use anyhow::Result;
use colored::*;
use goblin::pe::PE;
use indicatif::{ProgressBar, ProgressStyle};

/// Suspicious Windows APIs commonly used by malware
/// They aren't necessarily malicious, but warrant attention
const SUSPICIOUS_APIS: &[&str] = &[
    // Process manipulation
    "CreateRemoteThread",
    "WriteProcessMemory",
    "VirtualAllocEx",
    "SetWindowsHookEx",
    "OpenProcess",
    // Code injection
    "NtQueueApcThread",
    "RtlCreateUserThread",
    "QueueUserAPC",
    // Persistence
    "RegSetValueEx",
    "RegCreateKeyEx",
    "CreateService",
    "StartService",
    // Anti-analysis
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugString",
    "NtQueryInformationProcess",
    // Network
    "InternetOpen",
    "InternetOpenUrl",
    "URLDownloadToFile",
    "WinHttpOpen",
    "WSAStartup",
    "socket",
    "connect",
    // Crypto (used for C2 communication)
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptAcquireContext",
    // Keylogging
    "GetAsyncKeyState",
    "SetWindowsHookExA",
    "GetForegroundWindow",
    // File operations
    "CreateFile",
    "DeleteFile",
    "MoveFile",
    "CopyFile",
    // Privilege escalation
    "AdjustTokenPrivileges",
    "OpenProcessToken",
];

/// Analyses a Windows PE (Portable Executable) file and displays detailed information
///
/// This function performs comprehensive static analysis of PE files including:
/// - Header information (architecture, entry point, image base)
/// - Security features (ASLR, DEP/NX)
/// - Section analysis with per-section entropy calculation
/// - Import table analysis with suspicious API detection
/// - Export table analysis (for DLLs)
///
/// # Arguments
///
/// * `data` - Raw bytes of the PE file
/// * `output_level` - Controls verbosity of output
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if parsing fails
///
/// # Examples
///
/// ```no_run
/// use anya::pe_parser;
/// use anya::OutputLevel;
/// use std::fs;
///
/// let data = fs::read("malware.exe")?;
/// pe_parser::analyse_pe(&data, OutputLevel::Normal)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn analyse_pe(data: &[u8], output_level: OutputLevel) -> Result<()> {
    // Show spinner for large files (1MB threshold to match main.rs)
    let is_large = data.len() > 1024 * 1024; // 1MB
    let pb = if is_large && output_level.should_print_info() {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        spinner.set_message("Parsing PE structure...");
        spinner.enable_steady_tick(std::time::Duration::from_millis(80));
        Some(spinner)
    } else {
        None
    };

    let pe = PE::parse(data)?;

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    // In quiet mode, just check for critical issues
    if output_level == OutputLevel::Quiet {
        return analyse_pe_quiet(&pe, data);
    }

    println!("{}", "=== PE File Analysis ===".bold().cyan());

    // Basic PE info
    print_pe_header_info(&pe, output_level);

    // Analyse sections
    print_sections(&pe, data, output_level);

    // Analyse imports
    print_imports(&pe, output_level);

    // Analyse exports
    print_exports(&pe, output_level);

    Ok(())
}

/// Analyses a PE file and returns structured data for JSON output
///
/// # Arguments
///
/// * `data` - Raw bytes of the PE file
///
/// # Returns
///
/// Returns structured PEAnalysis data or an error
pub fn analyse_pe_data(data: &[u8]) -> Result<output::PEAnalysis> {
    let pe = PE::parse(data)?;

    // Architecture
    let architecture = if pe.is_64 {
        "PE32+ (64-bit)".to_string()
    } else {
        "PE32 (32-bit)".to_string()
    };

    // Image base and entry point
    let image_base = format!("0x{:X}", pe.image_base);
    let entry_point = format!("0x{:X}", pe.entry);

    // File type
    let is_dll = pe.header.coff_header.characteristics & 0x2000 != 0;
    let file_type = if is_dll {
        "DLL".to_string()
    } else {
        "EXE".to_string()
    };

    // Security features
    let security = if let Some(header) = &pe.header.optional_header {
        let characteristics = header.windows_fields.dll_characteristics;
        output::SecurityFeatures {
            aslr_enabled: characteristics & 0x40 != 0,
            dep_enabled: characteristics & 0x100 != 0,
        }
    } else {
        output::SecurityFeatures {
            aslr_enabled: false,
            dep_enabled: false,
        }
    };

    // Analyse sections
    let sections: Vec<output::SectionInfo> = pe
        .sections
        .iter()
        .map(|section| {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();

            let section_start = section.pointer_to_raw_data as usize;
            let section_size = section.size_of_raw_data as usize;

            let entropy = if section_start + section_size <= data.len() {
                calculate_entropy(&data[section_start..section_start + section_size])
            } else {
                0.0
            };

            let characteristics = section.characteristics;
            let writable = characteristics & 0x80000000 != 0;
            let executable = characteristics & 0x20000000 != 0;

            output::SectionInfo {
                name,
                virtual_size: section.virtual_size,
                virtual_address: format!("0x{:X}", section.virtual_address),
                raw_size: section.size_of_raw_data,
                entropy,
                is_suspicious: entropy > 7.5,
                is_wx: writable && executable,
            }
        })
        .collect();

    // Analyse imports
    let mut suspicious_apis = Vec::new();
    for import in &pe.imports {
        let name = import.name.as_ref();
        if SUSPICIOUS_APIS.contains(&name) {
            suspicious_apis.push(output::SuspiciousAPI {
                name: name.to_string(),
                category: categorize_api(name).to_string(),
            });
        }
    }

    let imports = output::ImportAnalysis {
        dll_count: pe.libraries.len(),
        total_imports: pe.imports.len(),
        suspicious_api_count: suspicious_apis.len(),
        suspicious_apis,
        libraries: pe.libraries.iter().map(|s| s.to_string()).collect(),
    };

    // Analyse exports
    let exports = if !pe.exports.is_empty() {
        let samples: Vec<output::ExportInfo> = pe
            .exports
            .iter()
            .take(20)
            .map(|export| {
                let name = export
                    .name
                    .as_ref()
                    .map(|s| s.as_ref())
                    .unwrap_or("<unnamed>")
                    .to_string();
                output::ExportInfo {
                    name,
                    rva: format!("0x{:08X}", export.rva),
                }
            })
            .collect();

        Some(output::ExportAnalysis {
            total_count: pe.exports.len(),
            samples,
        })
    } else {
        None
    };

    Ok(output::PEAnalysis {
        architecture,
        is_64bit: pe.is_64,
        image_base,
        entry_point,
        file_type,
        security,
        sections,
        imports,
        exports,
    })
}

/// Quick analysis for quiet mode - only report critical issues
fn analyse_pe_quiet(pe: &PE, _data: &[u8]) -> Result<()> {
    let mut warnings = Vec::new();

    // Check security features
    if let Some(header) = &pe.header.optional_header {
        let characteristics = header.windows_fields.dll_characteristics;
        if characteristics & 0x40 == 0 {
            warnings.push("ASLR disabled".to_string());
        }
        if characteristics & 0x100 == 0 {
            warnings.push("DEP/NX disabled".to_string());
        }
    }

    // Check for suspicious APIs
    let mut suspicious_count = 0;
    for import in &pe.imports {
        let name = import.name.as_ref();
        if SUSPICIOUS_APIS.contains(&name) {
            suspicious_count += 1;
        }
    }

    if suspicious_count > 5 {
        warnings.push(format!("{} suspicious APIs detected", suspicious_count));
    }

    // Print warnings if any
    if !warnings.is_empty() {
        println!("{}", "⚠ WARNINGS:".yellow().bold());
        for warning in warnings {
            println!("  • {}", warning.red());
        }
    }

    Ok(())
}

/// Display PE header information
fn print_pe_header_info(pe: &PE, output_level: OutputLevel) {
    println!("\n{}", "PE Header Information:".bold());

    // Check if 32-bit or 64-bit
    let arch = if pe.is_64 {
        "PE32+ (64-bit)"
    } else {
        "PE32 (32-bit)"
    };
    println!("  Architecture: {}", arch);

    // Image base (where the PE expects to be loaded in memory)
    println!("  Image Base: 0x{:X}", pe.image_base);

    // Entry point (where execution starts)
    println!("  Entry Point: 0x{:X}", pe.entry);

    // Number of sections
    println!("  Number of Sections: {}", pe.sections.len());

    // Verbose mode: show more details
    if output_level.should_print_verbose()
        && let Some(header) = &pe.header.optional_header
    {
        println!(
            "  Size of Image: 0x{:X}",
            header.windows_fields.size_of_image
        );
        println!(
            "  Size of Headers: 0x{:X}",
            header.windows_fields.size_of_headers
        );
    }

    // Check for some characteristics
    if let Some(header) = &pe.header.optional_header {
        let characteristics = header.windows_fields.dll_characteristics;

        println!("\n  Security Features:");

        // ASLR
        if characteristics & 0x40 != 0 {
            println!("    {} ASLR enabled", "✓".green());
        } else {
            println!("    {} ASLR disabled (suspicious)", "✗".red());
        }

        // DEP
        if characteristics & 0x100 != 0 {
            println!("    {} DEP/NX enabled", "✓".green());
        } else {
            println!("    {} DEP/NX disabled (suspicious)", "✗".red());
        }

        // To DLL or not to DLL? That is the question.
        let is_dll = pe.header.coff_header.characteristics & 0x2000 != 0;
        if is_dll {
            println!("  Type: DLL (Dynamic Link Library)");
        } else {
            println!("  Type: Executable");
        }
    }
}

/// Analyse and display section information
fn print_sections(pe: &PE, data: &[u8], _output_level: OutputLevel) {
    println!("\n{}", "Section Analysis:".bold());
    println!(
        "  {:<12} {:<10} {:<10} {:<10} {:<10}",
        "Name", "VirtSize", "VirtAddr", "RawSize", "Entropy"
    );
    println!("  {}", "-".repeat(62));

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        // Calculate entropy for this section
        let section_start = section.pointer_to_raw_data as usize;
        let section_size = section.size_of_raw_data as usize;

        let entropy = if section_start + section_size <= data.len() {
            calculate_entropy(&data[section_start..section_start + section_size])
        } else {
            0.0
        };

        // Color code based on entropy
        let entropy_str = if entropy > 7.5 {
            format!("{:.2} {}", entropy, "⚠").red()
        } else if entropy > 6.5 {
            format!("{:.2}", entropy).yellow()
        } else {
            format!("{:.2}", entropy).green()
        };

        println!(
            "  {:<12} {:<10} 0x{:<8X} {:<10} {}",
            name,
            section.virtual_size,
            section.virtual_address,
            section.size_of_raw_data,
            entropy_str
        );

        // Flag suspicious characteristics
        let characteristics = section.characteristics;

        // Writable + Executable is very suspicious
        let writable = characteristics & 0x80000000 != 0;
        let executable = characteristics & 0x20000000 != 0;

        if writable && executable {
            println!(
                "    {} Section is both writable and executable (highly suspicious!)",
                "⚠".red().bold()
            );
        }
    }
}

/// Analyse and display imported functions
fn print_imports(pe: &PE, _output_level: OutputLevel) {
    println!("\n{}", "Import Analysis:".bold());

    if pe.imports.is_empty() {
        println!("  No imports found (suspicious for most executables)");
        return;
    }

    println!("  Imported DLLs: {}", pe.libraries.len());

    let mut suspicious_count = 0;
    let mut all_imports = Vec::new();

    // Collect all imports
    for import in &pe.imports {
        let name = import.name.as_ref();
        all_imports.push(name);

        // Check if it's a suspicious API
        if SUSPICIOUS_APIS.contains(&name) {
            suspicious_count += 1;
        }
    }

    println!("  Total Imports: {}", all_imports.len());
    println!(
        "  Suspicious APIs: {}",
        if suspicious_count > 0 {
            format!("{} ⚠", suspicious_count).red().to_string()
        } else {
            format!("{}", suspicious_count)
        }
    );

    // Display suspicious APIs if found
    if suspicious_count > 0 {
        println!("\n  {} Suspicious APIs Detected:", "⚠".red().bold());
        for import in &pe.imports {
            let name = import.name.as_ref();
            if SUSPICIOUS_APIS.contains(&name) {
                // Categorize the API
                let category = categorize_api(name);
                println!("    {} {} - {}", "•".red(), name.red(), category.yellow());
            }
        }
    }

    // Display all imported DLLs
    println!("\n  Imported Libraries:");
    for lib in &pe.libraries {
        println!("    • {}", lib);
    }
}

/// Categorize suspicious APIs by function
fn categorize_api(api: &str) -> &'static str {
    match api {
        "CreateRemoteThread"
        | "WriteProcessMemory"
        | "VirtualAllocEx"
        | "QueueUserAPC"
        | "NtQueueApcThread"
        | "RtlCreateUserThread" => "Code Injection",

        "RegSetValueEx" | "RegCreateKeyEx" | "CreateService" | "StartService" => {
            "Persistence Mechanism"
        }

        "IsDebuggerPresent"
        | "CheckRemoteDebuggerPresent"
        | "OutputDebugString"
        | "NtQueryInformationProcess" => "Anti-Analysis",

        "InternetOpen" | "InternetOpenUrl" | "URLDownloadToFile" | "WinHttpOpen" | "socket"
        | "connect" => "Network Activity",

        "CryptEncrypt" | "CryptDecrypt" | "CryptAcquireContext" => "Cryptography",

        "GetAsyncKeyState" | "SetWindowsHookExA" | "GetForegroundWindow" => {
            "Keylogging/Input Monitoring"
        }

        "AdjustTokenPrivileges" | "OpenProcessToken" => "Privilege Escalation",

        _ => "File/System Operation",
    }
}

/// Analyse and display exported functions (for DLLs)
fn print_exports(pe: &PE, _output_level: OutputLevel) {
    if pe.exports.is_empty() {
        return;
    }

    println!("\n{}", "Export Analysis:".bold());
    println!("  Total Exports: {}", pe.exports.len());

    // Show first 20 exports
    println!("\n  Exported Functions (showing first 20):");
    for (i, export) in pe.exports.iter().take(20).enumerate() {
        // export.name is Option<Cow<str>>, we need to get &str from it
        let name = export
            .name
            .as_ref()
            .map(|s| s.as_ref())
            .unwrap_or("<unnamed>");
        println!("    {} 0x{:08X}: {}", i + 1, export.rva, name);
    }

    if pe.exports.len() > 20 {
        println!("    ... and {} more", pe.exports.len() - 20);
    }
}

/// Calculate Shannon entropy for a section
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_apis_list_not_empty() {
        assert!(!SUSPICIOUS_APIS.is_empty());
        assert!(SUSPICIOUS_APIS.len() > 30);
    }

    #[test]
    fn test_categorize_api_code_injection() {
        assert_eq!(categorize_api("CreateRemoteThread"), "Code Injection");
        assert_eq!(categorize_api("WriteProcessMemory"), "Code Injection");
        assert_eq!(categorize_api("VirtualAllocEx"), "Code Injection");
    }

    #[test]
    fn test_categorize_api_persistence() {
        assert_eq!(categorize_api("RegSetValueEx"), "Persistence Mechanism");
        assert_eq!(categorize_api("CreateService"), "Persistence Mechanism");
    }

    #[test]
    fn test_categorize_api_anti_analysis() {
        assert_eq!(categorize_api("IsDebuggerPresent"), "Anti-Analysis");
        assert_eq!(
            categorize_api("CheckRemoteDebuggerPresent"),
            "Anti-Analysis"
        );
    }

    #[test]
    fn test_categorize_api_network() {
        assert_eq!(categorize_api("InternetOpen"), "Network Activity");
        assert_eq!(categorize_api("socket"), "Network Activity");
    }

    #[test]
    fn test_categorize_api_crypto() {
        assert_eq!(categorize_api("CryptEncrypt"), "Cryptography");
        assert_eq!(categorize_api("CryptDecrypt"), "Cryptography");
    }

    #[test]
    fn test_categorize_api_keylogging() {
        assert_eq!(
            categorize_api("GetAsyncKeyState"),
            "Keylogging/Input Monitoring"
        );
        assert_eq!(
            categorize_api("SetWindowsHookExA"),
            "Keylogging/Input Monitoring"
        );
    }

    #[test]
    fn test_categorize_api_privilege_escalation() {
        assert_eq!(
            categorize_api("AdjustTokenPrivileges"),
            "Privilege Escalation"
        );
        assert_eq!(categorize_api("OpenProcessToken"), "Privilege Escalation");
    }

    #[test]
    fn test_categorize_api_unknown() {
        assert_eq!(categorize_api("UnknownAPI"), "File/System Operation");
        assert_eq!(categorize_api("CreateFile"), "File/System Operation");
    }

    #[test]
    fn test_calculate_entropy_empty() {
        let data: Vec<u8> = vec![];
        assert_eq!(calculate_entropy(&data), 0.0);
    }

    #[test]
    fn test_calculate_entropy_uniform() {
        // All same byte = 0 entropy
        let data = vec![0xAA; 1000];
        assert_eq!(calculate_entropy(&data), 0.0);
    }

    #[test]
    fn test_calculate_entropy_perfect_distribution() {
        // All 256 possible bytes once each = max entropy
        let data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_calculate_entropy_half_distribution() {
        // Half the bytes used = moderate entropy
        let data: Vec<u8> = (0..128).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 6.0 && entropy < 8.0);
    }

    #[test]
    fn test_suspicious_apis_contains_common_malware_functions() {
        // Verify critical malware APIs are in the list
        assert!(SUSPICIOUS_APIS.contains(&"CreateRemoteThread"));
        assert!(SUSPICIOUS_APIS.contains(&"WriteProcessMemory"));
        assert!(SUSPICIOUS_APIS.contains(&"VirtualAllocEx"));
        assert!(SUSPICIOUS_APIS.contains(&"IsDebuggerPresent"));
        assert!(SUSPICIOUS_APIS.contains(&"RegSetValueEx"));
        assert!(SUSPICIOUS_APIS.contains(&"URLDownloadToFile"));
    }

    #[test]
    fn test_output_level_quiet_behavior() {
        assert!(!OutputLevel::Quiet.should_print_info());
        assert!(!OutputLevel::Quiet.should_print_verbose());
    }

    #[test]
    fn test_output_level_normal_behavior() {
        assert!(OutputLevel::Normal.should_print_info());
        assert!(!OutputLevel::Normal.should_print_verbose());
    }

    #[test]
    fn test_output_level_verbose_behavior() {
        assert!(OutputLevel::Verbose.should_print_info());
        assert!(OutputLevel::Verbose.should_print_verbose());
    }
}
