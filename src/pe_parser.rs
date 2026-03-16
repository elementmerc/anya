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
use md5::{Digest, Md5};

/// Tier 1 — genuinely suspicious APIs with very limited legitimate use.
/// These are strongly associated with malicious behaviour (process injection, hiding,
/// kernel bypasses). Scoring: 1–2 hits → Medium; 3+ hits → High.
const SUSPICIOUS_APIS_TIER1: &[&str] = &[
    // Process injection
    "CreateRemoteThread",
    "WriteProcessMemory",
    "VirtualAllocEx",
    "NtQueueApcThread",
    "QueueUserAPC",
    "RtlCreateUserThread",
    "NtCreateThreadEx",
    "NtMapViewOfSection",
    // Hooking / interception
    "SetWindowsHookEx",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    // Thread/process hiding and anti-debug (high-signal)
    "NtQueryInformationProcess",
    "ZwSetInformationThread",
    "NtSetInformationThread",
    // Persistence
    "RegSetValueEx",
    "RegCreateKeyEx",
    "CreateService",
    "StartService",
    // Network (deliberate comms)
    "InternetOpen",
    "InternetOpenUrl",
    "URLDownloadToFile",
    "WinHttpOpen",
    // Keylogging
    "GetAsyncKeyState",
];

/// Tier 2 — dual-use / noteworthy APIs.
/// Common in legitimate software but also appear in malware.
/// Flagged as "Noteworthy" only; never contribute to the severity score.
const NOTEWORTHY_APIS: &[&str] = &[
    "OpenProcess",
    "OpenProcessToken",
    "AdjustTokenPrivileges",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugString",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "DebugBreak",
    "CreateToolhelp32Snapshot",
    "WSAStartup",
    "socket",
    "connect",
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptAcquireContext",
    "DeleteFile",
    "MoveFile",
    "CopyFile",
];

// Tier 3 (removed entirely — pure UI/system primitives with no malware signal):
//   GetForegroundWindow, QueryPerformanceCounter, GetSystemInfo,
//   GetComputerNameA, GetComputerNameW, GetUserNameA, GetUserNameW

/// Check if an API name is in the Tier 1 suspicious list
pub fn is_suspicious_api(api_name: &str) -> bool {
    SUSPICIOUS_APIS_TIER1
        .iter()
        .any(|&a| a.eq_ignore_ascii_case(api_name))
}

/// Check if an API name is in the Tier 2 noteworthy list
pub fn is_noteworthy_api(api_name: &str) -> bool {
    NOTEWORTHY_APIS
        .iter()
        .any(|&a| a.eq_ignore_ascii_case(api_name))
}

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
//  use anya::pe_parser;
//  use anya::OutputLevel;
//  use std::fs;
//
//  let data = fs::read("malware.exe")?;
//  pe_parser::analyse_pe(&data, OutputLevel::Normal)?;
//  # Ok::<(), anyhow::Error>(())
/// ```text
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

    // Analyse sections (with W+X column + summary)
    print_sections(&pe, data, output_level);

    // Analyse imports
    print_imports(&pe, output_level);

    // Analyse exports
    print_exports(&pe, output_level);

    // ── Compute new analysis fields ───────────────────────────────────────────
    let imphash = calculate_imphash(&pe);
    let ordinal_imports = collect_ordinal_imports(&pe);
    let rich_header = parse_rich_header(data, &pe);
    let tls = detect_tls_callbacks(data, &pe);
    let checksum = validate_checksum(data, &pe);
    let overlay = detect_overlay(data, &pe);
    let compiler = detect_compiler(&pe, data, &rich_header);
    let packers = detect_packer(&pe, data);
    let anti_analysis = detect_anti_analysis(&pe);
    let authenticode = check_authenticode(data, &pe);
    let version_info = extract_version_info(&pe, data);

    // ── Display new sections ──────────────────────────────────────────────────
    print_version_info(&version_info, output_level);
    print_authenticode_info(&authenticode, output_level);
    print_imphash(&imphash, output_level);
    print_compiler_info(&compiler, output_level);
    print_packer_info(&packers, output_level);
    print_rich_header_info(&rich_header, output_level);
    print_tls_info(&tls, output_level);
    print_ordinal_imports(&ordinal_imports, output_level);
    print_checksum_info(&checksum, output_level);
    print_overlay_info(&overlay, output_level);
    print_anti_analysis_info(&anti_analysis, output_level);

    // ── Overall suspicion summary ─────────────────────────────────────────────
    print_pe_summary(
        &pe,
        data,
        &imphash,
        &ordinal_imports,
        &rich_header,
        &tls,
        &checksum,
        &overlay,
        &packers,
        &anti_analysis,
        &authenticode,
        &version_info,
        output_level,
    );

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
                name_anomaly: None, // Populated below after section collection
            }
        })
        .collect();

    // Analyse imports — Tier 1 only for suspicious_apis JSON field
    let mut suspicious_apis = Vec::new();
    for import in &pe.imports {
        let name = import.name.as_ref();
        if is_suspicious_api(name) {
            suspicious_apis.push(output::SuspiciousAPI {
                name: name.to_string(),
                category: categorize_api(name).to_string(),
            });
        }
    }

    let total_imports = pe.imports.len();
    let file_size_bytes = data.len();
    let imports_per_kb = if file_size_bytes > 0 {
        Some(((total_imports as f64 / (file_size_bytes as f64 / 1024.0)) * 100.0).round() / 100.0)
    } else {
        None
    };

    let imports = output::ImportAnalysis {
        dll_count: pe.libraries.len(),
        total_imports,
        suspicious_api_count: suspicious_apis.len(),
        suspicious_apis,
        libraries: pe.libraries.iter().map(|s| s.to_string()).collect(),
        imports_per_kb,
        import_ratio_suspicious: imports_per_kb.map(|r| r > 30.0),
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

    // Phase 1 analysis
    let imphash = calculate_imphash(&pe);
    let checksum = validate_checksum(data, &pe);
    let overlay = detect_overlay(data, &pe);
    let rich_header = parse_rich_header(data, &pe);
    let tls = detect_tls_callbacks(data, &pe);
    let ordinal_imports = collect_ordinal_imports(&pe);

    // Phase 2 heuristics
    let compiler = Some(detect_compiler(&pe, data, &rich_header));
    let packers = detect_packer(&pe, data);
    let anti_analysis = detect_anti_analysis(&pe);

    // Trust signals
    let authenticode = Some(check_authenticode(data, &pe));
    let version_info = extract_version_info(&pe, data);

    // New v1.0.2 features
    let debug_artifacts = Some(extract_debug_artifacts(data, &pe, &version_info));
    let weak_crypto = detect_weak_crypto(data);
    let compiler_deps = compiler.as_ref()
        .map(|c| infer_compiler_deps(&c.name, &imports.libraries))
        .unwrap_or_default();

    // Populate section name anomalies
    let sections = sections.into_iter().map(|mut s| {
        s.name_anomaly = Some(classify_section_name(&s.name, s.entropy));
        s
    }).collect();

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
        imphash,
        checksum: Some(checksum),
        rich_header,
        tls,
        overlay,
        compiler,
        packers,
        anti_analysis,
        ordinal_imports,
        authenticode,
        version_info,
        debug_artifacts,
        weak_crypto,
        compiler_deps,
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

    // Check for suspicious APIs (Tier 1 only)
    let mut suspicious_count = 0;
    for import in &pe.imports {
        let name = import.name.as_ref();
        if is_suspicious_api(name) {
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
        "  {:<12} {:<10} {:<10} {:<10} {:<10} Perms",
        "Name", "VirtSize", "VirtAddr", "RawSize", "Entropy"
    );
    println!("  {}", "-".repeat(70));

    let mut wx_count = 0usize;

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
            format!("{:.2} ⚠", entropy).red().to_string()
        } else if entropy > 6.5 {
            format!("{:.2}", entropy).yellow().to_string()
        } else {
            format!("{:.2}", entropy).green().to_string()
        };

        // RWX permissions column
        let characteristics = section.characteristics;
        let readable = characteristics & 0x40000000 != 0;
        let writable = characteristics & 0x80000000 != 0;
        let executable = characteristics & 0x20000000 != 0;

        let r = if readable { "R" } else { "-" };
        let w = if writable { "W" } else { "-" };
        let x = if executable { "X" } else { "-" };

        let perms = if writable && executable {
            wx_count += 1;
            format!("{}{}{} ⚠ W+X", r, w, x).red().bold().to_string()
        } else {
            format!("{}{}{}", r, w, x).normal().to_string()
        };

        println!(
            "  {:<12} {:<10} 0x{:<8X} {:<10} {:<16} {}",
            name,
            section.virtual_size,
            section.virtual_address,
            section.size_of_raw_data,
            entropy_str,
            perms
        );
    }

    // W+X summary line
    println!();
    if wx_count > 0 {
        println!(
            "  {} {} section(s) with W+X permissions — critical finding",
            "⚠".red().bold(),
            wx_count
        );
    } else {
        println!("  {} No W+X sections", "✓".green());
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
    println!("  Total Imports: {}", pe.imports.len());

    let mut tier1_hits: Vec<&str> = Vec::new();
    let mut tier2_hits: Vec<&str> = Vec::new();

    for import in &pe.imports {
        let name = import.name.as_ref();
        if is_suspicious_api(name) {
            tier1_hits.push(name);
        } else if is_noteworthy_api(name) {
            tier2_hits.push(name);
        }
    }

    // Tier 1 — suspicious
    if !tier1_hits.is_empty() {
        println!(
            "  Suspicious APIs: {} ⚠",
            tier1_hits.len().to_string().red().bold()
        );
        println!("\n  {} Suspicious APIs ⚠", "⚠".red().bold());
        for name in &tier1_hits {
            let category = categorize_api(name);
            println!("    {} {} — {}", "•".red(), name.red(), category.yellow());
        }
    } else {
        println!("  Suspicious APIs: {}", "0".green());
    }

    // Tier 2 — noteworthy (informational only)
    if !tier2_hits.is_empty() {
        println!(
            "\n  Noteworthy APIs (common in legitimate software): {}",
            tier2_hits.len()
        );
        for name in &tier2_hits {
            let category = categorize_api(name);
            println!("    {} {} — {}", "•".normal(), name, category);
        }
    }

    // Imported libraries list
    println!("\n  Imported Libraries:");
    for lib in &pe.libraries {
        println!("    • {}", lib);
    }
}

/// Categorize suspicious APIs by function
pub fn categorize_api(api_name: &str) -> &'static str {
    // Convert to lowercase for case-insensitive matching
    let api_lower = api_name.to_lowercase();

    match api_lower.as_str() {
        // Code Injection
        "createremotethread"
        | "writeprocessmemory"
        | "virtualallocex"
        | "setwindowshookex"
        | "openprocess"
        | "ntqueueapcthread"
        | "rtlcreateuserthread"
        | "queueuserapc"
        | "ntcreatethreadex"
        | "ntmapviewofsection" => "Code Injection",

        // Persistence
        "regsetvalueex" | "regcreatekeyex" | "createservice" | "startservice"
        | "createservicew" | "createservicea" => "Persistence Mechanism",

        // Anti-Analysis
        "isdebuggerpresent"
        | "checkremotedebuggerpresent"
        | "outputdebugstring"
        | "ntqueryinformationprocess"
        | "ntsetinformationthread" => "Anti-Analysis",

        // Network
        "internetopen" | "internetopenurl" | "internetreadfile" | "urldownloadtofile"
        | "urldownloadtofilew" | "socket" | "connect" | "send" | "recv" | "wsastartup" => {
            "Network Activity"
        }

        // Cryptography
        "cryptencrypt"
        | "cryptdecrypt"
        | "crypthashdata"
        | "cryptcreatehash"
        | "cryptderivekey"
        | "cryptacquirecontext"
        | "cryptgenrandom" => "Cryptography",

        // Keylogging
        "getasynckeystate" | "setwindowshookexa" | "setwindowshookexw" | "getkeystate"
        | "getkeyboardstate" => "Keylogging/Input Monitoring",

        // Privilege Escalation
        "adjusttokenprivileges"
        | "openprocesstoken"
        | "impersonateloggedonuser"
        | "setentriesinacl" => "Privilege Escalation",

        // Default
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

// ─── New display functions ────────────────────────────────────────────────────

fn print_imphash(imphash: &Option<String>, _output_level: OutputLevel) {
    println!("\n{}", "Import Hash (Imphash):".bold());
    match imphash {
        Some(hash) => println!("  {}", hash.green()),
        None => println!("  {} No named imports — imphash unavailable", "–".normal()),
    }
}

fn print_compiler_info(compiler: &output::CompilerInfo, _output_level: OutputLevel) {
    println!("\n{}", "Compiler Detection:".bold());
    let conf_color = match compiler.confidence.as_str() {
        "High" => compiler.confidence.green().to_string(),
        "Medium" => compiler.confidence.yellow().to_string(),
        _ => compiler.confidence.normal().to_string(),
    };
    println!(
        "  Detected: {} ({} confidence)",
        compiler.name.bold(),
        conf_color
    );
}

fn print_packer_info(packers: &[output::PackerFinding], _output_level: OutputLevel) {
    println!("\n{}", "Packer Detection:".bold());
    if packers.is_empty() {
        println!("  {} No packers detected", "✓".green());
    } else {
        for p in packers {
            let conf_color = match p.confidence.as_str() {
                "High" => p.confidence.red().to_string(),
                "Medium" => p.confidence.yellow().to_string(),
                _ => p.confidence.normal().to_string(),
            };
            println!(
                "  {} {} — detected via {} ({} confidence)",
                "⚠".red().bold(),
                p.name.red().bold(),
                p.detection_method,
                conf_color
            );
        }
    }
}

fn print_rich_header_info(rich: &Option<output::RichHeaderInfo>, output_level: OutputLevel) {
    println!("\n{}", "Rich Header:".bold());
    match rich {
        None => println!("  {} Not present (non-MSVC or stripped)", "✗".normal()),
        Some(r) => {
            println!(
                "  {} Present — {} build tool entr{}",
                "✓".green(),
                r.entries.len(),
                if r.entries.len() == 1 { "y" } else { "ies" }
            );
            // In verbose mode show up to 5 entries; in normal mode show only named ones
            let limit = if output_level.should_print_verbose() {
                5
            } else {
                3
            };
            for entry in r
                .entries
                .iter()
                .filter(|e| e.product_name.is_some())
                .take(limit)
            {
                println!(
                    "    Notable: {} (build {}, used {} time{})",
                    entry.product_name.as_deref().unwrap_or("?"),
                    entry.build_number,
                    entry.use_count,
                    if entry.use_count == 1 { "" } else { "s" }
                );
            }
        }
    }
}

fn print_tls_info(tls: &Option<output::TlsInfo>, output_level: OutputLevel) {
    println!("\n{}", "TLS Callbacks:".bold());
    match tls {
        None => println!("  {} None detected", "✓".green()),
        Some(t) if t.callback_count == 0 => println!("  {} None detected", "✓".green()),
        Some(t) => {
            println!(
                "  {} {} callback(s) detected — code executes before entry point",
                "⚠".red().bold(),
                t.callback_count
            );
            if output_level.should_print_verbose() {
                let offsets = t.callback_rvas.join(", ");
                println!("    Offsets: {}", offsets);
            } else if !t.callback_rvas.is_empty() {
                let preview: Vec<&str> =
                    t.callback_rvas.iter().map(|s| s.as_str()).take(4).collect();
                let suffix = if t.callback_rvas.len() > 4 {
                    format!(", … ({} total)", t.callback_rvas.len())
                } else {
                    String::new()
                };
                println!("    Offsets: {}{}", preview.join(", "), suffix);
            }
        }
    }
}

fn print_ordinal_imports(ordinals: &[output::OrdinalImport], output_level: OutputLevel) {
    println!("\n{}", "Ordinal Imports:".bold());
    if ordinals.is_empty() {
        println!("  {} None detected", "✓".green());
        return;
    }

    // Group by DLL
    let mut by_dll: std::collections::BTreeMap<&str, Vec<u16>> = std::collections::BTreeMap::new();
    for o in ordinals {
        by_dll.entry(&o.dll).or_default().push(o.ordinal);
    }

    println!(
        "  {} {} ordinal import(s) detected",
        "⚠".yellow(),
        ordinals.len()
    );
    for (dll, ords) in &by_dll {
        let sensitive =
            dll.eq_ignore_ascii_case("ntdll.dll") || dll.eq_ignore_ascii_case("kernel32.dll");
        let tag = if sensitive {
            format!(" {}", "[⚠ sensitive]".red())
        } else {
            String::new()
        };
        if output_level.should_print_verbose() {
            let ord_list: Vec<String> = ords.iter().map(|n| n.to_string()).collect();
            println!(
                "    {}: {} ordinal(s){} — [{}]",
                dll,
                ords.len(),
                tag,
                ord_list.join(", ")
            );
        } else {
            println!("    {}: {} ordinal(s){}", dll, ords.len(), tag);
        }
    }
}

fn print_checksum_info(checksum: &output::ChecksumInfo, _output_level: OutputLevel) {
    println!("\n{}", "Checksum Validation:".bold());
    if !checksum.stored_nonzero {
        println!(
            "  Stored:   0x{:08X} (not set — normal for user-mode apps)",
            checksum.stored
        );
        return;
    }
    println!("  Stored:   0x{:08X}", checksum.stored);
    println!("  Computed: 0x{:08X}", checksum.computed);
    if checksum.valid {
        println!("  {} Valid", "✓".green());
    } else {
        println!(
            "  {} Mismatch — binary may be patched or repacked",
            "⚠".red().bold()
        );
    }
}

fn print_overlay_info(overlay: &Option<output::OverlayInfo>, _output_level: OutputLevel) {
    println!("\n{}", "Overlay Detection:".bold());
    match overlay {
        None => println!("  {} None detected", "✓".green()),
        Some(o) => {
            println!(
                "  {} Overlay found at offset 0x{:X} ({} bytes)",
                "⚠".yellow(),
                o.offset,
                o.size
            );
            let entropy_note = if o.high_entropy {
                format!("{:.2} — {} likely encrypted payload", o.entropy, "⚠".red())
            } else {
                format!("{:.2} — low entropy", o.entropy)
            };
            println!("    Entropy: {}", entropy_note);
        }
    }
}

fn print_anti_analysis_info(findings: &[output::AntiAnalysisFinding], output_level: OutputLevel) {
    println!("\n{}", "Anti-Analysis Patterns:".bold());
    if findings.is_empty() {
        println!("  {} None detected", "✓".green());
        return;
    }

    // Group by category
    let mut by_cat: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
    for f in findings {
        by_cat.entry(&f.category).or_default().push(&f.indicator);
    }

    for (category, indicators) in &by_cat {
        let label = match *category {
            "VmDetection" => "VM detection APIs present",
            "DebuggerDetection" => "Debugger detection APIs present",
            "TimingCheck" => "Timing check APIs present",
            "SandboxDetection" => "Sandbox detection patterns present",
            other => other,
        };
        println!("  {} {}", "⚠".red().bold(), label.red());
        if output_level.should_print_verbose() {
            println!("    · {}", indicators.join(", "));
        } else {
            // Show up to 3
            let preview: Vec<&str> = indicators.iter().copied().take(3).collect();
            let suffix = if indicators.len() > 3 {
                format!(" … ({} total)", indicators.len())
            } else {
                String::new()
            };
            println!("    · {}{}", preview.join(", "), suffix);
        }
    }
}

/// Collect all suspicious indicators and render a calibrated verdict summary.
///
/// Scoring thresholds:
///   Critical ≥ 1                          → SUSPICIOUS
///   High ≥ 2  OR  (High = 1 AND Med ≥ 2)  → SUSPICIOUS
///   High = 1  OR  Med ≥ 2                 → REVIEW
///   Info / no findings                    → CLEAN
///
/// Authenticode-signed Microsoft binaries get a -3 point reduction.
/// Other signed binaries get -2.  Missing signature on an EXE is Informational.
#[allow(clippy::too_many_arguments)]
fn print_pe_summary(
    pe: &PE,
    data: &[u8],
    imphash: &Option<String>,
    ordinals: &[output::OrdinalImport],
    rich: &Option<output::RichHeaderInfo>,
    tls: &Option<output::TlsInfo>,
    checksum: &output::ChecksumInfo,
    overlay: &Option<output::OverlayInfo>,
    packers: &[output::PackerFinding],
    anti_analysis: &[output::AntiAnalysisFinding],
    authenticode: &output::AuthenticodeInfo,
    version_info: &Option<output::VersionInfo>,
    _output_level: OutputLevel,
) {
    let _ = imphash;
    let _ = rich;

    let mut critical: Vec<String> = Vec::new();
    let mut high: Vec<String> = Vec::new();
    let mut medium: Vec<String> = Vec::new();
    let mut info: Vec<String> = Vec::new();

    // W+X sections → Critical
    for section in &pe.sections {
        let ch = section.characteristics;
        if ch & 0x80000000 != 0 && ch & 0x20000000 != 0 {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();
            critical.push(format!("W+X section: {}", name));
        }
    }

    // Security features → Medium only
    if let Some(oh) = &pe.header.optional_header {
        let ch = oh.windows_fields.dll_characteristics;
        if ch & 0x40 == 0 {
            medium.push("ASLR disabled".to_string());
        }
        if ch & 0x100 == 0 {
            medium.push("DEP/NX disabled".to_string());
        }
    }

    // TLS callbacks — downgraded from High/Critical to Medium/High
    if let Some(t) = tls {
        if t.callback_count > 2 {
            high.push(format!(
                "{} TLS callbacks detected (execute before entry point — review if unexpected)",
                t.callback_count
            ));
        } else if t.callback_count > 0 {
            medium.push(format!(
                "{} TLS callback(s) detected — common in some legitimate binaries; review if unexpected",
                t.callback_count
            ));
        }
    }

    // Overlay
    if let Some(o) = overlay {
        if o.high_entropy {
            medium.push(format!(
                "Overlay at 0x{:X} ({} bytes, entropy {:.2}) — high entropy, may warrant review",
                o.offset, o.size, o.entropy
            ));
        } else {
            info.push(format!(
                "Overlay present at 0x{:X} ({} bytes)",
                o.offset, o.size
            ));
        }
    }

    // Checksum mismatch → Informational only (common in patched/resigned binaries)
    if checksum.stored_nonzero && !checksum.valid {
        info.push(format!(
            "PE checksum mismatch (stored 0x{:08X} ≠ computed 0x{:08X}) — may have been modified or rebuilt",
            checksum.stored, checksum.computed
        ));
    }

    // Packers — High confidence → High; Medium → Medium
    for p in packers {
        match p.confidence.as_str() {
            "High" => high.push(format!(
                "Packer detected: {} ({})",
                p.name, p.detection_method
            )),
            "Medium" => medium.push(format!(
                "Possible packer: {} ({})",
                p.name, p.detection_method
            )),
            _ => {}
        }
    }

    // Anti-analysis (high-signal APIs only after recalibration)
    let anti_cats: std::collections::HashSet<&str> =
        anti_analysis.iter().map(|f| f.category.as_str()).collect();
    if anti_cats.len() >= 2 {
        high.push(format!(
            "Multiple anti-analysis categories: {}",
            anti_cats.into_iter().collect::<Vec<_>>().join(", ")
        ));
    } else if !anti_analysis.is_empty() {
        medium.push(format!("Anti-analysis: {}", anti_analysis[0].category));
    }

    // Ordinal imports from sensitive DLLs → High
    for o in ordinals.iter().filter(|o| {
        o.dll.eq_ignore_ascii_case("ntdll.dll") || o.dll.eq_ignore_ascii_case("kernel32.dll")
    }) {
        high.push(format!(
            "Ordinal import from {} (ordinal {})",
            o.dll, o.ordinal
        ));
    }

    // Suspicious APIs (Tier 1 only) — 3+ → High; 1–2 → Medium
    let t1_count = pe
        .imports
        .iter()
        .filter(|i| is_suspicious_api(i.name.as_ref()))
        .count();

    // Check for injection cluster (3+ injection-class APIs)
    let injection_count = pe
        .imports
        .iter()
        .filter(|i| {
            let n = i.name.as_ref().to_lowercase();
            matches!(
                n.as_str(),
                "createremotethread"
                    | "writeprocessmemory"
                    | "virtualallocex"
                    | "ntqueueapcthread"
                    | "rtlcreateuserthread"
                    | "ntcreatethreadex"
            )
        })
        .count();

    if injection_count >= 3 {
        critical.push(format!(
            "{} process injection APIs clustered",
            injection_count
        ));
    } else if t1_count >= 3 {
        high.push(format!("{} Tier-1 suspicious APIs detected", t1_count));
    } else if t1_count > 0 {
        medium.push(format!("{} Tier-1 suspicious API(s) detected", t1_count));
    }

    // Very high entropy sections → High
    for section in &pe.sections {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        if start + size <= data.len() && size > 0 {
            let e = calculate_entropy(&data[start..start + size]);
            if e > 7.5 {
                let name = String::from_utf8_lossy(&section.name)
                    .trim_end_matches('\0')
                    .to_string();
                high.push(format!("Very high entropy section: {} ({:.2})", name, e));
            }
        }
    }

    // Filename mismatch between OriginalFilename and actual filename on disk
    if let Some(vi) = version_info
        && let Some(orig) = &vi.original_filename
    {
        // Only check if we have a path to compare against
        // (we don't store the on-disk filename here — leave to future integration)
        let _ = orig; // TODO: compare against actual filename when path is available
    }

    // No Authenticode signature on an EXE is informational
    let is_dll = pe.header.coff_header.characteristics & 0x2000 != 0;
    if !authenticode.present && !is_dll {
        info.push("No Authenticode signature".to_string());
    }

    // ── Authenticode trust reduction ──────────────────────────────────────────
    // Microsoft-signed → reduce score by removing up to 3 high-signal findings
    // that are common in system binaries (ASLR/DEP flags, TLS medium, etc.)
    // Other signed → remove up to 2
    let reduction = if authenticode.is_microsoft_signed {
        3usize
    } else if authenticode.present {
        2usize
    } else {
        0usize
    };

    // Apply reduction against medium first (weakest), then high
    let medium_to_remove = reduction.min(medium.len());
    for _ in 0..medium_to_remove {
        medium.pop();
    }
    let remaining = reduction.saturating_sub(medium_to_remove);
    let high_to_remove = remaining.min(high.len());
    for _ in 0..high_to_remove {
        high.pop();
    }

    // ── Verdict ───────────────────────────────────────────────────────────────
    let verdict =
        if !critical.is_empty() || high.len() >= 2 || (high.len() == 1 && medium.len() >= 2) {
            "SUSPICIOUS".red().bold().to_string()
        } else if !high.is_empty() || medium.len() >= 2 {
            "REVIEW".yellow().bold().to_string()
        } else {
            "CLEAN".green().bold().to_string()
        };

    let total = critical.len() + high.len() + medium.len() + info.len();

    println!("\n{}", "═══ Analysis Summary ═══".bold().cyan());
    if authenticode.is_microsoft_signed {
        println!(
            "  {} Microsoft-signed binary (trust score reduced)",
            "🛡".normal()
        );
    } else if authenticode.present {
        println!("  {} Signed binary (trust score reduced)", "🛡".normal());
    }
    println!("  Suspicious indicators: {}", total);

    for c in &critical {
        println!("  {} [CRITICAL] {}", "⚠".red().bold(), c.red());
    }
    for h in &high {
        println!("  {} [HIGH]     {}", "⚠".yellow(), h);
    }
    for m in &medium {
        println!("  {} [MEDIUM]   {}", "–".normal(), m);
    }
    for i in &info {
        println!("  {} [INFO]     {}", "·".normal(), i);
    }

    println!("  Verdict: {}", verdict);
}

// ─── Phase 1: new PE analysis helpers ────────────────────────────────────────

/// Convert an RVA to a file offset using the section table.
fn rva_to_file_offset(pe: &PE, rva: u32) -> Option<usize> {
    for section in &pe.sections {
        let va = section.virtual_address;
        let vs = section.virtual_size.max(section.size_of_raw_data);
        if rva >= va && rva < va.saturating_add(vs) {
            let offset = (rva - va) as usize + section.pointer_to_raw_data as usize;
            return Some(offset);
        }
    }
    None
}

/// Collect imports that are resolved by ordinal only (no function name string).
fn collect_ordinal_imports(pe: &PE) -> Vec<output::OrdinalImport> {
    let mut result = Vec::new();
    for import in &pe.imports {
        let name = import.name.as_ref();
        if name.starts_with("ORDINAL ")
            && let Ok(ordinal) = name["ORDINAL ".len()..].parse::<u16>()
        {
            result.push(output::OrdinalImport {
                dll: import.dll.to_string(),
                ordinal,
            });
        }
    }
    result
}

/// Calculate the imphash: MD5 of the normalised, comma-separated import list
/// in import-table order (compatible with VirusTotal / pefile).
fn calculate_imphash(pe: &PE) -> Option<String> {
    let mut entries: Vec<String> = Vec::new();

    for import in &pe.imports {
        let name = import.name.as_ref();
        // Skip ordinal-only imports
        if name.starts_with("ORDINAL ") {
            continue;
        }

        let dll_raw = import.dll;
        // Strip known PE DLL extensions, lowercase
        let dll_lower = dll_raw.to_lowercase();
        let dll_base = if let Some(stem) = dll_lower
            .strip_suffix(".dll")
            .or_else(|| dll_lower.strip_suffix(".exe"))
            .or_else(|| dll_lower.strip_suffix(".sys"))
            .or_else(|| dll_lower.strip_suffix(".ocx"))
        {
            stem.to_string()
        } else {
            dll_lower
        };

        let fn_lower = name.to_lowercase();
        entries.push(format!("{}.{}", dll_base, fn_lower));
    }

    if entries.is_empty() {
        return None;
    }

    let combined = entries.join(",");
    let mut hasher = Md5::new();
    hasher.update(combined.as_bytes());
    let digest = hasher.finalize();
    Some(format!("{:x}", digest))
}

/// Validate the PE checksum by computing it from raw bytes and comparing with
/// the stored value in the optional header.
fn validate_checksum(data: &[u8], pe: &PE) -> output::ChecksumInfo {
    let stored = pe
        .header
        .optional_header
        .as_ref()
        .map(|oh| oh.windows_fields.check_sum)
        .unwrap_or(0);

    if stored == 0 {
        return output::ChecksumInfo {
            stored: 0,
            computed: 0,
            valid: false,
            stored_nonzero: false,
        };
    }

    // Determine the file offset of the checksum field so we can skip it.
    // The checksum is at pe_pointer + 4 (PE sig) + 20 (COFF header) + 0x40 (into optional header).
    let checksum_offset = pe.header.dos_header.pe_pointer as usize + 4 + 20 + 0x40;

    // Sum all 16-bit words, little-endian, padding with 0 if odd length.
    let mut sum: u32 = 0;
    let len = data.len();
    let mut i = 0usize;
    while i + 1 < len {
        // Skip the 4 bytes of the checksum field
        if i == checksum_offset || i == checksum_offset + 2 {
            i += 2;
            continue;
        }
        let word = u16::from_le_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        // Fold carry
        sum = (sum & 0xFFFF) + (sum >> 16);
        i += 2;
    }
    // Handle odd-length file
    if len % 2 != 0 && i < len {
        let word = data[i] as u32;
        sum = sum.wrapping_add(word);
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // Final carry fold
    sum = (sum & 0xFFFF) + (sum >> 16);
    // Add file size
    sum = sum.wrapping_add(len as u32);

    let computed = sum & 0xFFFF;

    output::ChecksumInfo {
        stored,
        computed,
        valid: stored == computed,
        stored_nonzero: true,
    }
}

/// Detect overlay data: bytes appended after the last section.
///
/// The Authenticode certificate (Security Directory, data dir index 4) is stored as
/// a WIN_CERTIFICATE blob whose *file offset* is in virtual_address — not an RVA.
/// This is a PE spec special case.  If the "overlay" coincides with the cert block,
/// we return None and let check_authenticode report it instead.
fn detect_overlay(data: &[u8], pe: &PE) -> Option<output::OverlayInfo> {
    let end_of_sections = pe
        .sections
        .iter()
        .filter(|s| s.size_of_raw_data > 0)
        .map(|s| s.pointer_to_raw_data as usize + s.size_of_raw_data as usize)
        .max()?;

    if end_of_sections == 0 || end_of_sections >= data.len() {
        return None;
    }

    // Check if the trailing data is the Authenticode certificate block.
    // Data directory index 4 (Security Directory) uses a FILE OFFSET, not an RVA.
    if let Some(oh) = pe.header.optional_header.as_ref()
        && let Some(cert_dd) = oh.data_directories.get_certificate_table()
        && cert_dd.virtual_address != 0
        && cert_dd.size > 0
    {
        let cert_offset = cert_dd.virtual_address as usize;
        // Allow an 8-byte alignment tolerance
        if cert_offset >= end_of_sections && cert_offset <= end_of_sections + 8 {
            // The "overlay" is entirely the Authenticode cert — not a real overlay
            return None;
        }
    }

    let overlay_data = &data[end_of_sections..];
    let entropy = calculate_entropy(overlay_data);

    let overlay_mime = if overlay_data.len() >= 16 {
        infer::get(overlay_data).map(|t| t.mime_type().to_string())
    } else {
        None
    };

    let overlay_char = overlay_mime.as_deref().map(|m| match m {
        "application/zip" => "ZIP archive — possible payload container".to_string(),
        "application/x-dosexec" => "Embedded PE executable".to_string(),
        "application/pdf" => "PDF document".to_string(),
        m if m.starts_with("image/") => "Image data".to_string(),
        other => other.to_string(),
    }).or_else(|| Some("Unknown/random data".to_string()));

    Some(output::OverlayInfo {
        offset: end_of_sections,
        size: overlay_data.len(),
        entropy,
        high_entropy: entropy > 6.8,
        overlay_mime_type: overlay_mime,
        overlay_characterisation: overlay_char,
    })
}

/// Hardcoded table of common Rich header product IDs.
fn rich_product_name(product_id: u16) -> Option<&'static str> {
    match product_id {
        0x0001 => Some("Imported Symbol"),
        0x0006 => Some("LINK 5.10"),
        0x000A => Some("LINK 5.12"),
        0x000F => Some("LINK 6.00"),
        0x0015 => Some("LINK 7.00"),
        0x001C => Some("LINK 8.00"),
        0x001D => Some("C 7.00"),
        0x0022 => Some("MASM 7.00"),
        0x006D => Some("LINK 10.00 (VS2010)"),
        0x006E => Some("C/C++ 10.00 (VS2010)"),
        0x0078 => Some("LINK 11.00 (VS2012)"),
        0x0079 => Some("C/C++ 11.00 (VS2012)"),
        0x007D => Some("LINK 12.00 (VS2013)"),
        0x007E => Some("C/C++ 12.00 (VS2013)"),
        0x0083 => Some("LINK 14.00 (VS2015)"),
        0x0084 => Some("C/C++ 14.00 (VS2015)"),
        0x0091 => Some("LINK 14.10 (VS2017)"),
        0x0092 => Some("C/C++ 14.10 (VS2017)"),
        0x0099 => Some("LINK 14.20 (VS2019)"),
        0x009A => Some("C/C++ 14.20 (VS2019)"),
        0x00AA => Some("LINK 14.30 (VS2022)"),
        0x00AB => Some("C/C++ 14.30 (VS2022)"),
        _ => None,
    }
}

/// Parse the Rich header (XOR-encoded MSVC build metadata between DOS stub and PE signature).
fn parse_rich_header(data: &[u8], pe: &PE) -> Option<output::RichHeaderInfo> {
    let pe_ptr = pe.header.dos_header.pe_pointer as usize;
    if pe_ptr <= 0x80 || pe_ptr > data.len() {
        return None;
    }

    let region = &data[0x80..pe_ptr];
    if region.len() < 8 {
        return None;
    }

    // Find "Rich" marker (0x52 0x69 0x63 0x68) in the region
    let rich_pos = region.windows(4).position(|w| w == b"Rich")?;

    // The 4 bytes immediately after "Rich" are the XOR key
    if rich_pos + 8 > region.len() {
        return None;
    }
    let xor_key = u32::from_le_bytes([
        region[rich_pos + 4],
        region[rich_pos + 5],
        region[rich_pos + 6],
        region[rich_pos + 7],
    ]);

    // Compute XOR'd "DanS" to locate the start marker
    let dans_xored = [
        0x44u8 ^ (xor_key as u8),
        0x61u8 ^ ((xor_key >> 8) as u8),
        0x6Eu8 ^ ((xor_key >> 16) as u8),
        0x53u8 ^ ((xor_key >> 24) as u8),
    ];

    // Scan backward from rich_pos for the DanS marker
    let dans_pos = region[..rich_pos]
        .windows(4)
        .rposition(|w| w == dans_xored)?;

    // Entries start after DanS (4 bytes) + 3 padding DWORDs (12 bytes) = offset 16
    let entries_start = dans_pos + 16;
    if entries_start >= rich_pos {
        return Some(output::RichHeaderInfo {
            xor_key,
            entries: vec![],
        });
    }

    let entry_bytes = &region[entries_start..rich_pos];
    let mut entries = Vec::new();

    let mut i = 0;
    while i + 7 < entry_bytes.len() {
        let comp_id_raw = u32::from_le_bytes([
            entry_bytes[i],
            entry_bytes[i + 1],
            entry_bytes[i + 2],
            entry_bytes[i + 3],
        ]) ^ xor_key;
        let use_count_raw = u32::from_le_bytes([
            entry_bytes[i + 4],
            entry_bytes[i + 5],
            entry_bytes[i + 6],
            entry_bytes[i + 7],
        ]) ^ xor_key;

        let product_id = (comp_id_raw >> 16) as u16;
        let build_number = (comp_id_raw & 0xFFFF) as u16;
        let product_name = rich_product_name(product_id).map(|s| s.to_string());

        entries.push(output::RichEntry {
            product_id,
            build_number,
            use_count: use_count_raw,
            product_name,
        });

        i += 8;
    }

    Some(output::RichHeaderInfo { xor_key, entries })
}

/// Detect TLS callbacks by reading IMAGE_TLS_DIRECTORY and its callback array.
fn detect_tls_callbacks(data: &[u8], pe: &PE) -> Option<output::TlsInfo> {
    let oh = pe.header.optional_header.as_ref()?;
    let tls_dd = oh.data_directories.get_tls_table()?;

    if tls_dd.virtual_address == 0 {
        return None;
    }

    let tls_offset = rva_to_file_offset(pe, tls_dd.virtual_address)?;

    // Read AddressOfCallBacks VA from the TLS directory struct.
    // PE32:  StartAddressOfRawData(4) + EndAddressOfRawData(4) + AddressOfIndex(4) = 12 bytes in
    // PE32+: same fields are 8 bytes each, so offset is 8+8+8 = 24 bytes in
    let (callbacks_va, ptr_size): (u64, usize) = if pe.is_64 {
        if tls_offset + 32 > data.len() {
            return None;
        }
        let va = u64::from_le_bytes(data[tls_offset + 24..tls_offset + 32].try_into().ok()?);
        (va, 8)
    } else {
        if tls_offset + 16 > data.len() {
            return None;
        }
        let va = u32::from_le_bytes(data[tls_offset + 12..tls_offset + 16].try_into().ok()?) as u64;
        (va, 4)
    };

    if callbacks_va == 0 {
        return None;
    }

    // Convert VA → RVA → file offset
    let callbacks_rva = callbacks_va.wrapping_sub(pe.image_base as u64) as u32;
    let cb_offset = rva_to_file_offset(pe, callbacks_rva)?;

    let mut callback_rvas = Vec::new();
    let mut pos = cb_offset;
    let max_callbacks = 64;

    loop {
        if callback_rvas.len() >= max_callbacks || pos + ptr_size > data.len() {
            break;
        }

        let cb_va: u64 = if ptr_size == 8 {
            u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?)
        } else {
            u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as u64
        };

        if cb_va == 0 {
            break;
        }

        let cb_rva = cb_va.wrapping_sub(pe.image_base as u64) as u32;
        callback_rvas.push(format!("0x{:X}", cb_rva));
        pos += ptr_size;
    }

    Some(output::TlsInfo {
        callback_count: callback_rvas.len(),
        callback_rvas,
    })
}

// ─── Phase 2: Heuristic detection ────────────────────────────────────────────

/// Scan a byte slice for a sub-slice needle.
fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Detect the compiler or language used to build the PE.
fn detect_compiler(
    pe: &PE,
    data: &[u8],
    rich: &Option<output::RichHeaderInfo>,
) -> output::CompilerInfo {
    // 1. .NET: CLR data directory (index 14) non-zero AND mscoree.dll in imports
    if let Some(oh) = &pe.header.optional_header
        && let Some(clr_dd) = oh.data_directories.get_clr_runtime_header()
        && clr_dd.virtual_address != 0
    {
        let has_mscoree = pe
            .libraries
            .iter()
            .any(|lib| lib.to_lowercase() == "mscoree.dll");
        if has_mscoree {
            return output::CompilerInfo {
                name: ".NET".to_string(),
                confidence: "High".to_string(),
            };
        }
    }

    // 2. Go
    if bytes_contain(data, b"go.buildid")
        || pe
            .sections
            .iter()
            .any(|s| String::from_utf8_lossy(&s.name).trim_end_matches('\0') == ".symtab")
    {
        return output::CompilerInfo {
            name: "Go".to_string(),
            confidence: "High".to_string(),
        };
    }

    // 3. Rust
    if bytes_contain(data, b"__rust_begin_unwind") || bytes_contain(data, b"rust_begin_unwind") {
        return output::CompilerInfo {
            name: "Rust".to_string(),
            confidence: "High".to_string(),
        };
    }

    // 4. PyInstaller
    if bytes_contain(data, b"_MEIPASS2") || bytes_contain(data, b"PyInstaller") {
        return output::CompilerInfo {
            name: "PyInstaller (Python)".to_string(),
            confidence: "High".to_string(),
        };
    }

    // 5. Delphi
    let has_delphi_lib = pe
        .libraries
        .iter()
        .any(|lib| lib.to_lowercase().starts_with("rtl") && lib.to_lowercase().ends_with(".bpl"));
    if has_delphi_lib || bytes_contain(data, b"Embarcadero") || bytes_contain(data, b"Borland") {
        return output::CompilerInfo {
            name: "Delphi".to_string(),
            confidence: "Medium".to_string(),
        };
    }

    // 6. MSVC: rich header with known MSVC product IDs, or MSVC runtime imports
    let msvc_product_ids: &[u16] = &[
        0x006D, 0x006E, 0x0078, 0x0079, 0x007D, 0x007E, 0x0083, 0x0084, 0x0091, 0x0092, 0x0099,
        0x009A, 0x00AA, 0x00AB,
    ];
    let has_msvc_rich = rich.as_ref().is_some_and(|r| {
        r.entries
            .iter()
            .any(|e| msvc_product_ids.contains(&e.product_id))
    });
    let has_msvc_runtime = pe.libraries.iter().any(|lib| {
        let l = lib.to_lowercase();
        l.starts_with("msvcr") || l.starts_with("vcruntime") || l.starts_with("msvcp")
    });
    if has_msvc_rich {
        return output::CompilerInfo {
            name: "MSVC".to_string(),
            confidence: "High".to_string(),
        };
    }
    if has_msvc_runtime {
        return output::CompilerInfo {
            name: "MSVC".to_string(),
            confidence: "Medium".to_string(),
        };
    }

    // 7. GCC/MinGW
    let has_gcc_lib = pe.libraries.iter().any(|lib| {
        let l = lib.to_lowercase();
        l.starts_with("libgcc") || l.starts_with("libstdc++") || l.starts_with("libwinpthread")
    });
    if has_gcc_lib || bytes_contain(data, b"GCC: (") {
        return output::CompilerInfo {
            name: "GCC/MinGW".to_string(),
            confidence: "Medium".to_string(),
        };
    }

    // 8. Unknown
    output::CompilerInfo {
        name: "Unknown".to_string(),
        confidence: "Low".to_string(),
    }
}

/// Detect packers and protectors via string signatures, section names, and entropy heuristics.
fn detect_packer(pe: &PE, data: &[u8]) -> Vec<output::PackerFinding> {
    let mut findings = Vec::new();

    // Section name helper
    let section_names: Vec<String> = pe
        .sections
        .iter()
        .map(|s| {
            String::from_utf8_lossy(&s.name)
                .trim_end_matches('\0')
                .to_lowercase()
        })
        .collect();

    // String / section-name signature checks
    if bytes_contain(data, b"UPX0")
        || bytes_contain(data, b"UPX1")
        || bytes_contain(data, b"UPX!")
        || section_names.iter().any(|n| n == "upx0" || n == "upx1")
    {
        findings.push(output::PackerFinding {
            name: "UPX".to_string(),
            confidence: "High".to_string(),
            detection_method: "String".to_string(),
        });
    }

    if bytes_contain(data, b"ASPack") || section_names.iter().any(|n| n == ".aspack") {
        findings.push(output::PackerFinding {
            name: "ASPack".to_string(),
            confidence: "High".to_string(),
            detection_method: if bytes_contain(data, b"ASPack") {
                "String".to_string()
            } else {
                "SectionName".to_string()
            },
        });
    }

    if bytes_contain(data, b"Themida") || section_names.iter().any(|n| n == ".themida") {
        findings.push(output::PackerFinding {
            name: "Themida".to_string(),
            confidence: "High".to_string(),
            detection_method: if bytes_contain(data, b"Themida") {
                "String".to_string()
            } else {
                "SectionName".to_string()
            },
        });
        // TODO: advanced packer detection — integrate YARA rules for Themida/WinLicense
    }

    if bytes_contain(data, b"VMProtect")
        || section_names.iter().any(|n| n == ".vmp0" || n == ".vmp1")
    {
        findings.push(output::PackerFinding {
            name: "VMProtect".to_string(),
            confidence: "High".to_string(),
            detection_method: if bytes_contain(data, b"VMProtect") {
                "String".to_string()
            } else {
                "SectionName".to_string()
            },
        });
        // TODO: advanced packer detection — integrate YARA rules for VMProtect
    }

    if section_names
        .iter()
        .any(|n| n == "mpress1" || n == "mpress2")
    {
        findings.push(output::PackerFinding {
            name: "MPRESS".to_string(),
            confidence: "High".to_string(),
            detection_method: "SectionName".to_string(),
        });
    }

    // UPX entry-point heuristic: EP before first section start
    if findings.iter().all(|f| f.name != "UPX")
        && let Some(first_section) = pe.sections.first()
        && pe.entry > 0
        && (pe.entry as u32) < first_section.virtual_address
    {
        findings.push(output::PackerFinding {
            name: "UPX (entry point heuristic)".to_string(),
            confidence: "Medium".to_string(),
            detection_method: "Heuristic".to_string(),
        });
    }

    // Entropy heuristics — only emit if no named packer identified yet
    if findings.is_empty() {
        let section_entropies: Vec<(f64, bool)> = pe
            .sections
            .iter()
            .map(|s| {
                let start = s.pointer_to_raw_data as usize;
                let size = s.size_of_raw_data as usize;
                let entropy = if start + size <= data.len() && size > 0 {
                    calculate_entropy(&data[start..start + size])
                } else {
                    0.0
                };
                let executable = s.characteristics & 0x20000000 != 0;
                (entropy, executable)
            })
            .collect();

        let any_high_exec = section_entropies.iter().any(|(e, exec)| *exec && *e > 7.0);
        if any_high_exec {
            findings.push(output::PackerFinding {
                name: "high entropy executable section".to_string(),
                confidence: "Medium".to_string(),
                detection_method: "Entropy".to_string(),
            });
        }

        if !section_entropies.is_empty() && section_entropies.iter().all(|(e, _)| *e > 6.5) {
            findings.push(output::PackerFinding {
                name: "possible packed binary".to_string(),
                confidence: "Medium".to_string(),
                detection_method: "Entropy".to_string(),
            });
        }
    }

    findings
}

/// Detect anti-analysis techniques via import names.
///
/// String-based VM/sandbox detection requires the extracted strings to be passed in.
/// TODO: string-based anti-analysis detection requires string extraction pass to be passed into detect_anti_analysis
fn detect_anti_analysis(pe: &PE) -> Vec<output::AntiAnalysisFinding> {
    let mut findings = Vec::new();

    // VM / environment detection APIs.
    // GetSystemFirmwareTable is removed to Tier 2 (noteworthy) — too common in legitimate software.
    let vm_detection_apis: &[&str] = &[
        "NtQuerySystemInformation",
        "SetupDiGetClassDevs",
        "SetupDiGetClassDevsA",
        "SetupDiGetClassDevsW",
        "EnumDisplayDevices",
        "EnumDisplayDevicesA",
        "EnumDisplayDevicesW",
    ];

    // High-signal debugger detection APIs only.
    // IsDebuggerPresent, CheckRemoteDebuggerPresent, OutputDebugString, DebugBreak
    // are in Tier 2 (noteworthy) because they appear in many legitimate binaries.
    // Only escalate to anti-analysis when combined with the high-signal APIs below.
    let debugger_detection_apis: &[&str] = &[
        "NtQueryInformationProcess",
        "ZwSetInformationThread",
        "NtSetInformationThread",
    ];

    // Timing-based anti-debug/sandbox evasion.
    // QueryPerformanceCounter removed (Tier 3 — ubiquitous performance counter, no signal).
    let timing_apis: &[&str] = &[
        "GetTickCount",
        "GetTickCount64",
        "NtDelayExecution",
        "timeGetTime",
    ];

    for import in &pe.imports {
        let name = import.name.as_ref();

        if vm_detection_apis
            .iter()
            .any(|&api| api.eq_ignore_ascii_case(name))
        {
            findings.push(output::AntiAnalysisFinding {
                category: "VmDetection".to_string(),
                indicator: name.to_string(),
            });
        } else if debugger_detection_apis
            .iter()
            .any(|&api| api.eq_ignore_ascii_case(name))
        {
            findings.push(output::AntiAnalysisFinding {
                category: "DebuggerDetection".to_string(),
                indicator: name.to_string(),
            });
        } else if timing_apis
            .iter()
            .any(|&api| api.eq_ignore_ascii_case(name))
        {
            findings.push(output::AntiAnalysisFinding {
                category: "TimingCheck".to_string(),
                indicator: name.to_string(),
            });
        }
    }

    // TODO: sleep loop detection requires disassembler integration (e.g. capstone-rs)

    findings
}

// ─── Authenticode + Version Info ─────────────────────────────────────────────

/// Extract Authenticode signature information from the PE Security Directory (data dir index 4).
///
/// The Security Directory's virtual_address field is a FILE OFFSET (PE spec special case).
/// We parse the WIN_CERTIFICATE header and heuristically extract CN= strings from the PKCS#7
/// blob.  Full cryptographic chain validation is not performed.
///
/// TODO: full PKCS#7 parsing — integrate the `cms` + `der` crates for accurate extraction.
fn check_authenticode(data: &[u8], pe: &PE) -> output::AuthenticodeInfo {
    let absent = output::AuthenticodeInfo {
        present: false,
        signer_cn: None,
        issuer_cn: None,
        is_microsoft_signed: false,
        cert_size: 0,
        status: Some("Absent".to_string()),
        issuer: None,
        not_after: None,
    };

    let oh = match pe.header.optional_header.as_ref() {
        Some(oh) => oh,
        None => return absent,
    };

    let cert_dd = match oh.data_directories.get_certificate_table() {
        Some(dd) if dd.virtual_address != 0 && dd.size > 0 => dd,
        _ => return absent,
    };

    let cert_file_offset = cert_dd.virtual_address as usize;
    if cert_file_offset + 8 > data.len() {
        // Block present but truncated — report presence without detail
        return output::AuthenticodeInfo {
            present: true,
            signer_cn: None,
            issuer_cn: None,
            is_microsoft_signed: false,
            cert_size: cert_dd.size,
            status: Some("Present".to_string()),
            issuer: None,
            not_after: None,
        };
    }

    // WIN_CERTIFICATE:  dwLength(4) | wRevision(2) | wCertificateType(2) | bCertificate[…]
    let dw_length = u32::from_le_bytes(
        data[cert_file_offset..cert_file_offset + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let cert_end = (cert_file_offset + dw_length as usize).min(data.len());
    let blob = if cert_file_offset + 8 < cert_end {
        &data[cert_file_offset + 8..cert_end]
    } else {
        &[]
    };

    // Heuristic: scan for ASCII "CN=" patterns in the DER/PKCS#7 blob.
    // The first occurrence is the signer subject; the second is the issuer.
    // TODO: full PKCS#7 parsing for accurate subject/issuer extraction.
    let signer_cn = extract_cn_ascii(blob, 1);
    let issuer_cn = extract_cn_ascii(blob, 2);

    let is_microsoft_signed = signer_cn
        .as_deref()
        .map(|s| s.contains("Microsoft"))
        .unwrap_or(false);

    // Determine status: Self-signed if signer == issuer, otherwise Present
    let status = if signer_cn.is_some() && signer_cn == issuer_cn {
        "Self-signed".to_string()
    } else {
        "Present".to_string()
    };

    let issuer_for_new_field = issuer_cn.clone();

    output::AuthenticodeInfo {
        present: true,
        signer_cn,
        issuer_cn,
        is_microsoft_signed,
        cert_size: cert_dd.size,
        status: Some(status),
        issuer: issuer_for_new_field,
        not_after: None, // Full PKCS#7 parsing needed for expiry date
    }
}

/// Scan a byte slice for the N-th occurrence of an ASCII "CN=" pattern and return
/// the printable ASCII string that follows it (up to 128 chars or the next comma/null).
fn extract_cn_ascii(blob: &[u8], occurrence: usize) -> Option<String> {
    let needle = b"CN=";
    let mut found = 0usize;
    let mut pos = 0usize;

    while pos + 3 <= blob.len() {
        if &blob[pos..pos + 3] == needle {
            found += 1;
            if found == occurrence {
                let start = pos + 3;
                let end = blob[start..]
                    .iter()
                    .position(|&b| b == b',' || b == b'\0' || b == b'\n' || b == b'/')
                    .map(|p| (start + p).min(start + 128))
                    .unwrap_or((start + 128).min(blob.len()));
                let bytes = &blob[start..end];
                // Only keep runs that look like printable ASCII text
                if bytes.iter().all(|&b| (0x20..0x7f).contains(&b)) && !bytes.is_empty() {
                    return Some(String::from_utf8_lossy(bytes).into_owned());
                }
                return None;
            }
        }
        pos += 1;
    }
    None
}

/// Display Authenticode signature info.
fn print_authenticode_info(auth: &output::AuthenticodeInfo, _output_level: OutputLevel) {
    println!("\n{}", "Authenticode Signature:".bold());
    if !auth.present {
        println!(
            "  {} Not signed (no Authenticode signature found)",
            "✗".normal()
        );
        return;
    }
    println!("  {} Signature block present", "✓".green());
    if let Some(cn) = &auth.signer_cn {
        let label = if auth.is_microsoft_signed {
            format!("{} (Microsoft-signed)", cn.green())
        } else {
            cn.normal().to_string()
        };
        println!("  Signer:  {}", label);
    } else {
        println!("  Signer:  unknown");
    }
    if let Some(cn) = &auth.issuer_cn {
        println!("  Issuer:  {}", cn);
    }
    println!("  Note:    cryptographic chain validation not performed");
}

// ─── Version Information (VS_VERSIONINFO resource) ───────────────────────────

/// Minimal resource directory walker to find RT_VERSION (type 16) data.
/// Returns the raw bytes of the first VS_VERSIONINFO resource leaf, or None.
fn find_version_resource<'a>(data: &'a [u8], pe: &PE) -> Option<&'a [u8]> {
    // Find the .rsrc section
    let rsrc = pe.sections.iter().find(|s| {
        let name = String::from_utf8_lossy(&s.name);
        name.trim_end_matches('\0') == ".rsrc"
    })?;

    let rsrc_offset = rsrc.pointer_to_raw_data as usize;
    let rsrc_size = rsrc.size_of_raw_data as usize;
    let rsrc_rva = rsrc.virtual_address as usize;

    if rsrc_offset + rsrc_size > data.len() || rsrc_size < 16 {
        return None;
    }
    let rsrc_data = &data[rsrc_offset..rsrc_offset + rsrc_size];

    // Helper: read u16/u32 little-endian from rsrc_data at a given offset
    let read_u16 = |off: usize| -> u16 {
        if off + 2 <= rsrc_data.len() {
            u16::from_le_bytes([rsrc_data[off], rsrc_data[off + 1]])
        } else {
            0
        }
    };
    let read_u32 = |off: usize| -> u32 {
        if off + 4 <= rsrc_data.len() {
            u32::from_le_bytes(rsrc_data[off..off + 4].try_into().unwrap_or([0; 4]))
        } else {
            0
        }
    };

    // IMAGE_RESOURCE_DIRECTORY header: 16 bytes + entries (each 8 bytes)
    let parse_dir_entries = |dir_off: usize| -> Vec<(u32, u32)> {
        if dir_off + 16 > rsrc_data.len() {
            return vec![];
        }
        let n_named = read_u16(dir_off + 12) as usize;
        let n_id = read_u16(dir_off + 14) as usize;
        let total = n_named + n_id;
        let mut entries = Vec::with_capacity(total);
        for i in 0..total {
            let entry_off = dir_off + 16 + i * 8;
            if entry_off + 8 > rsrc_data.len() {
                break;
            }
            let name_or_id = read_u32(entry_off);
            let offset_or_data = read_u32(entry_off + 4);
            entries.push((name_or_id, offset_or_data));
        }
        entries
    };

    // Level 1: find type RT_VERSION (id = 16)
    let root_entries = parse_dir_entries(0);
    let rt_version_off = root_entries.iter().find_map(|&(id, off)| {
        // id entries have high bit clear; id & 0xFFFF == 16
        if id & 0x8000_0000 == 0 && (id & 0xFFFF) == 16 {
            if off & 0x8000_0000 != 0 {
                Some((off & 0x7FFF_FFFF) as usize)
            } else {
                None
            }
        } else {
            None
        }
    })?;

    // Level 2: take first entry (resource name/id)
    let lvl2_entries = parse_dir_entries(rt_version_off);
    let (_, lvl2_off) = lvl2_entries.first()?;
    if lvl2_off & 0x8000_0000 == 0 {
        return None; // expected subdirectory
    }
    let lang_dir_off = (lvl2_off & 0x7FFF_FFFF) as usize;

    // Level 3: take first language entry
    let lvl3_entries = parse_dir_entries(lang_dir_off);
    let (_, data_entry_off) = lvl3_entries.first()?;
    if data_entry_off & 0x8000_0000 != 0 {
        return None; // expected data entry, not subdirectory
    }
    let de_off = *data_entry_off as usize;

    // IMAGE_RESOURCE_DATA_ENTRY: OffsetToData(4) | Size(4) | CodePage(4) | Reserved(4)
    if de_off + 8 > rsrc_data.len() {
        return None;
    }
    let data_rva = read_u32(de_off) as usize;
    let data_size = read_u32(de_off + 4) as usize;

    // Convert RVA → file offset within the original `data` buffer
    if data_rva < rsrc_rva {
        return None;
    }
    let file_off = rsrc_offset + (data_rva - rsrc_rva);
    if file_off + data_size > data.len() || data_size == 0 {
        return None;
    }
    Some(&data[file_off..file_off + data_size])
}

/// Extract a UTF-16LE string value following a given key in VS_VERSIONINFO bytes.
///
/// Approach: find the UTF-16LE encoding of `key`, skip past the null terminator,
/// skip alignment padding, then read the next UTF-16LE string as the value.
/// This is a heuristic scan — not a full VS_VERSIONINFO parser.
fn extract_version_string(ver_bytes: &[u8], key: &str) -> Option<String> {
    // Encode key as null-terminated UTF-16LE
    let pattern: Vec<u8> = key
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let pos = ver_bytes
        .windows(pattern.len())
        .position(|w| w == pattern.as_slice())?;

    // Skip past the key's null terminator; pos already points to start of key
    let after_key = pos + pattern.len();

    // Skip zero-padding bytes to reach the value (align to 4-byte boundary from ver_bytes start)
    let mut val_start = after_key;
    // Consume at most 6 padding bytes (typical alignment is 0–3 bytes)
    let pad_limit = val_start + 6;
    while val_start + 1 < ver_bytes.len() && val_start < pad_limit {
        if ver_bytes[val_start] != 0 || ver_bytes[val_start + 1] != 0 {
            break;
        }
        val_start += 2;
    }

    // Read UTF-16LE chars until double-null or end of buffer
    let chars: Vec<u16> = ver_bytes[val_start..]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .take(256)
        .collect();

    if chars.is_empty() {
        return None;
    }
    let s = String::from_utf16_lossy(&chars);
    // Sanity-check: at least one printable ASCII character
    if s.chars().any(|c| c.is_ascii_graphic()) {
        Some(s)
    } else {
        None
    }
}

/// Extract VS_VERSIONINFO StringFileInfo fields from the PE .rsrc section.
///
/// Uses heuristic UTF-16LE key scanning rather than a full VS_VERSIONINFO parser.
fn extract_version_info(pe: &PE, data: &[u8]) -> Option<output::VersionInfo> {
    let ver_bytes = find_version_resource(data, pe)?;

    let get = |key: &str| extract_version_string(ver_bytes, key);

    let vi = output::VersionInfo {
        company_name: get("CompanyName"),
        product_name: get("ProductName"),
        file_description: get("FileDescription"),
        file_version: get("FileVersion"),
        original_filename: get("OriginalFilename"),
        legal_copyright: get("LegalCopyright"),
    };

    // Only return if we found at least one field
    if vi.company_name.is_some()
        || vi.product_name.is_some()
        || vi.file_description.is_some()
        || vi.file_version.is_some()
        || vi.original_filename.is_some()
    {
        Some(vi)
    } else {
        None
    }
}

/// Display version information.
fn print_version_info(vi: &Option<output::VersionInfo>, _output_level: OutputLevel) {
    let vi = match vi {
        Some(v) => v,
        None => return, // skip section entirely if no RT_VERSION resource
    };
    println!("\n{}", "Version Information:".bold());
    if let Some(v) = &vi.product_name {
        println!("  Product:   {}", v);
    }
    if let Some(v) = &vi.company_name {
        println!("  Company:   {}", v);
    }
    if let Some(v) = &vi.file_version {
        println!("  Version:   {}", v);
    }
    if let Some(v) = &vi.original_filename {
        println!("  Filename:  {}", v);
    }
    if let Some(v) = &vi.file_description {
        println!("  Desc:      {}", v);
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

// ─── New v1.0.2 analysis functions ───────────────────────────────────────────

/// Classify a section name as "Normal", "Elevated", or "Suspicious"
fn classify_section_name(name: &str, entropy: f64) -> String {
    const STANDARD_NAMES: &[&str] = &[
        ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".bss",
        ".edata", ".idata", ".tls", ".debug", ".ndata",
        "CODE", "DATA", "BSS",
    ];
    const PACKER_NAMES: &[&str] = &[
        ".MPRESS1", ".MPRESS2", "UPX0", "UPX1", ".themida",
        ".vmp0", ".vmp1", ".vmp2", ".packed", ".shrink", "ASPack",
    ];

    let name_upper = name.to_uppercase();
    if PACKER_NAMES.iter().any(|p| p.to_uppercase() == name_upper) {
        return "Suspicious".to_string();
    }

    let is_standard = STANDARD_NAMES.iter().any(|s| s.to_uppercase() == name_upper);
    if is_standard {
        if entropy > 7.0 {
            "Suspicious".to_string()
        } else if entropy > 5.0 {
            "Elevated".to_string()
        } else {
            "Normal".to_string()
        }
    } else if entropy > 7.0 {
        "Suspicious".to_string()
    } else if entropy > 5.0 {
        "Elevated".to_string()
    } else {
        "Normal".to_string()
    }
}

/// Extract debug artifacts from PE debug directory
fn extract_debug_artifacts(
    data: &[u8],
    pe: &PE,
    version_info: &Option<output::VersionInfo>,
) -> output::DebugArtifacts {
    let timestamp_zeroed = pe.header.coff_header.time_date_stamp == 0;

    // Extract PDB path from CODEVIEW debug entry
    let pdb_path = pe.debug_data.as_ref().and_then(|debug| {
        debug.codeview_pdb70_debug_info.as_ref().map(|cv| {
            String::from_utf8_lossy(&cv.filename).trim_end_matches('\0').to_string()
        })
    });

    // Check version info for suspicious repeated characters
    let version_info_suspicious = version_info.as_ref().map(|vi| {
        let fields = [
            &vi.company_name, &vi.product_name, &vi.file_description,
            &vi.file_version, &vi.original_filename, &vi.legal_copyright,
        ];
        fields.iter().any(|f| {
            if let Some(val) = f {
                if !val.is_empty() {
                    let chars: std::collections::HashSet<char> = val.chars().collect();
                    chars.len() <= 1
                } else {
                    false
                }
            } else {
                false
            }
        })
    }).unwrap_or(false);

    output::DebugArtifacts {
        pdb_path,
        timestamp_zeroed,
        version_info_suspicious,
    }
}

/// Detect weak cryptography constants in binary data
fn detect_weak_crypto(data: &[u8]) -> Vec<output::WeakCryptoIndicator> {
    let mut indicators = Vec::new();

    // MD5 init constants: 0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476
    let md5_init: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    if let Some(pos) = data.windows(16).position(|w| w == md5_init) {
        indicators.push(output::WeakCryptoIndicator {
            name: "MD5 init constants".to_string(),
            evidence: "MD5 initialisation vector found — may implement custom MD5 hashing".to_string(),
            offset: Some(format!("0x{:06X}", pos)),
        });
    }

    // AES S-box first 16 bytes
    let aes_sbox: [u8; 16] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ];
    if let Some(pos) = data.windows(16).position(|w| w == aes_sbox) {
        indicators.push(output::WeakCryptoIndicator {
            name: "AES S-box constants".to_string(),
            evidence: "AES substitution box found — custom AES implementation".to_string(),
            offset: Some(format!("0x{:06X}", pos)),
        });
    }

    indicators
}

/// Infer compiler dependencies from compiler name and imported libraries
fn infer_compiler_deps(compiler: &str, libraries: &[String]) -> Vec<output::CompilerDep> {
    let mut deps = Vec::new();
    let compiler_lower = compiler.to_lowercase();
    let libs_lower: Vec<String> = libraries.iter().map(|l| l.to_lowercase()).collect();

    if compiler_lower.contains("delphi") || compiler_lower.contains("borland") {
        deps.push(output::CompilerDep {
            name: "Borland RTL".to_string(),
            description: "Borland runtime library".to_string(),
            risk: "Expected".to_string(),
        });
        if libs_lower.iter().any(|l| l.contains("ws2_32") || l.contains("wsock32")) {
            deps.push(output::CompilerDep {
                name: "Network socket capability".to_string(),
                description: "ws2_32.dll present in a Delphi application".to_string(),
                risk: "Uncommon".to_string(),
            });
        }
    } else if compiler_lower.contains("msvc") {
        deps.push(output::CompilerDep {
            name: "MSVC CRT".to_string(),
            description: "Microsoft Visual C++ runtime".to_string(),
            risk: "Expected".to_string(),
        });
        for lib in &libs_lower {
            if lib.starts_with("msvcr") || lib.starts_with("vcruntime") || lib.starts_with("ucrtbase") {
                deps.push(output::CompilerDep {
                    name: lib.clone(),
                    description: "Visual C++ runtime library".to_string(),
                    risk: "Expected".to_string(),
                });
                break;
            }
        }
    } else if compiler_lower.contains("go") {
        deps.push(output::CompilerDep {
            name: "Go runtime".to_string(),
            description: "Self-contained binary, imports minimal system APIs".to_string(),
            risk: "Expected".to_string(),
        });
    } else if compiler_lower.contains("rust") {
        deps.push(output::CompilerDep {
            name: "Rust stdlib".to_string(),
            description: "Memory-safe runtime, typically statically linked".to_string(),
            risk: "Expected".to_string(),
        });
    }

    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_apis_list_not_empty() {
        assert!(!SUSPICIOUS_APIS_TIER1.is_empty());
        // Combined Tier 1 + Tier 2 should still be > 30
        assert!(SUSPICIOUS_APIS_TIER1.len() + NOTEWORTHY_APIS.len() > 30);
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
        // Tier 1 — injection / high-signal APIs
        assert!(SUSPICIOUS_APIS_TIER1.contains(&"CreateRemoteThread"));
        assert!(SUSPICIOUS_APIS_TIER1.contains(&"WriteProcessMemory"));
        assert!(SUSPICIOUS_APIS_TIER1.contains(&"VirtualAllocEx"));
        assert!(SUSPICIOUS_APIS_TIER1.contains(&"RegSetValueEx"));
        assert!(SUSPICIOUS_APIS_TIER1.contains(&"URLDownloadToFile"));
        // IsDebuggerPresent is Tier 2 (noteworthy, not suspicious)
        assert!(!SUSPICIOUS_APIS_TIER1.contains(&"IsDebuggerPresent"));
        assert!(NOTEWORTHY_APIS.contains(&"IsDebuggerPresent"));
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

    #[test]
    fn test_is_suspicious_api() {
        // Code injection APIs
        assert!(is_suspicious_api("CreateRemoteThread"));
        assert!(is_suspicious_api("VirtualAllocEx"));
        assert!(is_suspicious_api("WriteProcessMemory"));
        assert!(is_suspicious_api("NtQueueApcThread"));

        // Persistence APIs
        assert!(is_suspicious_api("RegSetValueEx"));
        assert!(is_suspicious_api("CreateService"));

        // IsDebuggerPresent and CheckRemoteDebuggerPresent are now Tier 2 (noteworthy)
        assert!(!is_suspicious_api("IsDebuggerPresent"));
        assert!(!is_suspicious_api("CheckRemoteDebuggerPresent"));
        assert!(is_noteworthy_api("IsDebuggerPresent"));
        assert!(is_noteworthy_api("CheckRemoteDebuggerPresent"));

        // Network
        assert!(is_suspicious_api("InternetOpen"));
        assert!(is_suspicious_api("URLDownloadToFile"));

        // Not suspicious
        assert!(!is_suspicious_api("CreateFileA"));
        assert!(!is_suspicious_api("GetProcAddress"));
        assert!(!is_suspicious_api("LoadLibraryA"));
        assert!(!is_suspicious_api("printf"));
    }

    #[test]
    fn test_categorize_all_categories() {
        // Code Injection
        assert_eq!(categorize_api("CreateRemoteThread"), "Code Injection");
        assert_eq!(categorize_api("WriteProcessMemory"), "Code Injection");
        assert_eq!(categorize_api("VirtualAllocEx"), "Code Injection");

        // Persistence
        assert_eq!(categorize_api("RegSetValueEx"), "Persistence Mechanism");
        assert_eq!(categorize_api("RegCreateKeyEx"), "Persistence Mechanism");
        assert_eq!(categorize_api("CreateService"), "Persistence Mechanism");

        // Anti-Analysis
        assert_eq!(categorize_api("IsDebuggerPresent"), "Anti-Analysis");
        assert_eq!(
            categorize_api("CheckRemoteDebuggerPresent"),
            "Anti-Analysis"
        );
        assert_eq!(categorize_api("NtQueryInformationProcess"), "Anti-Analysis");

        // Network
        assert_eq!(categorize_api("InternetOpen"), "Network Activity");
        assert_eq!(categorize_api("InternetOpenUrl"), "Network Activity");
        assert_eq!(categorize_api("URLDownloadToFile"), "Network Activity");

        // Crypto
        assert_eq!(categorize_api("CryptEncrypt"), "Cryptography");
        assert_eq!(categorize_api("CryptDecrypt"), "Cryptography");
        assert_eq!(categorize_api("CryptHashData"), "Cryptography");

        // Keylogging
        assert_eq!(
            categorize_api("GetAsyncKeyState"),
            "Keylogging/Input Monitoring"
        );
        assert_eq!(
            categorize_api("SetWindowsHookExA"),
            "Keylogging/Input Monitoring"
        );

        // Privilege Escalation
        assert_eq!(
            categorize_api("AdjustTokenPrivileges"),
            "Privilege Escalation"
        );
        assert_eq!(categorize_api("OpenProcessToken"), "Privilege Escalation");

        // Default
        assert_eq!(categorize_api("CreateFileA"), "File/System Operation");
        assert_eq!(categorize_api("unknown_function"), "File/System Operation");
    }

    #[test]
    fn test_categorize_api_case_insensitive() {
        assert_eq!(categorize_api("createremotethread"), "Code Injection");
        assert_eq!(categorize_api("CREATEREMOTETHREAD"), "Code Injection");
        assert_eq!(categorize_api("CreateRemoteThread"), "Code Injection");
    }

    #[test]
    fn test_suspicious_apis_list_complete() {
        // Combined Tier 1 + Tier 2 should have comprehensive coverage
        let combined: Vec<&str> = SUSPICIOUS_APIS_TIER1
            .iter()
            .chain(NOTEWORTHY_APIS.iter())
            .copied()
            .collect();
        assert!(
            combined.len() > 30,
            "Should have 30+ APIs across both tiers"
        );

        // Verify no duplicates within Tier 1
        use std::collections::HashSet;
        let set: HashSet<_> = SUSPICIOUS_APIS_TIER1.iter().collect();
        assert_eq!(
            set.len(),
            SUSPICIOUS_APIS_TIER1.len(),
            "No Tier1 duplicates"
        );
    }

    #[test]
    fn test_all_categories_covered() {
        // Ensure each category has at least one API across both tiers
        let all_apis: Vec<&str> = SUSPICIOUS_APIS_TIER1
            .iter()
            .chain(NOTEWORTHY_APIS.iter())
            .copied()
            .collect();
        let categories = vec![
            "Code Injection",
            "Persistence Mechanism",
            "Anti-Analysis",
            "Network Activity",
            "Cryptography",
            "Keylogging/Input Monitoring",
            "Privilege Escalation",
        ];

        for category in categories {
            let has_api = all_apis.iter().any(|api| categorize_api(api) == category);
            assert!(
                has_api,
                "Category '{}' should have at least one API",
                category
            );
        }
    }

    // ── is_noteworthy_api ────────────────────────────────────────────────────

    #[test]
    fn test_is_noteworthy_api_returns_true_for_tier2() {
        assert!(is_noteworthy_api("OpenProcess"));
        assert!(is_noteworthy_api("OpenProcessToken"));
        assert!(is_noteworthy_api("AdjustTokenPrivileges"));
        assert!(is_noteworthy_api("CryptEncrypt"));
        assert!(is_noteworthy_api("CryptDecrypt"));
        assert!(is_noteworthy_api("DeleteFile"));
        assert!(is_noteworthy_api("WSAStartup"));
        assert!(is_noteworthy_api("socket"));
        assert!(is_noteworthy_api("connect"));
    }

    #[test]
    fn test_is_noteworthy_api_returns_false_for_unknown() {
        assert!(!is_noteworthy_api("GetProcAddress"));
        assert!(!is_noteworthy_api("LoadLibraryA"));
        assert!(!is_noteworthy_api("printf"));
        assert!(!is_noteworthy_api("malloc"));
    }

    #[test]
    fn test_is_noteworthy_api_returns_false_for_tier1() {
        // Tier 1 (suspicious) APIs are NOT in the noteworthy list
        assert!(!is_noteworthy_api("CreateRemoteThread"));
        assert!(!is_noteworthy_api("WriteProcessMemory"));
        assert!(!is_noteworthy_api("VirtualAllocEx"));
        assert!(!is_noteworthy_api("URLDownloadToFile"));
    }

    #[test]
    fn test_is_noteworthy_api_case_insensitive() {
        assert!(is_noteworthy_api("OPENPROCESS"));
        assert!(is_noteworthy_api("openprocess"));
        assert!(is_noteworthy_api("OpenProcess"));
    }
}
