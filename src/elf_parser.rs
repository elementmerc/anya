// Ányá - Malware Analysis Platform
// ELF analysis module
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use crate::OutputLevel;
use crate::output;
use crate::pe_parser::is_suspicious_api;
use anyhow::{Context, Result};
use colored::*;
use goblin::elf::Elf;

// ─── ELF architecture / type helpers ─────────────────────────────────────────

fn elf_machine_to_str(e_machine: u16) -> &'static str {
    match e_machine {
        0x03 => "x86 (32-bit)",
        0x28 => "ARM (32-bit)",
        0x3E => "x86_64",
        0xB7 => "AArch64 (ARM64)",
        0xF3 => "RISC-V",
        0x08 => "MIPS",
        0x14 => "PowerPC (32-bit)",
        0x15 => "PowerPC (64-bit)",
        0x16 => "S390",
        _ => "Unknown",
    }
}

fn elf_type_to_str(e_type: u16) -> &'static str {
    match e_type {
        1 => "Relocatable",
        2 => "Executable",
        3 => "Shared Object",
        4 => "Core",
        _ => "Unknown",
    }
}

fn elf_section_type_to_str(sh_type: u32) -> &'static str {
    match sh_type {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        _ => "OTHER",
    }
}

// ─── Entropy (local copy to avoid cross-module dep) ──────────────────────────

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
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ─── Security feature detection ──────────────────────────────────────────────

/// Returns (is_pie, has_nx_stack, has_relro).
fn detect_elf_security(elf: &Elf) -> (bool, bool, bool) {
    // PIE: shared object type with non-zero entry point
    let is_pie = elf.header.e_type == 3 /* ET_DYN */ && elf.header.e_entry != 0;

    // PT_GNU_STACK (0x6474e551): NX = PF_X flag NOT set (PF_X = 0x1)
    const PT_GNU_STACK: u32 = 0x6474e551;
    const PT_GNU_RELRO: u32 = 0x6474e552;
    const PF_X: u32 = 0x1;

    let mut has_nx_stack = false;
    let mut has_relro = false;

    for ph in &elf.program_headers {
        if ph.p_type == PT_GNU_STACK {
            // NX stack = execute bit NOT set in GNU_STACK segment
            has_nx_stack = ph.p_flags & PF_X == 0;
        }
        if ph.p_type == PT_GNU_RELRO {
            has_relro = true;
        }
    }

    (is_pie, has_nx_stack, has_relro)
}

// ─── Section analysis ─────────────────────────────────────────────────────────

fn analyse_elf_sections(elf: &Elf, data: &[u8]) -> Vec<output::ElfSectionInfo> {
    const SHF_WRITE: u64 = 0x1;
    const SHF_EXECINSTR: u64 = 0x4;

    elf.section_headers
        .iter()
        .map(|sh| {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("<unnamed>")
                .to_string();

            let section_type = elf_section_type_to_str(sh.sh_type).to_string();

            let offset = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            let entropy = if sh.sh_type != 8 /* SHT_NOBITS */ && size > 0 && offset + size <= data.len() {
                calculate_entropy(&data[offset..offset + size])
            } else {
                0.0
            };

            let is_wx = sh.sh_flags & (SHF_WRITE | SHF_EXECINSTR) == (SHF_WRITE | SHF_EXECINSTR);

            output::ElfSectionInfo {
                name,
                section_type,
                size: sh.sh_size,
                entropy,
                is_wx,
                is_suspicious: entropy > 7.5,
            }
        })
        .collect()
}

// ─── Suspicious Linux function list ──────────────────────────────────────────

const SUSPICIOUS_LINUX_FUNCTIONS: &[&str] = &[
    "ptrace",
    "mprotect",
    "mmap",
    "system",
    "execve",
    "execvp",
    "dlopen",
    "dlsym",
    "fork",
    "popen",
    "prctl",
    "__libc_dlopen_mode",
];

fn is_suspicious_elf_function(name: &str) -> bool {
    SUSPICIOUS_LINUX_FUNCTIONS.contains(&name) || is_suspicious_api(name) // reuse the PE suspicious API list for common names
}

// ─── Import analysis ──────────────────────────────────────────────────────────

fn analyse_elf_imports(elf: &Elf) -> output::ElfImportAnalysis {
    let libraries: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();

    let mut suspicious_functions = Vec::new();
    let mut dynamic_symbol_count = 0;

    for sym in elf.dynsyms.iter() {
        // Only imported symbols have no section index (SHN_UNDEF = 0)
        if sym.st_shndx == 0 && sym.st_name != 0 {
            dynamic_symbol_count += 1;
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name)
                && is_suspicious_elf_function(name)
            {
                suspicious_functions.push(output::SuspiciousAPI {
                    name: name.to_string(),
                    category: "Suspicious Linux Function".to_string(),
                    confidence: None,
                });
            }
        }
    }

    output::ElfImportAnalysis {
        library_count: libraries.len(),
        libraries,
        dynamic_symbol_count,
        suspicious_functions,
    }
}

// ─── Packer detection ─────────────────────────────────────────────────────────

fn detect_elf_packers(elf: &Elf, data: &[u8]) -> Vec<output::PackerFinding> {
    let mut findings = Vec::new();

    // UPX string / section name detection
    if bytes_contain(data, b"UPX!") || bytes_contain(data, b"UPX0") {
        findings.push(output::PackerFinding {
            name: "UPX".to_string(),
            confidence: "High".to_string(),
            detection_method: "String".to_string(),
        });
    } else {
        let has_upx_section = elf.section_headers.iter().any(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map(|n| n == "UPX0" || n == "UPX1")
                .unwrap_or(false)
        });
        if has_upx_section {
            findings.push(output::PackerFinding {
                name: "UPX".to_string(),
                confidence: "High".to_string(),
                detection_method: "SectionName".to_string(),
            });
        }
    }

    // Stripped symbol check (informational heuristic)
    // Note: this is not a packer finding but a useful signal.

    findings
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Parse an ELF binary and return structured analysis data.
pub fn analyse_elf_data(data: &[u8]) -> Result<output::ELFAnalysis> {
    let elf = Elf::parse(data).context(
        "This file has an ELF signature but the header appears corrupt or truncated. It may have been modified or damaged.",
    )?;

    let architecture = elf_machine_to_str(elf.header.e_machine).to_string();
    let is_64bit = elf.is_64;
    let file_type = elf_type_to_str(elf.header.e_type).to_string();
    let entry_point = format!("0x{:X}", elf.header.e_entry);
    let interpreter = elf.interpreter.map(|s| s.to_string());

    let (is_pie, has_nx_stack, has_relro) = detect_elf_security(&elf);
    let is_stripped = elf.syms.is_empty();

    let sections = analyse_elf_sections(&elf, data);
    let imports = analyse_elf_imports(&elf);
    let packer_indicators = detect_elf_packers(&elf, data);

    Ok(output::ELFAnalysis {
        architecture,
        is_64bit,
        file_type,
        entry_point,
        interpreter,
        sections,
        imports,
        is_pie,
        has_nx_stack,
        has_relro,
        is_stripped,
        packer_indicators,
        // new fields — populated by analyse_elf_extended() in elf_analysis.rs
        got_plt_suspicious: vec![],
        rpath_anomalies: vec![],
        has_dwarf_info: false,
        interpreter_suspicious: false,
        suspicious_section_names: vec![],
        suspicious_libc_calls: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── elf_machine_to_str ────────────────────────────────────────────────

    #[test]
    fn test_elf_machine_x86_64() {
        assert_eq!(elf_machine_to_str(0x3E), "x86_64");
    }

    #[test]
    fn test_elf_machine_arm32() {
        assert_eq!(elf_machine_to_str(0x28), "ARM (32-bit)");
    }

    #[test]
    fn test_elf_machine_aarch64() {
        assert_eq!(elf_machine_to_str(0xB7), "AArch64 (ARM64)");
    }

    #[test]
    fn test_elf_machine_unknown() {
        assert_eq!(elf_machine_to_str(0xFF), "Unknown");
        assert_eq!(elf_machine_to_str(0x00), "Unknown");
    }

    // ── elf_type_to_str ───────────────────────────────────────────────────

    #[test]
    fn test_elf_type_executable() {
        assert_eq!(elf_type_to_str(2), "Executable");
    }

    #[test]
    fn test_elf_type_shared_object() {
        assert_eq!(elf_type_to_str(3), "Shared Object");
    }

    #[test]
    fn test_elf_type_relocatable() {
        assert_eq!(elf_type_to_str(1), "Relocatable");
    }

    #[test]
    fn test_elf_type_unknown() {
        assert_eq!(elf_type_to_str(99), "Unknown");
    }

    // ── elf_section_type_to_str ───────────────────────────────────────────

    #[test]
    fn test_elf_section_type_progbits() {
        assert_eq!(elf_section_type_to_str(1), "PROGBITS");
    }

    #[test]
    fn test_elf_section_type_symtab() {
        assert_eq!(elf_section_type_to_str(2), "SYMTAB");
    }

    #[test]
    fn test_elf_section_type_null() {
        assert_eq!(elf_section_type_to_str(0), "NULL");
    }

    #[test]
    fn test_elf_section_type_nobits() {
        assert_eq!(elf_section_type_to_str(8), "NOBITS");
    }

    #[test]
    fn test_elf_section_type_other() {
        assert_eq!(elf_section_type_to_str(255), "OTHER");
    }

    // ── calculate_entropy ─────────────────────────────────────────────────

    #[test]
    fn test_entropy_empty_data() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_uniform_bytes() {
        // All same byte → entropy = 0
        let data = vec![0xAA; 1000];
        assert_eq!(calculate_entropy(&data), 0.0);
    }

    #[test]
    fn test_entropy_all_256_values() {
        // Perfect uniform distribution → entropy ≈ 8.0
        let data: Vec<u8> = (0..=255u8).collect();
        let e = calculate_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "Expected ~8.0, got {}", e);
    }

    #[test]
    fn test_entropy_high_for_random_like_data() {
        // Cycling through 256 values many times keeps entropy at max
        let data: Vec<u8> = (0..512u16).map(|i| (i % 256) as u8).collect();
        let e = calculate_entropy(&data);
        assert!(e > 7.9, "Expected near-max entropy, got {}", e);
    }

    // ── bytes_contain ─────────────────────────────────────────────────────

    #[test]
    fn test_bytes_contain_found() {
        assert!(bytes_contain(b"Hello UPX! World", b"UPX!"));
    }

    #[test]
    fn test_bytes_contain_not_found() {
        assert!(!bytes_contain(b"Hello World", b"UPX!"));
    }

    #[test]
    fn test_bytes_contain_at_start() {
        assert!(bytes_contain(b"UPX!rest", b"UPX!"));
    }

    #[test]
    fn test_bytes_contain_at_end() {
        assert!(bytes_contain(b"restUPX!", b"UPX!"));
    }

    #[test]
    #[should_panic]
    fn test_bytes_contain_empty_needle_panics() {
        // slice.windows(0) panics — callers must never pass an empty needle
        bytes_contain(b"anything", b"");
    }

    #[test]
    fn test_bytes_contain_needle_longer_than_haystack() {
        assert!(!bytes_contain(b"AB", b"ABC"));
    }

    // ── is_suspicious_elf_function ────────────────────────────────────────

    #[test]
    fn test_is_suspicious_elf_function_ptrace() {
        assert!(is_suspicious_elf_function("ptrace"));
    }

    #[test]
    fn test_is_suspicious_elf_function_execve() {
        assert!(is_suspicious_elf_function("execve"));
    }

    #[test]
    fn test_is_suspicious_elf_function_dlopen() {
        assert!(is_suspicious_elf_function("dlopen"));
    }

    #[test]
    fn test_is_suspicious_elf_function_not_suspicious() {
        assert!(!is_suspicious_elf_function("printf"));
        assert!(!is_suspicious_elf_function("malloc"));
        assert!(!is_suspicious_elf_function("strlen"));
    }

    #[test]
    fn test_is_suspicious_elf_function_pe_crossover() {
        // PE suspicious APIs also flag as suspicious in ELF context
        assert!(is_suspicious_elf_function("CreateRemoteThread"));
        assert!(is_suspicious_elf_function("WriteProcessMemory"));
    }
}

/// Pretty-print ELF analysis to stdout.
pub fn analyse_elf(data: &[u8], output_level: OutputLevel) -> Result<()> {
    let analysis = analyse_elf_data(data)?;

    println!("{}", "=== ELF File Analysis ===".bold().cyan());

    println!("\n{}", "ELF Header Information:".bold());
    println!("  Architecture:  {}", analysis.architecture);
    println!("  Type:          {}", analysis.file_type);
    println!("  Entry Point:   {}", analysis.entry_point);
    if let Some(ref interp) = analysis.interpreter {
        println!("  Interpreter:   {}", interp);
    }

    println!("\n  Security Features:");
    if analysis.is_pie {
        println!("    {} PIE (Position Independent Executable)", "✓".green());
    } else {
        println!("    {} PIE not enabled", "✗".red());
    }
    if analysis.has_nx_stack {
        println!("    {} NX stack enabled", "✓".green());
    } else {
        println!("    {} NX stack NOT enabled (suspicious)", "✗".red());
    }
    if analysis.has_relro {
        println!("    {} RELRO enabled", "✓".green());
    } else {
        println!("    {} RELRO not enabled", "✗".yellow());
    }
    if analysis.is_stripped {
        println!("    {} Symbol table stripped", "⚠".yellow());
    }

    println!(
        "\n{} ({} sections)",
        "Section Analysis:".bold(),
        analysis.sections.len()
    );
    for section in &analysis.sections {
        if section.size == 0 {
            continue;
        }
        let entropy_str = if section.entropy > 7.5 {
            format!("{:.2} ⚠", section.entropy).red().to_string()
        } else if section.entropy > 6.5 {
            format!("{:.2}", section.entropy).yellow().to_string()
        } else {
            format!("{:.2}", section.entropy).green().to_string()
        };
        println!(
            "  {:<20} {:<12} size={:<10} entropy={}",
            section.name, section.section_type, section.size, entropy_str
        );
        if section.is_wx {
            println!(
                "    {} Section is both writable and executable (highly suspicious!)",
                "⚠".red().bold()
            );
        }
    }

    println!("\n{}", "Import Analysis:".bold());
    println!("  Libraries:       {}", analysis.imports.library_count);
    println!(
        "  Dynamic Symbols: {}",
        analysis.imports.dynamic_symbol_count
    );
    if !analysis.imports.suspicious_functions.is_empty() {
        println!("\n  {} Suspicious Functions Detected:", "⚠".red().bold());
        for f in &analysis.imports.suspicious_functions {
            println!(
                "    {} {} - {}",
                "•".red(),
                f.name.red(),
                f.category.yellow()
            );
        }
    }

    if output_level.should_print_verbose() {
        println!("\n  Linked Libraries:");
        for lib in &analysis.imports.libraries {
            println!("    • {}", lib);
        }
    }

    if !analysis.packer_indicators.is_empty() {
        println!("\n{}", "Packer Indicators:".bold().red());
        for packer in &analysis.packer_indicators {
            println!(
                "  {} {} ({} confidence, via {})",
                "⚠".red(),
                packer.name.red().bold(),
                packer.confidence,
                packer.detection_method
            );
        }
    }

    Ok(())
}
