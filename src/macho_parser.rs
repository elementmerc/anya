// Ányá - Malware Analysis Platform
// Mach-O analysis module
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use crate::output::MachoAnalysis;
use goblin::mach::{Mach, MachO};

// CPU type constants (match goblin's u32 representation)
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_ARM: u32 = 12;

// Header flags
const MH_PIE: u32 = 0x0020_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;

// Load command types
const LC_CODE_SIGNATURE: u32 = 29;
const LC_MAIN: u32 = 0x8000_0028;
const LC_UNIXTHREAD: u32 = 5;
const LC_LOAD_DYLIB: u32 = 12;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;

/// Analyse a Mach-O binary and return structured metadata.
/// Returns `None` if the data does not parse as a valid Mach-O.
pub fn analyse_macho_data(data: &[u8]) -> Option<MachoAnalysis> {
    match Mach::parse(data).ok()? {
        Mach::Binary(macho) => Some(analyse_single(data, &macho)),
        Mach::Fat(multi) => {
            // Universal binary — analyse first Mach-O arch slice
            let mut result: Option<MachoAnalysis> = None;
            for arch in &multi {
                if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch {
                    result = Some(analyse_single(data, &macho));
                    break;
                }
            }
            result.or_else(|| {
                // Could not parse any arch slice — return minimal universal info
                Some(MachoAnalysis {
                    architecture: "universal (fat)".to_string(),
                    is_64bit: false,
                    entry_point: "unknown".to_string(),
                    dylib_imports: vec![],
                    has_code_signature: false,
                    pie_enabled: false,
                    nx_enabled: false,
                })
            })
        }
    }
}

fn analyse_single(data: &[u8], macho: &MachO) -> MachoAnalysis {
    let cputype = macho.header.cputype;
    let flags = macho.header.flags;

    let architecture = match cputype {
        CPU_TYPE_X86_64 => "x86_64".to_string(),
        CPU_TYPE_ARM64 => "arm64".to_string(),
        CPU_TYPE_X86 => "x86 (32-bit)".to_string(),
        CPU_TYPE_ARM => "ARM (32-bit)".to_string(),
        _ => format!("unknown (cputype=0x{:x})", cputype),
    };

    let is_64bit = cputype == CPU_TYPE_X86_64 || cputype == CPU_TYPE_ARM64;
    let pie_enabled = (flags & MH_PIE) != 0;
    let nx_enabled = (flags & MH_NO_HEAP_EXECUTION) != 0;

    let mut has_code_signature = false;
    let mut entry_point = "unknown".to_string();
    let mut dylib_imports: Vec<String> = Vec::new();

    for lc in &macho.load_commands {
        let cmd = lc.command.cmd();
        match cmd {
            LC_CODE_SIGNATURE => {
                has_code_signature = true;
            }
            LC_MAIN => {
                entry_point = format!("0x{:x}", lc.offset);
            }
            LC_UNIXTHREAD => {
                if entry_point == "unknown" {
                    entry_point = format!("0x{:x} (thread)", lc.offset);
                }
            }
            cmd if cmd == LC_LOAD_DYLIB
                || cmd == LC_LOAD_WEAK_DYLIB
                || cmd == LC_REEXPORT_DYLIB =>
            {
                if let Some(name) = extract_dylib_name(data, lc.offset, lc.command.cmdsize()) {
                    dylib_imports.push(name);
                }
            }
            _ => {}
        }
    }

    // Fallback: use goblin's parsed entry point
    if entry_point == "unknown" && macho.entry != 0 {
        entry_point = format!("0x{:x}", macho.entry);
    }

    // Fallback: use goblin's libs if we didn't collect any
    if dylib_imports.is_empty() {
        dylib_imports = macho.libs.iter().map(|s| s.to_string()).collect();
    }

    MachoAnalysis {
        architecture,
        is_64bit,
        entry_point,
        dylib_imports,
        has_code_signature,
        pie_enabled,
        nx_enabled,
    }
}

/// Extract the dylib name string from a load command.
/// The dylib_command struct layout:
///   [0..4]  cmd (u32)
///   [4..8]  cmdsize (u32)
///   [8..12] name.offset (u32) — byte offset from start of lc to the name string
///   [12..16] timestamp, current_version, compatibility_version
fn extract_dylib_name(data: &[u8], cmd_start: usize, _cmdsize: usize) -> Option<String> {
    if cmd_start + 12 > data.len() {
        return None;
    }
    let name_offset =
        u32::from_le_bytes(data[cmd_start + 8..cmd_start + 12].try_into().ok()?) as usize;
    let abs_offset = cmd_start + name_offset;
    if abs_offset >= data.len() {
        return None;
    }
    let name_bytes = &data[abs_offset..];
    let end = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len().min(256));
    let name = std::str::from_utf8(&name_bytes[..end]).ok()?.trim();
    if name.is_empty() {
        return None;
    }
    // Return just the filename component
    let short = name.rsplit('/').next().unwrap_or(name);
    Some(short.to_string())
}
