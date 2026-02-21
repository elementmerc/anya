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

use goblin::pe::PE;
use anyhow::Result;
use colored::*;

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

/// Analyse and display detailed information
pub fn analyze_pe(data: &[u8]) -> Result<()> {
    let pe = PE::parse(data)?;
    
    println!("{}", "=== PE File Analysis ===".bold().cyan());
    
    // Basic PE info
    print_pe_header_info(&pe);
    
    // Analyze sections
    print_sections(&pe, data);
    
    // Analyze imports
    print_imports(&pe);
    
    // Analyze exports
    print_exports(&pe);
    
    Ok(())
}

/// Display PE header information
fn print_pe_header_info(pe: &PE) {
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
fn print_sections(pe: &PE, data: &[u8]) {
    println!("\n{}", "Section Analysis:".bold());
    println!("  {:<12} {:<10} {:<10} {:<10} {:<10}", 
             "Name", "VirtSize", "VirtAddr", "RawSize", "Entropy");
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
        
        println!("  {:<12} {:<10} 0x{:<8X} {:<10} {}", 
                 name,
                 section.virtual_size,
                 section.virtual_address,
                 section.size_of_raw_data,
                 entropy_str);
        
        // Flag suspicious characteristics
        let characteristics = section.characteristics;
        
        // Writable + Executable is very suspicious
        let writable = characteristics & 0x80000000 != 0;
        let executable = characteristics & 0x20000000 != 0;
        
        if writable && executable {
            println!("    {} Section is both writable and executable (highly suspicious!)", 
                     "⚠".red().bold());
        }
    }
}

/// Analyse and display imported functions
fn print_imports(pe: &PE) {
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
    println!("  Suspicious APIs: {}", 
             if suspicious_count > 0 {
                 format!("{} ⚠", suspicious_count).red().to_string()
             } else {
                 format!("{}", suspicious_count)
             });
    
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
        "CreateRemoteThread" | "WriteProcessMemory" | "VirtualAllocEx" | "QueueUserAPC" | "NtQueueApcThread" | "RtlCreateUserThread" 
            => "Code Injection",
        
        "RegSetValueEx" | "RegCreateKeyEx" | "CreateService" | "StartService"
            => "Persistence Mechanism",
        
        "IsDebuggerPresent" | "CheckRemoteDebuggerPresent" | "OutputDebugString" | "NtQueryInformationProcess"
            => "Anti-Analysis",
        
        "InternetOpen" | "InternetOpenUrl" | "URLDownloadToFile" | "WinHttpOpen" | "socket" | "connect"
            => "Network Activity",
        
        "CryptEncrypt" | "CryptDecrypt" | "CryptAcquireContext"
            => "Cryptography",
        
        "GetAsyncKeyState" | "SetWindowsHookExA" | "GetForegroundWindow"
            => "Keylogging/Input Monitoring",
        
        "AdjustTokenPrivileges" | "OpenProcessToken"
            => "Privilege Escalation",
        
        _ => "File/System Operation",
    }
}

/// Analyse and display exported functions (for DLLs)
fn print_exports(pe: &PE) {
    if pe.exports.is_empty() {
        return;
    }
    
    println!("\n{}", "Export Analysis:".bold());
    println!("  Total Exports: {}", pe.exports.len());
    
    // Show first 20 exports
    println!("\n  Exported Functions (showing first 20):");
    for (i, export) in pe.exports.iter().take(20).enumerate() {
        // export.name is Option<Cow<str>>, we need to get &str from it
        let name = export.name.as_ref().map(|s| s.as_ref()).unwrap_or("<unnamed>");
        println!("    {} 0x{:08X}: {}", 
                 i + 1, 
                 export.rva,
                 name);
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