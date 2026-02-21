// Anya - Malware Analysis Platform
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


// Import necessary libraries
use clap::Parser;  // For parsing command-line arguments
use std::fs;       // For file system operations
use std::path::PathBuf;  // For handling file paths
use anyhow::{Context, Result};  // For better error handling
use colored::*;    // For colored terminal output

// Hashing libraries
use md5::{Md5, Digest};
use sha1::Sha1;
use sha2::Sha256;

// Goblin for file format detection
use goblin::Object;

// Our PE parser module
mod pe_parser;

/// Ányá - A basic malware static analysis tool
/// This is our CLI structure using Clap
#[derive(Parser, Debug)]
#[command(name = "Anya")]
#[command(about = "Static analysis tool for suspicious files", long_about = None)]
struct Args {
    /// Path to the file to analyze
    #[arg(short, long)]
    file: PathBuf,

    /// Minimum string length to extract (default: 4)
    #[arg(short, long, default_value_t = 4)]
    min_string_length: usize,
}

fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Check if file exists
    if !args.file.exists() {
        anyhow::bail!("File does not exist: {:?}", args.file);
    }

    println!("{}", "=== Ányá v0.2 ===".bold().green());
    println!("Analyzing: {:?}\n", args.file);

    // Read the file into memory
    let file_data = fs::read(&args.file)
        .context("Failed to read file")?;

    // Display basic file information
    print_file_info(&args.file, &file_data)?;

    // Calculate and display hashes
    print_hashes(&file_data);

    // Detect file type and perform advanced analysis
    match Object::parse(&file_data) {
        Ok(Object::PE(_pe)) => {
            println!("{}", "\n🔍 Detected: Windows PE (Portable Executable)".bold().cyan());
            if let Err(e) = pe_parser::analyze_pe(&file_data) {
                eprintln!("{} PE analysis failed: {}", "⚠".yellow(), e);
            }
        }
        Ok(Object::Elf(_elf)) => {
            println!("{}", "\n🔍 Detected: Linux ELF (Executable and Linkable Format)".bold().cyan());
            println!("  ELF analysis coming in Phase 3!");
        }
        Ok(Object::Mach(_mach)) => {
            println!("{}", "\n🔍 Detected: macOS Mach-O".bold().cyan());
            println!("  Mach-O analysis coming in Phase 3!");
        }
        Ok(_) => {
            println!("{}", "\n🔍 Unknown executable format".yellow());
        }
        Err(_) => {
            println!("{}", "\n🔍 Not a recognized executable format - performing basic analysis only".yellow());
        }
    }

    // Always perform basic string extraction and entropy on full file
    print_strings(&file_data, args.min_string_length);
    print_entropy(&file_data);

    Ok(())
}

/// Display basic file information
fn print_file_info(path: &PathBuf, data: &[u8]) -> Result<()> {
    println!("{}", "=== File Information ===".bold().cyan());
    println!("Path: {:?}", path);
    println!("Size: {} bytes ({:.2} KB)", data.len(), data.len() as f64 / 1024.0);
    
    // Get file extension
    if let Some(ext) = path.extension() {
        println!("Extension: {}", ext.to_string_lossy());
    }
    println!();

    Ok(())
}

/// Calculate and display file hashes
fn print_hashes(data: &[u8]) {
    println!("{}", "=== File Hashes ===".bold().cyan());

    // MD5
    let mut hasher = Md5::new();
    hasher.update(data);
    let md5_result = hasher.finalize();
    println!("MD5:    {}", hex::encode(md5_result).green());

    // SHA1
    let mut hasher = Sha1::new();
    hasher.update(data);
    let sha1_result = hasher.finalize();
    println!("SHA1:   {}", hex::encode(sha1_result).green());

    // SHA256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256_result = hasher.finalize();
    println!("SHA256: {}", hex::encode(sha256_result).green());
    println!();
}

/// Extract printable ASCII strings from the binary (seeking hardcoded IPs, URLs, file paths, etc)
fn print_strings(data: &[u8], min_length: usize) {
    println!("{}", format!("=== Extracted Strings (min length: {}) ===", min_length).bold().cyan());

    let mut current_string = String::new();
    let mut string_count = 0;
    const MAX_DISPLAY: usize = 50;  // Only show first 50 strings

    for &byte in data {
        // Check if byte is printable ASCII (space to tilde)
        if byte >= 32 && byte <= 126 {
            current_string.push(byte as char);
        } else {
            // We hit a non-printable character
            if current_string.len() >= min_length {
                if string_count < MAX_DISPLAY {
                    println!("  {}", current_string.bright_white());
                    string_count += 1;
                } else if string_count == MAX_DISPLAY {
                    println!("  {}", format!("... (showing first {} strings only)", MAX_DISPLAY).yellow());
                    string_count += 1;
                }
            }
            current_string.clear();
        }
    }

    // Don't forget the last string if file doesn't end with non-printable
    if current_string.len() >= min_length && string_count < MAX_DISPLAY {
        println!("  {}", current_string.bright_white());
        string_count += 1;
    }

    println!("Total strings found: {}", string_count);
    println!();
}

/// Calculate Shannon entropy of the file
/// Entropy measures randomness. High entropy (close to 8.0) often indicates encryption, compression or packing
/// Low entropy suggests plain text or uncompressed data
fn print_entropy(data: &[u8]) {
    println!("{}", "=== Entropy Analysis (Full File) ===".bold().cyan());

    if data.is_empty() {
        println!("Cannot calculate entropy of empty file");
        return;
    }

    // Count frequency of each byte value (0-255)
    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    // Calculate Shannon entropy
    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    println!("Shannon Entropy: {:.4} / 8.0", entropy);
    
    // Provide interpretation with a splash of colours
    if entropy > 7.5 {
        println!("{}", "⚠ Very high entropy - likely encrypted or packed".red().bold());
    } else if entropy > 6.5 {
        println!("{}", "⚠ High entropy - possibly compressed or obfuscated".yellow());
    } else if entropy > 4.0 {
        println!("{}", "✓ Moderate entropy - typical for compiled executables".green());
    } else {
        println!("{}", "✓ Low entropy - likely plain text or simple data".green());
    }
    println!();
}

