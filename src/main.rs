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


// Import necessary libraries
use clap::Parser;  // For parsing command-line arguments
use std::fs;       // For file system operations
use std::path::PathBuf;  // For handling file paths
use anyhow::{Context, Result};  // For better error handling
use colored::*;    // For colored terminal output
use indicatif::{ProgressBar, ProgressStyle};  // For progress indicators

// Hashing libraries
use md5::{Md5, Digest};
use sha1::Sha1;
use sha2::Sha256;

// Goblin for file format detection
use goblin::Object;

// The PE parser module
mod pe_parser;

/// Output verbosity level
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputLevel {
    Quiet,   // Only warnings/errors
    Normal,  // Standard output
    Verbose, // Everything including debug info
}

impl OutputLevel {
    fn from_args(verbose: bool, quiet: bool) -> Self {
        if verbose {
            OutputLevel::Verbose
        } else if quiet {
            OutputLevel::Quiet
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

/// CLI structure using Clap
#[derive(Parser, Debug)]
#[command(name = "Anya")]
#[command(version)]
#[command(about = "Static analysis tool for suspicious files", long_about = None)]
#[command(after_help = "EXAMPLES:
    anya --file suspicious.exe
        Analyze a Windows executable
    
    anya --file malware.dll --min-string-length 8
        Analyze with custom string length threshold
    
    anya --file sample.exe --json > report.json
        Export results as JSON

For more information, visit: https://github.com/elementmerc/anya
")]
struct Args {
    /// Path to the file to analyze
    #[arg(short, long, value_name = "FILE")]
    file: PathBuf,

    /// Minimum string length to extract (default: 4)
    #[arg(short, long, default_value_t = 4, value_name = "LENGTH")]
    min_string_length: usize,

    /// Output results in JSON format
    #[arg(short, long)]
    json: bool,

    /// Save output to file instead of stdout
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Verbose output (show additional details)
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode (only show warnings and errors)
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

}

/// Create a progress bar for operations on large files
fn create_progress_bar(len: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {percent}% ({eta})")
            .unwrap()
            .progress_chars("█▓▒░ ")
    );
    pb.set_message(message.to_string());
    pb
}

/// Threshold for showing progress (1 MB)
const LARGE_FILE_THRESHOLD: u64 = 1024 * 1024;

fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Handle color settings
    if args.no_color {
        colored::control::set_override(false);
    }

    // Determine output level
    let output_level = OutputLevel::from_args(args.verbose, args.quiet);

    // Check if file exists
    if !args.file.exists() {
        anyhow::bail!("File does not exist: {:?}", args.file);
    }

    // Only show banner in normal/verbose mode
    if output_level.should_print_info() {
        println!("{}", "=== Ányá v0.3.0 ===".bold().green());
        println!("Analyzing: {:?}\n", args.file);
    }

    // Get file size to determine if we should show progress
    let file_size = fs::metadata(&args.file)?.len();
    let is_large_file = file_size > LARGE_FILE_THRESHOLD;

    // Read the file into memory with optional spinner for large files
    let file_data = if is_large_file && output_level.should_print_info() {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap()
        );
        spinner.set_message(format!("Reading file ({:.2} MB)...", file_size as f64 / (1024.0 * 1024.0)));
        spinner.enable_steady_tick(std::time::Duration::from_millis(80));
        
        let data = fs::read(&args.file).context("Failed to read file")?;
        
        spinner.finish_and_clear();
        data
    } else {
        fs::read(&args.file).context("Failed to read file")?
    };

    // Display basic file information
    if output_level.should_print_info() {
        print_file_info(&args.file, &file_data, output_level)?;
    }

    // Calculate and display hashes
    print_hashes(&file_data, output_level);

    // Detect file type and perform advanced analysis
    match Object::parse(&file_data) {
        Ok(Object::PE(_pe)) => {
            if output_level.should_print_info() {
                println!("{}", "\n🔍 Detected: Windows PE (Portable Executable)".bold().cyan());
            }
            if let Err(e) = pe_parser::analyze_pe(&file_data, output_level) {
                eprintln!("{} PE analysis failed: {}", "⚠".yellow(), e);
            }
        }
        Ok(Object::Elf(_elf)) => {
            if output_level.should_print_info() {
                println!("{}", "\n🔍 Detected: Linux ELF (Executable and Linkable Format)".bold().cyan());
                println!("  ELF analysis coming in Phase 3!");
            }
        }
        Ok(Object::Mach(_mach)) => {
            if output_level.should_print_info() {
                println!("{}", "\n🔍 Detected: macOS Mach-O".bold().cyan());
                println!("  Mach-O analysis coming in Phase 3!");
            }
        }
        Ok(_) => {
            if output_level.should_print_info() {
                println!("{}", "\n🔍 Unknown executable format".yellow());
            }
        }
        Err(_) => {
            if output_level.should_print_info() {
                println!("{}", "\n🔍 Not a recognized executable format - performing basic analysis only".yellow());
            }
        }
    }

    // Always perform basic string extraction and entropy on full file
    if output_level.should_print_info() {
        print_strings(&file_data, args.min_string_length);
        print_entropy(&file_data);
    }

    // In quiet mode, summarize findings
    if output_level == OutputLevel::Quiet {
        print_quiet_summary(&file_data);
    }

    Ok(())
}

/// Display basic file information
fn print_file_info(path: &PathBuf, data: &[u8], output_level: OutputLevel) -> Result<()> {
    println!("{}", "=== File Information ===".bold().cyan());
    println!("Path: {:?}", path);
    println!("Size: {} bytes ({:.2} KB)", data.len(), data.len() as f64 / 1024.0);
    
    // Get file extension
    if let Some(ext) = path.extension() {
        println!("Extension: {}", ext.to_string_lossy());
    }
    
    // Verbose mode: show more details
    if output_level.should_print_verbose() {
        if let Ok(metadata) = fs::metadata(path) {
            if let Ok(created) = metadata.created() {
                println!("Created: {:?}", created);
            }
            if let Ok(modified) = metadata.modified() {
                println!("Modified: {:?}", modified);
            }
            println!("Read-only: {}", metadata.permissions().readonly());
        }
    }
    
    println!();

    Ok(())
}

/// Calculate and display file hashes
fn print_hashes(data: &[u8], output_level: OutputLevel) {
    if !output_level.should_print_info() {
        return;
    }

    println!("{}", "=== File Hashes ===".bold().cyan());

    let is_large = data.len() as u64 > LARGE_FILE_THRESHOLD;

    // MD5
    let pb = if is_large {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap()
        );
        spinner.set_message("Calculating MD5...");
        spinner.enable_steady_tick(std::time::Duration::from_millis(80));
        Some(spinner)
    } else {
        None
    };
    
    let mut hasher = Md5::new();
    hasher.update(data);
    let md5_result = hasher.finalize();
    
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }
    println!("MD5:    {}", hex::encode(md5_result).green());

    // SHA1
    let pb = if is_large {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap()
        );
        spinner.set_message("Calculating SHA1...");
        spinner.enable_steady_tick(std::time::Duration::from_millis(80));
        Some(spinner)
    } else {
        None
    };
    
    let mut hasher = Sha1::new();
    hasher.update(data);
    let sha1_result = hasher.finalize();
    
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }
    println!("SHA1:   {}", hex::encode(sha1_result).green());

    // SHA256
    let pb = if is_large {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap()
        );
        spinner.set_message("Calculating SHA256...");
        spinner.enable_steady_tick(std::time::Duration::from_millis(80));
        Some(spinner)
    } else {
        None
    };
    
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256_result = hasher.finalize();
    
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }
    println!("SHA256: {}", hex::encode(sha256_result).green());
    println!();
}

/// Extract printable ASCII strings from the binary (seeking hardcoded IPs, URLs, file paths, etc)
fn print_strings(data: &[u8], min_length: usize) {
    println!("{}", format!("=== Extracted Strings (min length: {}) ===", min_length).bold().cyan());

    let is_large = data.len() as u64 > LARGE_FILE_THRESHOLD;
    let pb = if is_large {
        let bar = create_progress_bar(data.len() as u64, "Extracting strings");
        Some(bar)
    } else {
        None
    };

    let mut current_string = String::new();
    let mut string_count = 0;
    const MAX_DISPLAY: usize = 50;  // Only show first 50 strings
    const UPDATE_INTERVAL: usize = 256 * 1024;  // Update every 256KB (more frequent updates)

    for (idx, &byte) in data.iter().enumerate() {
        // Update progress more frequently for smoother progress bar
        if is_large && idx % UPDATE_INTERVAL == 0 {
            if let Some(ref pb) = pb {
                pb.set_position(idx as u64);
            }
        }

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

    // Finish progress bar at 100% AFTER all processing is done
    if let Some(pb) = pb {
        pb.set_position(data.len() as u64);  // Ensure we're at 100%
        pb.finish_and_clear();
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

    let is_large = data.len() as u64 > LARGE_FILE_THRESHOLD;
    let pb = if is_large {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap()
        );
        spinner.set_message("Calculating entropy...");
        spinner.enable_steady_tick(std::time::Duration::from_millis(80));
        Some(spinner)
    } else {
        None
    };

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

    if let Some(pb) = pb {
        pb.finish_and_clear();
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

/// Print a brief summary in quiet mode
fn print_quiet_summary(data: &[u8]) {
    // Calculate entropy
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

    // Only print if suspicious
    if entropy > 7.5 {
        println!("{}", "⚠ HIGH ENTROPY DETECTED - Likely packed/encrypted".red().bold());
    }
}