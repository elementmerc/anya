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
use anyhow::{Context, Result}; // For better error handling
use clap::Parser; // For parsing command-line arguments
use colored::*; // For colored terminal output
use indicatif::{ProgressBar, ProgressStyle};
use std::fs; // For file system operations
use std::path::PathBuf; // For handling file paths // For progress indicators

// Hashing libraries
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

// Goblin for file format detection
use goblin::Object;

// The PE parser module
mod pe_parser;

/// Output verbosity level for controlling what information is displayed
///
/// This enum controls the amount of output shown to the user during analysis:
/// - `Quiet`: Only critical warnings and errors
/// - `Normal`: Standard analysis output (default)
/// - `Verbose`: All available information including debug details
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputLevel {
    /// Only show warnings and errors
    Quiet,
    /// Standard output (default)
    Normal,
    /// Show everything including debug information
    Verbose,
}

impl OutputLevel {
    /// Creates an OutputLevel from command-line arguments
    ///
    /// # Arguments
    ///
    /// * `verbose` - Whether verbose mode is enabled
    /// * `quiet` - Whether quiet mode is enabled
    ///
    /// # Returns
    ///
    /// The appropriate OutputLevel based on the flags
    fn from_args(verbose: bool, quiet: bool) -> Self {
        if verbose {
            OutputLevel::Verbose
        } else if quiet {
            OutputLevel::Quiet
        } else {
            OutputLevel::Normal
        }
    }

    /// Checks if informational output should be printed
    ///
    /// Returns `true` for Normal and Verbose modes, `false` for Quiet mode
    pub fn should_print_info(&self) -> bool {
        matches!(self, OutputLevel::Normal | OutputLevel::Verbose)
    }

    /// Checks if verbose/debug output should be printed
    ///
    /// Returns `true` only for Verbose mode
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

/// Creates a styled progress bar for tracking long-running operations
///
/// # Arguments
///
/// * `len` - Total length/size of the operation (in bytes or items)
/// * `message` - Message to display alongside the progress bar
///
/// # Returns
///
/// A `ProgressBar` with cyan/blue styling
fn create_progress_bar(len: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {percent}% ({eta})")
            .unwrap()
            .progress_chars("█▓▒░ "),
    );
    pb.set_message(message.to_string());
    pb
}

/// File size threshold (in bytes) for showing progress indicators
///
/// Files larger than 1MB will display progress bars/spinners during analysis.
/// This prevents cluttering the output for small files while providing feedback
/// for operations that may take several seconds on large files.
const LARGE_FILE_THRESHOLD: u64 = 1024 * 1024; // 1 MB

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
                .unwrap(),
        );
        spinner.set_message(format!(
            "Reading file ({:.2} MB)...",
            file_size as f64 / (1024.0 * 1024.0)
        ));
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
                println!(
                    "{}",
                    "\n🔍 Detected: Windows PE (Portable Executable)"
                        .bold()
                        .cyan()
                );
            }
            if let Err(e) = pe_parser::analyze_pe(&file_data, output_level) {
                eprintln!("{} PE analysis failed: {}", "⚠".yellow(), e);
            }
        }
        Ok(Object::Elf(_elf)) => {
            if output_level.should_print_info() {
                println!(
                    "{}",
                    "\n🔍 Detected: Linux ELF (Executable and Linkable Format)"
                        .bold()
                        .cyan()
                );
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
                println!(
                    "{}",
                    "\n🔍 Not a recognized executable format - performing basic analysis only"
                        .yellow()
                );
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
    println!(
        "Size: {} bytes ({:.2} KB)",
        data.len(),
        data.len() as f64 / 1024.0
    );

    // Get file extension
    if let Some(ext) = path.extension() {
        println!("Extension: {}", ext.to_string_lossy());
    }

    // Verbose mode: show more details
    if output_level.should_print_verbose()
        && let Ok(metadata) = fs::metadata(path)
    {
        if let Ok(created) = metadata.created() {
            println!("Created: {:?}", created);
        }
        if let Ok(modified) = metadata.modified() {
            println!("Modified: {:?}", modified);
        }
        println!("Read-only: {}", metadata.permissions().readonly());
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
                .unwrap(),
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
                .unwrap(),
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
                .unwrap(),
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

/// Extract printable ASCII strings from the binary (looking for hardcoded IPs, URLs, file paths, etc)
fn print_strings(data: &[u8], min_length: usize) {
    println!(
        "{}",
        format!("=== Extracted Strings (min length: {}) ===", min_length)
            .bold()
            .cyan()
    );

    let is_large = data.len() as u64 > LARGE_FILE_THRESHOLD;
    let pb = if is_large {
        let bar = create_progress_bar(data.len() as u64, "Extracting strings");
        Some(bar)
    } else {
        None
    };

    let mut current_string = String::new();
    let mut string_count = 0;
    const MAX_DISPLAY: usize = 50; // Only show first 50 strings
    const UPDATE_INTERVAL: usize = 256 * 1024; // Update every 256KB (more frequent updates)

    for (idx, &byte) in data.iter().enumerate() {
        // Update progress more frequently for smoother progress bar
        if is_large
            && idx % UPDATE_INTERVAL == 0
            && let Some(ref pb) = pb
        {
            pb.set_position(idx as u64);
        }

        // Check if byte is printable ASCII (space to tilde)
        if (32..=126).contains(&byte) {
            current_string.push(byte as char);
        } else {
            // We hit a non-printable character
            if current_string.len() >= min_length {
                if string_count < MAX_DISPLAY {
                    println!("  {}", current_string.bright_white());
                    string_count += 1;
                } else if string_count == MAX_DISPLAY {
                    println!(
                        "  {}",
                        format!("... (showing first {} strings only)", MAX_DISPLAY).yellow()
                    );
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
        pb.set_position(data.len() as u64); // Ensure we're at 100%
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
                .unwrap(),
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

    // Provide interpretation with a lovely splash of colours
    if entropy > 7.5 {
        println!(
            "{}",
            "⚠ Very high entropy - likely encrypted or packed"
                .red()
                .bold()
        );
    } else if entropy > 6.5 {
        println!(
            "{}",
            "⚠ High entropy - possibly compressed or obfuscated".yellow()
        );
    } else if entropy > 4.0 {
        println!(
            "{}",
            "✓ Moderate entropy - typical for compiled executables".green()
        );
    } else {
        println!(
            "{}",
            "✓ Low entropy - likely plain text or simple data".green()
        );
    }
    println!();
}

/// Prints a brief summary in quiet mode, showing only critical findings
///
/// In quiet mode, this function calculates file entropy and only outputs
/// a warning if the entropy is suspiciously high (> 7.5), which typically
/// indicates encryption or packing.
///
/// # Arguments
///
/// * `data` - The file data to analyze
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
        println!(
            "{}",
            "⚠ HIGH ENTROPY DETECTED - Likely packed/encrypted"
                .red()
                .bold()
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_level_from_args() {
        // Test normal mode (default)
        assert_eq!(OutputLevel::from_args(false, false), OutputLevel::Normal);
        
        // Test verbose mode
        assert_eq!(OutputLevel::from_args(true, false), OutputLevel::Verbose);
        
        // Test quiet mode
        assert_eq!(OutputLevel::from_args(false, true), OutputLevel::Quiet);
        
        // Verbose takes precedence if both are set (though CLI prevents this)
        assert_eq!(OutputLevel::from_args(true, true), OutputLevel::Verbose);
    }

    #[test]
    fn test_output_level_should_print_info() {
        assert!(OutputLevel::Normal.should_print_info());
        assert!(OutputLevel::Verbose.should_print_info());
        assert!(!OutputLevel::Quiet.should_print_info());
    }

    #[test]
    fn test_output_level_should_print_verbose() {
        assert!(!OutputLevel::Normal.should_print_verbose());
        assert!(OutputLevel::Verbose.should_print_verbose());
        assert!(!OutputLevel::Quiet.should_print_verbose());
    }

    #[test]
    fn test_large_file_threshold() {
        assert_eq!(LARGE_FILE_THRESHOLD, 1024 * 1024);
        assert_eq!(LARGE_FILE_THRESHOLD, 1_048_576);
    }

    #[test]
    fn test_entropy_calculation_empty() {
        // Empty data should have 0 entropy
        let data: Vec<u8> = vec![];
        let mut frequency = [0u64; 256];
        
        for &byte in &data {
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
        
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_entropy_calculation_uniform() {
        // All same byte should have 0 entropy
        let data = vec![0u8; 1000];
        let mut frequency = [0u64; 256];
        
        for &byte in &data {
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
        
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_entropy_calculation_mixed() {
        // Mixed data should have moderate entropy
        let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut frequency = [0u64; 256];
        
        for &byte in &data {
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
        
        // Should be around 3.32 bits for 10 unique values
        assert!(entropy > 3.0 && entropy < 4.0);
    }

    #[test]
    fn test_entropy_calculation_random() {
        // Random-like data should have high entropy
        let data: Vec<u8> = (0..=255).collect();
        let mut frequency = [0u64; 256];
        
        for &byte in &data {
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
        
        // Perfect distribution of all 256 values should have entropy = 8.0
        assert!((entropy - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_string_detection_logic() {
        // Test printable ASCII detection
        assert!(32u8 >= 32 && 32u8 <= 126);  // Space
        assert!(65u8 >= 32 && 65u8 <= 126);  // 'A'
        assert!(126u8 >= 32 && 126u8 <= 126); // '~'
        assert!(!(31u8 >= 32 && 31u8 <= 126)); // Below range
        assert!(!(127u8 >= 32 && 127u8 <= 126)); // Above range
    }

    #[test]
    fn test_string_extraction_min_length() {
        let data = b"ABC\x00DEFGH\x00IJ\x00KLMNOPQRST";
        let min_length = 4;
        
        // Count strings that meet minimum length
        let mut current_string = String::new();
        let mut valid_strings = Vec::new();
        
        for &byte in data.iter() {
            if byte >= 32 && byte <= 126 {
                current_string.push(byte as char);
            } else {
                if current_string.len() >= min_length {
                    valid_strings.push(current_string.clone());
                }
                current_string.clear();
            }
        }
        
        // Check final string
        if current_string.len() >= min_length {
            valid_strings.push(current_string);
        }
        
        assert_eq!(valid_strings.len(), 2); // "DEFGH" and "KLMNOPQRST"
        assert_eq!(valid_strings[0], "DEFGH");
        assert_eq!(valid_strings[1], "KLMNOPQRST");
    }

    #[test]
    fn test_hash_consistency() {
        use md5::Md5;
        use sha1::Sha1;
        use sha2::Sha256;
        
        let test_data = b"test data for hashing";
        
        // MD5
        let mut hasher = Md5::new();
        hasher.update(test_data);
        let result1 = hasher.finalize();
        
        let mut hasher = Md5::new();
        hasher.update(test_data);
        let result2 = hasher.finalize();
        
        assert_eq!(result1, result2, "MD5 hashes should be consistent");
        
        // SHA1
        let mut hasher = Sha1::new();
        hasher.update(test_data);
        let result1 = hasher.finalize();
        
        let mut hasher = Sha1::new();
        hasher.update(test_data);
        let result2 = hasher.finalize();
        
        assert_eq!(result1, result2, "SHA1 hashes should be consistent");
        
        // SHA256
        let mut hasher = Sha256::new();
        hasher.update(test_data);
        let result1 = hasher.finalize();
        
        let mut hasher = Sha256::new();
        hasher.update(test_data);
        let result2 = hasher.finalize();
        
        assert_eq!(result1, result2, "SHA256 hashes should be consistent");
    }

    #[test]
    fn test_hash_different_data() {
        use sha2::Sha256;
        
        let data1 = b"data one";
        let data2 = b"data two";
        
        let mut hasher = Sha256::new();
        hasher.update(data1);
        let hash1 = hasher.finalize();
        
        let mut hasher = Sha256::new();
        hasher.update(data2);
        let hash2 = hasher.finalize();
        
        assert_ne!(hash1, hash2, "Different data should produce different hashes");
    }
}