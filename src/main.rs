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
use colored::*; // For coloured terminal output
use indicatif::{ProgressBar, ProgressStyle};
use std::fs; // For file system operations
use std::fs::OpenOptions; // For file creation and opening
use std::io::Write; // For writing to files
use std::path::PathBuf; // For handling file paths // For progress indicators
use walkdir::WalkDir; // For recursive directory traversal

// Hashing libraries
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

// Goblin for file format detection
use goblin::Object;

// The PE parser module
mod pe_parser;

// Output structures for JSON
mod output;

// Configuration management
mod config;

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
        Analyse a single Windows executable
    
    anya --directory ./samples
        Analyse all executables in a directory
    
    anya --directory ./samples --recursive
        Recursively analyse all executables in subdirectories
    
    anya --file malware.dll --min-string-length 8
        Analyse with custom string length threshold
    
    anya --file sample.exe --json
        Output analysis as JSON
    
    anya --directory ./malware --json --output results.jsonl --append
        Batch analyse and append all results to JSONL file
    
    anya --file sample.exe > output.txt
        Save text analysis to file (shell redirection)

For more information, visit: https://github.com/elementmerc/anya
")]
struct Args {
    /// Path to the file to analyse (use --directory for batch mode)
    #[arg(short, long, value_name = "FILE", conflicts_with = "directory")]
    file: Option<PathBuf>,

    /// Analyse all files in a directory (batch mode)
    #[arg(short, long, value_name = "DIR", conflicts_with = "file")]
    directory: Option<PathBuf>,

    /// Recursive directory traversal (requires --directory)
    #[arg(short, long, requires = "directory")]
    recursive: bool,

    /// Minimum string length to extract (overrides config file)
    #[arg(short = 's', long, value_name = "LENGTH")]
    min_string_length: Option<usize>,

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

    /// Disable coloured output
    #[arg(long)]
    no_color: bool,

    /// Append to output file instead of overwriting (requires --output)
    #[arg(short, long, requires = "output")]
    append: bool,

    /// Create default config file at ~/.config/anya/config.toml
    #[arg(long)]
    init_config: bool,

    /// Use custom config file (default: ~/.config/anya/config.toml)
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
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
/// A configured `ProgressBar` with cyan/blue styling
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

/// Writes output to either stdout or a file
///
/// # Rust Concepts Used:
/// - `Option<&PathBuf>` - A reference to an optional file path
/// - `&str` - A string slice (borrowed string data)
/// - `Result<()>` - Either success (Ok(())) or an error
/// - `if let Some(path)` - Pattern matching on Option
///
/// # Arguments
///
/// * `content` - The text to write (borrowed as &str)
/// * `output_path` - Optional file path (None = stdout)
/// * `append_mode` - If true, append to file instead of overwriting
///
/// # Returns
///
/// Returns Ok(()) on success, or an error if writing fails
///
/// # Example
///
/// ```no_run
/// write_output("Hello", None, false)?;  // Prints to screen
/// write_output("Hello", Some(&path), false)?;  // Writes to file
/// write_output("World", Some(&path), true)?;   // Appends to file
/// ```
fn write_output(content: &str, output_path: Option<&PathBuf>, append_mode: bool) -> Result<()> {
    // Pattern matching on Option: is there a file path or not?
    match output_path {
        // Some(path) means user provided --output flag
        Some(path) => {
            // OpenOptions is a builder pattern for configuring file creation
            let mut file = OpenOptions::new()
                .write(true)      // We want to write to this file
                .create(true)     // Create the file if it doesn't exist
                .truncate(!append_mode)  // If NOT appending, clear existing content
                .append(append_mode)     // If appending, add to end of file
                .open(path)       // Actually open/create the file
                .context(format!("Failed to open output file: {:?}", path))?;
                // The ? operator: if open() fails, return the error immediately
                // context() adds helpful error message
            
            // write_all() writes the entire string to the file
            // content.as_bytes() converts &str to &[u8] (bytes)
            file.write_all(content.as_bytes())
                .context(format!("Failed to write to file: {:?}", path))?;
            
            // Explicit flush ensures data is written to disk immediately
            // Without this, data might sit in a buffer
            file.flush()
                .context("Failed to flush file buffer")?;
            
            // Success! Return Ok(()) which is Rust's way of saying "no errors"
            Ok(())
        }
        // None means user didn't provide --output, so print to screen
        None => {
            // println! is a macro that prints to stdout
            println!("{}", content);
            Ok(())
        }
    }
}

/// Calculate file hashes and return structured data
fn calculate_hashes(data: &[u8]) -> output::Hashes {
    use md5::Md5;
    use sha1::Sha1;
    use sha2::Sha256;

    // MD5
    let mut hasher = Md5::new();
    hasher.update(data);
    let md5_result = hasher.finalize();

    // SHA1
    let mut hasher = Sha1::new();
    hasher.update(data);
    let sha1_result = hasher.finalize();

    // SHA256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256_result = hasher.finalize();

    output::Hashes {
        md5: hex::encode(md5_result),
        sha1: hex::encode(sha1_result),
        sha256: hex::encode(sha256_result),
    }
}

/// Calculate entropy and return structured data
fn calculate_file_entropy(data: &[u8]) -> output::EntropyInfo {
    if data.is_empty() {
        return output::EntropyInfo {
            value: 0.0,
            category: "Empty file".to_string(),
            is_suspicious: false,
        };
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

    let (category, is_suspicious) = if entropy > 7.5 {
        ("Very high - likely encrypted or packed".to_string(), true)
    } else if entropy > 6.5 {
        ("High - possibly compressed or obfuscated".to_string(), false)
    } else if entropy > 4.0 {
        ("Moderate - typical for compiled executables".to_string(), false)
    } else {
        ("Low - likely plain text or simple data".to_string(), false)
    };

    output::EntropyInfo {
        value: entropy,
        category,
        is_suspicious,
    }
}

/// Extract strings and return structured data
fn extract_strings_data(data: &[u8], min_length: usize) -> output::StringsInfo {
    let mut current_string = String::new();
    let mut all_strings = Vec::new();
    const MAX_SAMPLES: usize = 50;

    for &byte in data {
        if byte >= 32 && byte <= 126 {
            current_string.push(byte as char);
        } else {
            if current_string.len() >= min_length {
                all_strings.push(current_string.clone());
            }
            current_string.clear();
        }
    }

    // Don't forget the last string
    if current_string.len() >= min_length {
        all_strings.push(current_string);
    }

    let total_count = all_strings.len();
    let samples: Vec<String> = all_strings.into_iter().take(MAX_SAMPLES).collect();
    let sample_count = samples.len();

    output::StringsInfo {
        min_length,
        total_count,
        samples,
        sample_count,
    }
}

/// Summary information for batch analysis
///
/// **Rust Concept: Struct with Derived Traits**
/// - `#[derive(Debug)]` - Automatically implements Debug trait (for printing with {:?})
/// - `Default` - Provides default values (zeros and empty strings)
#[derive(Debug, Default)]
struct BatchSummary {
    /// Total files scanned
    total_files: usize,
    
    /// Successfully analysed files
    analysed: usize,
    
    /// Files that failed to analyse
    failed: usize,
    
    /// Files skipped (wrong type)
    skipped: usize,
    
    /// Suspicious files detected (high entropy or many suspicious APIs)
    suspicious: usize,
    
    /// Total time taken (in seconds)
    duration: f64,
}

impl BatchSummary {
    /// Print a formatted summary report
    ///
    /// **Rust Concept: Methods on Structs**
    /// - `&self` - Borrows the struct (read-only access)
    /// - Methods are defined in `impl` blocks
    fn print_summary(&self) {
        println!("\n{}", "=== Batch Analysis Summary ===".bold().cyan());
        println!("Total files found:    {}", self.total_files);
        println!("Successfully analysed: {}", self.analysed.to_string().green());
        println!("Failed:               {}", if self.failed > 0 { 
            self.failed.to_string().red() 
        } else { 
            self.failed.to_string().normal() 
        });
        println!("Skipped (wrong type): {}", self.skipped);
        
        if self.suspicious > 0 {
            println!("Suspicious files:     {}", self.suspicious.to_string().red().bold());
        }
        
        println!("Time taken:           {:.2}s", self.duration);
        
        if self.analysed > 0 {
            let rate = self.analysed as f64 / self.duration;
            println!("Analysis rate:        {:.1} files/sec", rate);
        }
    }
}

/// Checks if a file is an executable based on extension
///
/// **Rust Concept: Functions with Multiple Return Paths**
/// - Early returns with `return`
/// - Pattern matching with `match`
/// - String methods like `to_lowercase()`
fn is_executable_file(path: &PathBuf) -> bool {
    // Get file extension
    let extension = match path.extension() {
        Some(ext) => ext.to_string_lossy().to_lowercase(),
        None => return false,  // No extension = not executable
    };
    
    // Match against known executable extensions
    // **Rust Concept: Match with Multiple Patterns**
    // The `|` means "or" - match any of these
    matches!(
        extension.as_str(),
        "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | // Windows
        "elf" | "so" | "bin" |                          // Linux
        "dylib" | "bundle" | "app"                      // macOS
    )
}

fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Handle --init-config: create default config file and exit
    // **Rust Concept: Early Return**
    // If this flag is set, we create the config and exit immediately
    if args.init_config {
        let path = config::Config::create_default_file()?;
        println!("✓ Created default config file at: {}", path.display());
        println!("\nEdit this file to customise Anya's behaviour.");
        println!("Run 'anya --help' to see which CLI flags override config settings.");
        return Ok(());
    }

    // Load configuration from file
    // **Rust Concept: Option and Result Chaining**
    // We try custom path first, then default path, then fallback to defaults
    let config = if let Some(config_path) = &args.config {
        // User specified custom config file
        config::Config::load_from_file(config_path)
            .context(format!("Failed to load config from: {:?}", config_path))?
    } else {
        // Try to load from default location, use defaults if not found
        config::Config::load_or_default()?
    };
    
    // Merge CLI arguments with config
    // **Rust Concept: Option::unwrap_or()**
    // If CLI arg is Some(value), use it; otherwise use config value
    let min_string_length = args.min_string_length.unwrap_or(config.analysis.min_string_length);
    
    // Apply colour settings from config unless CLI overrides
    let use_colours = if args.no_color {
        false
    } else {
        config.output.use_colours
    };

    // Validate: must provide either --file or --directory
    if args.file.is_none() && args.directory.is_none() {
        anyhow::bail!(
            "Must specify either --file or --directory\n\
             \n\
             Examples:\n\
             anya --file malware.exe\n\
             anya --directory ./samples\n\
             anya --directory ./samples --recursive"
        );
    }

    // Validate: --output currently only works with --json
    if args.output.is_some() && !args.json {
        let example_path = args.file.as_ref()
            .or(args.directory.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "FILE".to_string());
        
        anyhow::bail!(
            "The --output flag currently only works with --json mode.\n\
             \n\
             For text output to file, use shell redirection:\n\
             anya --file {} > output.txt\n\
             \n\
             For JSON output to file:\n\
             anya --file {} --json --output report.json",
            example_path,
            example_path
        );
    }

    // Handle colour settings
    // Priority: CLI --no-color > config file > default (true)
    if !use_colours {
        colored::control::set_override(false);
    }

    // Automatically disable colours when writing to file
    if args.output.is_some() {
        colored::control::set_override(false);
    }

    // Determine output level
    let output_level = OutputLevel::from_args(args.verbose, args.quiet);

    // Choose mode: single file or batch
    if let Some(file_path) = &args.file {
        // Single file mode
        analyse_single_file(file_path, &args, output_level, min_string_length)?;
    } else if let Some(dir_path) = &args.directory {
        // Batch mode
        analyse_directory(dir_path, &args, output_level, min_string_length)?;
    }

    Ok(())
}

/// Analyses a single file
///
/// **Rust Concepts Used:**
/// - Function parameters with borrowing (`&Path`, `&Args`)
/// - Result type for error handling
/// - Conditional compilation with if/else
/// - Passing config values as parameters
fn analyse_single_file(
    file_path: &PathBuf,
    args: &Args,
    output_level: OutputLevel,
    min_string_length: usize,
) -> Result<()> {
    // Check if file exists
    if !file_path.exists() {
        anyhow::bail!("File does not exist: {:?}", file_path);
    }

    // Only show banner in normal/verbose mode (never in JSON mode)
    if output_level.should_print_info() && !args.json {
        println!("{}", "=== Ányá v0.3.0 ===".bold().green());
        println!("Analysing: {:?}\n", file_path);
    }

    // Get file size to determine if we should show progress
    let file_size = fs::metadata(file_path)?.len();
    let is_large_file = file_size > LARGE_FILE_THRESHOLD;

    // Read the file into memory with optional spinner for large files
    // Never show spinner in JSON mode to keep output pure JSON
    let file_data = if is_large_file && output_level.should_print_info() && !args.json {
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

        let data = fs::read(file_path).context("Failed to read file")?;

        spinner.finish_and_clear();
        data
    } else {
        fs::read(file_path).context("Failed to read file")?
    };

    // Calculate hashes (for both JSON and pretty output)
    let hashes = calculate_hashes(&file_data);
    
    // Calculate entropy (for both JSON and pretty output)
    let entropy_data = calculate_file_entropy(&file_data);
    
    // Extract strings (for both JSON and pretty output)
    // Using merged config value (CLI overrides config file)
    let strings_data = extract_strings_data(&file_data, min_string_length);
    
    // Determine file format and analyse
    let (file_format, pe_data) = match Object::parse(&file_data) {
        Ok(Object::PE(_pe)) => {
            let pe_analysis = pe_parser::analyse_pe_data(&file_data)?;
            ("Windows PE".to_string(), Some(pe_analysis))
        }
        Ok(Object::Elf(_elf)) => ("Linux ELF".to_string(), None),
        Ok(Object::Mach(_mach)) => ("macOS Mach-O".to_string(), None),
        Ok(_) => ("Unknown".to_string(), None),
        Err(_) => ("Unrecognized".to_string(), None),
    };

    // If JSON output requested, build and print/save JSON
    if args.json {
        let file_info = output::FileInfo {
            path: file_path.to_string_lossy().to_string(),
            size_bytes: file_data.len() as u64,
            size_kb: file_data.len() as f64 / 1024.0,
            extension: file_path.extension().map(|e| e.to_string_lossy().to_string()),
        };

        let result = output::AnalysisResult {
            file_info,
            hashes,
            entropy: entropy_data,
            strings: strings_data,
            pe_analysis: pe_data,
            file_format,
        };

        // Serialise to JSON (pretty-printed with indentation)
        let json = serde_json::to_string_pretty(&result)?;
        
        // Write to file or stdout using our helper function
        write_output(&json, args.output.as_ref(), args.append)?;
        
        // If we wrote to a file, let user know
        if let Some(path) = &args.output {
            if args.append {
                eprintln!("✓ JSON appended to: {:?}", path);
            } else {
                eprintln!("✓ JSON written to: {:?}", path);
            }
        }
        
        return Ok(());
    }

    // Otherwise, pretty print output
    if output_level.should_print_info() {
        print_file_info(file_path, &file_data, output_level)?;
    }

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
            if let Err(e) = pe_parser::analyse_pe(&file_data, output_level) {
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
        print_strings(&file_data, min_string_length);
        print_entropy(&file_data);
    }

    // In quiet mode, summarize findings
    if output_level == OutputLevel::Quiet {
        print_quiet_summary(&file_data);
    }

    Ok(())
}

/// Analyses all executable files in a directory
///
/// **Rust Concepts:**
/// - Iterator methods (`.filter()`, `.collect()`, `.enumerate()`)
/// - Vectors and collecting
/// - Timing with `std::time::Instant`
/// - Mutable variables with `mut`
fn analyse_directory(
    dir_path: &PathBuf,
    args: &Args,
    output_level: OutputLevel,
    min_string_length: usize,
) -> Result<()> {
    use std::time::Instant;
    
    if !dir_path.exists() {
        anyhow::bail!("Directory does not exist: {:?}", dir_path);
    }
    
    if !dir_path.is_dir() {
        anyhow::bail!("Path is not a directory: {:?}", dir_path);
    }
    
    // Banner for batch mode
    if output_level.should_print_info() && !args.json {
        println!("{}", "=== Ányá v0.3.0 - Batch Mode ===".bold().green());
        println!("Scanning directory: {:?}", dir_path);
        if args.recursive {
            println!("Mode: Recursive");
        } else {
            println!("Mode: Non-recursive (current directory only)");
        }
        println!();
    }
    
    // **Rust Concept: WalkDir Iterator**
    // WalkDir traverses directories lazily (one file at a time)
    // This is memory efficient - doesn't load all files at once
    let walker = if args.recursive {
        WalkDir::new(dir_path)
    } else {
        WalkDir::new(dir_path).max_depth(1)
    };
    
    // **Rust Concept: Iterator Chains**
    // We chain multiple operations: filter errors, filter files, filter executables
    // This is lazy - only processes what's needed
    let executable_files: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(|e| e.ok())  // Filter out directory read errors
        .filter(|e| e.file_type().is_file())  // Only files, not directories
        .map(|e| e.path().to_path_buf())  // Convert to PathBuf
        .filter(|path| is_executable_file(path))  // Only executables
        .collect();  // Collect into a Vector
    
    if executable_files.is_empty() {
        if output_level.should_print_info() {
            println!("No executable files found in directory");
        }
        return Ok(());
    }
    
    if output_level.should_print_info() && !args.json {
        println!("Found {} executable files\n", executable_files.len());
    }
    
    // **Rust Concept: Mutable Variables**
    // `mut` allows us to modify the variable
    let mut summary = BatchSummary::default();
    summary.total_files = executable_files.len();
    
    // Start timing
    let start_time = Instant::now();
    
    // **Rust Concept: Progress Bar with indicatif**
    // Only show progress bar in non-JSON mode
    let progress = if output_level.should_print_info() && !args.json {
        let pb = ProgressBar::new(executable_files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {eta}")
                .unwrap()
                .progress_chars("█▓▒░ "),
        );
        pb.set_message("Analysing files");
        Some(pb)
    } else {
        None
    };
    
    // **Rust Concept: Enumerate Iterator**
    // .enumerate() gives us (index, item) pairs
    // Useful for tracking position in iteration
    for (idx, file_path) in executable_files.iter().enumerate() {
        let filename = file_path.file_name().unwrap_or_default().to_string_lossy();
        
        // Show which file we're about to analyse in progress bar
        if let Some(ref pb) = progress {
            pb.set_message(format!("Analysing: {}", filename));
        }
        
        // Try to analyse the file
        // **Rust Concept: Result and match**
        // We handle both success and failure cases
        match analyse_single_file(file_path, args, OutputLevel::Quiet, min_string_length) {
            Ok(_) => {
                summary.analysed += 1;
                
                // Print one-line summary after analysis (not in JSON mode)
                // **Rust Concept: pb.println() vs println!()**
                // pb.println() works nicely with progress bars - prints above the bar
                // Regular println!() would interfere with the progress bar display
                if !args.json && output_level.should_print_info() {
                    if let Some(ref pb) = progress {
                        pb.println(format!("  ✓ {}", filename.green()));
                    } else {
                        println!("  ✓ {}", filename.green());
                    }
                }
            }
            Err(e) => {
                summary.failed += 1;
                
                // Always show failures (not in JSON mode)
                if !args.json {
                    if let Some(ref pb) = progress {
                        pb.println(format!("  ✗ {}: {}", filename.red(), e));
                    } else {
                        eprintln!("  ✗ {}: {}", filename.red(), e);
                    }
                }
            }
        }
        
        // Update progress bar AFTER analysis to show actual progress
        // **Rust Concept: idx + 1 because idx is 0-based**
        // When we finish file 0, we want to show 1/10, not 0/10
        if let Some(ref pb) = progress {
            pb.set_position((idx + 1) as u64);
        }
    }
    
    // Finish progress bar - keep it visible with final message
    // **Rust Concept: Consuming the Option with if let Some(pb)**
    // This takes ownership of pb (not a reference), so we can consume it
    if let Some(pb) = progress {
        pb.finish_with_message("✓ Analysis complete");
    }
    
    // Calculate duration
    summary.duration = start_time.elapsed().as_secs_f64();
    
    // Print summary (not in JSON mode)
    if output_level.should_print_info() && !args.json {
        summary.print_summary();
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

/// Extract printable ASCII strings from the binary (seeking hardcoded IPs, URLs, file paths, etc)
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

    // Provide interpretation with a splash of colours
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
/// * `data` - The file data to analyse
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