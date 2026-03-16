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
use anya_security_core::{
    BatchSummary, OutputLevel, analyse_file, case, compute_verdict, config, elf_parser,
    hash_check, is_executable_file, output, pe_parser, to_json_output, yara,
};
use anyhow::{Context, Result}; // For better error handling
use clap::{Parser, Subcommand}; // For parsing command-line arguments
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

    /// Show contextual learning lessons after analysis (Teacher Mode for CLI)
    #[arg(long)]
    guided: bool,

    /// Show plain-English explanations of findings at the bottom of output
    #[arg(long)]
    explain: bool,

    /// Show batch results as a summary table (requires --directory)
    #[arg(long, requires = "directory")]
    summary: bool,

    /// Save results to a named case for tracking investigations
    #[arg(long, value_name = "NAME")]
    case: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print a random Bible verse (NLT)
    Verse,

    /// Check if a file's hash appears in a hash list
    HashCheck {
        /// File path or hash string to check
        target: String,
        /// Path to hash list file (one hash per line)
        #[arg(long)]
        against: PathBuf,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// YARA rule utilities
    Yara {
        #[command(subcommand)]
        command: YaraCommands,
    },

    /// List and manage analysis cases
    Cases {
        /// List all cases
        #[arg(long)]
        list: bool,
    },
}

#[derive(Subcommand, Debug)]
enum YaraCommands {
    /// Merge .yar/.yara files from a directory into one file
    Combine {
        /// Directory containing YARA rule files
        input_dir: PathBuf,
        /// Output file path
        output_file: PathBuf,
        /// Recurse into subdirectories
        #[arg(short, long)]
        recursive: bool,
    },

    /// Generate a YARA rule skeleton from a list of strings
    FromStrings {
        /// Text file with one string per line
        strings_file: PathBuf,
        /// Write to file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Custom rule name (auto-generated if omitted)
        #[arg(short, long)]
        name: Option<String>,
        /// Overwrite existing output file
        #[arg(long)]
        overwrite: bool,
    },
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
            .template("{msg} [{bar:40.cyan/blue}] {percent}% ({elapsed})")
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
                .write(true) // We want to write to this file
                .create(true) // Create the file if it doesn't exist
                .truncate(!append_mode) // If NOT appending, clear existing content
                .append(append_mode) // If appending, add to end of file
                .open(path) // Actually open/create the file
                .with_context(|| format!(
                    "Couldn't write output to '{}'. Check that the directory exists and you have write permission.",
                    path.display()
                ))?;
            // The ? operator: if open() fails, return the error immediately
            // context() adds helpful error message

            // write_all() writes the entire string to the file
            // content.as_bytes() converts &str to &[u8] (bytes)
            file.write_all(content.as_bytes())
                .with_context(|| format!("Failed to write to '{}'. Disk may be full.", path.display()))?;

            // Explicit flush ensures data is written to disk immediately
            // Without this, data might sit in a buffer
            file.flush().context("Failed to flush file buffer")?;

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

fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Handle subcommands that don't need a file/directory argument
    match &args.command {
        Some(Commands::Verse) => {
            use anya_security_core::data::verses;
            let idx = verses::verse_index();
            let (text, reference) = verses::VERSES[idx];
            println!("{}", text.white().bold());
            println!("  — {}", reference.bright_cyan());
            return Ok(());
        }
        Some(Commands::HashCheck { target, against, json }) => {
            let matched = hash_check::run(target, against, *json)?;
            if matched {
                std::process::exit(1);
            }
            return Ok(());
        }
        Some(Commands::Yara { command }) => {
            match command {
                YaraCommands::Combine { input_dir, output_file, recursive } => {
                    yara::combine(input_dir, output_file, *recursive)?;
                }
                YaraCommands::FromStrings { strings_file, output, name, overwrite } => {
                    yara::from_strings(strings_file, output.as_deref(), name.as_deref(), *overwrite)?;
                }
            }
            return Ok(());
        }
        Some(Commands::Cases { list }) => {
            if *list {
                case::list_cases()?;
            } else {
                println!("Use --list to show all cases.");
            }
            return Ok(());
        }
        None => {} // Continue to file/directory analysis
    }

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
    let min_string_length = args
        .min_string_length
        .unwrap_or(config.analysis.min_string_length);

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
        let example_path = args
            .file
            .as_ref()
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

    // Validate: --summary and --json are mutually exclusive
    if args.summary && args.json {
        anyhow::bail!(
            "The --summary and --json flags can't be used together. Pick one output format."
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
        anyhow::bail!(
            "Couldn't find the file at '{}'. Double-check the path and try again.",
            file_path.display()
        );
    }

    // Get file size for spinner decision
    let file_size = fs::metadata(file_path)?.len();
    let is_large_file = file_size > LARGE_FILE_THRESHOLD;

    // Show spinner for large files in non-JSON pretty mode
    if is_large_file && output_level.should_print_info() && !args.json {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        spinner.set_message(format!(
            "Analysing ({:.2} MB)...",
            file_size as f64 / (1024.0 * 1024.0)
        ));
        spinner.enable_steady_tick(std::time::Duration::from_millis(80));
        // Spinner will be cleared when dropped
        let _ = spinner; // keep alive briefly
    }

    // ── Run full structured analysis ─────────────────────────────────────────
    let analysis = analyse_file(file_path.as_path(), min_string_length)?;
    let mut json_result = to_json_output(&analysis);

    // Compute verdict and top findings
    let (verdict_word, verdict_summary) = compute_verdict(&json_result);
    json_result.verdict_summary = Some(verdict_summary.clone());

    let top = anya_security_core::confidence::top_detections(&json_result, 3);
    json_result.top_findings = top
        .iter()
        .map(|d| output::TopFinding {
            label: d.description.clone(),
            confidence: d.confidence.clone(),
            technique_id: None, // TODO: extract from MITRE data if available
        })
        .collect();

    // ── JSON output ──────────────────────────────────────────────────────────
    if args.json {
        let json = serde_json::to_string_pretty(&json_result)?;
        write_output(&json, args.output.as_ref(), args.append)?;

        if let Some(path) = &args.output {
            if args.append {
                eprintln!("✓ JSON appended to: {:?}", path);
            } else {
                eprintln!("✓ JSON written to: {:?}", path);
            }
        }
        return Ok(());
    }

    // ── Pretty terminal output ───────────────────────────────────────────────

    // 1. Verdict line (always first)
    if output_level.should_print_info() || output_level == OutputLevel::Quiet {
        let coloured_verdict = match verdict_word.as_str() {
            "MALICIOUS" => format!("VERDICT: {}", verdict_summary).red().bold(),
            "SUSPICIOUS" => format!("VERDICT: {}", verdict_summary).yellow().bold(),
            "CLEAN" => format!("VERDICT: {}", verdict_summary).green().bold(),
            _ => format!("VERDICT: {}", verdict_summary).white().dimmed(),
        };
        println!("{}", coloured_verdict);
    }

    // 2. File type mismatch warning
    if let Some(ref m) = json_result.file_type_mismatch {
        let prefix = match m.severity {
            output::MismatchSeverity::High | output::MismatchSeverity::Medium => "⚠ ",
            output::MismatchSeverity::Low => "ℹ ",
        };
        println!(
            "{}FILE TYPE MISMATCH [{}] — detected {}, extension claims {}",
            prefix,
            m.severity,
            m.detected_type,
            m.claimed_extension
        );
    }

    // 3. Top findings summary
    if !top.is_empty() && output_level.should_print_info() {
        println!("\n{}", "TOP FINDINGS".bold().cyan());
        for d in &top {
            let level_str = format!("[{:?}]", d.confidence).to_uppercase();
            let padded = format!("{:<10}", level_str);
            let line = match d.confidence {
                output::ConfidenceLevel::Critical => format!("  {} {}", padded.red().bold(), d.description),
                output::ConfidenceLevel::High => format!("  {} {}", padded.yellow().bold(), d.description),
                output::ConfidenceLevel::Medium => format!("  {} {}", padded.white(), d.description),
                output::ConfidenceLevel::Low => format!("  {} {}", padded.white().dimmed(), d.description),
            };
            println!("{}", line);
        }
    }

    // Read raw file data for display functions that need it
    let file_data = fs::read(file_path)?;

    // 4. Banner + file info
    if output_level.should_print_info() {
        println!();
        println!("{}", "=== Ányá v1.1.0 ===".bold().green());
        println!("Analysing: {:?}\n", file_path);
        print_file_info(file_path, &file_data, output_level)?;
    }

    // 5. Hashes
    if output_level.should_print_info() {
        println!("{}", "=== Cryptographic Hashes ===".bold().cyan());
        println!("  MD5:    {}", json_result.hashes.md5.green());
        println!("  SHA1:   {}", json_result.hashes.sha1.green());
        println!("  SHA256: {}", json_result.hashes.sha256.green());
        if let Some(ref tlsh) = json_result.hashes.tlsh {
            println!("  TLSH:   {}", tlsh.green());
        }
        println!();
    }

    // 6. Format-specific detailed analysis (existing display functions)
    match Object::parse(&file_data) {
        Ok(Object::PE(_pe)) => {
            if output_level.should_print_info() {
                println!(
                    "{}",
                    "🔍 Detected: Windows PE (Portable Executable)"
                        .bold()
                        .cyan()
                );
            }
            if let Err(e) = pe_parser::analyse_pe(&file_data, output_level) {
                eprintln!("{} PE analysis failed: {}. The file may be corrupted, truncated, or not a valid PE binary.", "⚠".yellow(), e);
            }
        }
        Ok(Object::Elf(_elf)) => {
            if output_level.should_print_info() {
                println!(
                    "{}",
                    "🔍 Detected: Linux ELF (Executable and Linkable Format)"
                        .bold()
                        .cyan()
                );
            }
            if let Err(e) = elf_parser::analyse_elf(&file_data, output_level) {
                eprintln!("{} ELF analysis failed: {}. The file may be corrupted, truncated, or not a valid ELF binary.", "⚠".yellow(), e);
            }
        }
        Ok(Object::Mach(_)) => {
            if output_level.should_print_info() {
                println!("{}", "🔍 Detected: macOS Mach-O".bold().cyan());
            }
        }
        Ok(_) => {
            if output_level.should_print_info() {
                println!("{}", "🔍 Unknown executable format".yellow());
            }
        }
        Err(_) => {
            if output_level.should_print_info() {
                println!(
                    "{}",
                    "🔍 Not a recognized executable format - performing basic analysis only"
                        .yellow()
                );
            }
        }
    }

    // 7. Strings + entropy (existing display functions)
    if output_level.should_print_info() {
        print_strings(&file_data, min_string_length);
        print_entropy(&file_data);
    }

    // 8. IOC indicators section
    if let Some(ref ioc) = json_result.ioc_summary {
        print_ioc_section(ioc);
    }

    // In quiet mode, summarize findings
    if output_level == OutputLevel::Quiet {
        print_quiet_summary(&file_data);
    }

    // 9. --explain: print explanations at the bottom
    if args.explain {
        print_explanations(&json_result);
    }

    // 10. --guided: print contextual learning lessons
    if args.guided {
        use anya_security_core::{
            confidence::calculate_risk_score, data::mitre_mappings::map_techniques_from_imports,
            guided_output::print_guided_output,
        };
        let import_names: Vec<&str> = analysis
            .pe_analysis
            .as_ref()
            .map(|p| {
                p.imports
                    .suspicious_apis
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let techniques = map_techniques_from_imports(&import_names);
        let risk = calculate_risk_score(
            analysis.pe_analysis.as_ref(),
            analysis.elf_analysis.as_ref(),
        );
        print_guided_output(
            analysis.pe_analysis.as_ref(),
            analysis.elf_analysis.as_ref(),
            &techniques,
            risk,
        );
    }

    // 11. --case: save to case directory
    if let Some(ref case_name) = args.case {
        let json_report = serde_json::to_string_pretty(&json_result)?;
        case::save_to_case(
            case_name,
            file_path.as_path(),
            &json_result.hashes.sha256,
            &verdict_word,
            &json_report,
        )?;
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
        anyhow::bail!(
            "Couldn't find the directory at '{}'. Double-check the path and try again.",
            dir_path.display()
        );
    }

    if !dir_path.is_dir() {
        anyhow::bail!(
            "'{}' is not a directory. Provide a directory path for batch scanning.",
            dir_path.display()
        );
    }

    // Banner for batch mode
    if output_level.should_print_info() && !args.json {
        println!("{}", "=== Ányá v1.1.0 - Batch Mode ===".bold().green());
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
        .filter_map(|e| e.ok()) // Filter out directory read errors
        .filter(|e| e.file_type().is_file()) // Only files, not directories
        .map(|e| e.path().to_path_buf()) // Convert to PathBuf
        .filter(|path| is_executable_file(path)) // Only executables
        .collect(); // Collect into a Vector

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
    let mut summary = BatchSummary {
        total_files: executable_files.len(),
        ..Default::default()
    };

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

    // --summary mode: collect verdicts for table output
    if args.summary {
        struct SummaryRow {
            filename: String,
            verdict: String,
            top_indicator: String,
        }

        let mut rows: Vec<SummaryRow> = Vec::new();
        let mut malicious_count = 0usize;
        let mut suspicious_count = 0usize;
        let mut clean_count = 0usize;

        for (idx, file_path) in executable_files.iter().enumerate() {
            let filename = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();

            if let Some(ref pb) = progress {
                pb.set_message(format!("Analysing: {}", filename));
            }

            match analyse_file(file_path.as_path(), min_string_length) {
                Ok(result) => {
                    summary.analysed += 1;
                    let json_result = to_json_output(&result);
                    let (verdict_word, _) = compute_verdict(&json_result);
                    let top = anya_security_core::confidence::top_detections(&json_result, 1);
                    let top_indicator = top.first().map(|d| {
                        format!("{} [{:?}]", d.description, d.confidence)
                    }).unwrap_or_else(|| "—".to_string());

                    match verdict_word.as_str() {
                        "MALICIOUS" => malicious_count += 1,
                        "SUSPICIOUS" => suspicious_count += 1,
                        _ => clean_count += 1,
                    }

                    // Save to case if --case provided
                    if let Some(ref case_name) = args.case {
                        if let Ok(json_report) = serde_json::to_string_pretty(&json_result) {
                            let _ = case::save_to_case(
                                case_name,
                                file_path.as_path(),
                                &json_result.hashes.sha256,
                                &verdict_word,
                                &json_report,
                            );
                        }
                    }

                    rows.push(SummaryRow { filename, verdict: verdict_word, top_indicator });
                }
                Err(e) => {
                    summary.failed += 1;
                    rows.push(SummaryRow {
                        filename,
                        verdict: "ERROR".to_string(),
                        top_indicator: format!("{}", e),
                    });
                }
            }

            if let Some(ref pb) = progress {
                pb.set_position((idx + 1) as u64);
            }
        }

        if let Some(pb) = progress {
            pb.finish_and_clear();
        }

        summary.duration = start_time.elapsed().as_secs_f64();

        // Sort: MALICIOUS first, then SUSPICIOUS, then CLEAN, then others
        rows.sort_by_key(|r| match r.verdict.as_str() {
            "MALICIOUS" => 0,
            "SUSPICIOUS" => 1,
            "CLEAN" => 2,
            _ => 3,
        });

        // Print summary table
        println!(
            "\n{}",
            format!(
                "BATCH ANALYSIS SUMMARY — {} files, {} malicious, {} suspicious, {} clean",
                executable_files.len(), malicious_count, suspicious_count, clean_count
            )
            .bold()
            .cyan()
        );
        println!("Completed in {:.1}s\n", summary.duration);

        println!(
            "{:<30} {:<12} {}",
            "FILE".bold(),
            "VERDICT".bold(),
            "TOP INDICATOR".bold()
        );

        for row in &rows {
            let name = if row.filename.len() > 30 {
                format!("{}...", &row.filename[..27])
            } else {
                row.filename.clone()
            };
            let verdict_coloured = match row.verdict.as_str() {
                "MALICIOUS" => format!("{:<12}", row.verdict).red().bold(),
                "SUSPICIOUS" => format!("{:<12}", row.verdict).yellow().bold(),
                "CLEAN" => format!("{:<12}", row.verdict).green(),
                _ => format!("{:<12}", row.verdict).white().dimmed(),
            };
            println!("{:<30} {} {}", name, verdict_coloured, row.top_indicator);
        }

        return Ok(());
    }

    // Default batch mode (existing behaviour)
    for (idx, file_path) in executable_files.iter().enumerate() {
        let filename = file_path.file_name().unwrap_or_default().to_string_lossy();

        if let Some(ref pb) = progress {
            pb.set_message(format!("Analysing: {}", filename));
        }

        match analyse_single_file(file_path, args, OutputLevel::Quiet, min_string_length) {
            Ok(_) => {
                summary.analysed += 1;
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
                if !args.json {
                    if let Some(ref pb) = progress {
                        pb.println(format!("  ✗ {}: {}", filename.red(), e));
                    } else {
                        eprintln!("  ✗ {}: {}", filename.red(), e);
                    }
                }
            }
        }

        if let Some(ref pb) = progress {
            pb.set_position((idx + 1) as u64);
        }
    }

    if let Some(pb) = progress {
        pb.finish_with_message("✓ Analysis complete");
    }

    summary.duration = start_time.elapsed().as_secs_f64();

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
#[allow(dead_code)]
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
        "\n{}",
        format!("═══ Extracted Strings (min length: {}) ═══", min_length)
            .bold()
            .cyan()
    );

    let is_large = data.len() as u64 > LARGE_FILE_THRESHOLD;
    let start_time = std::time::Instant::now();

    let pb = if is_large {
        let bar = create_progress_bar(data.len() as u64, "Extracting strings");
        Some(bar)
    } else {
        None
    };

    let mut current_string = String::new();
    let mut string_count = 0;
    const MAX_DISPLAY: usize = 50; // Only show first 50 strings
    const UPDATE_INTERVAL: usize = 256 * 1024; // Update every 256KB

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
                    // Print above progress bar if it exists
                    if let Some(ref pb) = pb {
                        pb.println(format!("  {}", current_string.bright_white()));
                    } else {
                        println!("  {}", current_string.bright_white());
                    }
                    string_count += 1;
                } else if string_count == MAX_DISPLAY {
                    let msg = format!(
                        "  {}",
                        format!("... (showing first {} strings only)", MAX_DISPLAY).yellow()
                    );
                    if let Some(ref pb) = pb {
                        pb.println(msg);
                    } else {
                        println!("{}", msg);
                    }
                    string_count += 1;
                }
            }
            current_string.clear();
        }
    }

    // Don't forget the last string if file doesn't end with non-printable
    if current_string.len() >= min_length && string_count < MAX_DISPLAY {
        if let Some(ref pb) = pb {
            pb.println(format!("  {}", current_string.bright_white()));
        } else {
            println!("  {}", current_string.bright_white());
        }
        string_count += 1;
    }

    let elapsed = start_time.elapsed();

    // Finish progress bar properly - keep it visible at 100%
    if let Some(pb) = pb {
        pb.set_position(data.len() as u64); // Ensure we're at 100%
        pb.finish_with_message(format!(
            "✓ Extracted {} strings ({:.2}s)",
            string_count,
            elapsed.as_secs_f64()
        ));
    }

    println!(
        "\nTotal strings found: {}",
        string_count.to_string().green().bold()
    );
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

// ── IOC indicators section ──────────────────────────────────────────────────

fn print_ioc_section(ioc: &output::IocSummary) {
    use std::collections::HashMap;

    if ioc.ioc_strings.is_empty() {
        return;
    }

    println!(
        "\n{}",
        format!("IOC INDICATORS ({} found)", ioc.ioc_strings.len())
            .bold()
            .cyan()
    );

    // Group by IOC type
    let mut grouped: HashMap<String, Vec<&output::ExtractedString>> = HashMap::new();
    for es in &ioc.ioc_strings {
        let key = es
            .ioc_type
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "other".to_string());
        grouped.entry(key).or_default().push(es);
    }

    let type_order = [
        "url", "ipv4", "ipv6", "domain", "email", "registry_key",
        "windows_path", "linux_path", "mutex", "base64_blob",
    ];
    let type_labels: HashMap<&str, &str> = [
        ("url", "URLs"), ("ipv4", "IPv4"), ("ipv6", "IPv6"),
        ("domain", "Domains"), ("email", "Emails"), ("registry_key", "Registry"),
        ("windows_path", "Win paths"), ("linux_path", "Linux paths"),
        ("mutex", "Mutexes"), ("base64_blob", "Base64 blob"),
    ]
    .into();

    for type_key in &type_order {
        if let Some(entries) = grouped.get(*type_key) {
            let label = type_labels.get(type_key).unwrap_or(type_key);
            for (i, es) in entries.iter().take(3).enumerate() {
                let display = if *type_key == "base64_blob" {
                    format!("[{} chars, offset 0x{:x}]", es.value.len(), es.offset)
                } else if es.value.len() > 80 {
                    format!("{}...", &es.value[..77])
                } else {
                    es.value.clone()
                };
                if i == 0 {
                    println!("  {:<13}({})  {}", label, entries.len(), display);
                } else {
                    println!("  {:<18}{}", "", display);
                }
            }
            if entries.len() > 3 {
                println!("  {:<18}... and {} more", "", entries.len() - 3);
            }
        }
    }
}

// ── Explanations section (--explain) ────────────────────────────────────────

fn print_explanations(result: &output::AnalysisResult) {
    use anya_security_core::confidence::top_detections;

    let detections = top_detections(result, 10);
    if detections.is_empty() {
        return;
    }

    println!("\n{}", "━".repeat(50));
    println!("{}", "EXPLANATIONS".bold().cyan());
    println!("{}\n", "━".repeat(50));

    for d in &detections {
        let conf_str = format!("{:?}", d.confidence).to_uppercase();
        println!("{} — {} confidence", d.description.bold(), conf_str);

        // Generate a brief explanation based on the detection description
        let explanation = generate_explanation(&d.description);
        // Word-wrap to 70 chars
        for line in word_wrap(&explanation, 70) {
            println!("  {}", line);
        }
        println!();
    }
}

fn generate_explanation(description: &str) -> String {
    let desc_lower = description.to_lowercase();

    if desc_lower.contains("process injection") || desc_lower.contains("virtualallocex") && desc_lower.contains("writeprocessmemory") {
        "VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread imported together is the classic signature of process injection: malware allocating memory inside another running process and writing shellcode into it. This allows malware to run hidden inside a legitimate process like explorer.exe. Commonly seen in: RATs, banking trojans, loaders.".to_string()
    } else if desc_lower.contains("createremotethread") {
        "CreateRemoteThread creates a new thread in a remote process. Alone, it may be used legitimately, but it is a building block of process injection. Combined with other APIs, it raises confidence significantly.".to_string()
    } else if desc_lower.contains("persistence") || desc_lower.contains("regsetvalue") {
        "Registry modification combined with service creation or run-key paths indicates the malware is trying to survive reboots. This is a common persistence mechanism used by most malware families.".to_string()
    } else if desc_lower.contains("debugger") || desc_lower.contains("isdebuggerpresent") {
        "Debugger detection APIs check whether the process is being analysed. Malware uses these to alter its behaviour when under inspection, making dynamic analysis harder.".to_string()
    } else if desc_lower.contains("entropy") || desc_lower.contains("packed") || desc_lower.contains("encrypted") {
        "High entropy means the file's contents are nearly random. Legitimate executables rarely exceed 7.0. This strongly suggests the file is packed or encrypted — a common technique to hide malware from static analysis and antivirus scanners.".to_string()
    } else if desc_lower.contains("packer") {
        "A packer compresses or encrypts the original executable and wraps it in a decompression stub. While some legitimate software uses packers to reduce file size, packers are heavily used by malware to evade signature-based detection.".to_string()
    } else if desc_lower.contains("tls callback") {
        "TLS callbacks execute before the program's main entry point. Malware uses them to run anti-debugging checks or unpack code before analysts can attach a debugger.".to_string()
    } else if desc_lower.contains("overlay") {
        "Overlay data is appended after the last PE section. It can contain embedded payloads, encrypted configurations, or additional executables that the main program extracts at runtime.".to_string()
    } else if desc_lower.contains("mismatch") || desc_lower.contains("disguised") {
        "The file's actual format (detected from magic bytes) doesn't match its extension. This is a social engineering technique — a PE executable named .pdf or .jpg tricks users into opening it.".to_string()
    } else if desc_lower.contains("ioc") || desc_lower.contains("domain") || desc_lower.contains("url") {
        "Network indicators (URLs, domains, IPs) found in the binary's strings suggest the program communicates with remote servers. These could be command-and-control servers, download sites, or data exfiltration endpoints.".to_string()
    } else if desc_lower.contains("anti-analysis") || desc_lower.contains("vm") || desc_lower.contains("sandbox") {
        "Anti-analysis techniques detect whether the malware is running in a virtual machine, sandbox, or debugger. If detected, the malware may refuse to execute or behave benignly to avoid being flagged.".to_string()
    } else if desc_lower.contains("network") || desc_lower.contains("wsa") || desc_lower.contains("socket") {
        "Network APIs indicate the program creates network connections. Combined with other suspicious APIs, this may indicate a reverse shell, data exfiltration, or command-and-control communication.".to_string()
    } else if desc_lower.contains("checksum") {
        "A PE checksum mismatch means the file has been modified after compilation. This is common in cracked, patched, or tampered binaries. Most legitimate compilers set the correct checksum.".to_string()
    } else if desc_lower.contains("w+x") || desc_lower.contains("writable and executable") {
        "A section that is both writable and executable allows code to be modified at runtime. This is a strong indicator of self-modifying code, common in packers and shellcode.".to_string()
    } else if desc_lower.contains("ordinal") {
        "Importing by ordinal number instead of function name hides which APIs the program actually calls. This makes static analysis harder and is commonly seen in malware.".to_string()
    } else if desc_lower.contains("base64") {
        "Large Base64-encoded blobs in a binary often contain embedded payloads, encoded commands, or obfuscated configuration data that the malware decodes at runtime.".to_string()
    } else if desc_lower.contains("registry") {
        "Registry key references suggest the program reads or modifies Windows registry settings. This may be used for persistence, configuration storage, or system modification.".to_string()
    } else {
        "This detection was flagged based on static analysis indicators found in the binary. Review the technical details above for specifics.".to_string()
    }
}

fn word_wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() > width {
            lines.push(current_line);
            current_line = word.to_string();
        } else {
            current_line.push(' ');
            current_line.push_str(word);
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(32u8 >= 32 && 32u8 <= 126); // Space
        assert!(65u8 >= 32 && 65u8 <= 126); // 'A'
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

        assert_ne!(
            hash1, hash2,
            "Different data should produce different hashes"
        );
    }
}
