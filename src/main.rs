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
    find_executable_files, hash_check, is_executable_file, output, pe_parser, to_json_output,
};
use anyhow::{Context, Result}; // For better error handling
use clap::{CommandFactory, Parser, Subcommand}; // For parsing command-line arguments
use colored::*; // For coloured terminal output
use indicatif::{ProgressBar, ProgressStyle};
use std::fs; // For file system operations
use std::fs::OpenOptions; // For file creation and opening
use std::io::Write; // For writing to files
use std::path::PathBuf; // For handling file paths // For progress indicators
use walkdir::WalkDir; // For recursive directory traversal

mod compare;
mod watch;

use anya_security_core::report;

// Hashing libraries
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

// Goblin for file format detection
use goblin::Object;

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), env!("ANYA_VERSION_SUFFIX"),);

/// Bundled config values passed to analysis functions
struct RunConfig<'a> {
    min_string_length: usize,
    effective_json: bool,
    json_compact: bool,
    effective_html: bool,
    effective_pdf: bool,
    effective_markdown: bool,
    packed_entropy: f64,
    suspicious_entropy: f64,
    cases_dir_override: Option<&'a str>,
}

/// CLI structure using Clap
#[derive(Parser, Debug)]
#[command(name = "Anya")]
#[command(version = VERSION)]
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

    /// Output results in JSON format (pretty-printed by default)
    #[arg(short, long)]
    json: bool,

    /// Output compact JSON (single line, no indentation)
    #[arg(long)]
    json_compact: bool,

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

    /// Output format: text (default), json, html, pdf, or markdown
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    format: OutputFormat,

    /// Save results to a named case for tracking investigations
    #[arg(long, value_name = "NAME")]
    case: Option<String>,

    /// Disable Known Sample Database (TLSH similarity) matching
    #[arg(long)]
    no_ksd: bool,

    /// Custom TLSH distance threshold for KSD matching (default: 150)
    #[arg(long, value_name = "DISTANCE", default_value = "150")]
    ksd_threshold: u32,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Output format for analysis results
#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Html,
    Pdf,
    Markdown,
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

    /// Watch a directory for new files and analyse them automatically
    Watch {
        /// Directory to watch
        #[arg(value_name = "DIR")]
        directory: PathBuf,
        /// Watch subdirectories too
        #[arg(short, long)]
        recursive: bool,
    },

    /// Compare two files side by side
    Compare {
        /// First file to compare
        #[arg(value_name = "FILE1")]
        file1: PathBuf,
        /// Second file to compare
        #[arg(value_name = "FILE2")]
        file2: PathBuf,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Benchmark detection rate and performance against a sample dataset
    Benchmark {
        /// Directory containing sample files to benchmark against
        #[arg(value_name = "DIR")]
        directory: PathBuf,
        /// Recurse into subdirectories
        #[arg(short, long)]
        recursive: bool,
        /// Number of parallel workers (default: auto-detect from CPU cores)
        #[arg(short, long, value_name = "N")]
        workers: Option<usize>,
        /// Use all available CPU cores (overrides --workers)
        #[arg(long)]
        max: bool,
        /// Expected ground truth: "malware" or "benign" (for detection rate calculation)
        #[arg(long, value_name = "LABEL")]
        ground_truth: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Manage the Known Sample Database (TLSH similarity matching)
    Ksd {
        #[command(subcommand)]
        command: KsdCommands,
    },
}

#[derive(Subcommand, Debug)]
enum KsdCommands {
    /// Import known samples from a calibration results JSON file
    Import {
        /// Path to calibration_results.json (with --store-raw data)
        file: PathBuf,
    },

    /// List known samples in the database
    List {
        /// Filter by malware family
        #[arg(long)]
        family: Option<String>,
        /// Maximum entries to show
        #[arg(long, default_value = "50")]
        limit: usize,
    },

    /// Show database statistics
    Stats,

    /// Add a single known sample manually
    Add {
        /// TLSH hash of the sample
        #[arg(long)]
        tlsh: String,
        /// Malware family name
        #[arg(long)]
        family: String,
        /// Malware function (loader, dropper, stealer, etc.)
        #[arg(long, default_value = "unknown")]
        function: String,
        /// SHA256 hash (optional reference)
        #[arg(long, default_value = "manual")]
        sha256: String,
    },

    /// Export the database to a JSON file
    Export {
        /// Output file path
        file: PathBuf,
    },

    /// Remove a sample from the overlay database
    Remove {
        /// SHA256 hash of the sample to remove
        #[arg(long)]
        sha256: String,
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
            file.write_all(content.as_bytes()).with_context(|| {
                format!("Failed to write to '{}'. Disk may be full.", path.display())
            })?;

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

fn main() {
    if let Err(e) = run() {
        eprintln!("{}: {:#}", "Error".red().bold(), e);
        if let Some(hint) = anya_security_core::errors::suggest(&format!("{:#}", e)) {
            eprintln!("  {} {}", "Hint:".yellow(), hint);
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    // Initialize structured logging — ANYA_LOG env var controls level
    // Default: warn (quiet), --verbose: info, ANYA_LOG=debug for development
    let env_filter = tracing_subscriber::EnvFilter::try_from_env("ANYA_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

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
        Some(Commands::HashCheck {
            target,
            against,
            json,
        }) => {
            let matched = hash_check::run(target, against, *json)?;
            if matched {
                std::process::exit(1);
            }
            return Ok(());
        }
        Some(Commands::Yara { command: _ }) => {
            println!(
                "YARA integration is coming soon. We're ironing out the kinks \u{2014} stay tuned."
            );
            return Ok(());
        }
        Some(Commands::Cases { list }) => {
            if *list {
                case::list_cases(None)?;
            } else {
                println!("Use --list to show all cases.");
            }
            return Ok(());
        }
        Some(Commands::Watch {
            directory,
            recursive,
        }) => {
            let cfg = if let Some(config_path) = &args.config {
                config::Config::load_from_file(config_path)?
            } else {
                config::Config::load_or_default()?
            };
            let msl = args
                .min_string_length
                .unwrap_or(cfg.analysis.min_string_length);
            watch::watch_directory(directory, *recursive, msl)?;
            return Ok(());
        }
        Some(Commands::Compare { file1, file2 }) => {
            let cfg = if let Some(config_path) = &args.config {
                config::Config::load_from_file(config_path)?
            } else {
                config::Config::load_or_default()?
            };
            let msl = args
                .min_string_length
                .unwrap_or(cfg.analysis.min_string_length);
            compare::compare_files(file1, file2, msl)?;
            return Ok(());
        }
        Some(Commands::Completions { shell }) => {
            let mut cmd = Args::command();
            clap_complete::generate(*shell, &mut cmd, "anya", &mut std::io::stdout());
            return Ok(());
        }
        Some(Commands::Ksd { command }) => {
            let overlay_path = dirs::config_dir()
                .map(|d| d.join("anya").join("known_samples.json"))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Could not determine config directory. Set $HOME or $XDG_CONFIG_HOME."
                    )
                })?;

            match command {
                KsdCommands::Import { file } => {
                    println!("Importing known samples from: {}", file.display());
                    let samples = anya_scoring::ksd::KnownSampleDb::import_calibration(file)
                        .map_err(|e| anyhow::anyhow!(e))?;
                    if samples.is_empty() {
                        println!("No samples with TLSH hashes found in the file.");
                    } else {
                        println!("Parsed {} samples with TLSH hashes.", samples.len());
                        anya_scoring::ksd::KnownSampleDb::save_overlay(&samples, &overlay_path)
                            .map_err(|e| anyhow::anyhow!(e))?;
                        println!("Overlay saved to: {}", overlay_path.display());
                    }
                }
                KsdCommands::List { family, limit } => {
                    let db = anya_scoring::ksd::KnownSampleDb::load(Some(&overlay_path));
                    if db.is_empty() {
                        println!("Known Sample Database is empty.");
                        println!("Run 'anya ksd import <calibration_results.json>' to populate.");
                    } else {
                        let samples = db.samples();
                        let filtered: Vec<_> = if let Some(fam) = family {
                            samples.iter().filter(|s| s.family == *fam).collect()
                        } else {
                            samples.iter().collect()
                        };
                        println!("{:<18} {:<14} {:<10} TLSH", "SHA256", "Family", "Function");
                        println!("{}", "-".repeat(72));
                        for s in filtered.iter().take(*limit) {
                            println!(
                                "{:<18} {:<14} {:<10} {}",
                                &s.sha256[..16.min(s.sha256.len())],
                                s.family,
                                s.function,
                                &s.tlsh[..20.min(s.tlsh.len())],
                            );
                        }
                        if filtered.len() > *limit {
                            println!(
                                "... and {} more (use --limit to see more)",
                                filtered.len() - limit
                            );
                        }
                    }
                }
                KsdCommands::Stats => {
                    let db = anya_scoring::ksd::KnownSampleDb::load(Some(&overlay_path));
                    let stats = db.stats();
                    println!("Known Sample Database Statistics");
                    println!("  Total samples: {}", stats.total_samples);
                    if !stats.families.is_empty() {
                        println!("  Families:");
                        let mut families: Vec<_> = stats.families.iter().collect();
                        families.sort_by(|a, b| b.1.cmp(a.1));
                        for (family, count) in families {
                            println!("    {:<16} {}", family, count);
                        }
                    }
                    println!("  Overlay path: {}", overlay_path.display());
                }
                KsdCommands::Add {
                    tlsh,
                    family,
                    function,
                    sha256,
                } => {
                    let sample = anya_scoring::ksd::KnownSample {
                        tlsh: tlsh.clone(),
                        sha256: sha256.clone(),
                        family: family.clone(),
                        function: function.clone(),
                        tags: vec![],
                    };
                    anya_scoring::ksd::KnownSampleDb::save_overlay(&[sample], &overlay_path)
                        .map_err(|e| anyhow::anyhow!(e))?;
                }
                KsdCommands::Remove { sha256 } => {
                    println!("WARNING: This action is permanent and cannot be reversed.");
                    println!("Remove sample {}?", &sha256[..16.min(sha256.len())]);
                    print!("Type 'y' to confirm: ");
                    use std::io::Write;
                    std::io::stdout().flush().ok();
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).ok();
                    if input.trim().to_lowercase() != "y" {
                        println!("Cancelled.");
                        return Ok(());
                    }
                    anya_scoring::ksd::KnownSampleDb::remove_from_overlay(sha256, &overlay_path)
                        .map_err(|e| anyhow::anyhow!(e))?;
                }
                KsdCommands::Export { file } => {
                    let db = anya_scoring::ksd::KnownSampleDb::load(Some(&overlay_path));
                    let json = serde_json::to_string_pretty(db.samples())
                        .map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))?;
                    std::fs::write(file, json)?;
                    println!("Exported {} samples to {}", db.len(), file.display());
                }
            }
            return Ok(());
        }
        Some(Commands::Benchmark {
            directory,
            recursive,
            workers,
            max,
            ground_truth,
            json: bench_json,
        }) => {
            run_benchmark(
                directory,
                *recursive,
                *workers,
                *max,
                ground_truth.as_deref(),
                *bench_json,
            )?;
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

        // Create YARA rules directory
        let rules_dir = anya_security_core::yara::scanner::default_rules_dir();
        if !rules_dir.exists() {
            std::fs::create_dir_all(&rules_dir).ok();
            println!("✓ Created YARA rules directory at: {}", rules_dir.display());
            println!("  Place .yar/.yara files here for signature-based detection.");
        } else {
            let count = anya_security_core::yara::scanner::rule_file_count();
            println!(
                "✓ YARA rules directory: {} ({} rule files)",
                rules_dir.display(),
                count
            );
        }

        println!("\nEdit the config to customise Anya's behaviour.");
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

    // Merge --format with --json flag: --json is shorthand for --format json
    let effective_json =
        args.json || args.json_compact || matches!(args.format, OutputFormat::Json);
    let effective_html = matches!(args.format, OutputFormat::Html);
    let effective_pdf = matches!(args.format, OutputFormat::Pdf);
    let effective_markdown = matches!(args.format, OutputFormat::Markdown);

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

    // When --format text (default) is used with --output, produce Markdown instead
    let effective_markdown =
        effective_markdown || (matches!(args.format, OutputFormat::Text) && args.output.is_some());

    // Validate: --summary and --json are mutually exclusive
    if args.summary && effective_json {
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
    let run_cfg = RunConfig {
        min_string_length,
        effective_json,
        json_compact: args.json_compact,
        effective_html,
        effective_pdf,
        effective_markdown,
        packed_entropy: config.thresholds.packed_entropy,
        suspicious_entropy: config.thresholds.suspicious_entropy,
        cases_dir_override: config.cases_directory.as_deref(),
    };

    if let Some(file_path) = &args.file {
        // Single file mode
        analyse_single_file(file_path, &args, output_level, &run_cfg)?;
    } else if let Some(dir_path) = &args.directory {
        // Batch mode
        analyse_directory(dir_path, &args, output_level, &run_cfg)?;
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
    cfg: &RunConfig<'_>,
) -> Result<()> {
    let RunConfig {
        min_string_length,
        effective_json,
        json_compact,
        effective_html,
        effective_pdf,
        effective_markdown,
        packed_entropy,
        suspicious_entropy,
        cases_dir_override,
    } = *cfg;
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
    if is_large_file && output_level.should_print_info() && !effective_json && !effective_html {
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
    let json_result = to_json_output(&analysis);

    // verdict_summary and top_findings are now populated by to_json_output()
    let (mut verdict_word, verdict_summary) = compute_verdict(&json_result);

    // Known sample match overrides the heuristic verdict word
    if let Some(ref ks) = json_result.known_sample {
        verdict_word = ks.verdict.clone();
    }

    // ── JSON output ──────────────────────────────────────────────────────────
    if effective_json {
        let json = if json_compact {
            serde_json::to_string(&json_result)?
        } else {
            serde_json::to_string_pretty(&json_result)?
        };
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

    // ── HTML report output ──────────────────────────────────────────────────
    if effective_html {
        let output_path = args.output.clone().unwrap_or_else(|| {
            let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
            PathBuf::from(format!("{}_report.html", stem))
        });
        report::generate_html_report(&json_result, &output_path)?;
        return Ok(());
    }

    // ── PDF report output ──────────────────────────────────────────────────
    if effective_pdf {
        let output_path = args.output.clone().unwrap_or_else(|| {
            let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
            PathBuf::from(format!("{}_report.pdf", stem))
        });
        report::generate_pdf_report(&json_result, &output_path)?;
        return Ok(());
    }

    // ── Markdown report output ─────────────────────────────────────────────
    if effective_markdown {
        let output_path = args.output.clone().unwrap_or_else(|| {
            let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
            PathBuf::from(format!("{}_report.md", stem))
        });
        report::generate_markdown_report(&json_result, &output_path)?;
        return Ok(());
    }

    // ── Pretty terminal output ───────────────────────────────────────────────

    // 1. Verdict line (always first)
    if output_level.should_print_info() || output_level == OutputLevel::Quiet {
        let coloured_verdict = match verdict_word.as_str() {
            "MALICIOUS" => format!("VERDICT: {}", verdict_summary).red().bold(),
            "SUSPICIOUS" => format!("VERDICT: {}", verdict_summary).yellow().bold(),
            "CLEAN" => format!("VERDICT: {}", verdict_summary).green().bold(),
            "TOOL" => format!("VERDICT: {}", verdict_summary).cyan().bold(),
            "PUP" => format!("VERDICT: {}", verdict_summary).yellow(),
            "TEST" => format!("VERDICT: {}", verdict_summary).magenta().bold(),
            _ => format!("VERDICT: {}", verdict_summary).white().dimmed(),
        };
        println!("{}", coloured_verdict);

        // Known sample annotation
        if let Some(ref ks) = json_result.known_sample {
            println!("  {} [{}]", ks.name.cyan(), ks.category);
            println!("  {}", ks.description.dimmed());
        }

        // Forensic fragment annotation
        if let Some(ref frag) = json_result.forensic_fragment {
            println!(
                "  {} Associated family: {}",
                "FORENSIC FRAGMENT".yellow(),
                frag.associated_family
            );
            println!("  {}", frag.explanation.dimmed());
        }

        // Family annotation from KSD match
        if let Some(ref fa) = json_result.family_annotation {
            println!("  {} [{}]", fa.name.blue().bold(), fa.category);
            println!("  {}", fa.description.dimmed());
            if !fa.aliases.is_empty() {
                println!("  Also known as: {}", fa.aliases.join(", ").dimmed());
            }
        }
    }

    // 2. File type mismatch warning
    if let Some(ref m) = json_result.file_type_mismatch {
        let prefix = match m.severity {
            output::MismatchSeverity::High | output::MismatchSeverity::Medium => "⚠ ",
            output::MismatchSeverity::Low => "ℹ ",
        };
        println!(
            "{}FILE TYPE MISMATCH [{}] — detected {}, extension claims {}",
            prefix, m.severity, m.detected_type, m.claimed_extension
        );
    }

    // 3. Top findings summary
    if !json_result.top_findings.is_empty() && output_level.should_print_info() {
        println!("\n{}", "TOP FINDINGS".bold().cyan());
        for f in &json_result.top_findings {
            let level_str = format!("[{:?}]", f.confidence).to_uppercase();
            let padded = format!("{:<10}", level_str);
            let line = match f.confidence {
                output::ConfidenceLevel::Critical => {
                    format!("  {} {}", padded.red().bold(), f.label)
                }
                output::ConfidenceLevel::High => {
                    format!("  {} {}", padded.yellow().bold(), f.label)
                }
                output::ConfidenceLevel::Medium => {
                    format!("  {} {}", padded.white(), f.label)
                }
                output::ConfidenceLevel::Low => {
                    format!("  {} {}", padded.white().dimmed(), f.label)
                }
            };
            println!("{}", line);
        }
    }

    // Read raw file data for display functions that need it
    let file_data = fs::read(file_path)?;

    // 4. Banner + file info
    if output_level.should_print_info() {
        println!();
        println!(
            "{}",
            format!("=== Ányá v{VERSION} ===").as_str().bold().green()
        );
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
                eprintln!(
                    "{} PE analysis failed: {}. The file may be corrupted, truncated, or not a valid PE binary.",
                    "⚠".yellow(),
                    e
                );
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
                eprintln!(
                    "{} ELF analysis failed: {}. The file may be corrupted, truncated, or not a valid ELF binary.",
                    "⚠".yellow(),
                    e
                );
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
        print_entropy(&file_data, packed_entropy, suspicious_entropy);
    }

    // 8. IOC indicators section
    if let Some(ref ioc) = json_result.ioc_summary {
        print_ioc_section(ioc);
    }

    // 8b. YARA matches
    if !json_result.yara_matches.is_empty() {
        println!("\n{}", "YARA MATCHES".bold().cyan());
        for ym in &json_result.yara_matches {
            let desc = ym.description.as_deref().unwrap_or("No description");
            println!(
                "  {} {} {}",
                "MATCH".red().bold(),
                ym.rule_name.bold(),
                format!("({})", ym.namespace).dimmed()
            );
            println!("    {}", desc.dimmed());
            if !ym.matched_strings.is_empty() {
                for ms in ym.matched_strings.iter().take(5) {
                    println!(
                        "    {} @ offset {:#x} ({} bytes)",
                        ms.identifier.yellow(),
                        ms.offset,
                        ms.length
                    );
                }
                if ym.matched_strings.len() > 5 {
                    println!("    {} more match(es)...", ym.matched_strings.len() - 5);
                }
            }
        }
    }

    // In quiet mode, summarize findings
    if output_level == OutputLevel::Quiet {
        print_quiet_summary(&file_data, packed_entropy);
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
        let risk = calculate_risk_score(&json_result);
        print_guided_output(
            analysis.pe_analysis.as_ref(),
            analysis.elf_analysis.as_ref(),
            analysis.mach_analysis.is_some(),
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
            cases_dir_override,
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
    cfg: &RunConfig<'_>,
) -> Result<()> {
    let RunConfig {
        min_string_length,
        effective_json,
        packed_entropy,
        suspicious_entropy,
        cases_dir_override,
        ..
    } = *cfg;
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
    if output_level.should_print_info() && !effective_json {
        println!(
            "{}",
            format!("=== Ányá v{VERSION} - Batch Mode ===")
                .as_str()
                .bold()
                .green()
        );
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

    if output_level.should_print_info() && !effective_json {
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
    let progress = if output_level.should_print_info() && !effective_json && !args.summary {
        let pb = ProgressBar::new(executable_files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} | {msg} | {per_sec}")
                .unwrap()
                .progress_chars("█▓░"),
        );
        pb.set_message("Analysing files");
        Some(pb)
    } else {
        None
    };

    // --summary mode: collect verdicts for table output + relationship graph
    if args.summary {
        struct SummaryRow {
            filename: String,
            verdict: String,
            top_indicator: String,
            tlsh: String,
            family: String,
        }

        let mut rows: Vec<SummaryRow> = Vec::new();
        let mut malicious_count = 0usize;
        let mut suspicious_count = 0usize;
        let mut clean_count = 0usize;

        for (idx, file_path) in executable_files.iter().enumerate() {
            let filename = file_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            if let Some(ref pb) = progress {
                pb.set_message(format!("Analysing: {}", filename));
            }

            match analyse_file(file_path.as_path(), min_string_length) {
                Ok(result) => {
                    summary.analysed += 1;
                    let json_result = to_json_output(&result);
                    let (mut verdict_word, _) = compute_verdict(&json_result);

                    // Known sample match overrides heuristic verdict
                    if let Some(ref ks) = json_result.known_sample {
                        verdict_word = ks.verdict.clone();
                    }
                    let top = anya_security_core::confidence::top_detections(&json_result, 1);
                    let top_indicator = top
                        .first()
                        .map(|d| format!("{} [{:?}]", d.description, d.confidence))
                        .unwrap_or_else(|| "—".to_string());

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
                                cases_dir_override,
                            );
                        }
                    }

                    let tlsh = json_result.hashes.tlsh.clone().unwrap_or_default();
                    let family = json_result
                        .ksd_match
                        .as_ref()
                        .map(|k| k.family.clone())
                        .unwrap_or_default();

                    rows.push(SummaryRow {
                        filename,
                        verdict: verdict_word,
                        top_indicator,
                        tlsh,
                        family,
                    });
                }
                Err(e) => {
                    summary.failed += 1;
                    rows.push(SummaryRow {
                        filename,
                        verdict: "ERROR".to_string(),
                        top_indicator: format!("{}", e),
                        tlsh: String::new(),
                        family: String::new(),
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
                executable_files.len(),
                malicious_count,
                suspicious_count,
                clean_count
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
                "TOOL" => format!("{:<12}", row.verdict).cyan().bold(),
                "PUP" => format!("{:<12}", row.verdict).yellow(),
                "TEST" => format!("{:<12}", row.verdict).magenta().bold(),
                _ => format!("{:<12}", row.verdict).white().dimmed(),
            };
            println!("{:<30} {} {}", name, verdict_coloured, row.top_indicator);
        }

        // ── Relationship output (TLSH similarity + KSD family) ───────────
        let mut relationships: Vec<(usize, usize, i32, &str)> = Vec::new();
        for (i, ri) in rows.iter().enumerate() {
            if ri.tlsh.is_empty() {
                continue;
            }
            for (j, rj) in rows.iter().enumerate().skip(i + 1) {
                if rj.tlsh.is_empty() {
                    continue;
                }
                if let Some(distance) = anya_security_core::tlsh_distance(&ri.tlsh, &rj.tlsh) {
                    if distance <= 150 {
                        let label = if distance <= 30 {
                            "near-identical"
                        } else if distance <= 80 {
                            "similar"
                        } else {
                            "related"
                        };
                        relationships.push((i, j, distance, label));
                    }
                }
            }
        }

        // Also connect same KSD family
        for (i, ri) in rows.iter().enumerate() {
            if ri.family.is_empty() {
                continue;
            }
            for (j, rj) in rows.iter().enumerate().skip(i + 1) {
                if ri.family == rj.family {
                    let already = relationships
                        .iter()
                        .any(|&(a, b, _, _)| (a == i && b == j) || (a == j && b == i));
                    if !already {
                        relationships.push((i, j, 0, "same family"));
                    }
                }
            }
        }

        if !relationships.is_empty() {
            println!(
                "\n{}",
                format!("RELATIONSHIPS — {} connections found", relationships.len())
                    .bold()
                    .cyan()
            );
            println!(
                "{:<30} {:<4} {:<30} {}",
                "FILE A".bold(),
                "".bold(),
                "FILE B".bold(),
                "RELATIONSHIP".bold()
            );
            for &(i, j, distance, label) in &relationships {
                let name_a = if rows[i].filename.len() > 28 {
                    format!("{}...", &rows[i].filename[..25])
                } else {
                    rows[i].filename.clone()
                };
                let name_b = if rows[j].filename.len() > 28 {
                    format!("{}...", &rows[j].filename[..25])
                } else {
                    rows[j].filename.clone()
                };
                let rel_text = if distance > 0 {
                    format!("{} (TLSH distance: {})", label, distance)
                } else {
                    format!("{}: {}", label, rows[i].family)
                };
                let rel_coloured = match label {
                    "near-identical" => rel_text.red().bold(),
                    "similar" => rel_text.yellow(),
                    "same family" => rel_text.magenta(),
                    _ => rel_text.white().dimmed(),
                };
                println!(
                    "{:<30} {} {:<30} {}",
                    name_a,
                    "<->".dimmed(),
                    name_b,
                    rel_coloured
                );
            }
        }

        return Ok(());
    }

    // Default batch mode (existing behaviour)
    for (idx, file_path) in executable_files.iter().enumerate() {
        let filename = file_path.file_name().unwrap_or_default().to_string_lossy();

        if let Some(ref pb) = progress {
            pb.set_message(filename.to_string());
        }

        let batch_cfg = RunConfig {
            min_string_length,
            effective_json,
            json_compact: false,
            effective_html: false,
            effective_pdf: false,
            effective_markdown: false,
            packed_entropy,
            suspicious_entropy,
            cases_dir_override,
        };
        match analyse_single_file(file_path, args, OutputLevel::Quiet, &batch_cfg) {
            Ok(_) => {
                summary.analysed += 1;
                if !effective_json && output_level.should_print_info() {
                    if let Some(ref pb) = progress {
                        pb.println(format!("  ✓ {}", filename.green()));
                    } else {
                        println!("  ✓ {}", filename.green());
                    }
                }
            }
            Err(e) => {
                summary.failed += 1;
                if !effective_json {
                    let msg = format!("{}", e);
                    let hint = anya_security_core::errors::suggest(&msg)
                        .map(|h| format!("  {} {}", "Hint:".yellow(), h))
                        .unwrap_or_default();
                    if let Some(ref pb) = progress {
                        pb.println(format!(
                            "  ✗ {}: {}{}",
                            filename.red(),
                            e,
                            if hint.is_empty() {
                                String::new()
                            } else {
                                format!("\n{}", hint)
                            }
                        ));
                    } else {
                        eprintln!("  ✗ {}: {}", filename.red(), e);
                        if !hint.is_empty() {
                            eprintln!("{}", hint);
                        }
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

    if output_level.should_print_info() && !effective_json {
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
fn print_entropy(data: &[u8], packed_threshold: f64, suspicious_threshold: f64) {
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
    if entropy > packed_threshold {
        println!(
            "{}",
            "⚠ Very high entropy - likely encrypted or packed"
                .red()
                .bold()
        );
    } else if entropy > suspicious_threshold {
        println!(
            "{}",
            "⚠ Elevated entropy - possibly compressed or obfuscated".yellow()
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

// ═══════════════════════════════════════════════════════════════════════════════
// Benchmark command
// ═══════════════════════════════════════════════════════════════════════════════

fn run_benchmark(
    directory: &std::path::Path,
    recursive: bool,
    workers_override: Option<usize>,
    use_max: bool,
    ground_truth: Option<&str>,
    output_json: bool,
) -> Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    // Auto-detect worker count
    let available_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let workers = if use_max {
        available_cores
    } else {
        workers_override.unwrap_or_else(|| available_cores.saturating_sub(1).max(1))
    };

    // Find files
    let files = find_executable_files(directory, recursive)?;
    if files.is_empty() {
        anyhow::bail!("No files found in '{}'", directory.display());
    }

    if !output_json {
        println!("\n{}", "ANYA BENCHMARK".bold().cyan());
        println!("  {}   {}", "Directory:".bold(), directory.display());
        println!("  {}       {} files", "Files:".bold(), files.len());
        println!(
            "  {}     {} (of {} available)",
            "Workers:".bold(),
            workers,
            available_cores
        );
        if let Some(gt) = ground_truth {
            println!("  {} {}", "Ground truth:".bold(), gt);
        }
        println!();
    }

    // Benchmark counters
    let analysed = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let malicious = Arc::new(AtomicUsize::new(0));
    let suspicious = Arc::new(AtomicUsize::new(0));
    let clean = Arc::new(AtomicUsize::new(0));
    let yara_matches = Arc::new(AtomicUsize::new(0));

    // Progress bar
    let pb = if !output_json {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/dim}] {pos}/{len} ({per_sec}) ETA {eta}")
                .expect("progress style")
                .progress_chars("━━╌"),
        );
        Some(pb)
    } else {
        None
    };

    let start = Instant::now();

    // Run analysis with rayon thread pool
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .unwrap_or_else(|e| {
            eprintln!(
                "Failed to create thread pool with {} workers: {}. Using default.",
                workers, e
            );
            rayon::ThreadPoolBuilder::new()
                .build()
                .unwrap_or_else(|e2| {
                    eprintln!("Fatal: could not create any thread pool: {}", e2);
                    std::process::exit(1);
                })
        });

    pool.scope(|s| {
        for file_path in &files {
            let analysed = Arc::clone(&analysed);
            let failed = Arc::clone(&failed);
            let malicious = Arc::clone(&malicious);
            let suspicious = Arc::clone(&suspicious);
            let clean = Arc::clone(&clean);
            let yara_matches = Arc::clone(&yara_matches);
            let pb = pb.clone();

            s.spawn(move |_| {
                match analyse_file(file_path, 4) {
                    Ok(result) => {
                        analysed.fetch_add(1, Ordering::Relaxed);
                        let json_result = to_json_output(&result);
                        let (verdict_word, _) = compute_verdict(&json_result);

                        match verdict_word.as_str() {
                            "MALICIOUS" => {
                                malicious.fetch_add(1, Ordering::Relaxed);
                            }
                            "SUSPICIOUS" => {
                                suspicious.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                clean.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        if !json_result.yara_matches.is_empty() {
                            yara_matches
                                .fetch_add(json_result.yara_matches.len(), Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if let Some(ref pb) = pb {
                    pb.inc(1);
                }
            });
        }
    });

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    let duration = start.elapsed();
    let total = files.len();
    let analysed_count = analysed.load(Ordering::Relaxed);
    let failed_count = failed.load(Ordering::Relaxed);
    let malicious_count = malicious.load(Ordering::Relaxed);
    let suspicious_count = suspicious.load(Ordering::Relaxed);
    let clean_count = clean.load(Ordering::Relaxed);
    let yara_count = yara_matches.load(Ordering::Relaxed);
    let detected = malicious_count + suspicious_count;
    let files_per_sec = if duration.as_secs_f64() > 0.0 {
        analysed_count as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    // Detection rate calculation
    let detection_rate = if let Some(gt) = ground_truth {
        match gt {
            "malware" => {
                if analysed_count > 0 {
                    Some(detected as f64 / analysed_count as f64 * 100.0)
                } else {
                    None
                }
            }
            "benign" => {
                // FP rate: how many benign files were flagged
                if analysed_count > 0 {
                    Some(detected as f64 / analysed_count as f64 * 100.0)
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    };

    if output_json {
        let result = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "directory": directory.to_string_lossy(),
            "total_files": total,
            "analysed": analysed_count,
            "failed": failed_count,
            "verdicts": {
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "clean": clean_count,
            },
            "detected": detected,
            "yara_matches": yara_count,
            "duration_secs": duration.as_secs_f64(),
            "files_per_sec": files_per_sec,
            "workers": workers,
            "available_cores": available_cores,
            "ground_truth": ground_truth,
            "detection_rate": detection_rate,
            "fp_rate": if ground_truth == Some("benign") { detection_rate } else { serde_json::Value::Null.as_f64() },
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("\n{}", "BENCHMARK RESULTS".bold().cyan());
        println!(
            "  {}   {:.1}s ({:.1} files/sec)",
            "Duration:".bold(),
            duration.as_secs_f64(),
            files_per_sec
        );
        println!(
            "  {}    {}/{} ({} failed)",
            "Analysed:".bold(),
            analysed_count,
            total,
            failed_count
        );
        println!(
            "  {}    {} (of {} available)",
            "Workers:".bold(),
            workers,
            available_cores
        );
        println!();

        // Verdict breakdown
        println!("  {}", "Verdict Breakdown:".bold());
        println!("    {}  {}", "MALICIOUS".red().bold(), malicious_count);
        println!("    {} {}", "SUSPICIOUS".yellow().bold(), suspicious_count);
        println!("    {}      {}", "CLEAN".green(), clean_count);
        println!("    {}    {} total", "Detected:".bold(), detected);

        if yara_count > 0 {
            println!(
                "    {} {} rule match(es)",
                "YARA:".bold().magenta(),
                yara_count
            );
        }

        // Detection metrics
        if let Some(gt) = ground_truth {
            println!();
            match gt {
                "malware" => {
                    if let Some(rate) = detection_rate {
                        let color = if rate >= 99.0 {
                            "green"
                        } else if rate >= 90.0 {
                            "yellow"
                        } else {
                            "red"
                        };
                        let rate_str = format!("{:.1}%", rate);
                        let colored_rate = match color {
                            "green" => rate_str.green().bold(),
                            "yellow" => rate_str.yellow().bold(),
                            _ => rate_str.red().bold(),
                        };
                        println!("  {} {}", "Detection rate:".bold(), colored_rate);
                        let fn_count = analysed_count - detected;
                        println!(
                            "  {} {} ({:.1}%)",
                            "False negatives:".bold(),
                            fn_count,
                            fn_count as f64 / analysed_count as f64 * 100.0
                        );
                    }
                }
                "benign" => {
                    if let Some(rate) = detection_rate {
                        let fp_str = format!("{:.1}%", rate);
                        let colored_fp = if rate <= 1.0 {
                            fp_str.green().bold()
                        } else if rate <= 5.0 {
                            fp_str.yellow().bold()
                        } else {
                            fp_str.red().bold()
                        };
                        println!(
                            "  {} {} ({} of {} benign files flagged)",
                            "False positive rate:".bold(),
                            colored_fp,
                            detected,
                            analysed_count
                        );
                    }
                }
                _ => {}
            }
        }

        println!();
        println!(
            "  Anya v{} — privacy-first malware analysis",
            env!("CARGO_PKG_VERSION")
        );
    }

    Ok(())
}

/// Prints a brief entropy warning in quiet mode.
fn print_quiet_summary(data: &[u8], packed_threshold: f64) {
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

    // Only print if above packed threshold
    if entropy > packed_threshold {
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
        "url",
        "ipv4",
        "ipv6",
        "domain",
        "email",
        "registry_key",
        "windows_path",
        "linux_path",
        "mutex",
        "base64_blob",
    ];
    let type_labels: HashMap<&str, &str> = [
        ("url", "URLs"),
        ("ipv4", "IPv4"),
        ("ipv6", "IPv6"),
        ("domain", "Domains"),
        ("email", "Emails"),
        ("registry_key", "Registry"),
        ("windows_path", "Win paths"),
        ("linux_path", "Linux paths"),
        ("mutex", "Mutexes"),
        ("base64_blob", "Base64 blob"),
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

    if desc_lower.contains("process injection")
        || desc_lower.contains("virtualallocex") && desc_lower.contains("writeprocessmemory")
    {
        "VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread imported together is the classic signature of process injection: malware allocating memory inside another running process and writing shellcode into it. This allows malware to run hidden inside a legitimate process like explorer.exe. Commonly seen in: RATs, banking trojans, loaders.".to_string()
    } else if desc_lower.contains("createremotethread") {
        "CreateRemoteThread creates a new thread in a remote process. Alone, it may be used legitimately, but it is a building block of process injection. Combined with other APIs, it raises confidence significantly.".to_string()
    } else if desc_lower.contains("persistence") || desc_lower.contains("regsetvalue") {
        "Registry modification combined with service creation or run-key paths indicates the malware is trying to survive reboots. This is a common persistence mechanism used by most malware families.".to_string()
    } else if desc_lower.contains("debugger") || desc_lower.contains("isdebuggerpresent") {
        "Debugger detection APIs check whether the process is being analysed. Malware uses these to alter its behaviour when under inspection, making dynamic analysis harder.".to_string()
    } else if desc_lower.contains("entropy")
        || desc_lower.contains("packed")
        || desc_lower.contains("encrypted")
    {
        "High entropy means the file's contents are nearly random. Legitimate executables rarely exceed 7.0. This strongly suggests the file is packed or encrypted — a common technique to hide malware from static analysis and antivirus scanners.".to_string()
    } else if desc_lower.contains("packer") {
        "A packer compresses or encrypts the original executable and wraps it in a decompression stub. While some legitimate software uses packers to reduce file size, packers are heavily used by malware to evade signature-based detection.".to_string()
    } else if desc_lower.contains("tls callback") {
        "TLS callbacks execute before the program's main entry point. Malware uses them to run anti-debugging checks or unpack code before analysts can attach a debugger.".to_string()
    } else if desc_lower.contains("overlay") {
        "Overlay data is appended after the last PE section. It can contain embedded payloads, encrypted configurations, or additional executables that the main program extracts at runtime.".to_string()
    } else if desc_lower.contains("mismatch") || desc_lower.contains("disguised") {
        "The file's actual format (detected from magic bytes) doesn't match its extension. This is a social engineering technique — a PE executable named .pdf or .jpg tricks users into opening it.".to_string()
    } else if desc_lower.contains("ioc")
        || desc_lower.contains("domain")
        || desc_lower.contains("url")
    {
        "Network indicators (URLs, domains, IPs) found in the binary's strings suggest the program communicates with remote servers. These could be command-and-control servers, download sites, or data exfiltration endpoints.".to_string()
    } else if desc_lower.contains("anti-analysis")
        || desc_lower.contains("vm")
        || desc_lower.contains("sandbox")
    {
        "Anti-analysis techniques detect whether the malware is running in a virtual machine, sandbox, or debugger. If detected, the malware may refuse to execute or behave benignly to avoid being flagged.".to_string()
    } else if desc_lower.contains("network")
        || desc_lower.contains("wsa")
        || desc_lower.contains("socket")
    {
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
        // Test printable ASCII detection via runtime function
        let is_printable = |b: u8| (32..=126).contains(&b);
        assert!(is_printable(32)); // Space
        assert!(is_printable(65)); // 'A'
        assert!(is_printable(126)); // '~'
        assert!(!is_printable(31)); // Below range
        assert!(!is_printable(127)); // Above range
    }

    #[test]
    fn test_string_extraction_min_length() {
        let data = b"ABC\x00DEFGH\x00IJ\x00KLMNOPQRST";
        let min_length = 4;

        // Count strings that meet minimum length
        let mut current_string = String::new();
        let mut valid_strings = Vec::new();

        for &byte in data.iter() {
            if (32..=126).contains(&byte) {
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
