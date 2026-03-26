// Anya - Malware Analysis Platform
// Watch module: monitor a directory for new files and analyse them automatically
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;

use anya_security_core::{analyse_file, compute_verdict, is_executable_file, to_json_output};
use colored::*;

/// Watch a directory for newly created files and analyse executables automatically.
///
/// When a file with a recognised executable extension is created, Anya waits
/// briefly for the write to finish, then runs a full analysis and prints a
/// compact one-line verdict.
pub fn watch_directory(
    dir: &Path,
    recursive: bool,
    min_string_length: usize,
) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

    let mode = if recursive {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };
    watcher.watch(dir, mode)?;

    eprintln!(
        "{} Watching {} for new files... (Ctrl+C to stop)",
        ">>>".bold().cyan(),
        dir.display()
    );

    for event in rx {
        match event {
            Ok(event) => {
                if event.kind.is_create() {
                    for path in &event.paths {
                        if is_executable_file(path) {
                            // Small delay for file to finish writing
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            eprintln!("  {} New file: {}", "-->".cyan(), path.display());
                            match analyse_file(path, min_string_length) {
                                Ok(result) => {
                                    let json_result = to_json_output(&result);
                                    let (verdict_word, verdict_summary) =
                                        compute_verdict(&json_result);
                                    print_watch_result(path, &verdict_word, &verdict_summary);
                                }
                                Err(e) => {
                                    eprintln!(
                                        "  {} Error analysing {}: {}",
                                        "!".red().bold(),
                                        path.display(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("{} Watch error: {}", "!".red().bold(), e),
        }
    }
    Ok(())
}

/// Print a compact one-line result for watch mode.
fn print_watch_result(path: &Path, verdict_word: &str, verdict_summary: &str) {
    let filename = path.file_name().unwrap_or_default().to_string_lossy();

    let coloured_verdict = match verdict_word {
        "MALICIOUS" => verdict_word.red().bold(),
        "SUSPICIOUS" => verdict_word.yellow().bold(),
        "CLEAN" => verdict_word.green().bold(),
        _ => verdict_word.white().dimmed(),
    };

    println!(
        "  {} {:<30} {} -- {}",
        "|".cyan(),
        filename,
        coloured_verdict,
        verdict_summary,
    );
}
