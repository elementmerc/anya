// Anya - Malware Analysis Platform
// Watch module: monitor a directory for new files and analyse them automatically
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use anya_security_core::{
    analyse_file, compute_verdict, config, is_executable_file, to_json_output,
};
use colored::*;

/// Watch a directory for newly created files and analyse executables automatically.
///
/// When a file with a recognised executable extension is created, Anya
/// debounces for 500ms so that multiple events for the same file (common
/// during writes) result in a single analysis pass. Each file is then
/// analysed and a compact one-line verdict is printed.
///
/// When `json_output` is true, each result is emitted as a JSON object instead
/// of the human readable one-liner. Use `json_compact` to emit single-line JSON.
pub fn watch_directory(
    dir: &Path,
    recursive: bool,
    min_string_length: usize,
    json_output: bool,
    json_compact: bool,
    depth: config::AnalysisDepth,
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

    // Debounce: collect all created files within a 500ms window, then
    // analyse each unique path exactly once.
    let mut pending: HashSet<PathBuf> = HashSet::new();

    loop {
        // Block until the first event arrives
        match rx.recv() {
            Ok(Ok(event)) => {
                if event.kind.is_create() {
                    for path in &event.paths {
                        if is_executable_file(path) {
                            pending.insert(path.clone());
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::error!("Watch error: {}", e);
            }
            Err(_) => break, // Channel closed
        }

        // Drain any additional events that arrive within the debounce window
        std::thread::sleep(std::time::Duration::from_millis(500));
        while let Ok(event) = rx.try_recv() {
            match event {
                Ok(event) => {
                    if event.kind.is_create() {
                        for path in &event.paths {
                            if is_executable_file(path) {
                                pending.insert(path.clone());
                            }
                        }
                    }
                }
                Err(e) => tracing::error!("Watch error: {}", e),
            }
        }

        // Analyse all unique files that arrived during the window
        for path in pending.drain() {
            eprintln!("  {} New file: {}", "-->".cyan(), path.display());
            match analyse_file(&path, min_string_length, depth) {
                Ok(result) => {
                    let json_result = to_json_output(&result);
                    if json_output {
                        let serialised = if json_compact {
                            serde_json::to_string(&json_result)?
                        } else {
                            serde_json::to_string_pretty(&json_result)?
                        };
                        println!("{}", serialised);
                        std::io::stdout().flush()?;
                    } else {
                        let (verdict_word, verdict_summary) = compute_verdict(&json_result);
                        print_watch_result(&path, &verdict_word, &verdict_summary);
                    }
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
