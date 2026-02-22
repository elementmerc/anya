//! Batch directory processing example
//!
//! Demonstrates how to analyze all executable files in a directory.
//!
//! Run with:
//! ```bash
//! cargo run --example batch_processing -- path/to/directory
//! ```

use anya_security_core::{BatchSummary, analyse_file, find_executable_files};
use std::env;
use std::path::Path;
use std::time::Instant;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <directory-path>", args[0]);
        std::process::exit(1);
    }

    let dir_path = Path::new(&args[1]);

    // Find all executable files
    println!("Scanning directory: {}", dir_path.display());
    let files = find_executable_files(dir_path, false)?;
    println!("Found {} executable files\n", files.len());

    // Analyze each file
    let mut summary = BatchSummary {
        total_files: files.len(),
        ..Default::default()
    };

    let start = Instant::now();

    for (idx, file) in files.iter().enumerate() {
        print!(
            "[{}/{}] Analyzing {}... ",
            idx + 1,
            files.len(),
            file.display()
        );

        match analyse_file(file, 4) {
            Ok(result) => {
                summary.analysed += 1;

                // Check if suspicious
                if result.entropy.is_suspicious {
                    summary.suspicious += 1;
                    println!("⚠ SUSPICIOUS (high entropy: {:.2})", result.entropy.value);
                } else if let Some(ref pe) = result.pe_analysis {
                    if pe.imports.suspicious_api_count > 5 {
                        summary.suspicious += 1;
                        println!(
                            "⚠ SUSPICIOUS ({} suspicious APIs)",
                            pe.imports.suspicious_api_count
                        );
                    } else {
                        println!("✓ OK");
                    }
                } else {
                    println!("✓ OK");
                }
            }
            Err(e) => {
                summary.failed += 1;
                println!("✗ FAILED: {}", e);
            }
        }
    }

    summary.duration = start.elapsed().as_secs_f64();

    // Print summary
    println!("\n{}", "=".repeat(50));
    println!("Batch Analysis Complete");
    println!("{}", "=".repeat(50));
    println!("Total files:    {}", summary.total_files);
    println!("Analysed:       {}", summary.analysed);
    println!("Failed:         {}", summary.failed);
    println!("Suspicious:     {}", summary.suspicious);
    println!("Duration:       {:.2}s", summary.duration);
    println!("Success rate:   {:.1}%", summary.success_rate());
    println!("Analysis rate:  {:.1} files/sec", summary.analysis_rate());

    Ok(())
}
