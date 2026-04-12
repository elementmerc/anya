//! Basic file analysis example
//!
//! Demonstrates how to analyze a single file and print results.
//!
//! Run with:
//! ```bash
//! cargo run --example basic_analysis -- path/to/file.exe
//! ```

use anya_security_core::analyse_file;
use std::env;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    // Get file path from command line
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file-path>", args[0]);
        std::process::exit(1);
    }

    let file_path = Path::new(&args[1]);

    // Analyze the file
    println!("Analyzing: {}", file_path.display());
    let result = analyse_file(
        file_path,
        4,
        anya_security_core::config::AnalysisDepth::Standard,
    )?;

    // Print results
    println!("\n=== Analysis Results ===");
    println!("File: {}", result.path.display());
    println!("Size: {} bytes", result.size_bytes);
    println!("Format: {}", result.file_format);

    println!("\nHashes:");
    println!("  MD5:    {}", result.hashes.md5);
    println!("  SHA1:   {}", result.hashes.sha1);
    println!("  SHA256: {}", result.hashes.sha256);

    println!("\nEntropy:");
    println!("  Value: {:.2}", result.entropy.value);
    println!("  Category: {}", result.entropy.category);
    println!("  Suspicious: {}", result.entropy.is_suspicious);

    println!("\nStrings:");
    println!("  Total found: {}", result.strings.total_count);
    println!("  Sample (first {}):", result.strings.sample_count);
    for s in &result.strings.samples {
        println!("    {}", s);
    }

    if let Some(pe) = result.pe_analysis {
        println!("\nPE Analysis:");
        println!("  Architecture: {}", pe.architecture);
        println!("  Entry Point: {}", pe.entry_point);
        println!("  Sections: {}", pe.sections.len());
        println!("  Imported DLLs: {}", pe.imports.dll_count);
        println!("  Suspicious APIs: {}", pe.imports.suspicious_api_count);

        if pe.imports.suspicious_api_count > 0 {
            println!("\n  ⚠ Suspicious APIs found:");
            for api in &pe.imports.suspicious_apis {
                println!("    - {} ({})", api.name, api.category);
            }
        }
    }

    Ok(())
}
