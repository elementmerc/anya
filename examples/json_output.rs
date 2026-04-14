//! JSON output example
//!
//! Demonstrates how to export analysis results as JSON.
//!
//! Run with:
//! ```bash
//! cargo run --example json_output -- file.exe > output.json
//! ```

use anya_security_core::{analyse_file, to_json_output};
use std::env;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file-path>", args[0]);
        std::process::exit(1);
    }

    let file_path = Path::new(&args[1]);

    // Analyze file
    let result = analyse_file(
        file_path,
        4,
        anya_security_core::config::AnalysisDepth::Standard,
    )?;

    // Convert to JSON output format
    let json_result = to_json_output(&result);

    // Print as pretty JSON
    let json = serde_json::to_string_pretty(&json_result)?;
    println!("{}", json);

    Ok(())
}
