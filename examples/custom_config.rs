//! Custom configuration example
//!
//! Demonstrates how to load and use a custom config file.
//!
//! Run with:
//! ```bash
//! cargo run --example custom_config
//! ```

use anya_security_core::config::Config;

fn main() -> anyhow::Result<()> {
    // Load default config or from file
    let config = Config::load_or_default()?;
    
    println!("Current Configuration:");
    println!("=====================");
    
    println!("\nAnalysis Settings:");
    println!("  Min string length: {}", config.analysis.min_string_length);
    println!("  Entropy threshold: {}", config.analysis.entropy_threshold);
    println!("  Show progress:     {}", config.analysis.show_progress);
    
    println!("\nOutput Settings:");
    println!("  Use colours: {}", config.output.use_colours);
    println!("  Format:      {}", config.output.format);
    println!("  Verbosity:   {}", config.output.verbosity);
    
    // Create a default config file
    println!("\nTo create a default config file, run:");
    println!("  anya --init-config");
    
    // Show config location
    if let Some(path) = Config::default_path() {
        println!("\nConfig file location:");
        println!("  {}", path.display());
    }

    Ok(())
}