# Anya Examples

This directory contains practical examples demonstrating Anya's capabilities.

## Running Examples

```bash
# Basic file analysis
cargo run --example basic_analysis -- path/to/file.exe

# Batch directory processing
cargo run --example batch_processing -- path/to/directory

# JSON output
cargo run --example json_output -- file.exe > output.json

# View configuration
cargo run --example custom_config
```

## Examples Overview

| Example | Purpose |
|---------|---------|
| `basic_analysis.rs` | Analyze single file and print all results
| `batch_processing.rs` | Process entire directory with summary
| `json_output.rs` | Export analysis as JSON 
| `custom_config.rs` | View and manage configuration 

## What Each Example Demonstrates

### basic_analysis.rs
**Learn:** Core analysis workflow
- Reading and analyzing a single file
- Accessing all analysis results
- Conditional logic based on findings
- Formatted output

**Use when:** You want to understand the basic analysis API

### batch_processing.rs
**Learn:** Batch operations and error handling
- Finding executable files in directories
- Processing multiple files
- Progress tracking
- Summary statistics
- Error recovery

**Use when:** Processing multiple files at once

### json_output.rs
**Learn:** Data serialization
- Converting analysis results to JSON
- Output formatting
- Integration with other tools

**Use when:** Integrating Anya with scripts or pipelines

### custom_config.rs
**Learn:** Configuration management
- Loading config files
- Default values
- Config file locations

**Use when:** Customizing Anya's behavior

## Quick Start

### 1. Analyze a File

```bash
# Use any PE file, or compile a test binary (see tests/fixtures/README.md)
cargo run --example basic_analysis -- /path/to/file.exe
```

### 2. Batch Process a Directory

```bash
# Analyze all .exe files in a directory
cargo run --example batch_processing -- /path/to/samples
```

### 3. Export to JSON

```bash
# Create JSON output
cargo run --example json_output -- test.exe > analysis.json

# Pretty-print with jq
cargo run --example json_output -- test.exe | jq .
```

## Tips

- Use `--release` for faster execution: `cargo run --release --example basic_analysis`
- Pipe JSON to `jq` for pretty formatting

## Need Help?

- Check the main README.md
- See API documentation: `cargo doc --open`
- File an issue: https://github.com/elementmerc/anya/issues

## License

These examples are part of Anya and are licensed under AGPL-3.0-or-later.