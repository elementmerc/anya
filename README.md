# Anya - Malware Analysis Tool in Rust

## Overview

Anya (meaning "eye" in Igbo) performs static analysis on binary files to identify suspicious characteristics without executing them. It's built in Rust for memory safety and performance (pretty important when you're deliberately parsing potentially hostile input)

**Current capabilities:**
- Cryptographic hashing (MD5, SHA1, SHA256)
- Batch directory scanning with progress tracking
- Configurable analysis via TOML config files
- Multiple output modes (quiet, normal, verbose)
- File output with append mode
- ASCII string extraction with configurable minimum length
- Shannon entropy calculation (file-level and per-section)
- PE (Portable Executable) structure parsing
- Import/export table analysis
- Suspicious Windows API detection
- Security mitigation analysis (ASLR, DEP/NX)

## Installation

**Requirements:**
- Rust 1.75+ (for building from source)

**Via Cargo:**
```bash
cargo install anya-security-core
```

**Via Docker (Coming Soon):**
```bash
# Pull from Docker Hub
docker pull anya-security/anya:latest

# Analyze a file
docker run -v ./samples:/samples anya --file /samples/malware.exe

# Interactive TUI (coming soon)
docker run -it anya-tui
```

**Pre-built binaries:**
Available for Linux, Windows, and macOS on the [releases page](https://github.com/elementmerc/anya/releases).

**From source:**
```bash
git clone https://github.com/elementmerc/anya
cd anya
cargo build --release
# Binary will be in target/release/anya-security-core
```

## Quick Start

### Single File Analysis
```bash
# Basic analysis
anya --file suspicious.exe

# Verbose output
anya --file suspicious.exe --verbose

# Quiet mode (errors only)
anya --file suspicious.exe --quiet
```

### Batch Processing
```bash
# Analyze directory
anya --directory ./samples

# Recursive scanning
anya --directory ./samples --recursive
```

## Configuration

Anya supports persistent configuration via TOML files:
```bash
# Create default config
anya --init-config
```

**Config file location:**
- Linux/macOS: `~/.config/anya/config.toml`
- Windows: `%APPDATA%\anya\config.toml`

**Example config:**
```toml
[analysis]
min_string_length = 4
entropy_threshold = 7.5
show_progress = true

[output]
use_colours = true
format = "text"
verbosity = "normal"
```

CLI arguments always override config file settings.

### JSON Output
```bash
# Output as JSON
anya --file malware.exe --json

# Save to file
anya --file malware.exe --json --output report.json

# Append to existing file (batch processing)
anya --file sample1.exe --json --output batch.jsonl --append
```

### Configuration
```bash
# Create default config file
anya --init-config
# Edit: ~/.config/anya/config.toml (Linux/macOS)
#    or: %APPDATA%\anya\config.toml (Windows)

# Use custom config
anya --config ./custom-config.toml --file malware.exe
```

### Full Help
```bash
anya --help
```

## Analysis Modules

### Hash Calculation
Generates MD5, SHA1, and SHA256 hashes for file identification and comparison against known malware databases like VirusTotal

### String Extraction
Scans for printable ASCII strings that might reveal:
- Hardcoded IP addresses or domains
- File paths and registry keys
- Command-line arguments
- Error messages and debug strings
- Obfuscated or cleartext credentials

### Entropy Analysis
Calculates Shannon entropy to identify:
- **High entropy (> 7.5)**: Encrypted or packed sections (common obfuscation technique)
- **Moderate entropy (4.0-7.5)**: Normal compiled code
- **Low entropy (< 4.0)**: Plain text or simple data structures

### PE Analysis (Windows Executables)

**Header Information:**
- Architecture (32-bit vs 64-bit)
- Entry point and image base addresses
- Compilation timestamp (can be forged)

**Security Features:**
- ASLR status (disabled = easier exploitation)
- DEP/NX status (disabled = code execution in data sections)

**Section Analysis:**
- Per-section entropy (spots packed/encrypted regions)
- Unusual section names (e.g., UPX packers)
- Executable + writable sections (major red flag)

**Import Analysis:**
Detects 40+ suspicious Windows APIs categorised by:
- Code injection techniques
- Anti-analysis/debugging
- Persistence mechanisms
- Network operations
- Cryptography
- Keylogging/input monitoring
- Privilege escalation

## Interpreting Results

Anya provides indicators, not verdicts. Always consider the full context:

**Highly suspicious combinations:**
- High section entropy + disabled ASLR/DEP + code injection APIs
- Anti-debugging APIs + obfuscated strings + unusual sections
- Persistence APIs + network APIs + no digital signature

**Might be legitimate:**
- Popular packers (UPX) on commercial software
- Debug-related APIs in development builds
- Registry access in installers

When in doubt, check hashes against VirusTotal or submit to a sandbox.

## Safety Considerations

Static analysis is safer than dynamic analysis but not risk-free:
- Parse bugs could be exploited (I used well-tested libraries, but still)
- Always work in isolated environments (VMs, air-gapped machines)
- Don't analyse on production systems
- Maintain VM snapshots for quick recovery

## Technical Details

**Built with:**
- Rust 1.75+
- Dependencies: See [Cargo.toml](Cargo.toml)

**Tested on:**
- Linux (Ubuntu 22.04+)
- Windows 10/11
- Docker (multi-arch: amd64, arm64)

## Contributing

Contributions are always welcome. Please:
1. Fork the repository
2. Create a feature branch
3. Run `cargo fmt` and `cargo clippy`
4. Submit a pull request

## License

AGPL-3.0-or-later

For commercial licensing inquiries, contact: daniel@themalwarefiles.com

## Etymology

**Anya** (pronounced AHN-yah) means "eye" in Igbo, a language spoken in southeastern Nigeria. The name reflects the tool's purpose to see into the inner workings of potentially malicious software.

## Roadmap

**Coming Soon:**
- 🚀 Terminal User Interface (TUI) for interactive analysis
- 🐳 Docker support with pre-built images
- 🤫 Secret stuff
