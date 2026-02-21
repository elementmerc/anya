# Anya - Malware Analysis Tool in Rust

## Overview

Anya (meaning "eye" in Igbo) performs static analysis on binary files to identify suspicious characteristics without executing them. It's built in Rust for memory safety and performance (pretty important when you're deliberately parsing potentially hostile input)

**Current capabilities:**
- Cryptographic hashing (MD5, SHA1, SHA256)
- ASCII string extraction with configurable minimum length
- Shannon entropy calculation (file-level and per-section)
- PE (Portable Executable) structure parsing
- Import/export table analysis
- Suspicious Windows API detection
- Security mitigation analysis (ASLR, DEP/NX)

## Installation

**Via Cargo:**
```bash
cargo install anya
```

**Pre-built binaries:**
Available for Linux, Windows, and macOS on the [releases page](https://github.com/elementmerc/anya/releases).

**From source:**
```bash
git clone https://github.com/elementmerc/anya
cd anya
cargo build --release
# Binary will be in target/release/anya
```

## Usage
```bash
# Standard analysis
anya --file <path-to-file>

# JSON output (suitable for automation/scripting)
anya --file <path-to-file> --json

# Write results to file
anya --file <path-to-file> --output report.txt

# Adjust string extraction threshold
anya --file <path-to-file> --min-string-length 6

# Full help
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

## Next update

**v0.4.0** - ELF support for Linux binaries  

## Technical Details

**Tested on:**
- Rust 1.70+
- Linux, Windows 10/11, macOS 12+

## License

Dual-licensed under AGPL-3.0 or commercial license.
See LICENSE for details.

## Etymology

**Anya** (pronounced AHN-yah) means "eye" in Igbo, a language spoken in southeastern Nigeria. The name reflects the tool's purpose to see into the inner workings of potentially malicious software.
