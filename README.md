# Anya — Malware Analysis Tool

Anya (meaning "eye" in Igbo) performs static analysis on binary files to identify suspicious characteristics without executing them. Built in Rust for memory safety and performance — important when parsing potentially hostile input.

Anya ships in two forms: a command-line tool for scripting and automation, and a desktop GUI for interactive investigation.

**Licence:** AGPL-3.0-or-later — see [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) for proprietary use.

---

## Capabilities

- Cryptographic hashing — MD5, SHA-1, SHA-256
- Shannon entropy calculation — file-level and per section
- ASCII string extraction with configurable minimum length
- PE (Portable Executable) structure parsing
  - Section analysis with per-section entropy and W+X detection
  - Import table analysis with 40+ suspicious Windows API signatures
  - Export table analysis
  - Security mitigation detection — ASLR, DEP/NX
- Batch directory scanning with progress tracking
- JSON output for integration with automation pipelines
- Configurable analysis via TOML config files

---

## Installation

### Pre-built binaries

Download the latest release from the [releases page](https://github.com/elementmerc/anya/releases). Builds are provided for:

- Linux x86_64
- Windows x86_64
- macOS x86_64 / ARM64

### Docker

```bash
# Pull image
docker pull elementmerc/anya:latest

# Analyse a single file
docker run --rm \
  -v "$(pwd)/samples:/samples:ro" \
  -v "$(pwd)/output:/output" \
  elementmerc/anya:latest \
  --file /samples/suspicious.exe --json --output /output/result.json

# Batch scan a directory
docker run --rm \
  -v "$(pwd)/samples:/samples:ro" \
  -v "$(pwd)/output:/output" \
  elementmerc/anya:latest \
  --directory /samples --recursive --json --output /output/batch.jsonl

# Build locally
make docker-build
```

See [docker-compose.yml](docker-compose.yml) for a ready-to-use compose configuration.

### From source — CLI

Requires Rust 1.85 or later (edition 2024).

```bash
git clone https://github.com/elementmerc/anya
cd anya
cargo build --release
# Binary: target/release/anya-security-core
```

### From source — Desktop GUI

Requires Rust 1.85+, Node.js 18+, and the [Tauri prerequisites](https://tauri.app/start/prerequisites/) for your platform.

```bash
git clone https://github.com/elementmerc/anya
cd anya
npm install
npm run tauri build
# Installer: src-tauri/target/release/bundle/
```

To run the GUI in development mode:

```bash
npm run tauri dev
```

---

## Quick Start — CLI

### Single file analysis

```bash
# Basic analysis
anya-security-core --file suspicious.exe

# Verbose output
anya-security-core --file suspicious.exe --verbose

# Quiet mode (errors only)
anya-security-core --file suspicious.exe --quiet
```

### Batch processing

```bash
# Analyse directory
anya-security-core --directory ./samples

# Recursive
anya-security-core --directory ./samples --recursive
```

### JSON output

```bash
# Print JSON to stdout
anya-security-core --file malware.exe --json

# Write to file
anya-security-core --file malware.exe --json --output report.json

# Append (batch JSONL)
anya-security-core --file sample.exe --json --output batch.jsonl --append
```

See [JSON_SCHEMA.md](JSON_SCHEMA.md) for the full output schema.

### Configuration

```bash
# Create default config
anya-security-core --init-config

# Use custom config
anya-security-core --config ./custom.toml --file malware.exe
```

Config file locations:
- Linux/macOS: `~/.config/anya/config.toml`
- Windows: `%APPDATA%\anya\config.toml`

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

---

## Quick Start — Desktop GUI

Launch the Anya GUI, then drag and drop a file onto the drop zone. The GUI provides:

- **Overview** — risk score, file metadata, hash display
- **Sections** — PE section table with entropy bars and W+X highlighting
- **Imports** — suspicious API list grouped by category
- **Entropy** — full entropy chart with per-section breakdown
- **Strings** — extracted ASCII strings
- **Security** — ASLR, DEP, version information

Analysis history is stored locally in a SQLite database. No data leaves your device. See [PRIVACY.md](PRIVACY.md).

Settings (theme, font size, database path) are accessible via the gear icon.

---

## Analysis Modules

### Hash calculation

Generates MD5, SHA-1, and SHA-256 hashes for file identification and comparison against known-bad hash databases.

### String extraction

Scans for printable ASCII strings that may reveal hardcoded IP addresses or domains, file paths, registry keys, command-line arguments, error messages, or obfuscated credentials.

### Entropy analysis

Calculates Shannon entropy to identify:

- **High (> 7.5)** — encrypted or packed content
- **Moderate (4.0–7.5)** — normal compiled code
- **Low (< 4.0)** — plain text or simple data

### PE analysis

Header information (architecture, entry point, image base, compilation timestamp), section analysis (per-section entropy, W+X detection, unusual names), import/export table analysis, and security mitigation detection (ASLR, DEP/NX).

**Suspicious API categories:**

| Category | Examples |
|---|---|
| Code injection | `CreateRemoteThread`, `WriteProcessMemory` |
| Persistence | `RegSetValueEx`, `CreateService` |
| Anti-analysis | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` |
| Network | `InternetOpen`, `URLDownloadToFile` |
| Cryptography | `CryptEncrypt`, `CryptDecrypt` |
| Keylogging | `GetAsyncKeyState`, `SetWindowsHookEx` |
| Privilege escalation | `AdjustTokenPrivileges` |

---

## Interpreting Results

Anya provides indicators, not verdicts. Consider the full context:

**Highly suspicious combinations:**
- High section entropy + disabled ASLR/DEP + code injection APIs
- Anti-debugging APIs + obfuscated strings + unusual section names

**May be legitimate:**
- UPX sections on commercial software
- Debug APIs in development builds
- Registry access in installers

A low score means Anya found no indicators it was looking for — not that the file is safe. See [SECURITY.md](SECURITY.md) for the tool's explicit scope and limitations.

---

## Safety

Static analysis is safer than dynamic analysis but not without risk:

- Parse vulnerabilities could theoretically be triggered by malformed input — Anya uses well-tested libraries (goblin), but no parser is bulletproof.
- Always work in isolated environments — VMs or air-gapped machines.
- Do not analyse on production systems.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run `cargo fmt` and `cargo clippy` — both must pass clean
4. Submit a pull request

By submitting a pull request you agree your contribution may be dual-licensed under AGPL-3.0 and future commercial licences. See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).

---

## Licence

AGPL-3.0-or-later. See [LICENSE.TXT](LICENSE.TXT).

For commercial licensing: daniel@themalwarefiles.com

---

**Anya** (pronounced AHN-yah) means "eye" in Igbo, a language spoken in southeastern Nigeria.
