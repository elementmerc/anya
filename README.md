<div align="center">

<!-- <img src="docs/assets/anya-logo.png" alt="Anya logo" width="96" height="96"> -->

# Anya

**Fast static malware analysis**

[![CI](https://github.com/elementmerc/anya/actions/workflows/ci.yml/badge.svg)](https://github.com/elementmerc/anya/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/elementmerc/anya)](https://github.com/elementmerc/anya/releases/latest)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE.TXT)
[![crates.io](https://img.shields.io/crates/v/anya-security-core)](https://crates.io/crates/anya-security-core)

<!-- <img src="docs/assets/demo.gif" alt="Anya GUI demo" width="720"> -->

</div>

---

Anya analyses binary files without executing them. Drop a PE or ELF onto the GUI, or pipe files through the CLI. Get hashes, entropy, imports, sections, MITRE ATT&CK mappings, and a risk score. All in under a second, all locally.

**Anya** (AHN-yah) means "eye" in Igbo.

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/master/install.sh | bash
```

Prompts for CLI, GUI, or both. No root required for CLI.

### Platform grid

| Platform | CLI | GUI |
|---|---|---|
| **Linux x86_64** | `.tar.gz` + `musl` | `.AppImage` / `.deb` |
| **Linux arm64** | `.tar.gz` + `musl` | — |
| **macOS (Intel + Apple Silicon)** | Universal binary | `.dmg` (universal) |
| **Windows x86_64** | `.zip` | `.msi` |
| **Docker** | `linux/amd64` + `linux/arm64` | — |

### Docker

```bash
docker pull elementmerc/anya:latest

docker run --rm \
  -v "$(pwd)/samples:/samples:ro" \
  elementmerc/anya:latest \
  --file /samples/malware.exe --json
```

### From source

```bash
# CLI
cargo install anya-security-core --locked

# GUI (requires Node 20 + Tauri prerequisites)
npm ci && npm run tauri build
```

---

## CLI usage

```bash
# Analyse a file
anya --file suspicious.exe

# JSON output
anya --file suspicious.exe --json

# Batch scan
anya --directory ./samples --recursive --json --output results.jsonl --append

# Teacher Mode (guided lessons inline)
anya --file suspicious.exe --guided

# Random Bible verse
anya verse

# Init config
anya --init-config
```

Full flag reference: `anya --help`

---

## GUI

Launch Anya, drag a file onto the drop zone. Seven tabs:

| Tab | What it shows |
|---|---|
| Overview | Risk score, file metadata, SHA-256 |
| Entropy | Full entropy chart + per-section breakdown |
| Imports | Suspicious API table grouped by category |
| Sections | W+X detection, per-section entropy, characteristics |
| Strings | Extracted ASCII strings |
| Security | ASLR, DEP, version info, signed status |
| MITRE | Mapped ATT&CK techniques with tactic tagging |

**Teacher Mode** (toggle in Settings → Learning) surfaces contextual lessons as you navigate findings. **Bible Verses** (same section) shows a rotating NLT verse in the status bar.

Analysis history is stored in a local SQLite database. Nothing leaves your device.

---

## Why Anya?

| | Anya | VirusTotal | Ghidra | CAPA |
|---|---|---|---|---|
| Offline | ✓ | ✗ | ✓ | ✓ |
| No cloud upload | ✓ | ✗ | ✓ | ✓ |
| Desktop GUI | ✓ | Browser | ✓ | ✗ |
| < 1 s analysis | ✓ | Network-bound | ✗ | Seconds |
| MITRE mapping | ✓ | Partial | ✗ | ✓ |
| Beginner-friendly | ✓ | — | ✗ | — |

---

## Docs

- [Architecture](ARCHITECTURE.md)
- [JSON output schema](JSON_SCHEMA.md)
- [CHANGELOG](CHANGELOG.md)
- [Security scope & limitations](SECURITY.md)
- [Privacy policy](PRIVACY.md)
- [Commercial licensing](COMMERCIAL_LICENSE.md)

---

## Licence

AGPL-3.0-or-later. See [LICENSE.TXT](LICENSE.TXT).

Commercial licensing: daniel@themalwarefiles.com
