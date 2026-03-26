<div align="center">

<img src="icon.svg" alt="Anya logo" width="96" height="96">

# Anya

**Fast static malware analysis**

[![CI](https://github.com/elementmerc/anya/actions/workflows/ci.yml/badge.svg)](https://github.com/elementmerc/anya/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/elementmerc/anya)](https://github.com/elementmerc/anya/releases/latest)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE.TXT)
[![crates.io](https://img.shields.io/crates/v/anya-security-core)](https://crates.io/crates/anya-security-core)

<img src="docs/demo.gif" alt="Anya GUI demo" width="720">

</div>

---

Anya analyses binary files without executing them. Drop a PE or ELF onto the GUI, or pipe files through the CLI. Get hashes, entropy, imports, sections, IOC indicators, MITRE ATT&CK mappings, a confidence-scored verdict, and a risk score. All in under seconds, all locally.

**Anya** (AHN-yah) means "eye" in Igbo.

---

## Install

### Download

Grab the latest release for your platform:

**[Download from GitHub Releases →](https://github.com/elementmerc/anya/releases/latest)**

| Platform | GUI | CLI |
|---|---|---|
| **Windows** | `.msi` installer | `.zip` |
| **macOS** | `.dmg` (Intel + Apple Silicon) | Universal binary |
| **Linux** | `.AppImage` / `.deb` | `.tar.gz` (x86_64 + arm64) |

### One-liner (CLI)

```bash
curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/master/install.sh | bash
```

Prompts for CLI, GUI, or both. No root required for CLI.

### Docker

```bash
docker pull elementmerc/anya:latest

docker run --rm \
  -v "$(pwd)/samples:/samples:ro" \
  elementmerc/anya:latest \
  --file /samples/malware.exe --json
```

### Building from source

Building from source is **not supported** for public users. Anya relies on
a private git submodule (`anya-proprietary`) containing the scoring engine
and educational data. The public repo includes stub crates that allow the
workspace to resolve, but the build will fail without the real content.
Use the install script, Docker image, or pre-built releases above.

Attempting to build from source without authorised access may lead to
*unexpected consequences*.

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

# Verdict + explanations
anya --file suspicious.exe --explain

# Batch summary table
anya --directory ./samples --recursive --summary

# Check hash against known-bad list
anya hash-check suspicious.exe --against known-bad.txt

# Generate YARA rule from strings
anya yara from-strings strings.txt --output rule.yar

# Combine YARA rules
anya yara combine ./rules combined.yar --recursive

# Save to investigation case
anya --file suspicious.exe --case operation-nightfall

# List cases
anya cases --list
```

### Additional commands

```bash
# Watch a directory for new malware samples
anya watch ./incoming --recursive

# Compare two files side by side
anya compare sample_v1.exe sample_v2.exe

# Generate a standalone HTML report
anya --file suspicious.exe --format html --output report.html

# Generate shell completions
anya completions bash > ~/.bash_completion.d/anya

# Batch analysis with progress bar
anya --directory ./samples --recursive
```

Full flag reference: `anya --help`

---

## GUI

Launch Anya, drag a file onto the drop zone — or use the **+** button for single file or **Batch Analysis** (analyse a whole folder).

| Tab | What it shows |
|---|---|
| Overview | Risk score ring, file metadata, hashes, "Why this verdict?" explanation |
| Entropy | Full entropy chart + per-section breakdown with configurable thresholds |
| Imports | DLL tree with expandable function lists and inline explanations |
| Sections | Section permission analysis, per-section entropy, characteristics |
| Strings | Extracted strings with indicator extraction and classification |
| Security | ASLR, DEP, Authenticode, overlay, debug artifacts — click any card for explanations |
| MITRE | Mapped ATT&CK techniques with tactic tagging and real-world attack examples |

**Batch Analysis** — select a folder to scan all executables. Files appear in a collapsible sidebar with colour-coded verdicts. A summary dashboard shows verdict breakdown and a donut chart.

**Teacher Mode** (toggle in Settings → Learning) surfaces contextual lessons as you navigate. Click any DLL, security card, IOC block, or MITRE technique for beginner-friendly explanations with real-world examples.

**Case management** — Save to Case button in the TopBar, Case Browser on the DropZone for browsing and reopening past investigations.

**Keyboard shortcuts** — Ctrl+O to open a file, 1-7 to switch tabs, ? for a shortcuts overlay.

**File comparison** — side-by-side diff of two analyses highlighting verdict, entropy, import, and string differences.

**Pin findings** — pin important findings to the top of the Overview tab for quick reference.

**Copy-friendly output** — hover any hash, finding, or section to copy it to the clipboard.

**Drag-and-drop tab reorder** — reorder analysis tabs to match your workflow.

**Export HTML report** — generate a standalone HTML report with embedded CSS and SVG charts from the export dropdown.

**Recent files** appear on the drop zone for quick re-analysis. A **guided tour** walks first-time users through the interface.

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
| Batch analysis | ✓ | ✓ | ✗ | ✓ |
| IOC extraction | ✓ | ✓ | ✗ | Partial |

---

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [JSON output schema](docs/JSON_SCHEMA.md)
- [CHANGELOG](docs/CHANGELOG.md)
- [Security scope & limitations](SECURITY.md)
- [Privacy policy](docs/PRIVACY.md)
- [Commercial licensing](docs/COMMERCIAL_LICENSE.md)

---

## Uninstalling

- **Windows**: Use Add/Remove Programs — the uninstaller launches automatically.
- **Linux**: `sudo apt remove anya` — the uninstaller runs during removal.
- **macOS**: Drag Anya.app to the Trash, then optionally run:
  `~/Applications/Anya.app/Contents/MacOS/anya-gui --uninstall`
  to remove your analysis database and preferences.

---

## Licence

AGPL-3.0-or-later. See [LICENSE.TXT](LICENSE.TXT).

Commercial licensing: daniel@themalwarefiles.com
