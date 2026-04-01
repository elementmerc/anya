<div align="center">

<img src="icon.svg" alt="Anya logo" width="96" height="96">

# Anya

**Fast, offline static malware analysis platform**

<p>
  <a href="https://github.com/elementmerc/anya/actions/workflows/ci.yml"><img src="https://github.com/elementmerc/anya/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/elementmerc/anya/releases/latest"><img src="https://img.shields.io/github/v/release/elementmerc/anya?color=blue" alt="Release" /></a>
  <a href="LICENSE.TXT"><img src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20Commercial-blue" alt="AGPL-3.0 | Commercial" /></a>
  <a href="https://github.com/elementmerc/anya"><img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey" alt="Platform" /></a>
</p>
<p>
  <a href="https://github.com/elementmerc/anya"><img src="https://img.shields.io/badge/any%20file-20%2B%20deep%20parsers-brightgreen" alt="Any file, 20+ deep parsers" /></a>
  <a href="https://github.com/elementmerc/anya"><img src="https://img.shields.io/badge/detection-99.9%25-brightgreen" alt="99.9% detection" /></a>
  <a href="https://github.com/elementmerc/anya"><img src="https://img.shields.io/badge/network-zero%20calls-success" alt="Zero network calls" /></a>
  <a href="https://github.com/elementmerc/anya"><img src="https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-blueviolet" alt="MITRE ATT&CK" /></a>
</p>

<img src="docs/demo.gif" alt="Anya GUI demo" width="720">

</div>

---

Anya analyses files without executing them. Drop a PE, ELF, Mach-O, PDF, Office doc, script, archive, or any of 20+ supported formats onto the GUI, or pipe files through the CLI. Get hashes, entropy, imports, sections, IOC indicators, MITRE ATT&CK mappings, known malware family matching, a confidence-scored verdict, and a risk score. 200+ files per minute, entirely offline.

**Anya** (AHN-yah) means "eye" in Igbo.

---

## Install

**[Download from GitHub Releases →](https://github.com/elementmerc/anya/releases/latest)**

| Platform | GUI | CLI |
|---|---|---|
| **Windows** | `.msi` installer | `.zip` |
| **macOS** | `.dmg` (Intel + Apple Silicon) | Universal binary (`.tar.gz`) |
| **Linux** | `.AppImage` / `.deb` / `.rpm` | Static musl binary (`.tar.gz`) |

Also available on **[SourceForge](https://sourceforge.net/projects/anya/)**.

```bash
# One-liner install (prompts for CLI, GUI, or both)
curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/main/install.sh | bash
```

```bash
# Docker
docker run --rm -v "$(pwd)/samples:/samples:ro" elementmerc/anya:latest --file /samples/malware.exe --json
```

> [!WARNING]
> Seriously, just use the installer or grab a release. The source is here for transparency, not for building. If you clone and `cargo build` anyway — well, don't say I didn't warn you.

---

## CLI

```bash
anya --file suspicious.exe                    # Analyse a file
anya --file suspicious.exe --json             # JSON output
anya --file suspicious.exe --explain          # Verdict + explanations
anya --directory ./samples --recursive        # Batch scan with progress bar
anya --file suspicious.exe --case nightfall   # Save to investigation case
anya --file suspicious.exe --format html --output report.html
```

Full flag reference: `anya --help`

---

## GUI

Launch Anya, drag a file or folder onto the drop zone — or use the **+** button for single file, batch analysis, or file comparison.

| Tab | What it shows |
|---|---|
| Overview | Risk score ring, file metadata, hashes, KSD match, forensic fragment |
| Entropy | Section entropy chart, byte histogram, distribution flatness analysis |
| Imports | DLL tree with expandable function lists and inline explanations |
| Sections | Section permissions, per-section entropy, characteristics |
| Strings | Extracted strings with IOC extraction, classification, and filtering |
| Security | ASLR, DEP, Authenticode, overlay, debug artifacts, toolchain detection, certificate reputation |
| Format | Format-specific analysis for JS, PowerShell, VBS, OLE, ZIP, HTML, XML, LNK, ISO, and more |
| MITRE | Mapped ATT&CK techniques with tactic tagging and real-world attack examples |
| Graph | IOC/Import evidence web (single file) or TLSH relationship graph (batch) with Obsidian-style interactions |

**Batch Analysis** — drop a folder to scan all executables. Files appear in a searchable sidebar with colour-coded verdicts. The Graph tab shows an interactive relationship graph with TLSH similarity edges, cluster halos, and hover spotlight.

**Single-File Graph** — the Graph tab visualises DLLs, suspicious APIs, IOCs, and behavioural categories as an interconnected evidence web. Hover any node to spotlight its connections.

**Teacher Mode** (toggle in Settings) surfaces contextual lessons as you navigate. Click any DLL, security card, IOC, or MITRE technique for beginner-friendly explanations with real-world examples.

---

## Why Anya?

| | Anya | VirusTotal | PEStudio | CAPA | DIE |
|---|---|---|---|---|---|
| Offline / no upload | ✓ | ✗ | ✓ | ✓ | ✓ |
| Formats | Any file (20+ deep) | Many | PE only | PE/ELF | PE/ELF/Mach-O |
| Heuristic verdict | ✓ | Aggregates | ✗ | ✗ | ✗ |
| MITRE ATT&CK | ✓ | Partial | ✗ | ✓ | ✗ |
| YARA scanning | ✓ | ✓ (cloud) | ✗ | ✗ | ✗ |
| GUI + CLI | Both | Browser | GUI only | CLI only | Both |
| Batch analysis | ✓ | API | ✗ | Scriptable | Scriptable |
| IOC extraction | ✓ | ✓ | ✗ | ✗ | ✗ |
| Case management | ✓ | ✗ | ✗ | ✗ | ✗ |
| Cross-platform | ✓ | Web | Windows | ✓ | ✓ |
| Price | Free / Commercial | Free / $10K+ | Free / €200+ | Free | Free |

---

## Calibration

Anya's scoring engine is calibrated against real malware and benign samples. Every release is tested before shipping.

```mermaid
xychart-beta
    title "Detection & False Positive Rate"
    x-axis ["v1.0", "v1.1", "v1.2", "v2.0"]
    y-axis "%" 0 --> 100
    line "Detection" [73.0, 82.0, 87.5, 99.9]
    line "FP rate (x10)" [27.0, 15.0, 3.0, 1.0]
```

*FP rate scaled 10x for visibility on the same axis.*

| Version | Malware | Benign | Total | Detection | FP Rate |
|---|---|---|---|---|---|
| **v2.0** | **~5,100** | **~5,300** | **~10,300** | **99.9%** | **0.1%** |

> **Verify independently:** `anya benchmark ./your-samples/ --ground-truth malware --json`

---

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [JSON output schema](docs/JSON_SCHEMA.md)
- [CHANGELOG](docs/CHANGELOG.md)
- [Security scope & limitations](SECURITY.md)
- [Privacy policy](docs/PRIVACY.md)
- [Commercial licensing](docs/COMMERCIAL_LICENSE.md)

---

## Licence

AGPL-3.0-or-later. See [LICENSE.TXT](LICENSE.TXT).

Commercial licensing: daniel@themalwarefiles.com
