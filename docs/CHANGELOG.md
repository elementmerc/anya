# Changelog

## [2.0.4] - 2026-04-14

### Detection
- Fewer false positives on legitimate security tools and development utilities (FLOSS, tooling suites, dual use binaries)
- Better handling of JARs, Python wheels, Chrome extensions, APKs, and Office OOXML documents, which no longer flag as suspicious simply for containing executable entries
- More accurate compiler and toolchain identification for unsigned binaries, reducing noise on small MSVC utilities, Apple tooling, and MinGW compiled programs
- Reduced noise on ELF shared libraries and relocatable object files, which no longer trigger hardening detections that only apply to executables
- New detection signals for Batch and CMD scripts: LOLBin usage (certutil, bitsadmin, mshta, regsvr32, and similar), Windows Defender tampering patterns, hidden execution flags, and privilege escalation bypass patterns
- New entry point signature matching for packed PE binaries, with coverage for UPX, ASPack, Themida, MPRESS, PECompact, FSG, Enigma, and VMProtect
- Known sample lookups now short circuit to a clean verdict for curated tools and test files, so legitimate analysis utilities no longer surface as suspicious because of their metadata profile

### CLI
- `--no-ksd` and `--ksd-threshold` flags now work (previously accepted but ignored); use `--no-ksd` to see the pure heuristic verdict and `--ksd-threshold N` to tighten or loosen the similarity cutoff

### Other
- Bug fixes and improvements

## [2.0.3] - 2026-04-11

### Detection
- 7 new format parsers (VHD, OneNote, IMG, RAR, GZIP, 7-Zip, TAR)
- Secrets detection (AWS keys, JWTs, private keys, API tokens)
- Kernel driver analysis (.sys files)
- Improved scoring for HTA, JavaScript, VBScript, shell scripts, ISO, and XML
- Scoring engine recalibrated for improved detection across all file formats
- Known sample verdicts for security tools, development utilities, and test files
- Malware family context with descriptions and aliases for 50+ families

### GUI
- Notes section on Overview tab for known sample and fragment annotations
- Teacher Mode guidance for Graph tab with interactive node explanations
- Threat path highlighting in batch graph (click to trace connected clusters)
- 260 DLL explanations and 8 API category explanations in Teacher Mode
- Proprietary explanation data served via IPC

### CLI
- JSONL streaming output (`--jsonl`) for pipeline integration
- YARA only scanning mode (`--yara-only`) for fast rule testing
- Configurable analysis depth (`--depth quick|standard|deep`)
- Exit code from verdict (`--exit-code-from-verdict`) for CI/CD integration
- Watch mode JSON output (`anya watch --json`) for structured monitoring
- Coloured verdict output for TOOL, PUP, and TEST classifications

### Other
- Bug fixes and improvements

## [2.0.2] - 2026-04-01

### Detection
- Calibrated scoring engine: 99.9% detection, 0.1% FP on 10,320 samples
- Comprehensive known-product suppression (MinGW, .NET, Wine, Node.js, Ghidra tools)
- Python exec+subprocess scoring refined (exec+network = High, exec+subprocess = Medium)
- Archive format suppression for ZIP/JAR/7z entropy and IOC volume
- DLL weighted verdict threshold raised to reduce structural heuristic FPs

### GUI
- Dedicated Graph tab with Obsidian-style 2D force-directed visualization
- Single-file IOC/Import evidence web (DLLs, APIs, IOCs, categories as nodes)
- Batch TLSH relationship graph with cluster halos and search-to-highlight
- Constellation emerge animation, smooth hover spotlight with alpha interpolation
- Edge labels on hover, drag-and-release (nodes spring back)
- Tab state persistence (scroll position and search filters preserved)
- Animated SVG empty state icons matching tab lucide icons
- Folder drag-and-drop triggers batch analysis automatically
- Batch sidebar search bar for filtering file list
- Teacher Mode for all Security tab cards and Graph tab
- Keyboard shortcut hints in New Analysis menu

### CLI
- `--json-compact` flag for single-line JSON output

### Other
- Bug fixes and improvements

## [2.0.0] - 2026-03-30

### Detection
- 20 format parsers (PE, ELF, Mach-O, JS, PowerShell, VBS, Batch, Python, OLE, RTF, ZIP, HTML, XML, Image, LNK, ISO, CAB, MSI, PDF, Office)
- YARA-X integration with rules loaded from `~/.config/anya/rules/`
- Compiler/toolchain fingerprinting and import behavioural clustering
- Known-product suppression, benign IOC marking, byte histogram analysis
- TLSH Known Sample Database with forensic fragment annotation
- 99.6% detection, 0.8% FP on ~7,100 samples

### GUI
- Force-directed network graph (batch + single-file modes)
- Format Analysis tab with 17 format-specific cards
- YARA matches, forensic fragments, toolchain detection in Security/Overview tabs
- PDF export, histogram flatness, benign IOC marking

### CLI
- `anya benchmark` — detection rate and performance benchmarking
- `--format pdf` and `--format markdown` report output
- Batch `--summary` shows TLSH similarity relationships

### Reports
- PDF, Markdown, and HTML report generation
- All formats include KSD match, MITRE ATT&CK, analyst findings

### Other
- Bug fixes and improvements

## [1.2.2] - 2026-03-27

### Scoring Engine
- Improved detection accuracy across PE, ELF, and Mach-O formats
- Fallback PE import parser for packed/malformed import tables
- IOC volume now contributes to verdict
- ELF signals now feed into verdict (GOT/PLT, interpreter, RPATH, W+X, security features)
- Mach-O signal amplification for unsigned binaries
- Weighted verdict thresholds for signal accumulation
- Unrecognized file formats now check signals before returning UNKNOWN

### Architecture
- Refactored scoring engine into modular architecture
- Consolidated detection patterns into dedicated scoring module
- Eliminated duplicate scoring implementation in Tauri IPC layer

### CI/CD
- Dockerfile: fixed missing anya-stubs/proprietary COPY, sed pattern, env var
- Release workflow: trimmed from 17 to 11 assets (removed linux-gnu, arch-specific macOS, NSIS exe, app.tar.gz)
- CI: added Docker build validation and musl cross-compile jobs
- CI: runs on dev pushes only (not main) to reduce redundant builds
- Tauri targets: appimage, deb, rpm, dmg, msi (removed NSIS and app.tar.gz)

### Install Script
- Fixed piped `curl | bash` silently defaulting to CLI-only (now prompts via /dev/tty)
- Added --cli, --gui, --both flags
- Changed default to "both" (was "cli")
- Added --help, platform context in prompt, post-install launch hints

### GUI
- Guided tour: Skip button now readable, tooltips clamped to viewport

### Packaging
- Chocolatey community package scaffolded (.choco/ directory)

### Other
- Internal testing improvements

## [1.1.0] - 2026-03-16

- Case management — save, browse, and organise investigation cases (CLI + GUI)
- Watch mode — auto-analyse new files dropped into a directory
- Compare mode — side-by-side diff of two file analyses
- HTML report export
- Batch analysis in GUI with summary dashboard
- Keyboard shortcuts and drag-and-drop tab reorder
- IOC detection (IPv4, IPv6, URL, domain, email, registry, paths, mutex, Base64)
- File type mismatch detection
- Confidence scoring on all detections
- 15 new Teacher Mode lessons
- Private repo split for scoring engine and educational data
- Bug fixes and improvements

## [1.0.2] - 2026-03-15

- Custom uninstaller wizard
- DLL and function explanations in Imports tab
- Draggable Teacher Mode sidebar
- Native installer branding for all platforms
- RPM packaging support
- Bug fixes and improvements

## [1.0.1] - 2026-03-14

- First-run installer wizard
- Splash screen with theme adaptation
- Sliding tab indicator and settings animations
- Docker fixes (binary path, runtime image, permissions)
- Bug fixes and improvements

## [1.0.0] - 2026-03-14

- PE and ELF static analysis with MITRE ATT&CK mapping
- Packer, compiler, and anti-analysis detection
- Entropy analysis with per-section breakdown
- Desktop GUI (Tauri v2 + React) with 7 analysis tabs
- Teacher Mode — contextual lessons for learning while analysing
- CLI with batch scanning, JSON output, and configuration
- Docker support, Debian packaging, one-liner install script

## [0.3.2] - 2026-03-14

- Bible verse status bar (CLI + GUI)
- ELF binary analysis
- PE extended analysis (imphash, Rich header, TLS callbacks, overlay)
- MITRE ATT&CK tab in GUI
- Debian/Kali packaging and install script
- Bug fixes and improvements

## [0.3.1] - 2026-02-22

- Testing infrastructure and CI/CD pipeline
- Library API, examples, and benchmarks
- Bug fixes and improvements

## [0.3.0] - 2026-02-22

- Batch directory scanning
- Configuration file support
- JSON and file output modes
- Progress bars

## [0.2.0] - 2026-02-15

- PE parsing, import/export analysis, suspicious API detection
- Security feature detection (ASLR, DEP/NX)
- Per-section entropy calculation

## [0.1.0] - 2026-02-08

- Initial release — hashes, strings, entropy for PE files
