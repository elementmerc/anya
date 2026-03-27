# Changelog

## [Unreleased]

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
- CI: runs on dev pushes only (not master) to reduce redundant builds
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
