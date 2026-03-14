# Changelog

All notable changes to Anya will be documented in this file.

## [1.0.1] - 2026-03-14

### Added
- **First-run installer** — 5-step setup wizard (licence, install location, preferences, progress, done) with live dark/light theme switching
- **DLL and function explanations** — inline descriptions for 40 DLLs and 112 suspicious APIs in the Imports tab, loaded from JSON data files
- **Draggable Teacher sidebar** — left edge drag handle to resize from 280px up to 50% of window width
- **DLL/function focus in Teacher Mode** — clicking a DLL or function in the Imports tab shows its explanation in the Teacher sidebar
- **Splash screen theme adaptation** — splash background and logo colours match the user's dark/light theme
- **Settings modal animations** — scale + fade enter/exit transitions
- **Sliding tab indicator** — active tab underline smoothly slides between tabs
- **Risk ring animation delay** — 400ms delay before the score counter starts, 50% slower fill animation

### Fixed
- **Dockerfile** — wrong binary path (`anya-security-core` → `anya`), stale stub binary due to missing fingerprint cleanup, Rust version too old for `let_chains`
- **Docker runtime** — switched from `debian:bookworm-slim` (128MB) to `gcr.io/distroless/cc-debian12:nonroot` (40.5MB); fixed container write permissions for non-root user
- **Icon quality** — regenerated `icon.ico` with standard Windows sizes (16/24/32/48/64/256px) at 8-bit depth; fixed macOS `Rgba16` bundling error
- **Settings modal overflow** — added `max-h-[85vh]` with scrollable content area
- **Entropy chart labels** — moved "Suspicious" and "Encrypted" text above reference lines with proper top margin
- **Integration tests** — fixed binary name, Bible verse subcommand detection, batch JSON validation, Docker output permissions, `debian/rules` execute bit
- **`export_json` path validation** — canonicalization, blocked system directories, `.json` extension enforcement
- **`debian/control`** — removed `cargo, rustc` from `Build-Depends` (installed via rustup in CI)
- **Release workflow** — Node.js 20 → 22, added `publish-crate` job for crates.io
- Minor fixes and improvements

## [1.0.0] - 2026-03-14

### Analysis engine
- PE static analysis with 40+ suspicious API detections across 7 categories
- ELF support with GOT/PLT inspection and capability detection
- MITRE ATT&CK mapping on all detections with local JSON lookup
- Confidence scoring (low/medium/high/critical) on all findings
- Packer detection: UPX, ASPack, Themida, VMProtect, MPRESS
- Compiler/language detection: MSVC, GCC/MinGW, Delphi, .NET, Go, Rust, PyInstaller
- Entropy analysis with per-section breakdown, overlay detection, Rich header parsing
- TLS callback detection, import-by-ordinal detection
- Section permissions with W+X flagging
- Imphash calculation and PE checksum validation

### GUI (Tauri v2 + React)
- Drag-and-drop binary analysis with tab-based results
- Seven tabs: Overview, Entropy, Imports, Sections, Strings, Security, MITRE
- Interactive MITRE ATT&CK tab with technique cards grouped by tactic
- Teacher Mode — contextual lesson sidebar for learning while analysing
- Bible verse status bar (optional, toggled in Settings)
- Splash screen with animated logo
- Dark/light theme toggle with persistence
- JSON export and click-to-copy hashes
- Local SQLite history — no data leaves the device

### CLI
- Single-file and batch directory analysis (`--file`, `--directory --recursive`)
- JSON and plain-text output with `--output` and `--append` support
- `verse` subcommand — random NLT Bible verse
- `--guided` flag — inline Teacher Mode lessons
- TOML configuration via `--init-config` / `--config`

### Distribution
- One-liner install script (`curl | bash`) for Linux, macOS, Windows/WSL
- GitHub Actions CI/CD — test, lint, audit, build, release
- Debian packaging (`debian/` directory, man page)
- Tauri bundles: `.AppImage`, `.deb` (Linux), `.dmg` (macOS), `.msi` (Windows)
- Docker support with multi-stage build (distroless runtime, <50 MB image)
- `docker-compose.yml` with single-file and batch-scan service definitions

## [0.3.2] - 2026-03-14

### Added
- **`anya verse`** CLI subcommand — prints a random NLT Bible verse from a 30-verse hardcoded pool; time-seeded, no `rand` dependency
- **Bible Verses** GUI setting — toggle in Settings → Learning; shows a 36 px status bar at the bottom of the window cycling a new verse every 10 minutes
- **ELF binary analysis** — sections, imports, security features (PIE, NX stack, RELRO, stripped detection), packer indicators
- **PE extended analysis** — imphash, PE checksum validation, Rich header parsing with product lookup, TLS callback detection, overlay detection
- **Compiler detection** — identifies MSVC, GCC/MinGW, Rust, Go, .NET, Delphi, PyInstaller from PE metadata and byte patterns
- **Packer detection** — UPX, ASPack, Themida, VMProtect, MPRESS via string signatures and section names; entropy heuristics for unknown packers
- **Anti-analysis API detection** — VM detection, debugger detection, and timing-check APIs flagged from import table
- **MITRE ATT&CK tab** — dedicated tab in the GUI mapping findings to ATT&CK techniques with tactic grouping and cross-tab navigation
- **Teacher Mode** — contextual lesson sidebar in the GUI; CLI equivalent via `--guided` flag; persisted to `teacher_settings` table
- **Debian/Kali packaging** — `debian/` directory with full dpkg build support; `man anya` man page; `.github/workflows/package.yml` builds `.deb` and `.rpm` on release tags
- **One-line install script** — `install.sh` at project root; platform detection (Linux, macOS, Windows/WSL); choice of CLI/GUI/Both; falls back to `cargo install` if no pre-built binary; idempotent
- Desktop GUI (`anya-gui`) — Tauri v2 app with React/TypeScript frontend
  - Drag-and-drop file analysis with tab-based results (Overview, Sections, Imports, Entropy, Strings, Security, MITRE)
  - Risk scoring system (0–100) with colour-coded severity
  - Local SQLite history via `@tauri-apps/plugin-sql` — no data leaves the device
  - Dark/light theme toggle with persistence
  - Font size setting (Small 13 px / Default 14 px / Large 15 px / XL 16 px) with persistence
  - Configurable database path
- Docker support
  - Multi-stage `Dockerfile` targeting `debian:bookworm-slim` runtime (<50 MB)
  - `docker-compose.yml` with single-file and batch-scan service definitions
  - `docker/seccomp.json` — minimal syscall allowlist; explicit deny for `ptrace`, `mount`, `kexec_load`
  - `Makefile` with `docker-build`, `docker-test`, `docker-push` targets
- Legal and policy documents
  - `COMMERCIAL_LICENSE.md` — dual-licensing notice, rights table, commercial enquiry path
  - `SECURITY.md` — responsible disclosure policy, scope definition, response timeline, safe harbour
  - `PRIVACY.md` — zero-collection privacy policy; local SQLite only; per-platform DB paths
  - `TERMS_OF_SERVICE_STUB.md` — pre-release stub; AGPL-3.0 as operative licence until formal terms are published

### Changed
- README rewritten: minimalist style, one-liner install, platform grid, comparison table, correct binary name (`anya`)
- ARCHITECTURE.md updated: workspace structure, Tauri IPC table, settings keys, binary name corrections
- CLI binary renamed from `anya-security-core` to `anya` in all documentation

## [0.3.1] - 2026-02-22
### Added
- Production testing infrastructure (23% coverage, 75+ tests)
- 4 practical examples (`basic_analysis`, `batch_processing`, `json_output`, `custom_config`)
- ARCHITECTURE.md - complete technical documentation
- CI/CD pipeline (GitHub Actions)
- Issue templates (bug reports, features, questions)
- New library API: `analyse_file()`, `is_suspicious_file()`, `BatchSummary`
- Benchmark suite for performance tracking

### Fixed
- Progress bars now show accurate elapsed time and stay visible
- String extraction progress displaying incorrectly
- Case-insensitive API categorization in PE parser
- Missing `Clone` derives on output structs

### Improved
- Refactored code structure (lib.rs for testable logic, main.rs for CLI)
- Enhanced progress indicators with real-time updates
- Better error messages and status output

### Technical
- Test coverage: 7.31% → 23.09%
- 60+ unit tests, 15+ integration tests
- lib.rs: 86% coverage | config.rs: 62.5% | output.rs: 85%

## [0.3.0] - 2026-02-22

### Added
- Batch directory scanning with `--directory` flag
- Recursive scanning with `--recursive` flag
- Progress bars for large files and batch operations
- Configuration file support (`~/.config/anya/config.toml`)
- `--init-config` flag to create default config
- `--config` flag for custom config paths
- JSON output with `--json` flag
- File output with `--output` flag
- Append mode with `--append` flag
- Verbose mode with `--verbose` flag
- Quiet mode with `--quiet` flag
- Comprehensive test coverage (75%+)
- Documentation improvements

### Changed
- Renamed project to "Anya" (from previous name)
- Improved progress indicator accuracy
- Better error messages and validation

### Fixed
- Progress bars now update correctly during analysis
- Colour output works correctly when piping to files

## [0.2.0] - 2026-02-15

### Added
- PE (Portable Executable) parsing
- Import/export table analysis
- Suspicious API detection (40+ APIs categorised)
- Security feature detection (ASLR, DEP/NX)
- Per-section entropy calculation
- Command-line interface with Clap

### Changed
- Improved string extraction performance
- Better entropy visualisation

## [0.1.0] - 2026-02-08

### Added
- Initial release
- Basic static analysis (hashes, strings, entropy)
- Support for PE files
- MD5, SHA1, SHA256 hash calculation
- ASCII string extraction
- Shannon entropy calculation