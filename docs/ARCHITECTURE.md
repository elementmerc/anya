# Anya — Architecture

**Name origin:** Anya (pronounced AHN-yah) means "eye" in Igbo, reflecting the tool's purpose of seeing into the inner workings of potentially malicious software.

---

## Design Principles

1. **Safety first** — never execute the sample; static analysis only
2. **Memory safety** — Rust prevents the buffer overflows and use-after-free bugs that would otherwise be a serious concern when parsing untrusted binary input
3. **No data exfiltration** — network access is disabled at the OS permission layer in the desktop app; the CLI makes no outbound connections
4. **Modularity** — clean separation between analysis logic, output serialisation, and the user interface layers
5. **Testability** — business logic lives in `lib.rs`, not entangled with CLI or IPC handlers

---

## Workspace Structure

```
anya/
├── src/                        # anya-security-core (Rust crate)
│   ├── main.rs                 # CLI entry point (binary: anya)
│   ├── lib.rs                  # Public library API + core orchestration
│   ├── config.rs               # TOML configuration management
│   ├── output.rs               # JSON-serialisable data structures
│   ├── pe_parser.rs            # PE analysis logic
│   ├── elf_parser.rs           # ELF analysis logic
│   ├── macho_parser.rs         # Mach-O analysis logic
│   ├── errors.rs               # Error suggestion hints (plain-English)
│   ├── ioc.rs                  # IOC regex detection (IPv4, URL, domain, etc.)
│   ├── dotnet_parser.rs        # .NET CLR metadata parser (obfuscation, reflection, P/Invoke)
│   ├── cert_db.rs              # Certificate reputation database (publisher trust checking)
│   ├── hash_check.rs           # Hash list lookup subcommand
│   ├── yara.rs                 # YARA utilities (placeholder — coming soon)
│   ├── case.rs                 # Case management (YAML persistence)
│   ├── confidence.rs           # Scoring bridge (extracts signals → delegates to anya-scoring)
│   ├── watch.rs              # Directory watch mode (anya watch)
│   ├── compare.rs            # File comparison (anya compare)
│   ├── report.rs             # HTML report generation
│   └── data/
│       ├── mod.rs              # Data submodule exports
│       ├── explanations.rs     # Human-readable finding descriptions
│       ├── lessons.rs          # Teacher Mode lesson definitions + trigger logic
│       ├── mitre_mappings.rs   # API → MITRE ATT&CK technique mappings
│       ├── verses.rs           # 30 NLT Bible verses (shared CLI + GUI pool)
│       └── explanations_data.json # Explanation entries for --explain flag
├── src-tauri/                  # anya-gui (Tauri package)
│   ├── src/
│   │   ├── main.rs             # Tauri application entry point
│   │   └── lib.rs              # Tauri commands (IPC handlers)
│   ├── capabilities/
│   │   └── default.json        # OS permission grants (no network)
│   └── tauri.conf.json         # App metadata, window config, plugin list
├── ui/                         # React/TypeScript frontend
│   ├── main.tsx                # App bootstrap + anti-flash font init
│   ├── App.tsx                 # Root component, state, tab routing
│   ├── globals.css             # Global styles + CSS custom properties
│   ├── types/
│   │   └── analysis.ts         # Shared TypeScript types
│   ├── components/
│   │   ├── DropZone.tsx        # File drop target
│   │   ├── TopBar.tsx          # Header with file info and controls
│   │   ├── BibleVerseBar.tsx   # 36 px status bar — rotating NLT verse (10-min cycle)
│   │   ├── SettingsModal.tsx   # Settings panel (theme, font size, DB path, Teacher Mode, Bible Verses)
│   │   ├── TeacherSidebar.tsx  # Contextual lesson sidebar (Teacher Mode, draggable width)
│   │   ├── SplashScreen.tsx    # Animated splash overlay (theme-aware)
│   │   ├── Installer.tsx       # 5-step first-run setup wizard
│   │   ├── Installer.css       # Installer + uninstaller theme-aware styles
│   │   ├── Uninstaller.tsx     # 4-step uninstall cleanup wizard
│   │   ├── BatchSidebar.tsx  # Collapsible file list for batch analysis
│   │   ├── BatchDashboard.tsx # Batch summary with verdict cards + donut chart
│   │   ├── Toast.tsx         # Toast notification system (ToastProvider + useToast)
│   │   ├── SkeletonLoader.tsx # Shimmer placeholder during loading
│   │   ├── GuidedTour.tsx    # 5-step first-analysis walkthrough
│   │   ├── TabNav.tsx        # Tab navigation with sliding indicator + disabled state
│   │   ├── CaseBrowser.tsx    # Case list + file browser on DropZone
│   │   ├── CompareView.tsx    # Side-by-side analysis comparison
│   │   ├── CopyButton.tsx     # Reusable copy-to-clipboard button
│   │   ├── KeyboardShortcutsOverlay.tsx # ? shortcut overlay
│   │   └── tabs/
│   │       ├── OverviewTab.tsx
│   │       ├── SectionsTab.tsx
│   │       ├── ImportsTab.tsx
│   │       ├── EntropyTab.tsx
│   │       ├── StringsTab.tsx
│   │       ├── SecurityTab.tsx   # Security features + cert reputation + .NET + Rich Header
│   │       ├── IdentityTab.tsx  # KSD match details + .NET metadata (conditional)
│   │       └── MitreTab.tsx     # MITRE ATT&CK technique display
│   ├── hooks/
│   │   ├── useAnalysis.ts      # File analysis state management
│   │   ├── useTheme.ts         # Theme persistence
│   │   ├── useFontSize.ts      # Font size persistence
│   │   ├── useTeacherMode.ts   # Teacher Mode context + focus/blur helpers
│   │   └── useKeyboardShortcuts.ts # Global keyboard shortcuts
│   ├── data/
│   │   ├── mitre_attack.json           # MITRE ATT&CK techniques
│   │   ├── technique_explanations.json # Simple explanations for Teacher Mode (includes real_world_example field)
│   │   ├── dll_explanations.json       # One-line DLL descriptions (140 entries)
│   │   └── function_explanations.json  # Suspicious API explanations (324 entries)
│   └── lib/
│       ├── db.ts               # SQLite access via plugin-sql
│       ├── risk.ts             # Risk score calculation
│       ├── apiDescriptions.ts  # API description lookup (imports from function_explanations.json)
│       ├── tauri-bridge.ts     # Typed wrappers around invoke()
│       └── utils.ts            # Shared helpers
├── debian/                     # Debian/Kali packaging
│   ├── control
│   ├── changelog
│   ├── rules
│   ├── copyright
│   ├── install
│   ├── anya.1                  # Man page
│   └── README.Debian
├── tests/                      # Integration tests (anya-security-core)
│   ├── config_tests.rs
│   ├── json_output_tests.rs
│   ├── batch_tests.rs
│   └── fixtures/
│       └── simple.exe
├── benches/
│   └── analysis_benchmarks.rs
├── examples/
│   ├── basic_analysis.rs
│   ├── batch_processing.rs
│   ├── json_output.rs
│   └── custom_config.rs
├── docker/
│   └── seccomp.json            # Minimal seccomp allowlist for container
├── anya-stubs/                 # Stub crates (committed, public repo)
│   ├── scoring/                # anya-scoring stub (zero-value weights, _STUB marker)
│   └── data/                   # anya-data stub (empty JSON strings)
├── anya-proprietary/           # Git submodule → private repo (authorised only)
│   ├── scoring/                # Real scoring engine
│   │   ├── api_lists.rs        #   Suspicious API name lists
│   │   ├── confidence.rs       #   Scoring logic and score_signals()
│   │   ├── detection_patterns.rs # Detection pattern definitions
│   │   ├── ioc.rs              #   IOC regex patterns
│   │   ├── thresholds.rs       #   Default thresholds
│   │   └── types.rs            #   SignalSet, ScoringResult, shared types
│   └── data/                   # Real educational content
├── .cargo/
│   ├── config.toml             # Path override: stubs → submodule (gitignored)
│   └── config.toml.example     # Template for authorised developers
├── private/                    # Internal (gitignored)
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── Cargo.toml                  # Workspace root + anya-security-core package
```

---

### Modular Architecture

Anya's analysis engine is split into modular crates. All scoring logic,
detection patterns, verdict thresholds, and API lists live in a private
repository (`anya-proprietary`), included as a git submodule. The public
repo ships stub crates in `anya-stubs/` that mirror the API surface but
contain no real weights, patterns, or content.

The public `confidence.rs` extracts signals from `AnalysisResult` into a
`SignalSet` struct (defined in the scoring crate), passes it to
`score_signals()`, and returns results. This keeps scoring logic cleanly
separated from the analysis output layer.

A `.cargo/config.toml` path override (gitignored) redirects Cargo from
stubs to the submodule when present. Pre-built binaries include all
modules. Building from source requires authorised access — see README.

---

## anya-security-core

### lib.rs — Public API

The library crate separates testable analysis logic from both the CLI and the Tauri IPC layer. Both consumers call the same functions.

**Exports:**

| Function | Description |
|---|---|
| `analyse_file(path, min_len)` | Main entry point — returns `FileAnalysisResult` |
| `calculate_hashes(data)` | MD5, SHA-1, SHA-256 |
| `calculate_file_entropy(data)` | Shannon entropy for the whole file |
| `extract_strings_data(data, min_len)` | ASCII string extraction |
| `find_executable_files(dir, recursive)` | Directory scanning with extension filter |
| `is_suspicious_file(result)` | Heuristic threat assessment |
| `to_json_output(result)` | Converts `FileAnalysisResult` to `AnalysisResult` (JSON-serialisable) |

**Core types:**

| Type | Description |
|---|---|
| `FileAnalysisResult` | All analysis data for one file |
| `BatchSummary` | Statistics for a directory analysis run |
| `OutputLevel` | Verbosity: `Quiet` / `Normal` / `Verbose` |

### config.rs

TOML-based user preferences. Loading priority (highest to lowest):

1. CLI arguments
2. `--config <path>` custom file
3. `~/.config/anya/config.toml` (Linux/macOS) / `%APPDATA%\anya\config.toml` (Windows)
4. Hardcoded defaults

Configurable thresholds for entropy classification and risk scoring. Defaults are set internally and adjustable via the GUI.

```toml
[analysis]
min_string_length = 4
entropy_threshold = 7.5
show_progress = true

[output]
use_colours = true
format = "text"
verbosity = "normal"

[suspicious_apis]
enabled = false
additional = []
ignore = []
custom_list = []
```

### output.rs

All JSON-serialisable structs. Every struct derives `Debug`, `Clone`, `Serialize`, `Deserialize`.

| Type | Purpose |
|---|---|
| `AnalysisResult` | Top-level JSON output |
| `FileInfo` | Path, size, extension |
| `Hashes` | MD5, SHA-1, SHA-256 |
| `EntropyInfo` | Value, category, suspicious flag |
| `StringsInfo` | Count and samples |
| `PEAnalysis` | PE-specific fields |
| `ImportAnalysis` | DLLs, function list, suspicious count |
| `SectionInfo` | Name, sizes, entropy, W+X flag |
| `SecurityFeatures` | ASLR and DEP/NX status |

### pe_parser.rs

PE analysis via [`goblin`](https://github.com/m4b/goblin).

1. Headers — architecture, entry point, image base, timestamp
2. Sections — name, virtual/raw size, permissions, per-section entropy, W+X detection
3. Import table — DLL list, function names, suspicious API detection with categorised heuristics
4. Export table — function names and RVAs
5. Security features — ASLR (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`), DEP/NX (`IMAGE_DLLCHARACTERISTICS_NX_COMPAT`)

---

## anya-gui

### Tauri IPC layer

The desktop app uses Tauri v2. Rust logic is exposed to the frontend as Tauri commands:

```
Frontend (TypeScript)                   Rust (Tauri commands)
──────────────────────────────────      ────────────────────────────────────────────
invoke("analyze_file", { path })    →   analyse_file() → anya_security_core::analyse_file()
invoke("export_json", { … })        →   export_json()  → std::fs::write()
invoke("get_settings")              →   get_settings() → AppSettings
invoke("save_settings", { … })      →   save_settings() (telemetry always false)
invoke("get_triggered_lessons", …)  →   get_triggered_lessons() → Lesson[]
invoke("get_random_verse")          →   get_random_verse() → { text, reference }
invoke("get_thresholds")            →   get_thresholds() → ThresholdConfig
invoke("save_thresholds", { … })    →   save_thresholds() → validates + writes anya.toml
invoke("analyze_directory", { path, recursive, batchId }) → analyze_directory() + batch events
invoke("poll_directory", { path, recursive })              → poll_directory() → Vec<String>
invoke("save_to_case", { result, caseName })   → save_to_case()
invoke("list_cases")                            → list_cases() → CaseSummary[]
invoke("get_case", { name })                    → get_case() → CaseDetail
invoke("delete_case", { name })                 → delete_case()
invoke("export_html_report", { result, path })  → export_html_report()
```

### Tauri Events (batch analysis)

The `analyze_directory` command streams results via events:

| Event | Payload | When |
|-------|---------|------|
| `batch-started` | Structured payloads with file identification, analysis results, and progress metadata. | Directory scan complete |
| `batch-file-result` | Structured payloads with file identification, analysis results, and progress metadata. | Each file analysed |
| `batch-complete` | Structured payloads with file identification, analysis results, and progress metadata. | All files done |

Frontend uses `batch_id` to ignore events from stale/cancelled batches.

Network access is disabled by omitting all network permissions from `src-tauri/capabilities/default.json`. The OS will not grant network access to the process regardless of what the application code attempts.

### SQLite storage

The plugin `@tauri-apps/plugin-sql` provides SQLite access from TypeScript. The database is initialised on first launch at the platform default path:

| Platform | Default path |
|---|---|
| Windows | `%APPDATA%\com.anya.app\anya.db` |
| macOS | `~/Library/Application Support/com.anya.app/anya.db` |
| Linux | `~/.local/share/com.anya.app/anya.db` |

Local SQLite database stores analysis history, settings, and teacher mode progress. Schema is managed internally.

### Frontend architecture

The React frontend uses [shadcn/ui](https://ui.shadcn.com/) component primitives, [Recharts](https://recharts.org/) for the entropy chart, and [Tailwind CSS](https://tailwindcss.com/) for utility styling.

Font scaling is implemented with a CSS custom property (`--font-size-base`) on `:root`. The value is read from `localStorage` synchronously in `main.tsx` before the first render, preventing a flash of the wrong font size.

Theme (dark/light) follows the same pattern — the class is applied to `<html>` before React mounts.

---

## Data Flow

### CLI — single file

```
anya --file malware.exe
        ↓
main.rs: parse args, load config
        ↓
lib::analyse_file(path, min_string_length)
  ├── fs::read()
  ├── calculate_hashes(data)
  ├── calculate_file_entropy(data)
  ├── extract_strings_data(data, min_len)
  └── goblin::Object::parse(data)
       ├── PE  → pe_parser::analyse_pe_data(data, pe)
       └── ELF / Mach-O → format logged; no deep analysis
        ↓
FileAnalysisResult
        ↓
main.rs: format text output  OR  to_json_output() → print JSON
```

### CLI — batch directory

```
anya --directory /samples --recursive
        ↓
lib::find_executable_files(dir, recursive)
  ├── WalkDir traversal
  └── filter by extension (.exe, .dll, .sys, .bin, …)
        ↓
for each file:
  ├── lib::analyse_file(path, min_len)
  ├── lib::is_suspicious_file(result) → bool
  └── update BatchSummary
        ↓
BatchSummary: total / analysed / failed / suspicious / duration / rate
```

### GUI — file drop

```
User drops file onto DropZone
        ↓
useAnalysis.ts: invoke("analyse_file", { path })
        ↓
src-tauri/src/lib.rs: analyse_file Tauri command
  └── anya_security_core::analyse_file()
  └── anya_security_core::to_json_output()
        ↓
AnalysisResult returned to frontend as JSON
        ↓
risk.ts: calculateRiskScore(result) → 0–100
        ↓
db.ts: storeAnalysis(result, score) → SQLite upsert
        ↓
App.tsx: update state → tabs render with results
```

---

## Security Considerations

### Input handling

- Untrusted binary data is passed directly to the goblin parser. Goblin is fuzz-tested and widely used; parse errors surface as Rust `Result::Err` values that are handled gracefully.
- No `unsafe` code is introduced by `anya-security-core` beyond what goblin itself uses internally.
- Resource consumption is bounded: string extraction has a configurable minimum length; section analysis operates on the PE section table, which is structurally bounded.

### Threat model

**Protected against:**
- Malformed PE/ELF files — handled as parse errors, not panics or crashes
- Code execution from samples — static analysis only; bytes are read but never interpreted as instructions
- Data exfiltration — no network permissions; no outbound connections at the OS level

**Not protected against:**
- Zero-day vulnerabilities in goblin (keep dependencies updated)
- Social engineering — the user must not execute samples they are investigating
- Malicious TOML config files loaded via `--config` (do not load untrusted config files)

---

## Dependencies

### Rust (`anya-security-core`)

| Crate | Purpose |
|---|---|
| `goblin` | PE/ELF/Mach-O binary parsing |
| `md-5`, `sha1`, `sha2` | Cryptographic hashing |
| `hex` | Hash hex encoding |
| `serde`, `serde_json` | Serialisation |
| `clap` | CLI argument parsing |
| `colored` | Terminal colour output |
| `indicatif` | Progress bars |
| `walkdir` | Directory traversal |
| `toml` | Config file parsing |
| `dirs` | Platform config directory paths |
| `anyhow` | Error handling |
| `tempfile` | Test fixtures (dev) |
| `criterion` | Benchmarking (dev) |

### JavaScript (`anya-gui`)

| Package | Purpose |
|---|---|
| `react`, `react-dom` | UI framework |
| `@tauri-apps/api` | Tauri IPC |
| `@tauri-apps/plugin-sql` | SQLite access |
| `recharts` | Entropy chart |
| `tailwindcss` | Utility CSS |
| `shadcn/ui` (radix-ui) | UI component primitives |
| `vite` | Frontend build tool |

---

## Testing

### Unit tests

Located in `#[cfg(test)]` blocks within each source file. Run with `cargo test`.

### Integration tests

Located in `tests/`. Use `tempfile` for scratch directories and `tests/fixtures/simple.exe` as a known-good PE sample.

| File | Covers |
|---|---|
| `config_tests.rs` | Config loading, validation, defaults, priority chain |
| `json_output_tests.rs` | JSON serialisation, schema shape |
| `batch_tests.rs` | Directory scanning, extension filtering, error handling |

### Benchmarks

```bash
cargo bench                          # All benchmarks
cargo bench hash_calculation         # Specific benchmark
cargo bench --save-baseline main     # Save baseline for comparison
```

Benchmarked operations: hash calculation, entropy calculation, string extraction — at 1 KB / 10 KB / 100 KB / 1 MB input sizes.

---

## Known Sample Database (KSD)

TLSH-based fuzzy matching against known malware samples. Every analysed file gets a TLSH hash compared against a database of known samples.

**Storage:** Layered — embedded default DB (private crate) + user overlay at `~/.config/anya/known_samples.json`.

**CLI commands:**
- `anya ksd import <calibration.json>` — import samples from calibration data
- `anya ksd stats` — show database statistics
- `anya ksd list [--family emotet] [--limit 50]` — browse entries
- `anya ksd add --tlsh <hash> --family <name> --function <type>` — manual entry
- `anya ksd remove --sha256 <hash>` — remove entry (permanent, with confirmation)
- `anya ksd export <file>` — export to JSON

**Matching:** LSH-bucketed search for O(N/128) average-case on large databases. Distance-based confidence tiers.

**Config:** `[ksd]` section in `config.toml` — `enabled`, `max_distance`, `overlay_path`.

---

## .NET Metadata Analysis

`dotnet_parser.rs` — Parses CLR metadata from .NET assemblies:
- Metadata streams: #~, #Strings, #Blob
- Obfuscation detection: unprintable type/method names, known obfuscator fingerprints (ConfuserEx, .NET Reactor, SmartAssembly, Dotfuscator, Babel, Crypto Obfuscator, Eazfuscator)
- Behavioural signals: reflection API usage, suspicious P/Invoke, high-entropy blob streams
- Uses Aho-Corasick single-pass detection for all patterns

---

## Certificate Reputation

`cert_db.rs` — Offline publisher trust checking:
- Token-based CN matching against 40+ trusted publisher names
- Prevents substring spoofing (e.g. "not-microsoft.evil.com")
- Self-signed certificate detection
- 230+ test variants covering real-world certificate CNs

---

**Last updated:** 2026-03-28 (v1.2.4 — KSD, .NET analysis, certificate reputation, 100% detection)
**Maintainer:** Daniel Iwugo — daniel@themalwarefiles.com
