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
│   └── data/
│       ├── mod.rs              # Data submodule exports
│       ├── explanations.rs     # Human-readable finding descriptions
│       ├── lessons.rs          # Teacher Mode lesson definitions + trigger logic
│       ├── mitre_mappings.rs   # API → MITRE ATT&CK technique mappings
│       └── verses.rs           # 30 NLT Bible verses (shared CLI + GUI pool)
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
│   │   └── tabs/
│   │       ├── OverviewTab.tsx
│   │       ├── SectionsTab.tsx
│   │       ├── ImportsTab.tsx
│   │       ├── EntropyTab.tsx
│   │       ├── StringsTab.tsx
│   │       ├── SecurityTab.tsx
│   │       └── MitreTab.tsx    # MITRE ATT&CK technique display
│   ├── hooks/
│   │   ├── useAnalysis.ts      # File analysis state management
│   │   ├── useTheme.ts         # Theme persistence
│   │   ├── useFontSize.ts      # Font size persistence
│   │   └── useTeacherMode.ts   # Teacher Mode context + focus/blur helpers
│   ├── data/
│   │   ├── mitre_attack.json           # MITRE ATT&CK techniques
│   │   ├── technique_explanations.json # Simple explanations for Teacher Mode
│   │   ├── dll_explanations.json       # One-line DLL descriptions (40 entries)
│   │   └── function_explanations.json  # Suspicious API explanations (112 entries)
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
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── Cargo.toml                  # Workspace root + anya-security-core package
```

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
3. Import table — DLL list, function names, suspicious API matching (40+ signatures across 7 categories)
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
```

Network access is disabled by omitting all network permissions from `src-tauri/capabilities/default.json`. The OS will not grant network access to the process regardless of what the application code attempts.

### SQLite storage

The plugin `@tauri-apps/plugin-sql` provides SQLite access from TypeScript. The database is initialised on first launch at the platform default path:

| Platform | Default path |
|---|---|
| Windows | `%APPDATA%\com.anya.app\anya.db` |
| macOS | `~/Library/Application Support/com.anya.app/anya.db` |
| Linux | `~/.local/share/com.anya.app/anya.db` |

**Schema:**

```sql
CREATE TABLE IF NOT EXISTS analyses (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  file_name   TEXT NOT NULL,
  file_path   TEXT NOT NULL,
  file_hash   TEXT NOT NULL,   -- SHA-256
  analysed_at TEXT NOT NULL,   -- ISO 8601 timestamp
  risk_score  INTEGER NOT NULL,
  result_json TEXT NOT NULL    -- full AnalysisResult as JSON
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
```

Settings keys in use: `theme` (`"dark"` | `"light"`), `font_size` (`"small"` | `"default"` | `"large"` | `"xl"`), `bible_verses_enabled` (`"true"` | `"false"`).

Teacher settings are stored in a separate `teacher_settings` table with keys: `enabled`, `auto_show_on_trigger`, `show_beginner`, `show_intermediate`, `show_advanced`.

If the same file (same SHA-256) is analysed more than once, the existing row is updated in place rather than creating a duplicate entry.

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

**Last updated:** 2026-03-15
**Version:** 1.0.2
**Maintainer:** Daniel Iwugo — daniel@themalwarefiles.com
