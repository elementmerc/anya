# Anya — Architecture

**Name origin:** Anya (pronounced AHN-yah) means "eye" in Igbo, reflecting the tool's purpose of seeing into the inner workings of potentially malicious software.

---

## Design Principles

1. **Safety first** — never execute the sample; static analysis only
2. **Memory safety** — Rust prevents buffer overflows and use-after-free bugs when parsing untrusted input
3. **No data exfiltration** — network access disabled at the OS permission layer; zero outbound connections
4. **Modularity** — clean separation between analysis, scoring, output, and UI via traits and registries
5. **Testability** — business logic in `lib.rs`, not entangled with CLI or IPC handlers
6. **Multi-layered detection** — heuristic scoring and YARA signature matching work together
7. **Library-first** — `analyse_bytes()` works on raw data; `analyse_file()` is a convenience wrapper
8. **Forward-compatible** — schema versions on all outputs; database migrations; feature flags

---

## Workspace Structure

```
anya/
├── src/                          # anya-security-core (Rust crate)
│   ├── main.rs                   # CLI entry point (binary: anya)
│   ├── lib.rs                    # Public library API + core orchestration
│   ├── config.rs                 # TOML configuration (versioned schema)
│   ├── output.rs                 # JSON-serialisable data structures (versioned)
│   ├── parser_registry.rs        # FormatParser trait + ParserRegistry
│   ├── events.rs                 # AnalysisEvent enum + EventBus + EventListener trait
│   ├── export.rs                 # OutputFormat trait + FormatRegistry
│   ├── confidence.rs             # Signal extraction → scoring bridge
│   ├── pe_parser.rs              # PE analysis (3,400+ lines)
│   ├── elf_parser.rs             # ELF analysis
│   ├── macho_parser.rs           # Mach-O analysis
│   ├── dotnet_parser.rs          # .NET CLR metadata (obfuscation, P/Invoke, reflection)
│   ├── js_parser.rs              # JavaScript/JScript analysis
│   ├── ps_parser.rs              # PowerShell analysis
│   ├── vbs_parser.rs             # VBScript analysis
│   ├── script_parser.rs          # Batch/Shell script analysis
│   ├── python_parser.rs          # Python analysis
│   ├── ole_parser.rs             # OLE compound document analysis
│   ├── rtf_parser.rs             # RTF analysis
│   ├── zip_parser.rs             # ZIP archive analysis
│   ├── html_parser.rs            # HTML/HTA analysis
│   ├── xml_parser.rs             # XML/SVG analysis
│   ├── image_parser.rs           # Image metadata/steganography analysis
│   ├── lnk_parser.rs             # Windows shortcut analysis
│   ├── iso_parser.rs             # ISO 9660 disk image analysis
│   ├── cab_parser.rs             # Windows Cabinet analysis
│   ├── msi_parser.rs             # MSI installer analysis
│   ├── yara.rs                   # YARA utilities + YARA-X scanning engine
│   ├── cert_db.rs                # Certificate reputation database
│   ├── ioc.rs                    # IOC regex detection
│   ├── errors.rs                 # Plain-English error suggestions
│   ├── hash_check.rs             # Hash list lookup subcommand
│   ├── case.rs                   # Case management (YAML persistence)
│   ├── watch.rs                  # Directory watch mode
│   ├── compare.rs                # File comparison
│   ├── report.rs                 # HTML, PDF, and Markdown report generation
│   ├── guided_output.rs          # Teacher Mode CLI output
│   └── data/
│       ├── mod.rs                # Data submodule exports
│       ├── explanations.rs       # Finding descriptions
│       ├── lessons.rs            # Teacher Mode lesson definitions + triggers
│       ├── mitre_mappings.rs     # API → MITRE ATT&CK technique mappings
│       └── verses.rs             # NLT Bible verses
├── src-tauri/                    # anya-gui (Tauri v2)
│   ├── src/lib.rs                # IPC commands (API_VERSION stamped)
│   ├── rules/                    # YARA rules bundled by installer
│   └── tauri.conf.json           # App config (bundle.resources for rules)
├── ui/                           # React + TypeScript frontend
│   ├── App.tsx                   # Root component, tab routing, batch state
│   ├── types/analysis.ts         # Shared TypeScript types (schema_version aware)
│   ├── components/
│   │   ├── BatchGraph.tsx        # 3D force-directed network graph (Three.js)
│   │   ├── BatchDashboard.tsx    # Summary/Graph toggle, verdict cards, donut chart
│   │   └── tabs/
│   │       ├── OverviewTab.tsx   # Risk ring, KSD, forensic fragment, KSD graph
│   │       ├── EntropyTab.tsx    # Section entropy, byte histogram, flatness analysis
│   │       ├── SecurityTab.tsx   # Mitigations, toolchain, cert reputation, YARA matches
│   │       ├── FormatAnalysisTab.tsx  # Conditional: 17 format-specific cards
│   │       ├── StringsTab.tsx    # Virtual-scrolled strings with benign IOC marking
│   │       └── [+ IdentityTab, ImportsTab, SectionsTab, MitreTab]
│   ├── hooks/
│   │   └── useKeyboardShortcuts.ts  # 1-9 tab switching + Ctrl shortcuts
│   └── lib/
│       ├── db.ts                 # SQLite with versioned migration system
│       └── tauri-bridge.ts       # Typed IPC wrappers (api_version aware)
├── anya-stubs/                   # Stub crates (public repo)
│   ├── scoring/                  # Scoring interface stubs
│   └── data/                     # Data interface stubs
└── anya-proprietary/             # Git submodule
    ├── scoring/                  # Scoring crate
    └── data/                     # Data crate
```

---

## Architectural Foundations (V2)

### Parser Registry

Every format parser implements `FormatParser` trait and registers in `ParserRegistry`:

```rust
pub trait FormatParser: Send + Sync {
    fn name(&self) -> &'static str;
    fn can_parse(&self, ctx: &ParseContext) -> bool;
    fn analyze(&self, ctx: &ParseContext) -> Option<FormatAnalysis>;
}
```

17 built-in parsers registered via `default_registry()`. Adding a new parser = implement the trait + one line in the registry.

### Library-First API

```rust
// Works on raw bytes — no filesystem required
pub fn analyse_bytes(data: &[u8], metadata: &FileMetadata, min_string_length: usize) -> Result<FileAnalysisResult>

// Convenience wrapper — opens file, mmaps, delegates to analyse_bytes()
pub fn analyse_file(path: &Path, min_string_length: usize) -> Result<FileAnalysisResult>
```

### Output Format Trait

```rust
pub trait OutputFormat: Send + Sync {
    fn id(&self) -> &'static str;
    fn render(&self, result: &AnalysisResult) -> Result<Vec<u8>, String>;
    fn supports_batch(&self) -> bool;
}
```

Ships with JSON format. Additional formats can be added by implementing the trait.

### Event System

```rust
pub enum AnalysisEvent {
    AnalysisStarting { path, size_bytes, mime_type },
    FormatDetected { format_label, extension },
    FindingDetected { title, confidence, mitre_id },
    VerdictComputed { verdict, risk_score, finding_count },
    AnalysisComplete { path, verdict, duration_ms },
    // + batch events, system events
}

pub trait EventListener: Send + Sync {
    fn on_event(&self, event: &AnalysisEvent) -> bool;
}
```

Events are defined and dispatched. Listeners can subscribe via the `EventBus`.

### Versioning

| Layer | Constant | Purpose |
|---|---|---|
| Analysis output | `ANALYSIS_SCHEMA_VERSION` (2.0.0) | Forward/backward compat for stored results |
| Config file | `CONFIG_SCHEMA_VERSION` (2.0) | Config migration on upgrade |
| IPC responses | `API_VERSION` (2.0.0) | Frontend/backend version skew detection |
| SQLite schema | `SCHEMA_VERSION` (2) | Numbered migration system in db.ts |

### Feature Flags

```toml
[features]
default = ["cli", "extended-parsers", "yara"]
cli = []
extended-parsers = []
yara = ["dep:yara-x"]
```

### YARA Integration

- Engine: `yara-x` (pure Rust YARA implementation by VirusTotal)
- Rules loaded from `~/.config/anya/rules/` on startup
- Default ruleset bundled in installer packages
- Feature-gated: `yara` feature flag, graceful no-op when disabled

---

## IPC Commands

```
Frontend (TypeScript)                        Rust (Tauri commands)
──────────────────────────────────────       ──────────────────────────────────────
invoke("analyze_file", { path })          →  AnalyzeResponse { api_version, result, risk_score }
invoke("export_json", { result, path })   →  validated path write
invoke("export_html_report", { … })       →  report::generate_html_report() [consolidated]
invoke("export_pdf_report", { … })        →  report::generate_pdf_report()
invoke("get_settings")                    →  AppSettings
invoke("save_settings", { … })            →  telemetry always false
invoke("get_triggered_lessons", …)        →  TriggeredLesson[]
invoke("get_thresholds") / save           →  ThresholdConfig
invoke("analyze_directory", { … })        →  batch events (started/file-result/complete)
invoke("poll_directory", { … })           →  Vec<String>
invoke("save_to_case", { … })             →  case management
invoke("list_cases") / get / delete       →  case CRUD
invoke("get_cases_dir")                   →  platform path
invoke("get_batch_graph_data", { … })     →  GraphData { nodes, links }
invoke("get_ksd_neighborhood", { … })     →  { neighbors: KsdNeighbor[] }
invoke("install_bundled_yara_rules")      →  copies rules from app resources
invoke("is_first_run")                    →  "first_run" | "upgrade" | "current"
invoke("complete_setup", { … })           →  writes version marker + installs YARA rules
```

---

## SQLite Schema (Migration System)

Managed by `ui/lib/db.ts` with numbered migrations:

| Version | Description |
|---|---|
| 1 | Initial: analyses, settings, teacher_progress, teacher_settings |
| 2 | V2: verdict column, yara_match_count, file_format on analyses |

Schema tracked in `schema_migrations` table. Migrations run once on app startup.

---

## Detection Architecture

```
File bytes
    │
    ├── calculate_hashes() → MD5, SHA1, SHA256, TLSH
    ├── calculate_entropy_and_histogram() → entropy + 256-byte histogram
    ├── extract_strings_with_offsets() → strings + IOCs (single pass)
    ├── goblin::Object::parse() → PE / ELF / Mach-O deep analysis
    ├── ParserRegistry.analyze_all() → 17 format-specific parsers
    ├── yara::scanner::scan_bytes() → YARA signature matches
    │
    ▼
FileAnalysisResult
    │
    ├── confidence::extract_signals() → SignalSet (80+ signals)
    │       │
    │       ▼
    │   anya_scoring::score_signals() → weighted verdict + findings
    │
    ├── KSD lookup (TLSH similarity to known malware)
    ├── Forensic fragment annotation (sub-100B files)
    │
    ▼
AnalysisResult (schema_version: "2.0.0")
    │
    ├── CLI: colored terminal output / JSON / HTML / PDF / Markdown
    └── GUI: AnalyzeResponse { api_version: "2.0.0", result, risk_score }
```

---

## Security Considerations

### Input handling
- Untrusted binary data parsed by goblin (fuzz-tested)
- No `unsafe` in anya-security-core beyond goblin internals
- File size capped at 1GB (memory-mapped)
- String extraction bounded by configurable min length
- YARA rules compiled once, scanned per-file (no rule injection from samples)

### Threat model

**Protected against:**
- Malformed PE/ELF/Mach-O files — parse errors, not panics
- Code execution from samples — static analysis only
- Data exfiltration — no network permissions at OS level
- Stale schema — versioned outputs, config migration, DB migrations

**Not protected against:**
- Zero-day vulnerabilities in goblin/yara-x (keep deps updated)
- Malicious YARA rules placed in the rules directory
- Social engineering — user must not execute investigated samples

---

## Dependencies

### Rust

| Crate | Purpose |
|---|---|
| `goblin` | PE/ELF/Mach-O parsing |
| `yara-x` | Pure Rust YARA engine (optional, feature-gated) |
| `tlsh2` | TLSH fuzzy hashing |
| `md-5`, `sha1`, `sha2` | Cryptographic hashing |
| `printpdf` | PDF report generation |
| `tracing`, `tracing-subscriber` | Structured logging |
| `rayon` | Parallel analysis (benchmark command) |
| `serde`, `serde_json`, `toml`, `serde_yaml` | Serialisation |
| `clap` | CLI argument parsing |
| `regex`, `aho-corasick` | Pattern matching |
| `goblin`, `memmap2` | Binary parsing + memory-mapped I/O |
| `anyhow` | Error handling |

### TypeScript

| Package | Purpose |
|---|---|
| `react`, `react-dom` | UI framework |
| `@tauri-apps/api`, `plugin-sql`, `plugin-dialog`, `plugin-fs` | Tauri IPC |
| `react-force-graph-3d` | 3D network graph (Three.js/WebGL) |
| `recharts` | Charts (entropy, donut) |
| `radix-ui` | UI primitives |
| `tailwindcss` | Utility CSS |
| `lucide-react` | Icons |

---

## Testing

| Suite | Count | Runner |
|---|---|---|
| Rust unit tests | 263 | `cargo test -p anya-security-core` |
| Frontend tests | 46 | `npx vitest run` |
| Integration tests | 298 | `private/scripts/integration_test.sh` |
| **Total** | **607** | |

Integration tests cover: CLI flags, edge cases (unicode paths, malformed input, 1-byte files, all-zeros, random data), format parsers, report generation (HTML/PDF/Markdown), batch analysis, case management, YARA engine, schema versioning, and output invariants.

---

**Last updated:** 2026-03-30 (v2.0.0-beta)
**Maintainer:** Daniel Iwugo — daniel@themalwarefiles.com
