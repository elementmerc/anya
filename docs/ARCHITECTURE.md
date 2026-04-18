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
│   ├── vhd_parser.rs             # VHD/VHDX disk image analysis
│   ├── onenote_parser.rs         # Microsoft OneNote document analysis
│   ├── img_parser.rs             # Raw disk image (IMG) analysis
│   ├── rar_parser.rs             # RAR archive analysis
│   ├── gzip_parser.rs            # GZIP compressed file analysis
│   ├── sevenz_parser.rs          # 7-Zip archive analysis
│   ├── tar_parser.rs             # TAR archive analysis
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
│   │   ├── BatchGraph.tsx        # 2D force-directed network graph (batch TLSH relationships)
│   │   ├── SingleFileGraph.tsx   # IOC/Import evidence web (single-file analysis)
│   │   ├── AnimatedEmptyState.tsx # Cinematic SVG line-draw empty state icons
│   │   ├── BatchDashboard.tsx    # Verdict summary cards and donut chart
│   │   └── tabs/
│   │       ├── OverviewTab.tsx   # Risk ring, KSD, forensic fragment, KSD graph
│   │       ├── EntropyTab.tsx    # Section entropy, byte histogram, flatness analysis
│   │       ├── SecurityTab.tsx   # Mitigations, toolchain, cert reputation, YARA matches
│   │       ├── FormatAnalysisTab.tsx  # Conditional: 24 format-specific cards
│   │       ├── StringsTab.tsx    # Virtual-scrolled strings with benign IOC marking
│   │       └── [+ IdentityTab, ImportsTab, SectionsTab, MitreTab]
│   ├── hooks/
│   │   └── useKeyboardShortcuts.ts  # 1-9 tab switching + Ctrl shortcuts
│   └── lib/
│       ├── db.ts                 # SQLite with versioned migration system
│       └── tauri-bridge.ts       # Typed IPC wrappers (api_version aware)
└── anya-stubs/                   # Stub crates (public repo)
    ├── scoring/                  # Scoring interface stubs
    └── data/                     # Data interface stubs
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

24 built-in parsers registered via `default_registry()`. Adding a new parser = implement the trait + one line in the registry.

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
invoke("get_dll_explanations")            →  DLL descriptions JSON
invoke("get_function_explanations")       →  API function descriptions JSON
invoke("get_technique_explanations")      →  MITRE technique explanations JSON
invoke("get_mitre_attack_data")           →  MITRE ATT&CK catalogue JSON
invoke("get_category_explanations")       →  API category descriptions JSON
invoke("yara_scan_only", { path })        →  YaraOnlyResult (fast YARA scan without full analysis)
```

### CLI Flags (v2.0.3+)

```
--jsonl                     Stream results as one JSON object per line (flushed)
--yara-only                 Run YARA rules only (skip full analysis)
--depth quick|standard|deep Analysis depth (quick: hash+entropy+YARA, standard: default, deep: extended strings)
--exit-code-from-verdict    Set exit code based on verdict (0=clean, 1=malicious, 2=suspicious, 10=error)
```

Watch mode also supports `--json` and `--json-compact` for structured output.

### Output Formats (`--format`)

Selected via `--format <name>`. Default is human-readable text.

| Format | Module | Typical consumer |
|---|---|---|
| `text` | `output::format::text` | Terminal user, default |
| `json` | `serde_json` direct on `AnalysisResult` | Programmatic consumer, pipelines, SIEM ingest |
| `html` | `report::generate_html_report` | Analyst handover, case documentation |
| `pdf` | `report::generate_pdf_report` | Archival, distribution |
| `markdown` | `report::generate_markdown_report` | Documentation, post-incident write-ups |
| `sarif` | `sarif::render` → `serde-sarif` crate | GitHub Code Scanning, Azure DevOps, GitLab Security, SIEM / SOAR |

#### SARIF 2.1.0 output (v2.0.5+)

`--format sarif` emits OASIS SARIF 2.1.0 documents compatible with enterprise CI pipelines. Shape:

- Top-level `$schema` = `https://json.schemastore.org/sarif-2.1.0.json`, `version` = `"2.1.0"`
- One `Run` per invocation with tool driver + the full 15-rule catalogue embedded in `driver.rules[]` (see `engine/docs/SARIF_RULES.md` for the canonical reference)
- Always-emit verdict carrier (`ANYA-V001`) so every scan produces at least one `Result` even for clean files (scan-of-record pattern)
- MITRE ATT&CK emitted as a structured SARIF `taxonomies[]` component with `taxa[]` entries populated from techniques the analyser attached to findings
- Per-finding `properties.tags[]` uses a disciplined colon-prefixed namespace vocabulary: `verdict:`, `mitre:`, `family:`, `confidence:`, `signal:`, `format:`
- Level mapping: MALICIOUS → `error`, SUSPICIOUS → `warning`, CLEAN / TOOL / PUP / TEST / UNKNOWN → `note`
- Rule IDs follow a 3-letter class prefix convention: `ANYA-V*` (verdict carrier), `ANYA-H*` (heuristic signals), `ANYA-P*` (parser signals), `ANYA-D*` (detection database matches)

The SARIF writer lives at `engine/src/sarif.rs`. Golden fixtures (shape examples for clean and suspicious scans) live at `engine/tests/fixtures/sarif-golden/`. Integration tests are in `engine/tests/sarif_output_tests.rs`.

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
    ├── ParserRegistry.analyze_all() → 24 format-specific parsers
    ├── yara::scanner::scan_bytes() → YARA signature matches
    │
    ▼
FileAnalysisResult
    │
    ├── confidence::extract_signals() → SignalSet (80+ signals)
    │       │
    │       ▼
    │   score_signals() → weighted verdict + findings
    │
    ├── Known sample lookup (tools, test files, known clean binaries)
    ├── Family annotation lookup (malware family context)
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
| `force-graph` | 2D force-directed graph (canvas, d3-force) |
| `recharts` | Charts (entropy) |
| `radix-ui` | UI primitives |
| `tailwindcss` | Utility CSS |
| `lucide-react` | Icons |

---

## Testing

| Suite | Count | Runner |
|---|---|---|
| Rust unit tests | 23 | `cargo test -p anya-security-core` |
| Frontend tests | 46 | `npx vitest run` |
| Integration tests | 304 | `scripts/integration_test.sh` |
| **Total** | **373** | |

Integration tests cover: CLI flags, edge cases (unicode paths, malformed input, 1-byte files, all-zeros, random data), format parsers, report generation (HTML/PDF/Markdown), batch analysis, case management, YARA engine, schema versioning, and output invariants.

---

**Last updated:** 2026-04-11 (v2.0.3)
**Maintainer:** Daniel Iwugo — daniel@themalwarefiles.com
