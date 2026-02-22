# Anya Architecture

## Overview

Anya is a modular malware analysis platform built in Rust, designed for speed, safety, and extensibility. It performs comprehensive static analysis on binary files without executing them.

**Name Origin:** Anya (pronounced AHN-yah) means "eye" in Igbo, reflecting the tool's purpose to see into the inner workings of potentially malicious software.

## Design Principles

1. **Safety First** - Never execute malware, only static analysis
2. **Fast** - Rust performance with efficient algorithms
3. **Modular** - Clean separation between analysis, output, and CLI
4. **Testable** - High test coverage with unit and integration tests
5. **Extensible** - Plugin-friendly architecture for future expansion

## Project Structure

```
anya/
├── src/
│   ├── main.rs           # CLI entry point 
│   ├── lib.rs            # Library interface + core functions
│   ├── config.rs         # Configuration management
│   ├── output.rs         # JSON serialization structures
│   └── pe_parser.rs      # Windows PE file analysis
├── tests/
│   ├── config_tests.rs   # Config integration tests
│   ├── json_output_tests.rs  # JSON output tests
│   ├── batch_tests.rs    # Batch processing tests
│   └── fixtures/         # Test files (sample PEs, etc.)
├── benches/
│   └── analysis_benchmarks.rs  # Performance benchmarks
├── examples/             # Usage examples
│   ├── basic_analysis.rs
│   ├── batch_processing.rs
│   ├── json_output.rs
│   └── custom_config.rs
└── docs/                 # Additional documentation
```

## Module Architecture

### Core Library (lib.rs)

**Purpose:** Testable business logic separated from CLI

**Exports:**
- `analyse_file()` - Main analysis function
- `calculate_hashes()` - MD5, SHA1, SHA256 generation
- `calculate_file_entropy()` - Shannon entropy calculation
- `extract_strings_data()` - ASCII string extraction
- `find_executable_files()` - Directory scanning with filtering
- `is_executable_file()` - Extension-based file type detection
- `is_suspicious_file()` - Threat assessment based on entropy and APIs
- `to_json_output()` - Convert results to JSON format

**Core Types:**
- `FileAnalysisResult` - Complete analysis data for one file
- `BatchSummary` - Statistics for directory analysis
- `OutputLevel` - Verbosity control (Quiet/Normal/Verbose)

**Test Coverage:** 22.78% (72 unit tests),
**Test Coverage (core library only):** : 42.16% (72 unit tests)

### Configuration (config.rs)

**Purpose:** User preferences and persistent settings

**Format:** TOML files
**Locations:** 
- Linux/macOS: `~/.config/anya/config.toml`
- Windows: `%APPDATA%\anya\config.toml`

**Sections:**
```toml
[analysis]
min_string_length = 4      # Minimum string length to extract
entropy_threshold = 7.5    # Flag files above this entropy
show_progress = true       # Display progress bars

[output]
use_colours = true         # Coloured terminal output
format = "text"            # "text" or "json"
verbosity = "normal"       # "quiet", "normal", "verbose"

[suspicious_apis]
enabled = false            # Use custom API lists
additional = []            # Add to built-in list
ignore = []                # Remove from built-in list
custom_list = []           # Replace built-in entirely
```

**Priority Chain:** CLI args > Custom config > Default config > Hardcoded defaults

**Test Coverage:** 62.5% (9 tests)

### Output Structures (output.rs)

**Purpose:** JSON serialization and data interchange

**Key Types:**
- `AnalysisResult` - Top-level JSON output
- `FileInfo` - Path, size, extension
- `Hashes` - MD5, SHA1, SHA256
- `EntropyInfo` - Value, category, suspicious flag
- `StringsInfo` - Total count, samples
- `PEAnalysis` - PE-specific analysis
- `ImportAnalysis` - DLLs, APIs, suspicious count
- `SectionInfo` - Name, size, entropy, permissions
- `SecurityFeatures` - ASLR, DEP/NX status

**All structs implement:**
- `Debug` - For debugging
- `Clone` - For copying results
- `Serialize` - For JSON output
- `Deserialize` - For JSON input

### PE Parser (pe_parser.rs)

**Purpose:** Windows PE file analysis

**Analyses:**
1. **Headers:**
   - DOS header
   - PE header (machine type, timestamp)
   - Optional header (entry point, image base)

2. **Sections:**
   - Name, virtual/raw size, permissions
   - Per-section entropy (detects packed sections)
   - Suspicious combinations (W+X sections)

3. **Import Table:**
   - Imported DLLs and their functions
   - 40+ suspicious API detection
   - Categorization by behavior

4. **Export Table:**
   - Exported functions (if DLL)

5. **Security Features:**
   - ASLR (Address Space Layout Randomization)
   - DEP/NX (Data Execution Prevention)

**Suspicious API Categories:**

| Category | Examples | Risk |
|----------|----------|------|
| Code Injection | CreateRemoteThread, WriteProcessMemory | High |
| Persistence | RegSetValueEx, CreateService | Medium |
| Anti-Analysis | IsDebuggerPresent, CheckRemoteDebugger | Medium |
| Network | InternetOpen, URLDownloadToFile | Medium |
| Cryptography | CryptEncrypt, CryptDecrypt | Low |
| Keylogging | GetAsyncKeyState, SetWindowsHookEx | High |
| Privilege Escalation | AdjustTokenPrivileges | High |

### CLI Interface (main.rs)

**Purpose:** Command-line interface and user interaction

**Responsibilities:**
- Argument parsing (using clap)
- Progress indicators (using indicatif)
- Coloured output (using colored)
- File I/O coordination
- Error messages and help text
- Orchestrating lib.rs functions

**NOT responsible for:**
- Business logic (delegated to lib.rs)
- Analysis algorithms (in modules)
- Data structures (in output.rs)

**Test Coverage:** ~5% (CLI is hard to unit test - covered by integration tests)

## Data Flow

### Single File Analysis

```
User Command: anya --file malware.exe
    ↓
main.rs: Parse arguments (clap)
    ↓
main.rs: Load config (merge with CLI args)
    ↓
lib::analyse_file(path, min_string_length)
    ├→ fs::read() - Read file data
    ├→ calculate_hashes(data) - MD5, SHA1, SHA256
    ├→ calculate_file_entropy(data) - Shannon entropy
    ├→ extract_strings_data(data, min_len) - ASCII strings
    └→ goblin::Object::parse(data)
         ├→ PE → pe_parser::analyse_pe_data(data)
         │        ├→ Parse headers
         │        ├→ Analyze sections
         │        ├→ Parse imports
         │        ├→ Detect suspicious APIs
         │        └→ Check security features
         ├→ ELF → (future support)
         └→ Mach-O → (future support)
    ↓
FileAnalysisResult (all data combined)
    ↓
main.rs: Print formatted output OR JSON
    ↓
User sees results
```

### Batch Directory Analysis

```
User Command: anya --directory /samples --recursive
    ↓
lib::find_executable_files(dir, recursive)
    ├→ WalkDir traversal
    ├→ Filter by extension (.exe, .dll, .sys, etc.)
    └→ Return Vec<PathBuf>
    ↓
For each file:
    ├→ lib::analyse_file(path, min_len)
    ├→ Check lib::is_suspicious_file(result)
    └→ Update BatchSummary stats
    ↓
BatchSummary::print_summary()
    ├→ Total files, analysed, failed
    ├→ Suspicious count
    ├→ Duration, success rate
    └→ Analysis rate (files/sec)
    ↓
User sees summary
```

## Performance Considerations

### Fast Path Operations

**Hashing:** O(n) single pass
- Streaming for large files
- Parallel hash computation (future)

**Entropy:** O(n) single pass
- Byte frequency array (256 buckets)
- Single traversal of data

**Strings:** O(n) state machine
- No regex overhead
- Early termination on non-printable

**PE Parsing:** O(n) zero-copy
- Goblin uses memory-mapped parsing
- No unnecessary allocations

### Progress Updates

**Large files (>1MB):**
- Progress bar shown
- Updates every 256KB
- Smooth visual feedback

**Small files (<1MB):**
- No progress bar
- Instant analysis
- Reduced overhead

### Memory Efficiency

**Per-file limits:**
- File data: ~1x file size (memory-mapped future)
- Analysis results: ~50KB structures
- String samples: Limited to 10 samples
- Total: <50MB per file typically

## Performance Targets

### Current (v0.3.0)

| Metric | Small (<1MB) | Medium (1-10MB) | Large (>10MB) |
|--------|--------------|-----------------|---------------|
| Single file | <100ms | <500ms | ~2-5s |
| Memory | <10MB | <30MB | <50MB |
| Batch rate | 10 files/sec | 5 files/sec | 2 files/sec |

### Goals (v1.0)

| Metric | Small | Medium | Large |
|--------|-------|--------|-------|
| Single file | <50ms | <200ms | <1s |
| Memory | <5MB | <20MB | <30MB |
| Batch rate | 20 files/sec | 10 files/sec | 5 files/sec |

**Planned Optimisations:**
- Rayon for parallel batch processing
- Async file I/O (tokio)
- Memory-mapped file reading
- SIMD for hash calculations

## Testing Strategy

### Unit Tests (in modules)

**Location:** `#[cfg(test)]` blocks in source files

**Purpose:** Test individual functions in isolation

**Characteristics:**
- No real files needed (mock data)
- Fast execution (<1s total)
- Run with every `cargo test`

**Coverage by module:**
- lib.rs: 86% (26 tests) ✅
- config.rs: 62.5% (9 tests) ✅
- pe_parser.rs: 11.6% (needs fixtures)

### Integration Tests (tests/)

**Location:** `tests/` directory

**Purpose:** Test complete workflows end-to-end

**Files:**
- `config_tests.rs` - Config loading, validation, defaults
- `json_output_tests.rs` - JSON serialization, schema validation
- `batch_tests.rs` - Directory scanning, filtering, error handling

**Characteristics:**
- Use temp files and fixtures
- Test CLI binary behavior
- Cover error cases and edge conditions

### Benchmarks (benches/)

**Location:** `benches/analysis_benchmarks.rs`

**Purpose:** Track performance over time

**Benchmarked operations:**
- Hash calculation (1KB, 10KB, 100KB, 1MB)
- Entropy calculation (various sizes)
- String extraction (different min lengths)
- File reading I/O

**Usage:**
```bash
cargo bench                    # Run all benchmarks
cargo bench hash_calculation   # Run specific benchmark
cargo bench --save-baseline main  # Save baseline
```

### Overall Coverage

**Target:** 60%+ (production quality)
**Current:** ~23% overall

**Breakdown:**
- Testable code (lib, config, output): ~70% ✅
- PE parser: 11.6% (needs PE fixtures)
- CLI (main.rs): ~5% (hard to test)

**Note:** Excluding untestable CLI code, coverage is ~34%, which is good for a malware analysis tool.

## Configuration System Architecture

### Loading Priority

```
1. CLI Arguments (highest priority)
   ↓ (if not specified)
2. Custom Config File (--config path/to/config.toml)
   ↓ (if not found)
3. User Config (~/.config/anya/config.toml)
   ↓ (if not found)
4. Default Config (Config::default())
   ↓
5. Hardcoded Defaults (lowest priority)
```

### Example Priority Resolution

```bash
# Config file: min_string_length = 6
# CLI: --min-string-length 10
# Result: 10 (CLI wins)

# Config file: min_string_length = 6
# CLI: (not specified)
# Result: 6 (config used)

# No config file
# CLI: (not specified)
# Result: 4 (hardcoded default)
```

### Config File Creation

```bash
# Create default config
anya --init-config

# Verify location
anya --config ~/.config/anya/config.toml --file test.exe
```

## Security Considerations

### Input Validation

- **Never trust malware samples**
- Parse with well-tested libraries (goblin)
- Limit resource consumption (memory, time)
- No unsafe code in critical paths

### Safe by Design

- Rust's memory safety prevents buffer overflows
- Static analysis only (never execute)
- Sandboxed execution planned (Docker/gVisor)
- Fuzzing-tested parsers (goblin is fuzz-tested)

### Threat Model

**Protected Against:**
- Malformed PE files → Handled by goblin
- Resource exhaustion → Memory limits
- Code execution → Static analysis only

**NOT Protected Against:**
- Social engineering (user must not execute samples)
- Malicious TOML configs (don't load untrusted configs)

## Future Architecture

### Planned Features (v0.4-1.0)

```
src/
├── tui/              # Terminal User Interface
│   ├── mod.rs
│   ├── dashboard.rs
│   ├── file_browser.rs
│   └── analysis_view.rs
├── integrations/     # External services
│   ├── virustotal.rs
│   ├── cuckoo.rs
│   └── yara.rs
├── database/         # SQLite for history
│   ├── mod.rs
│   └── queries.rs
├── plugins/          # Dynamic plugins
│   └── api.rs
└── ml/               # ML models (future)
    └── classifier.rs
```

### Plugin System Design (v1.0+)

```rust
/// Plugin trait for extensibility
pub trait AnalysisPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn analyze(&self, data: &[u8]) -> Result<PluginResult>;
}

// User creates: plugins/custom_detector.so
// Anya loads: dynamically at runtime
// Security: Sandboxed execution
```

### Database Schema (v0.5+)

```sql
CREATE TABLE files (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    md5 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    analyzed_at TIMESTAMP,
    file_type TEXT,
    is_suspicious BOOLEAN,
    tags TEXT  -- JSON array
);

CREATE TABLE analysis_results (
    id INTEGER PRIMARY KEY,
    file_id INTEGER,
    entropy REAL,
    suspicious_api_count INTEGER,
    results_json TEXT,
    FOREIGN KEY(file_id) REFERENCES files(id)
);
```

## Dependencies

### Core
- `anyhow` - Error handling
- `goblin` - Binary parsing (PE/ELF/Mach-O)
- `md5`, `sha1`, `sha2` - Cryptographic hashing

### CLI
- `clap` - Argument parsing
- `colored` - Terminal colors
- `indicatif` - Progress bars

### Config
- `toml` - TOML parsing
- `serde` - Serialization
- `dirs` - Platform directories

### Development
- `tempfile` - Test fixtures
- `criterion` - Benchmarking

### Future
- `ratatui` - TUI framework (v0.4)
- `reqwest` - HTTP client (integrations)
- `rusqlite` - Database (v0.5)
- `yara` - YARA engine (v0.6)

## Contributing

See `CONTRIBUTING.md` for:
- Code style guidelines (rustfmt)
- Testing requirements (60%+ coverage)
- Pull request process
- Architecture decision records

## License

AGPL-3.0-or-later

For commercial licensing inquiries: daniel@themalwarefiles.com

---

**Last Updated:** 2026-02-22  
**Version:** 0.3.1  
**Maintainer:** Daniel Iwugo