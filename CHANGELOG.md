# Changelog

All notable changes to Anya will be documented in this file.

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