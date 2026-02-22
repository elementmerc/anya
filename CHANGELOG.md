# Changelog

All notable changes to Anya will be documented in this file.

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