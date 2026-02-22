// Ányá - Malware Analysis Platform
// Copyright (C) 2026 Daniel Iwugo
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// For commercial licensing, contact: daniel@themalwarefiles.com

/// Configuration management for Anya
///
/// **Rust Concepts:**
/// - TOML serialization/deserialization
/// - File I/O with home directory
/// - Option types for optional config values
/// - Default trait implementation

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Main configuration structure
///
/// **Rust Concept: Derive Macros**
/// - `Serialize` - Can convert to TOML/JSON
/// - `Deserialize` - Can parse from TOML/JSON
/// - `Debug` - Can print with {:?}
/// - `Clone` - Can be duplicated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Analysis settings
    #[serde(default)]
    pub analysis: AnalysisConfig,
    
    /// Output preferences
    #[serde(default)]
    pub output: OutputConfig,
    
    /// Custom suspicious APIs (overrides built-in list if provided)
    #[serde(default)]
    pub suspicious_apis: SuspiciousApiConfig,
}

/// Analysis-related settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Minimum string length to extract (default: 4)
    #[serde(default = "default_min_string_length")]
    pub min_string_length: usize,
    
    /// Entropy threshold for suspicious files (default: 7.5)
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    
    /// Whether to show progress bars (default: true)
    #[serde(default = "default_true")]
    pub show_progress: bool,
}

/// Output-related settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Use coloured output (default: true)
    #[serde(default = "default_true")]
    pub use_colours: bool,
    
    /// Default output format ("text" or "json")
    #[serde(default = "default_output_format")]
    pub format: String,
    
    /// Verbosity level ("quiet", "normal", "verbose")
    #[serde(default = "default_verbosity")]
    pub verbosity: String,
}

/// Custom suspicious API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousApiConfig {
    /// Enable custom API list (if false, uses built-in list)
    #[serde(default)]
    pub enabled: bool,
    
    /// Additional APIs to flag (in addition to built-in)
    #[serde(default)]
    pub additional: Vec<String>,
    
    /// APIs to ignore (remove from built-in list)
    #[serde(default)]
    pub ignore: Vec<String>,
    
    /// Complete custom list (replaces built-in if not empty)
    #[serde(default)]
    pub custom_list: Vec<String>,
}

// **Rust Concept: Default Value Functions**
// These functions provide default values for serde
// Used with #[serde(default = "function_name")]

fn default_min_string_length() -> usize {
    4
}

fn default_entropy_threshold() -> f64 {
    7.5
}

fn default_true() -> bool {
    true
}

fn default_output_format() -> String {
    "text".to_string()
}

fn default_verbosity() -> String {
    "normal".to_string()
}

// **Rust Concept: Default Trait Implementation**
// This allows Config::default() to create a default config
impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            min_string_length: default_min_string_length(),
            entropy_threshold: default_entropy_threshold(),
            show_progress: default_true(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            use_colours: default_true(),
            format: default_output_format(),
            verbosity: default_verbosity(),
        }
    }
}

impl Default for SuspiciousApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            additional: Vec::new(),
            ignore: Vec::new(),
            custom_list: Vec::new(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            analysis: AnalysisConfig::default(),
            output: OutputConfig::default(),
            suspicious_apis: SuspiciousApiConfig::default(),
        }
    }
}

impl Config {
    /// Get the default config file path
    ///
    /// **Rust Concept: dirs Crate**
    /// - `dirs::config_dir()` finds the user's config directory
    /// - Windows: C:\Users\Username\AppData\Roaming
    /// - macOS: /Users/Username/Library/Application Support
    /// - Linux: /home/username/.config
    ///
    /// **Returns:** `Option<PathBuf>` - might not find config dir
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|mut path| {
            path.push("anya");
            path.push("config.toml");
            path
        })
    }
    
    /// Load configuration from file
    ///
    /// **Rust Concepts:**
    /// - `?` operator for error propagation
    /// - `fs::read_to_string()` reads entire file
    /// - `toml::from_str()` parses TOML
    /// - `.context()` adds helpful error messages
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .context(format!("Failed to read config file: {:?}", path))?;
        
        let config: Config = toml::from_str(&contents)
            .context("Failed to parse config file as TOML")?;
        
        Ok(config)
    }
    
    /// Load config from default location, or create default if not found
    ///
    /// **Rust Concept: Fallback Pattern**
    /// - Try to load from file
    /// - If file doesn't exist, use defaults
    /// - If file exists but can't parse, return error
    pub fn load_or_default() -> Result<Self> {
        let path = match Self::default_path() {
            Some(p) => p,
            None => {
                // Can't find config directory, use defaults
                eprintln!("Warning: Could not determine config directory, using defaults");
                return Ok(Config::default());
            }
        };
        
        if path.exists() {
            Self::load_from_file(&path)
        } else {
            // Config file doesn't exist, use defaults
            Ok(Config::default())
        }
    }
    
    /// Save configuration to file
    ///
    /// **Rust Concepts:**
    /// - `toml::to_string_pretty()` serialises to TOML with formatting
    /// - `fs::create_dir_all()` creates parent directories if needed
    /// - `fs::write()` writes entire string to file
    #[allow(dead_code)]
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        // Serialise config to TOML
        let toml_string = toml::to_string_pretty(self)
            .context("Failed to serialise config to TOML")?;
        
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .context(format!("Failed to create config directory: {:?}", parent))?;
        }
        
        // Write to file
        fs::write(path, toml_string)
            .context(format!("Failed to write config file: {:?}", path))?;
        
        Ok(())
    }
    
    /// Save to default location
    #[allow(dead_code)]
    pub fn save_default(&self) -> Result<()> {
        let path = Self::default_path()
            .context("Could not determine config directory")?;
        
        self.save_to_file(&path)
    }
    
    /// Create a default config file with comments
    ///
    /// **Rust Concept: String Literal**
    /// - Multi-line string with `r#"..."#`
    /// - Raw string (no escape sequences)
    pub fn create_default_file() -> Result<PathBuf> {
        let path = Self::default_path()
            .context("Could not determine config directory")?;
        
        // Create parent directory
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Default config with helpful comments
        let default_config = r#"# Ányá Configuration File
# Located at: ~/.config/anya/config.toml (Linux/macOS)
#          or: %APPDATA%\anya\config.toml (Windows)

[analysis]
# Minimum string length to extract from files
min_string_length = 4

# Entropy threshold for flagging suspicious files (0.0 - 8.0)
# Files with entropy > this value are flagged as potentially packed/encrypted
entropy_threshold = 7.5

# Show progress bars during analysis
show_progress = true

[output]
# Use coloured terminal output
use_colours = true

# Default output format: "text" or "json"
format = "text"

# Default verbosity: "quiet", "normal", or "verbose"
verbosity = "normal"

[suspicious_apis]
# Enable custom API list
enabled = false

# Additional APIs to flag (in addition to built-in list)
# Example: additional = ["MyCustomAPI", "SuspiciousFunction"]
additional = []

# APIs to ignore (remove from built-in list)
# Example: ignore = ["RegOpenKeyEx"]  # if you don't want to flag registry access
ignore = []

# Complete custom API list (replaces built-in if not empty)
# Example: custom_list = ["CreateRemoteThread", "VirtualAllocEx"]
custom_list = []
"#;
        
        fs::write(&path, default_config)?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.analysis.min_string_length, 4);
        assert_eq!(config.analysis.entropy_threshold, 7.5);
        assert_eq!(config.output.format, "text");
    }
    
    #[test]
    fn test_default_analysis_config() {
        let config = AnalysisConfig::default();
        assert_eq!(config.min_string_length, 4);
        assert_eq!(config.entropy_threshold, 7.5);
        assert!(config.show_progress);
    }
    
    #[test]
    fn test_default_output_config() {
        let config = OutputConfig::default();
        assert!(config.use_colours);
        assert_eq!(config.format, "text");
        assert_eq!(config.verbosity, "normal");
    }
    
    #[test]
    fn test_suspicious_api_config() {
        let config = SuspiciousApiConfig::default();
        assert!(!config.enabled);
        assert!(config.additional.is_empty());
        assert!(config.ignore.is_empty());
        assert!(config.custom_list.is_empty());
    }
    
    #[test]
    fn test_config_serialisation() {
        let config = Config::default();
        let toml = toml::to_string(&config).unwrap();
        
        // Should be valid TOML
        assert!(toml.contains("[analysis]"));
        assert!(toml.contains("min_string_length"));
    }
    
    #[test]
    fn test_config_deserialisation() {
        let toml_str = r#"
            [analysis]
            min_string_length = 8
            
            [output]
            format = "json"
        "#;
        
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.analysis.min_string_length, 8);
        assert_eq!(config.output.format, "json");
    }
    
    #[test]
    fn test_partial_config() {
        // Missing fields should use defaults
        let toml_str = r#"
            [analysis]
            min_string_length = 10
        "#;
        
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.analysis.min_string_length, 10);
        assert_eq!(config.analysis.entropy_threshold, 7.5); // Default
        assert_eq!(config.output.format, "text"); // Default
    }
    
    #[test]
    fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");
        
        let toml_content = r#"
[analysis]
min_string_length = 6
entropy_threshold = 6.0

[output]
format = "json"
"#;
        fs::write(&config_path, toml_content).unwrap();
        
        let config = Config::load_from_file(&config_path).unwrap();
        assert_eq!(config.analysis.min_string_length, 6);
        assert_eq!(config.analysis.entropy_threshold, 6.0);
        assert_eq!(config.output.format, "json");
    }
    
    #[test]
    fn test_load_or_default() {
        // Should not fail even if config doesn't exist
        let config = Config::load_or_default().unwrap();
        assert_eq!(config.analysis.min_string_length, 4);
    }
}