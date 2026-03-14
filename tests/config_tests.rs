// Integration tests for configuration loading

use anya_security_core::config::Config;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_load_default_config() {
    let config = Config::default();
    assert_eq!(config.analysis.min_string_length, 4);
    assert_eq!(config.analysis.entropy_threshold, 7.5);
}

#[test]
fn test_load_custom_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    
    let custom = r#"
[analysis]
min_string_length = 10

[output]
format = "json"
"#;
    
    fs::write(&config_path, custom).unwrap();
    let config = Config::load_from_file(&config_path).unwrap();
    
    assert_eq!(config.analysis.min_string_length, 10);
    assert_eq!(config.output.format, "json");
}

#[test]
fn test_partial_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("partial.toml");
    
    fs::write(&config_path, "[analysis]\nmin_string_length = 8").unwrap();
    let config = Config::load_from_file(&config_path).unwrap();
    
    assert_eq!(config.analysis.min_string_length, 8);
    assert_eq!(config.analysis.entropy_threshold, 7.5); // Default
}

