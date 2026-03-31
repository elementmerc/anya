// Ányá - Malware Analysis Platform
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later
//
// Output format trait — extensible export format system.
// Each format is a struct implementing `OutputFormat`.

use crate::output::AnalysisResult;

/// Trait for rendering analysis results into different output formats.
///
/// Implementors convert a completed `AnalysisResult` into bytes in their format
/// (JSON, HTML, PDF, Markdown, etc.).
///
/// Supported formats: JSON, HTML, PDF, Markdown.
/// Additional formats can be added by implementing this trait.
pub trait OutputFormat: Send + Sync {
    /// Short identifier for the format (e.g. "json", "html", "pdf").
    fn id(&self) -> &'static str;

    /// Human-readable display name (e.g. "JSON", "HTML Report", "PDF").
    fn display_name(&self) -> &'static str;

    /// MIME type for the output (e.g. "application/json", "text/html", "application/pdf").
    fn content_type(&self) -> &'static str;

    /// Default file extension without dot (e.g. "json", "html", "pdf", "md").
    fn file_extension(&self) -> &'static str;

    /// Render the analysis result into this format's byte representation.
    ///
    /// Returns `Ok(bytes)` on success, or an error message.
    /// For text formats, the bytes are UTF-8 encoded.
    fn render(&self, result: &AnalysisResult) -> Result<Vec<u8>, String>;

    /// Whether this format supports rendering multiple results into a single output
    /// (e.g. JSONL for batch analysis).
    fn supports_batch(&self) -> bool {
        false
    }

    /// Render multiple results into a single output (for batch/directory analysis).
    /// Default: renders each individually and concatenates with newlines (JSONL-style).
    fn render_batch(&self, results: &[AnalysisResult]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for r in results {
            out.extend(self.render(r)?);
            out.push(b'\n');
        }
        Ok(out)
    }
}

// ── Built-in: JSON format ────────────────────────────────────────────────────

/// Standard JSON output — the default format since V1.
pub struct JsonFormat {
    /// Pretty-print with indentation (default: true for files, false for piping)
    pub pretty: bool,
}

impl Default for JsonFormat {
    fn default() -> Self {
        Self { pretty: true }
    }
}

impl OutputFormat for JsonFormat {
    fn id(&self) -> &'static str {
        "json"
    }
    fn display_name(&self) -> &'static str {
        "JSON"
    }
    fn content_type(&self) -> &'static str {
        "application/json"
    }
    fn file_extension(&self) -> &'static str {
        "json"
    }
    fn render(&self, result: &AnalysisResult) -> Result<Vec<u8>, String> {
        let json = if self.pretty {
            serde_json::to_vec_pretty(result)
        } else {
            serde_json::to_vec(result)
        };
        json.map_err(|e| format!("JSON serialization error: {e}"))
    }
    fn supports_batch(&self) -> bool {
        true
    }
    fn render_batch(&self, results: &[AnalysisResult]) -> Result<Vec<u8>, String> {
        // JSONL format — one JSON object per line
        let mut out = Vec::new();
        for r in results {
            let line =
                serde_json::to_vec(r).map_err(|e| format!("JSON serialization error: {e}"))?;
            out.extend(line);
            out.push(b'\n');
        }
        Ok(out)
    }
}

// ── Format registry ──────────────────────────────────────────────────────────

/// Registry of available output formats. Extensible at runtime.
pub struct FormatRegistry {
    formats: Vec<Box<dyn OutputFormat>>,
}

impl FormatRegistry {
    pub fn new() -> Self {
        Self {
            formats: Vec::new(),
        }
    }

    /// Register a new output format.
    pub fn register<F: OutputFormat + 'static>(&mut self, format: F) {
        self.formats.push(Box::new(format));
    }

    /// Look up a format by its short ID (e.g. "json", "html").
    pub fn get(&self, id: &str) -> Option<&dyn OutputFormat> {
        self.formats.iter().find(|f| f.id() == id).map(|f| &**f)
    }

    /// List all registered format IDs.
    pub fn available_ids(&self) -> Vec<&'static str> {
        self.formats.iter().map(|f| f.id()).collect()
    }
}

impl Default for FormatRegistry {
    fn default() -> Self {
        let mut reg = Self::new();
        reg.register(JsonFormat::default());
        reg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_format_produces_valid_json() {
        let fmt = JsonFormat { pretty: false };
        let result = AnalysisResult {
            schema_version: crate::output::ANALYSIS_SCHEMA_VERSION.to_string(),
            file_info: crate::output::FileInfo {
                path: "test.exe".into(),
                size_bytes: 100,
                size_kb: 0.1,
                extension: Some("exe".into()),
                mime_type: None,
            },
            hashes: crate::output::Hashes {
                md5: "d41d8cd98f00b204e9800998ecf8427e".into(),
                sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".into(),
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                tlsh: None,
            },
            entropy: crate::output::EntropyInfo {
                value: 0.0,
                category: "empty".into(),
                is_suspicious: false,
                confidence: None,
            },
            strings: crate::output::StringsInfo {
                min_length: 4,
                total_count: 0,
                samples: vec![],
                sample_count: 0,
                classified: None,
                suppressed_reason: None,
            },
            file_format: "test".into(),
            ..Default::default()
        };

        let bytes = fmt.render(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["file_info"]["path"], "test.exe");
    }

    #[test]
    fn format_registry_default_has_json() {
        let reg = FormatRegistry::default();
        assert!(reg.get("json").is_some());
        assert_eq!(reg.available_ids(), vec!["json"]);
    }
}
