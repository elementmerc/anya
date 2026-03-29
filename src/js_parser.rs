// JavaScript / JScript static analysis
// Detection patterns are loaded from the private scoring crate.

use crate::output::JavaScriptAnalysis;
use anya_scoring::detection_patterns::{JS_OBFUSCATION_PATTERNS, JS_SUSPICIOUS_PATTERNS};
use regex::Regex;
use std::sync::LazyLock;

/// Compiled regexes from private pattern strings
static JS_COMPILED: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let labels = [
        "eval/Function constructor",
        "Function constructor",
        "ActiveXObject creation",
        "WScript.Shell access",
        "document.write",
        "setTimeout with string arg",
        "XMLHttpRequest",
        "fetch API",
        "WebSocket connection",
        "String.fromCharCode chain",
        "atob Base64 decoding",
        "Shell.Application",
        "Scripting.FileSystemObject",
    ];
    JS_SUSPICIOUS_PATTERNS
        .iter()
        .zip(labels.iter().cycle())
        .filter_map(|(pat, label)| Regex::new(pat).ok().map(|r| (r, *label)))
        .collect()
});

static JS_OBF_COMPILED: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    JS_OBFUSCATION_PATTERNS
        .iter()
        .filter_map(|pat| Regex::new(pat).ok())
        .collect()
});

/// Analyse a file's bytes as JavaScript/JScript. Returns None if no
/// suspicious patterns are found.
pub fn detect_javascript_analysis(data: &[u8]) -> Option<JavaScriptAnalysis> {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let mut patterns: Vec<String> = Vec::new();
    let mut has_eval = false;
    let mut has_activex = false;
    let mut has_wscript = false;

    for (re, label) in JS_COMPILED.iter() {
        if re.is_match(text) {
            patterns.push(label.to_string());
            let lower = label.to_lowercase();
            if lower.contains("eval") || lower.contains("function constructor") {
                has_eval = true;
            }
            if lower.contains("activex") {
                has_activex = true;
            }
            if lower.contains("wscript") {
                has_wscript = true;
            }
        }
    }

    // Obfuscation scoring
    let mut obf_score: u8 = 0;
    let mut encoded_payloads: usize = 0;

    for (i, re) in JS_OBF_COMPILED.iter().enumerate() {
        let count = re.find_iter(text).count();
        if count > 0 {
            encoded_payloads += count;
            match i {
                0 => {
                    obf_score = obf_score.saturating_add(20.min(count as u8 * 5));
                    patterns.push(format!("Hex-encoded strings ({count})"));
                }
                1 => {
                    obf_score = obf_score.saturating_add(15.min(count as u8 * 5));
                    patterns.push(format!("Unicode escape sequences ({count})"));
                }
                2 => {
                    obf_score = obf_score.saturating_add(25);
                    patterns.push("Large integer array (possible shellcode)".into());
                }
                _ => {}
            }
        }
    }

    // Long lines (minified/obfuscated)
    let max_line_len = text.lines().map(|l| l.len()).max().unwrap_or(0);
    if max_line_len > 5000 {
        obf_score = obf_score.saturating_add(15);
        patterns.push(format!("Very long line ({max_line_len} chars)"));
    }

    // Base64 blobs
    let b64_matches = text
        .split_whitespace()
        .filter(|w| w.len() > 100 && is_base64_like(w))
        .count();
    if b64_matches > 0 {
        obf_score = obf_score.saturating_add(20);
        encoded_payloads += b64_matches;
        patterns.push(format!("Base64-encoded blobs ({b64_matches})"));
    }

    if has_eval {
        obf_score = obf_score.saturating_add(10);
    }

    if patterns.is_empty() {
        return None;
    }

    Some(JavaScriptAnalysis {
        obfuscation_score: obf_score.min(100),
        suspicious_patterns: patterns,
        has_eval,
        has_activex,
        has_wscript,
        encoded_payloads,
    })
}

fn is_base64_like(s: &str) -> bool {
    let valid = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=');
    valid && s.len() % 4 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_js() {
        let code = b"function hello() { console.log('Hello World'); }";
        assert!(detect_javascript_analysis(code).is_none());
    }

    #[test]
    fn test_eval_detection() {
        let code = b"var x = eval('alert(1)');";
        let r = detect_javascript_analysis(code).unwrap();
        assert!(r.has_eval);
    }

    #[test]
    fn test_wscript_detection() {
        let code = b"WScript.Shell.Run('cmd /c calc');";
        let r = detect_javascript_analysis(code).unwrap();
        assert!(r.has_wscript);
    }
}
