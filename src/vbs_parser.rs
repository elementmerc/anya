// VBScript / VBA static analysis
// Detection patterns loaded from private scoring crate.

use crate::output::VbScriptAnalysis;
use anya_scoring::detection_patterns::VBS_SUSPICIOUS_KEYWORDS;
use regex::Regex;
use std::sync::LazyLock;

static RE_CHR_CHAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Chr\s*\(\s*\d+\s*\)\s*&\s*Chr\s*\(\s*\d+\s*\)").unwrap());
static RE_EXECUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(Execute|ExecuteGlobal)\s*[("']"#).unwrap());

/// Analyse file bytes as VBScript/VBA.
pub fn detect_vbscript_analysis(data: &[u8]) -> Option<VbScriptAnalysis> {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let mut patterns: Vec<String> = Vec::new();
    let mut has_shell_exec = false;
    let mut has_wmi = false;
    let mut has_download = false;

    // Check each keyword from private crate
    for kw in VBS_SUSPICIOUS_KEYWORDS.iter() {
        if text.contains(kw.as_str()) {
            patterns.push(kw.clone());
            let lower = kw.to_lowercase();
            if lower.contains("shell") || lower.contains("wscript.shell") {
                has_shell_exec = true;
            }
            if lower.contains("winmgmts") {
                has_wmi = true;
            }
            if lower.contains("xmlhttp") || lower.contains("adodb") || lower.contains("winhttp") {
                has_download = true;
            }
        }
    }

    let chr_chain_count = RE_CHR_CHAIN.find_iter(text).count();
    if chr_chain_count > 3 {
        patterns.push(format!("Chr() concatenation chains ({chr_chain_count})"));
    }

    let mut obf_score: u8 = 0;
    if chr_chain_count > 3 {
        obf_score = obf_score.saturating_add((chr_chain_count as u8).min(40) * 2);
    }
    if RE_EXECUTE.is_match(text) {
        obf_score = obf_score.saturating_add(15);
        patterns.push("Execute/ExecuteGlobal".into());
    }

    if patterns.is_empty() {
        return None;
    }

    Some(VbScriptAnalysis {
        has_shell_exec,
        has_wmi,
        has_download,
        chr_chain_count,
        obfuscation_score: obf_score.min(100),
        suspicious_patterns: patterns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_vbs() {
        let code = b"Dim x\nx = 42\nMsgBox x";
        assert!(detect_vbscript_analysis(code).is_none());
    }

    #[test]
    fn test_shell_creation() {
        let code = b"Set objShell = CreateObject(\"WScript.Shell\")";
        let r = detect_vbscript_analysis(code).unwrap();
        assert!(r.has_shell_exec);
    }

    #[test]
    fn test_chr_obfuscation() {
        let code = b"x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111) & Chr(32) & Chr(87) & Chr(111) & Chr(114) & Chr(108) & Chr(100)";
        let r = detect_vbscript_analysis(code).unwrap();
        assert!(r.chr_chain_count > 0);
    }

    #[test]
    fn test_download() {
        let code = b"Set http = CreateObject(\"MSXML2.XMLHTTP\")";
        let r = detect_vbscript_analysis(code).unwrap();
        assert!(r.has_download);
    }
}
