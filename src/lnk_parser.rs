// Windows LNK (shortcut) file static analysis
// Detection patterns loaded from private scoring crate.

use crate::output::LnkAnalysis;
use anya_scoring::detection_patterns::LNK_SUSPICIOUS_TARGETS;

/// LNK magic bytes (4 bytes header + CLSID)
const LNK_MAGIC: [u8; 4] = [0x4C, 0x00, 0x00, 0x00];
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// Analyse file bytes as Windows LNK shortcut. Returns None if not a valid
/// LNK or no suspicious content.
pub fn detect_lnk_analysis(data: &[u8]) -> Option<LnkAnalysis> {
    // Validate LNK header
    if data.len() < 76 {
        return None;
    }
    if data[0..4] != LNK_MAGIC || data[4..20] != LNK_CLSID {
        return None;
    }

    // Extract strings from the LNK file for analysis
    let strings = extract_lnk_strings(data);

    let mut target_path = String::new();
    let mut arguments: Option<String> = None;
    let mut icon_location: Option<String> = None;
    let mut has_suspicious_target = false;
    let mut has_encoded_args = false;
    let mut indicators: Vec<String> = Vec::new();

    // Try to find target path and arguments from extracted strings
    for s in &strings {
        let lower = s.to_lowercase();

        // Identify target path (typically the first string containing a path)
        if target_path.is_empty()
            && (lower.contains(".exe")
                || lower.contains(".cmd")
                || lower.contains(".bat")
                || lower.contains("\\system32\\")
                || lower.contains("\\windows\\"))
        {
            target_path = s.clone();
        }

        // Check for suspicious targets from private pattern list
        for target in LNK_SUSPICIOUS_TARGETS.iter() {
            if lower.contains(target.as_str()) {
                has_suspicious_target = true;
                if !indicators.iter().any(|i| i.contains(target)) {
                    indicators.push(format!("Target: {target}"));
                }
            }
        }

        // Check for encoded arguments
        if lower.contains("-enc ") || lower.contains("-encodedcommand ") {
            has_encoded_args = true;
            arguments = Some(s.clone());
            indicators.push("Encoded PowerShell command".into());
        }
        if lower.contains("-e ") && lower.contains("base64") {
            has_encoded_args = true;
            indicators.push("Base64-encoded argument".into());
        }

        // Check for download patterns
        if lower.contains("http://") || lower.contains("https://") {
            indicators.push("URL in shortcut".into());
        }
        if lower.contains("certutil") && lower.contains("-decode") {
            indicators.push("certutil decode in shortcut".into());
        }

        // Icon location extraction
        if (lower.contains(".ico") || lower.contains(".dll,") || lower.contains(".exe,"))
            && icon_location.is_none()
        {
            icon_location = Some(s.clone());
        }

        // Environment variable abuse
        if lower.contains("%appdata%")
            || lower.contains("%temp%")
            || lower.contains("%localappdata%")
            || lower.contains("%public%")
        {
            indicators.push("Environment variable in path".into());
        }
    }

    // If no target found from strings, use placeholder
    if target_path.is_empty() {
        target_path = "(unable to extract)".to_string();
    }

    if !has_suspicious_target && !has_encoded_args && indicators.is_empty() {
        return None;
    }

    // Deduplicate indicators
    indicators.sort();
    indicators.dedup();

    Some(LnkAnalysis {
        target_path,
        arguments,
        icon_location,
        has_suspicious_target,
        has_encoded_args,
        suspicious_indicators: indicators,
    })
}

/// Extract printable strings from LNK binary data
fn extract_lnk_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    // Extract ASCII strings (min length 6)
    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\\' || byte == b'/' {
            current.push(byte);
        } else {
            if current.len() >= 6 {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    if strings.len() < 50 {
                        strings.push(s);
                    }
                }
            }
            current.clear();
        }
    }
    if current.len() >= 6 {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(s);
        }
    }

    // Also extract UTF-16LE strings (common in LNK)
    let mut utf16_buf: Vec<u8> = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];
        if hi == 0 && (lo.is_ascii_graphic() || lo == b' ' || lo == b'\\' || lo == b'/') {
            utf16_buf.push(lo);
        } else {
            if utf16_buf.len() >= 6 {
                if let Ok(s) = String::from_utf8(utf16_buf.clone()) {
                    if strings.len() < 100 && !strings.contains(&s) {
                        strings.push(s);
                    }
                }
            }
            utf16_buf.clear();
        }
        i += 2;
    }
    if utf16_buf.len() >= 6 {
        if let Ok(s) = String::from_utf8(utf16_buf) {
            if !strings.contains(&s) {
                strings.push(s);
            }
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_lnk() {
        assert!(detect_lnk_analysis(b"Not a LNK file").is_none());
    }

    #[test]
    fn test_lnk_header_validation() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(&LNK_MAGIC);
        data[4..20].copy_from_slice(&LNK_CLSID);
        // No suspicious strings, should return None
        assert!(detect_lnk_analysis(&data).is_none());
    }

    #[test]
    fn test_lnk_with_suspicious_target() {
        let mut data = vec![0u8; 200];
        data[0..4].copy_from_slice(&LNK_MAGIC);
        data[4..20].copy_from_slice(&LNK_CLSID);
        // Embed a suspicious string
        let target = b"C:\\Windows\\system32\\cmd.exe";
        data[76..76 + target.len()].copy_from_slice(target);
        let r = detect_lnk_analysis(&data).unwrap();
        assert!(r.has_suspicious_target);
    }
}
