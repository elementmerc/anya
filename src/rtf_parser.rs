// RTF document static analysis
// Detects embedded objects, PE payloads, and exploit patterns

use crate::output::RtfAnalysis;

/// RTF magic bytes
const RTF_MAGIC: &[u8] = b"{\\rtf";

/// Suspicious RTF control words that indicate embedded objects
const OBJECT_KEYWORDS: &[&[u8]] = &[
    b"\\objocx",
    b"\\objemb",
    b"\\objlink",
    b"\\objhtml",
    b"\\objdata",
    b"\\objupdate",
    b"\\object",
];

/// Control words associated with known CVE exploits
const EXPLOIT_KEYWORDS: &[&[u8]] = &[
    b"\\objupdate", // Used in CVE-2017-0199
    b"\\equation",  // Equation Editor exploits (CVE-2017-11882)
    b"\\ddeauto",   // DDE auto-execute
    b"\\dde",       // DDE field
];

/// Analyse file bytes as RTF document. Returns None if not RTF or no
/// suspicious content.
pub fn detect_rtf_analysis(data: &[u8]) -> Option<RtfAnalysis> {
    if data.len() < 6 || !data.starts_with(RTF_MAGIC) {
        return None;
    }

    let mut has_embedded_objects = false;
    let mut has_objdata = false;
    let mut contains_pe_bytes = false;
    let mut suspicious_words: Vec<String> = Vec::new();

    // Check for object embedding keywords
    for kw in OBJECT_KEYWORDS {
        if find_bytes(data, kw).is_some() {
            has_embedded_objects = true;
            let name = String::from_utf8_lossy(kw)
                .trim_start_matches('\\')
                .to_string();
            if !suspicious_words.contains(&name) {
                suspicious_words.push(name);
            }
        }
    }

    // Check for exploit-associated keywords
    for kw in EXPLOIT_KEYWORDS {
        if find_bytes(data, kw).is_some() {
            let name = String::from_utf8_lossy(kw)
                .trim_start_matches('\\')
                .to_string();
            if !suspicious_words.contains(&name) {
                suspicious_words.push(name);
            }
        }
    }

    // Check for \objdata containing hex-encoded PE header
    if let Some(pos) = find_bytes(data, b"\\objdata") {
        has_objdata = true;
        // Look for hex-encoded MZ header (4d5a or 4D5A) after \objdata
        let search_area = &data[pos..data.len().min(pos + 8192)];
        if find_bytes(search_area, b"4d5a").is_some() || find_bytes(search_area, b"4D5A").is_some()
        {
            contains_pe_bytes = true;
            suspicious_words.push("PE header in objdata".into());
        }
    }

    // Check for very large hex streams (common in RTF exploits)
    // Look for long runs of hex characters after object control words
    if has_embedded_objects {
        let text = String::from_utf8_lossy(data);
        // Count consecutive hex chars after any object keyword
        let hex_chars: usize = text.chars().filter(|c| c.is_ascii_hexdigit()).count();
        let ratio = hex_chars as f64 / data.len() as f64;
        if ratio > 0.5 {
            suspicious_words.push(format!("High hex density ({:.0}%)", ratio * 100.0));
        }
    }

    if !has_embedded_objects && !has_objdata && suspicious_words.is_empty() {
        return None;
    }

    Some(RtfAnalysis {
        has_embedded_objects,
        has_objdata,
        contains_pe_bytes,
        suspicious_control_words: suspicious_words,
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_rtf() {
        assert!(detect_rtf_analysis(b"Not RTF").is_none());
    }

    #[test]
    fn test_clean_rtf() {
        let data = b"{\\rtf1\\ansi Hello World}";
        assert!(detect_rtf_analysis(data).is_none());
    }

    #[test]
    fn test_rtf_with_objdata() {
        let mut data = b"{\\rtf1\\ansi \\objdata ".to_vec();
        data.extend_from_slice(b"4d5a900003"); // hex-encoded MZ header
        data.push(b'}');
        let r = detect_rtf_analysis(&data).unwrap();
        assert!(r.has_objdata);
        assert!(r.contains_pe_bytes);
    }

    #[test]
    fn test_rtf_with_objemb() {
        let data = b"{\\rtf1\\ansi \\objemb some data}";
        let r = detect_rtf_analysis(data).unwrap();
        assert!(r.has_embedded_objects);
    }
}
