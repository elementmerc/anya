// OLE Compound Document analysis (Office 97-2003: .doc, .xls, .ppt)
// Detection patterns loaded from private scoring crate.

use crate::output::OleAnalysis;
use anya_scoring::detection_patterns::{
    OLE_AUTO_EXECUTE_NAMES, OLE_MACRO_STREAM_NAMES, OLE_SUSPICIOUS_KEYWORDS,
};

/// OLE magic bytes: D0 CF 11 E0 A1 B1 1A E1
const OLE_MAGIC: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

/// Analyse file bytes as OLE Compound Document. Returns None if not OLE
/// or no suspicious content.
pub fn detect_ole_analysis(data: &[u8]) -> Option<OleAnalysis> {
    if data.len() < 512 || !data.starts_with(OLE_MAGIC) {
        return None;
    }

    let mut macro_streams: Vec<String> = Vec::new();
    let mut has_embedded_objects = false;

    // Scan for macro-related stream names from private pattern list
    for name in OLE_MACRO_STREAM_NAMES.iter() {
        if find_bytes(data, name).is_some() {
            let name_str = String::from_utf8_lossy(name).to_string();
            if !macro_streams.contains(&name_str) {
                macro_streams.push(name_str);
            }
        }
    }

    // Check for embedded OLE objects
    if find_bytes(data, b"\x01Ole").is_some()
        || find_bytes(data, b"Package").is_some()
        || find_bytes(data, b"ObjInfo").is_some()
    {
        has_embedded_objects = true;
    }

    // Also check for embedded MZ header (PE inside OLE)
    if find_bytes(data, b"MZ").is_some() {
        // Verify it looks like a real PE header (not just the letters "MZ")
        for i in 0..data.len().saturating_sub(64) {
            if data[i] == b'M' && data[i + 1] == b'Z' {
                // Check for PE signature pointer at offset 0x3C
                if i + 0x3C + 4 <= data.len() {
                    let pe_offset = u32::from_le_bytes([
                        data[i + 0x3C],
                        data[i + 0x3D],
                        data[i + 0x3E],
                        data[i + 0x3F],
                    ]) as usize;
                    if pe_offset < 0x1000
                        && i + pe_offset + 4 <= data.len()
                        && &data[i + pe_offset..i + pe_offset + 4] == b"PE\0\0"
                    {
                        has_embedded_objects = true;
                        break;
                    }
                }
            }
        }
    }

    let has_macros = !macro_streams.is_empty();

    // Scan for auto-execute keywords from private pattern list
    let text_view = String::from_utf8_lossy(data);
    let has_auto_execute = OLE_AUTO_EXECUTE_NAMES
        .iter()
        .any(|name| text_view.contains(name.as_str()));

    // Scan for suspicious keywords from private pattern list
    let mut suspicious: Vec<String> = Vec::new();
    for kw in OLE_SUSPICIOUS_KEYWORDS.iter() {
        if text_view.contains(kw.as_str()) {
            suspicious.push(kw.clone());
        }
    }

    if !has_macros && !has_embedded_objects && !has_auto_execute && suspicious.is_empty() {
        return None;
    }

    Some(OleAnalysis {
        has_macros,
        has_auto_execute,
        macro_stream_names: macro_streams,
        has_embedded_objects,
        suspicious_keywords: suspicious,
    })
}

/// Find first occurrence of needle in haystack
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_ole_returns_none() {
        assert!(detect_ole_analysis(b"Not an OLE file").is_none());
    }

    #[test]
    fn test_ole_magic_but_small() {
        assert!(detect_ole_analysis(OLE_MAGIC).is_none());
    }

    #[test]
    fn test_ole_with_macro_streams() {
        let mut data = vec![0u8; 1024];
        data[..8].copy_from_slice(OLE_MAGIC);
        // Inject a VBA stream name marker
        data[512..515].copy_from_slice(b"VBA");
        let r = detect_ole_analysis(&data).unwrap();
        assert!(r.has_macros);
    }
}
