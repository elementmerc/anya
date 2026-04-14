// Microsoft OneNote document analysis
// Detects embedded file data objects, especially executable attachments

use crate::output::OneNoteAnalysis;
use anya_scoring::detection_patterns::EXECUTABLE_EXTENSIONS;

/// OneNote file format GUID (16 bytes at offset 0)
const ONENOTE_MAGIC: [u8; 16] = [
    0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3,
];

/// Embedded file data object GUID
const FILE_DATA_GUID: [u8; 16] = [
    0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x4A, 0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC,
];

/// Analyse file bytes as a OneNote document. Returns None if not a valid
/// OneNote file or no embedded attachments found.
pub fn detect_onenote_analysis(data: &[u8]) -> Option<OneNoteAnalysis> {
    if data.len() < 16 {
        return None;
    }

    if data[0..16] != ONENOTE_MAGIC {
        return None;
    }

    // Scan for embedded file data object GUIDs
    let mut embedded_count = 0usize;
    let mut has_executable_attachments = false;
    let mut attachment_names: Vec<String> = Vec::new();

    let scan_limit = data.len();
    let mut i = 16; // Skip the header GUID

    while i + 16 <= scan_limit {
        if data[i..i + 16] == FILE_DATA_GUID {
            embedded_count += 1;

            // After the GUID, try to extract filename information.
            // The embedded file data structure has variable layout, but
            // filenames often appear as UTF-16LE strings near the GUID.
            // Scan ahead for a filename pattern.
            let search_end = (i + 1024).min(scan_limit);
            if let Some(name) = extract_filename_near(&data[i..search_end]) {
                let lower = name.to_lowercase();

                for ext in EXECUTABLE_EXTENSIONS.iter() {
                    let dotted = format!(".{ext}");
                    if lower.ends_with(&dotted) {
                        has_executable_attachments = true;
                        break;
                    }
                }

                if attachment_names.len() < 20 && !attachment_names.contains(&name) {
                    attachment_names.push(name);
                }
            }

            i += 16; // Move past the GUID
        } else {
            i += 1;
        }
    }

    if embedded_count == 0 {
        return None;
    }

    Some(OneNoteAnalysis {
        embedded_count,
        has_executable_attachments,
        attachment_names,
    })
}

/// Try to extract a filename from bytes near an embedded file data GUID.
/// Looks for UTF-16LE encoded strings that end with a file extension.
fn extract_filename_near(data: &[u8]) -> Option<String> {
    // Look for sequences of UTF-16LE characters that form a filename
    // (printable ASCII chars with null bytes between them, containing a dot)
    let mut best_name: Option<String> = None;
    let mut i = 0;

    while i + 2 <= data.len() {
        // Check for start of a UTF-16LE string (printable char + 0x00)
        if data[i].is_ascii_graphic() && i + 1 < data.len() && data[i + 1] == 0 {
            let mut chars = Vec::new();
            let mut j = i;
            while j + 1 < data.len() && data[j].is_ascii_graphic() && data[j + 1] == 0 {
                chars.push(data[j] as char);
                j += 2;
            }

            if chars.len() >= 5 {
                let s: String = chars.iter().collect();
                // Must look like a filename (contains a dot, reasonable length)
                if s.contains('.') && s.len() <= 260 {
                    let ext_pos = s.rfind('.');
                    if let Some(pos) = ext_pos {
                        let ext = &s[pos + 1..];
                        if !ext.is_empty()
                            && ext.len() <= 10
                            && ext.chars().all(|c| c.is_ascii_alphanumeric())
                        {
                            best_name = Some(s);
                            break;
                        }
                    }
                }
            }

            i = j;
        } else {
            i += 1;
        }
    }

    best_name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_onenote() {
        assert!(detect_onenote_analysis(b"Not a OneNote file").is_none());
    }

    #[test]
    fn test_onenote_header_only() {
        let mut data = vec![0u8; 1024];
        data[0..16].copy_from_slice(&ONENOTE_MAGIC);
        // No embedded objects
        assert!(detect_onenote_analysis(&data).is_none());
    }

    #[test]
    fn test_onenote_with_embedded_object() {
        let mut data = vec![0u8; 2048];
        data[0..16].copy_from_slice(&ONENOTE_MAGIC);
        // Place an embedded file data GUID at offset 100
        data[100..116].copy_from_slice(&FILE_DATA_GUID);
        let r = detect_onenote_analysis(&data).unwrap();
        assert_eq!(r.embedded_count, 1);
    }

    #[test]
    fn test_onenote_with_executable_attachment() {
        let mut data = vec![0u8; 2048];
        data[0..16].copy_from_slice(&ONENOTE_MAGIC);
        // Place an embedded file data GUID at offset 100
        data[100..116].copy_from_slice(&FILE_DATA_GUID);
        // Place a UTF-16LE filename "payload.exe" after the GUID
        let name = "payload.exe";
        let mut offset = 120;
        for ch in name.bytes() {
            data[offset] = ch;
            data[offset + 1] = 0;
            offset += 2;
        }
        let r = detect_onenote_analysis(&data).unwrap();
        assert!(r.has_executable_attachments);
        assert!(r.attachment_names.contains(&"payload.exe".to_string()));
    }

    #[test]
    fn test_extract_filename_utf16() {
        let mut buf = vec![0u8; 256];
        // Write "test.txt" as UTF-16LE at offset 10
        let name = "test.txt";
        let mut offset = 10;
        for ch in name.bytes() {
            buf[offset] = ch;
            buf[offset + 1] = 0;
            offset += 2;
        }
        let result = extract_filename_near(&buf);
        assert_eq!(result, Some("test.txt".to_string()));
    }
}
