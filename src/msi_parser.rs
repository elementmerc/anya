// MSI installer analysis
// Detection patterns loaded from private scoring crate.

use crate::output::MsiAnalysis;
use anya_scoring::detection_patterns::MSI_SUSPICIOUS_PATTERNS;

/// OLE magic bytes
const OLE_MAGIC: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

/// MSI-specific stream names
const MSI_STREAMS: &[&[u8]] = &[
    b"CustomAction",
    b"Binary",
    b"InstallExecuteSequence",
    b"InstallUISequence",
    b"Property",
    b"_Tables",
    b"_StringData",
    b"_StringPool",
];

/// Analyse file bytes as MSI installer. Returns None if not a valid MSI
/// or no suspicious content found.
pub fn detect_msi_analysis(data: &[u8]) -> Option<MsiAnalysis> {
    // MSI files are OLE Compound Documents
    if data.len() < 512 || !data.starts_with(OLE_MAGIC) {
        return None;
    }

    // Verify this is an MSI (not just any OLE document) by checking for
    // MSI-specific stream names
    let is_msi = MSI_STREAMS
        .iter()
        .any(|stream| find_bytes(data, stream).is_some());
    if !is_msi {
        return None;
    }

    let mut has_custom_actions = false;
    let mut has_embedded_binaries = false;
    let mut custom_action_types: Vec<String> = Vec::new();
    let mut suspicious_properties: Vec<String> = Vec::new();

    // Check for CustomAction stream
    if find_bytes(data, b"CustomAction").is_some() {
        has_custom_actions = true;
    }

    // Check for Binary stream (embedded executables/DLLs)
    if find_bytes(data, b"Binary").is_some() {
        // Look for MZ headers in the data (embedded PE)
        let mut mz_count = 0;
        for i in 512..data.len().saturating_sub(2) {
            if data[i] == b'M' && data[i + 1] == b'Z' {
                // Verify it's a real PE header
                if i + 0x40 < data.len() {
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
                        mz_count += 1;
                        has_embedded_binaries = true;
                        if mz_count >= 3 {
                            break; // Don't scan forever
                        }
                    }
                }
            }
        }
        if has_embedded_binaries {
            custom_action_types.push(format!("Embedded PE binaries ({mz_count})"));
        }
    }

    // Scan for suspicious command patterns from private pattern list
    let text_view = String::from_utf8_lossy(data);
    for pattern in MSI_SUSPICIOUS_PATTERNS.iter() {
        if text_view.contains(pattern.as_str()) {
            suspicious_properties.push(format!("References {pattern}"));
        }
    }

    // Check for specific action types
    if text_view.contains("Type=\"51\"") || text_view.contains("msidbCustomActionType") {
        custom_action_types.push("Custom action with directory set".into());
    }
    if text_view.contains("Type=\"50\"") {
        custom_action_types.push("Custom action with EXE execution".into());
    }

    if !has_custom_actions && !has_embedded_binaries && suspicious_properties.is_empty() {
        return None;
    }

    Some(MsiAnalysis {
        has_custom_actions,
        has_embedded_binaries,
        custom_action_types,
        suspicious_properties,
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_msi() {
        assert!(detect_msi_analysis(b"Not an MSI file").is_none());
    }

    #[test]
    fn test_ole_but_not_msi() {
        let mut data = vec![0u8; 1024];
        data[..8].copy_from_slice(OLE_MAGIC);
        // No MSI-specific streams
        assert!(detect_msi_analysis(&data).is_none());
    }

    #[test]
    fn test_msi_with_custom_action() {
        let mut data = vec![0u8; 1024];
        data[..8].copy_from_slice(OLE_MAGIC);
        // Inject MSI stream names
        let pos = 512;
        data[pos..pos + 12].copy_from_slice(b"CustomAction");
        let pos2 = 600;
        data[pos2..pos2 + 7].copy_from_slice(b"_Tables");
        let r = detect_msi_analysis(&data).unwrap();
        assert!(r.has_custom_actions);
    }
}
