// ISO 9660 disk image analysis
// Detects executables, AutoRun.inf, and suspicious file entries

use crate::output::IsoAnalysis;
use anya_scoring::detection_patterns::EXECUTABLE_EXTENSIONS;

/// ISO 9660 Primary Volume Descriptor signature at offset 32769 (0x8001)
const ISO_SIGNATURE: &[u8] = b"CD001";
/// Alternative: check at sector 16 (0x8000)
const PVD_OFFSET: usize = 0x8000;

/// Analyse file bytes as ISO 9660 disk image. Returns None if not a valid
/// ISO or no suspicious content found.
pub fn detect_iso_analysis(data: &[u8]) -> Option<IsoAnalysis> {
    // Check for ISO 9660 signature at sector 16
    if data.len() < PVD_OFFSET + 6 {
        return None;
    }

    // Standard ID "CD001" at PVD_OFFSET + 1
    if &data[PVD_OFFSET + 1..PVD_OFFSET + 6] != ISO_SIGNATURE {
        return None;
    }

    // Extract volume label from PVD (offset 40 from PVD start, 32 bytes)
    let vol_label_start = PVD_OFFSET + 40;
    let volume_label = if vol_label_start + 32 <= data.len() {
        let raw = &data[vol_label_start..vol_label_start + 32];
        let label = String::from_utf8_lossy(raw).trim().to_string();
        if label.is_empty() { None } else { Some(label) }
    } else {
        None
    };

    // Extract file names from directory records
    // Scan the data for directory entry patterns
    let file_names = extract_iso_filenames(data);
    let file_count = file_names.len();

    let mut has_executables = false;
    let mut executable_names: Vec<String> = Vec::new();
    let mut has_autorun = false;
    let mut suspicious: Vec<String> = Vec::new();

    for name in &file_names {
        let lower = name.to_lowercase();

        // Check for autorun.inf
        if lower == "autorun.inf"
            || lower.ends_with("\\autorun.inf")
            || lower.ends_with("/autorun.inf")
        {
            has_autorun = true;
            suspicious.push("AutoRun.inf present".into());
        }

        // Check for executables using private extension list
        for ext in EXECUTABLE_EXTENSIONS.iter() {
            let dotted = format!(".{ext}");
            if lower.ends_with(&dotted) {
                has_executables = true;
                if executable_names.len() < 20 {
                    executable_names.push(name.clone());
                }
                break;
            }
        }
    }

    if !has_executables && !has_autorun && suspicious.is_empty() {
        return None;
    }

    Some(IsoAnalysis {
        volume_label,
        file_count,
        has_executables,
        executable_names,
        has_autorun,
        suspicious_entries: suspicious,
    })
}

/// Extract file names from ISO 9660 directory records
/// This is a simplified parser that looks for directory entry patterns
fn extract_iso_filenames(data: &[u8]) -> Vec<String> {
    let mut names = Vec::new();

    // ISO 9660 directory entries contain file identifiers
    // Scan for printable filename-like strings in the directory area
    // (sectors 17+ typically contain path table and directory records)
    let scan_start = 0x8800.min(data.len()); // Start after PVD
    let scan_end = data.len().min(scan_start + 1024 * 1024); // Scan up to 1MB

    if scan_start >= data.len() {
        return names;
    }

    let mut current = Vec::new();
    for &byte in &data[scan_start..scan_end] {
        if byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' || byte == b'-' {
            current.push(byte);
        } else {
            if current.len() >= 5 {
                let s = String::from_utf8_lossy(&current).to_string();
                // Must look like a filename (contains a dot, not too long)
                if s.contains('.') && s.len() <= 255 && !names.contains(&s) {
                    names.push(s);
                }
            }
            current.clear();
        }
    }

    // Also check for ;1 version suffix (ISO 9660 convention)
    // and remove it for cleaner names
    names.iter_mut().for_each(|n| {
        if n.ends_with(";1") {
            n.truncate(n.len() - 2);
        }
    });

    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_iso() {
        assert!(detect_iso_analysis(b"Not an ISO").is_none());
    }

    #[test]
    fn test_iso_with_signature() {
        let mut data = vec![0u8; 0x9000];
        // Place CD001 signature
        data[PVD_OFFSET + 1..PVD_OFFSET + 6].copy_from_slice(ISO_SIGNATURE);
        // No files found — should return None
        assert!(detect_iso_analysis(&data).is_none());
    }

    #[test]
    fn test_iso_with_executable() {
        let mut data = vec![0u8; 0x9000];
        data[PVD_OFFSET + 1..PVD_OFFSET + 6].copy_from_slice(ISO_SIGNATURE);
        // Inject a filename in the directory area
        let name = b"PAYLOAD.EXE";
        data[0x8800..0x8800 + name.len()].copy_from_slice(name);
        let r = detect_iso_analysis(&data).unwrap();
        assert!(r.has_executables);
    }

    #[test]
    fn test_iso_with_autorun() {
        let mut data = vec![0u8; 0x9000];
        data[PVD_OFFSET + 1..PVD_OFFSET + 6].copy_from_slice(ISO_SIGNATURE);
        let name = b"AUTORUN.INF";
        data[0x8800..0x8800 + name.len()].copy_from_slice(name);
        let r = detect_iso_analysis(&data).unwrap();
        assert!(r.has_autorun);
    }
}
