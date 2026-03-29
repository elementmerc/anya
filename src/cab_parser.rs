// Microsoft CAB (Cabinet) archive analysis
// Detects executables and extracts file listing from CFHEADER/CFFILE structures

use crate::output::CabAnalysis;
use anya_scoring::detection_patterns::EXECUTABLE_EXTENSIONS;

/// CAB magic bytes: "MSCF" (Microsoft Cabinet File)
const CAB_MAGIC: [u8; 4] = [b'M', b'S', b'C', b'F'];

/// Analyse file bytes as Microsoft CAB archive. Returns None if not a valid
/// CAB or no suspicious content found.
pub fn detect_cab_analysis(data: &[u8]) -> Option<CabAnalysis> {
    // CFHEADER is at least 36 bytes
    if data.len() < 36 || data[0..4] != CAB_MAGIC {
        return None;
    }

    // Parse CFHEADER
    // Offset 8-11: cabinet size (u32 LE)
    let _cab_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    // Offset 16-19: offset to first CFFILE (u32 LE)
    let cffile_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
    // Offset 26-27: number of CFFILE entries (u16 LE)
    let file_count = u16::from_le_bytes([data[26], data[27]]) as usize;

    if cffile_offset >= data.len() || file_count == 0 {
        // Valid CAB header but can't parse files
        return None;
    }

    let mut has_executables = false;
    let mut executable_names: Vec<String> = Vec::new();
    let mut total_uncompressed_size: u64 = 0;

    // Parse CFFILE entries
    let mut offset = cffile_offset;
    let mut parsed = 0;
    while offset < data.len() && parsed < file_count {
        // CFFILE structure: 16 bytes fixed header + null-terminated filename
        if offset + 16 > data.len() {
            break;
        }

        // Uncompressed size (u32 LE at offset 0)
        let uncomp_size = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        total_uncompressed_size += uncomp_size as u64;

        // Filename starts at offset 16 (null-terminated)
        let name_start = offset + 16;
        let mut name_end = name_start;
        while name_end < data.len() && data[name_end] != 0 {
            name_end += 1;
        }

        if name_start < name_end {
            let name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
            let lower = name.to_lowercase();

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

        // Move to next CFFILE entry (16 bytes header + filename + null)
        offset = name_end + 1;
        parsed += 1;
    }

    if !has_executables {
        return None;
    }

    Some(CabAnalysis {
        file_count,
        has_executables,
        executable_names,
        total_uncompressed_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_cab() {
        assert!(detect_cab_analysis(b"Not a CAB file").is_none());
    }

    #[test]
    fn test_cab_header_only() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(&CAB_MAGIC);
        // No valid CFFILE entries
        assert!(detect_cab_analysis(&data).is_none());
    }

    #[test]
    fn test_cab_with_executable() {
        let mut data = vec![0u8; 200];
        data[0..4].copy_from_slice(&CAB_MAGIC);
        // cab_size
        data[8..12].copy_from_slice(&200u32.to_le_bytes());
        // cffile_offset
        data[16..20].copy_from_slice(&36u32.to_le_bytes());
        // file count = 1
        data[26..28].copy_from_slice(&1u16.to_le_bytes());
        // CFFILE at offset 36: uncompressed size
        data[36..40].copy_from_slice(&1024u32.to_le_bytes());
        // Filename at offset 52 (36 + 16)
        let name = b"payload.exe\0";
        data[52..52 + name.len()].copy_from_slice(name);

        let r = detect_cab_analysis(&data).unwrap();
        assert!(r.has_executables);
        assert_eq!(r.file_count, 1);
    }
}
