// RAR archive analysis
// Parses RAR4 and RAR5 file headers to extract filenames and detect executables.
// No decompression is performed.

use crate::output::RarAnalysis;
use anya_scoring::detection_patterns::EXECUTABLE_EXTENSIONS;

/// RAR4 magic: "Rar!\x1a\x07\x00"
const RAR4_MAGIC: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
/// RAR5 magic: "Rar!\x1a\x07\x01\x00"
const RAR5_MAGIC: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];

/// Analyse file bytes as a RAR archive. Returns None if not a valid RAR.
pub fn detect_rar_analysis(data: &[u8]) -> Option<RarAnalysis> {
    let is_rar5 = data.len() >= 8 && data[0..8] == RAR5_MAGIC;
    let is_rar4 = !is_rar5 && data.len() >= 7 && data[0..7] == RAR4_MAGIC;

    if !is_rar4 && !is_rar5 {
        return None;
    }

    let mut file_count = 0usize;
    let mut has_executables = false;
    let mut has_encrypted_entries = false;
    let mut has_double_extensions = false;
    let mut executable_names: Vec<String> = Vec::new();

    if is_rar4 {
        parse_rar4(
            data,
            &mut file_count,
            &mut has_executables,
            &mut has_encrypted_entries,
            &mut has_double_extensions,
            &mut executable_names,
        );
    } else {
        parse_rar5(
            data,
            &mut file_count,
            &mut has_executables,
            &mut has_encrypted_entries,
            &mut has_double_extensions,
            &mut executable_names,
        );
    }

    Some(RarAnalysis {
        file_count,
        has_executables,
        has_encrypted_entries,
        has_double_extensions,
        executable_names,
    })
}

/// Parse RAR4 archive headers
fn parse_rar4(
    data: &[u8],
    file_count: &mut usize,
    has_executables: &mut bool,
    has_encrypted_entries: &mut bool,
    has_double_extensions: &mut bool,
    executable_names: &mut Vec<String>,
) {
    // RAR4: skip the 7 byte signature
    let mut offset = 7;

    // Iterate through header blocks
    let max_iterations = 10_000; // Safety limit
    let mut iterations = 0;

    while offset + 7 <= data.len() && iterations < max_iterations {
        iterations += 1;

        // RAR4 block header: 2 bytes CRC, 1 byte type, 2 bytes flags, 2 bytes size
        let header_type = data[offset + 2];
        let flags = u16::from_le_bytes([data[offset + 3], data[offset + 4]]);
        let header_size = u16::from_le_bytes([data[offset + 5], data[offset + 6]]) as usize;

        if header_size < 7 || offset + header_size > data.len() {
            break;
        }

        // Type 0x74 = file header
        if header_type == 0x74 && header_size >= 32 {
            *file_count += 1;

            // Check encrypted flag (bit 2 of flags)
            if flags & 0x04 != 0 {
                *has_encrypted_entries = true;
            }

            // Filename size at offset 26-27 from header start
            if offset + 28 <= data.len() {
                let name_size = u16::from_le_bytes([data[offset + 26], data[offset + 27]]) as usize;
                let name_start = offset + 32;
                let name_end = (name_start + name_size).min(data.len());

                if name_start < name_end {
                    let name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
                    check_filename(
                        &name,
                        has_executables,
                        has_double_extensions,
                        executable_names,
                    );
                }
            }

            // If ADD_SIZE flag (bit 15) is set, there are 4 extra bytes of packed data size
            if flags & 0x8000 != 0 && offset + 11 <= data.len() {
                let packed_size = u32::from_le_bytes([
                    data[offset + 7],
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                ]) as usize;
                offset = offset + header_size + packed_size;
            } else {
                offset += header_size;
            }
        } else if header_type == 0x7B {
            // End of archive marker
            break;
        } else {
            // For other block types, check ADD_SIZE flag
            if flags & 0x8000 != 0 && offset + 11 <= data.len() {
                let add_size = u32::from_le_bytes([
                    data[offset + 7],
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                ]) as usize;
                offset = offset + header_size + add_size;
            } else {
                offset += header_size;
            }
        }
    }
}

/// Parse RAR5 archive headers
fn parse_rar5(
    data: &[u8],
    file_count: &mut usize,
    has_executables: &mut bool,
    has_encrypted_entries: &mut bool,
    has_double_extensions: &mut bool,
    executable_names: &mut Vec<String>,
) {
    // RAR5: skip the 8 byte signature
    let mut offset = 8;

    let max_iterations = 10_000;
    let mut iterations = 0;

    while offset < data.len() && iterations < max_iterations {
        iterations += 1;

        // RAR5 header: CRC32 (4 bytes), header size (vint), header type (vint)
        if offset + 4 >= data.len() {
            break;
        }

        // Skip CRC32
        let mut pos = offset + 4;

        // Read header size as vint
        let (header_size, bytes_read) = read_vint(data, pos);
        if bytes_read == 0 || header_size == 0 {
            break;
        }
        pos += bytes_read;
        let header_end = offset + 4 + bytes_read + header_size as usize;

        if header_end > data.len() {
            break;
        }

        // Read header type as vint
        let (header_type, type_bytes) = read_vint(data, pos);
        if type_bytes == 0 {
            break;
        }
        pos += type_bytes;

        // Read header flags as vint
        let (header_flags, flags_bytes) = read_vint(data, pos);
        if flags_bytes == 0 {
            break;
        }
        pos += flags_bytes;

        // Check if extra area size is present (bit 0 of flags)
        let mut _extra_area_size: u64 = 0;
        if header_flags & 0x01 != 0 {
            let (eas, eas_bytes) = read_vint(data, pos);
            if eas_bytes == 0 {
                break;
            }
            _extra_area_size = eas;
            pos += eas_bytes;
        }

        // Check if data area size is present (bit 1 of flags)
        let mut data_area_size: u64 = 0;
        if header_flags & 0x02 != 0 {
            let (das, das_bytes) = read_vint(data, pos);
            if das_bytes == 0 {
                break;
            }
            data_area_size = das;
            pos += das_bytes;
        }

        // Type 2 = file header
        if header_type == 2 {
            *file_count += 1;

            // File flags
            let (file_flags, ff_bytes) = read_vint(data, pos);
            if ff_bytes > 0 {
                pos += ff_bytes;

                // Bit 2: encrypted
                if file_flags & 0x04 != 0 {
                    *has_encrypted_entries = true;
                }

                // Skip unpacked size (vint)
                let (_, us_bytes) = read_vint(data, pos);
                if us_bytes > 0 {
                    pos += us_bytes;
                }

                // Skip attributes (vint)
                let (_, at_bytes) = read_vint(data, pos);
                if at_bytes > 0 {
                    pos += at_bytes;
                }

                // Skip mtime (4 bytes) if flag bit 1 set
                if file_flags & 0x02 != 0 && pos + 4 <= data.len() {
                    pos += 4;
                }

                // Skip data CRC32 if flag bit 0 set
                if file_flags & 0x01 != 0 && pos + 4 <= data.len() {
                    pos += 4;
                }

                // Compression info (vint)
                let (_, ci_bytes) = read_vint(data, pos);
                if ci_bytes > 0 {
                    pos += ci_bytes;
                }

                // Host OS (vint)
                let (_, os_bytes) = read_vint(data, pos);
                if os_bytes > 0 {
                    pos += os_bytes;
                }

                // Name length (vint) and name bytes
                let (name_len, nl_bytes) = read_vint(data, pos);
                if nl_bytes > 0 {
                    pos += nl_bytes;
                    let name_end = (pos + name_len as usize).min(data.len());
                    if pos < name_end {
                        let name = String::from_utf8_lossy(&data[pos..name_end]).to_string();
                        check_filename(
                            &name,
                            has_executables,
                            has_double_extensions,
                            executable_names,
                        );
                    }
                }
            }
        } else if header_type == 5 {
            // End of archive
            break;
        }

        // Move past the header and any data area
        offset = header_end + data_area_size as usize;
    }
}

/// Read a RAR5 variable-length integer
fn read_vint(data: &[u8], offset: usize) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut i = offset;
    let mut bytes_read = 0;

    while i < data.len() && bytes_read < 10 {
        let byte = data[i];
        result |= ((byte & 0x7F) as u64) << shift;
        bytes_read += 1;
        i += 1;

        if byte & 0x80 == 0 {
            return (result, bytes_read);
        }

        shift += 7;
    }

    (0, 0) // Failed to read
}

/// Check a filename for executable extensions and double extensions
fn check_filename(
    name: &str,
    has_executables: &mut bool,
    has_double_extensions: &mut bool,
    executable_names: &mut Vec<String>,
) {
    let lower = name.to_lowercase();
    // Extract just the filename component (handle paths with / or \)
    let filename = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);

    for ext in EXECUTABLE_EXTENSIONS.iter() {
        let dotted = format!(".{ext}");
        if filename.ends_with(&dotted) {
            *has_executables = true;
            if executable_names.len() < 20 {
                executable_names.push(name.to_string());
            }

            // Check for double extensions (e.g. "document.pdf.exe")
            let without_ext = &filename[..filename.len() - dotted.len()];
            if without_ext.contains('.') {
                *has_double_extensions = true;
            }
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_rar() {
        assert!(detect_rar_analysis(b"Not a RAR file").is_none());
    }

    #[test]
    fn test_rar4_magic() {
        let mut data = vec![0u8; 256];
        data[0..7].copy_from_slice(&RAR4_MAGIC);
        let r = detect_rar_analysis(&data).unwrap();
        assert_eq!(r.file_count, 0);
    }

    #[test]
    fn test_rar5_magic() {
        let mut data = vec![0u8; 256];
        data[0..8].copy_from_slice(&RAR5_MAGIC);
        let r = detect_rar_analysis(&data).unwrap();
        assert_eq!(r.file_count, 0);
    }

    #[test]
    fn test_read_vint() {
        // Single byte: 42
        assert_eq!(read_vint(&[42], 0), (42, 1));
        // Two bytes: 0x80 | 0x01, 0x02 = 1 + (2 << 7) = 257
        assert_eq!(read_vint(&[0x81, 0x02], 0), (257, 2));
    }

    #[test]
    fn test_check_filename_executable() {
        let mut has_exec = false;
        let mut has_double = false;
        let mut names = Vec::new();
        check_filename("test.exe", &mut has_exec, &mut has_double, &mut names);
        assert!(has_exec);
        assert!(!has_double);
    }

    #[test]
    fn test_check_filename_double_extension() {
        let mut has_exec = false;
        let mut has_double = false;
        let mut names = Vec::new();
        check_filename(
            "document.pdf.exe",
            &mut has_exec,
            &mut has_double,
            &mut names,
        );
        assert!(has_exec);
        assert!(has_double);
    }

    #[test]
    fn test_rar4_with_file_header() {
        let mut data = vec![0u8; 512];
        data[0..7].copy_from_slice(&RAR4_MAGIC);

        // Build a RAR4 archive header at offset 7
        // Type 0x73 (archive header), flags 0, size 13
        data[7 + 2] = 0x73; // header type
        data[7 + 5] = 13; // header size low byte

        // Build a file header at offset 20 (7 + 13)
        let file_hdr_start = 20;
        data[file_hdr_start + 2] = 0x74; // file header type
        // header size = 45 (32 fixed + 13 for filename)
        data[file_hdr_start + 5] = 45;
        data[file_hdr_start + 6] = 0;
        // name size at offset 26-27
        let name = b"malware.exe";
        data[file_hdr_start + 26] = name.len() as u8;
        data[file_hdr_start + 27] = 0;
        // Filename at offset 32
        data[file_hdr_start + 32..file_hdr_start + 32 + name.len()].copy_from_slice(name);

        let r = detect_rar_analysis(&data).unwrap();
        assert_eq!(r.file_count, 1);
        assert!(r.has_executables);
    }
}
