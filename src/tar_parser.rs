// TAR archive analysis
// Parses POSIX tar headers to extract file listings and detect executables/scripts

use crate::output::TarAnalysis;
use anya_scoring::detection_patterns::EXECUTABLE_EXTENSIONS;

/// POSIX tar magic at offset 257
const USTAR_MAGIC: &[u8] = b"ustar";

/// Script extensions to flag
const SCRIPT_EXTENSIONS: &[&str] = &["sh", "bash", "py", "pl", "rb", "lua", "ps1", "bat", "cmd"];

/// Analyse file bytes as a TAR archive. Returns None if not a valid TAR.
pub fn detect_tar_analysis(data: &[u8]) -> Option<TarAnalysis> {
    if data.len() < 512 {
        return None;
    }

    let is_ustar = data.len() >= 262 && &data[257..262] == USTAR_MAGIC;

    // If not ustar, try heuristic: check if the first 100 bytes (name field)
    // contain printable chars and the mode field (100-108) looks like octal
    let is_tar_heuristic = if !is_ustar {
        has_valid_tar_header(data)
    } else {
        false
    };

    if !is_ustar && !is_tar_heuristic {
        return None;
    }

    let mut file_count = 0usize;
    let mut has_executables = false;
    let mut has_scripts = false;
    let mut executable_names: Vec<String> = Vec::new();
    let mut has_setuid = false;

    let mut offset = 0;
    let max_iterations = 100_000; // Safety limit
    let mut iterations = 0;

    while offset + 512 <= data.len() && iterations < max_iterations {
        iterations += 1;

        // Check for two consecutive zero blocks (end of archive)
        if data[offset..offset + 512].iter().all(|&b| b == 0) {
            break;
        }

        // Parse tar header (512 bytes)
        // Name: 0-100 (null terminated)
        let name = read_tar_string(&data[offset..offset + 100]);

        if name.is_empty() {
            break;
        }

        // Mode: 100-108 (octal ASCII, null terminated)
        let mode_str = read_tar_string(&data[offset + 100..offset + 108]);
        let mode = parse_octal(&mode_str).unwrap_or(0);

        // Size: 124-136 (octal ASCII, null terminated)
        let size_str = read_tar_string(&data[offset + 124..offset + 136]);
        let entry_size = parse_octal(&size_str).unwrap_or(0) as usize;

        // Typeflag: byte 156
        let typeflag = data[offset + 156];

        // Count regular files (typeflag 0 or '0' or null)
        if typeflag == 0 || typeflag == b'0' || typeflag == b'5' || typeflag == b'2' {
            if typeflag != b'5' {
                // Not a directory
                file_count += 1;
            }

            let lower = name.to_lowercase();
            let filename = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);

            // Check for executable extensions
            for ext in EXECUTABLE_EXTENSIONS.iter() {
                let dotted = format!(".{ext}");
                if filename.ends_with(&dotted) {
                    has_executables = true;
                    if executable_names.len() < 20 {
                        executable_names.push(name.clone());
                    }
                    break;
                }
            }

            // Check for script extensions
            for &ext in SCRIPT_EXTENSIONS {
                let dotted = format!(".{ext}");
                if filename.ends_with(&dotted) {
                    has_scripts = true;
                    break;
                }
            }

            // Check for setuid/setgid bits (mode & 0o4000 or 0o2000)
            if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
                has_setuid = true;
            }

            // Also flag executable permission bits on regular files
            if !has_executables && (mode & 0o111 != 0) && (typeflag == 0 || typeflag == b'0') {
                // File is marked executable but we only flag known extensions above
            }
        }

        // Move to next entry: header (512) + data (rounded up to 512 boundary)
        let data_blocks = entry_size.div_ceil(512);
        offset += 512 + data_blocks * 512;
    }

    if file_count == 0 && !has_executables && !has_scripts {
        return None;
    }

    Some(TarAnalysis {
        file_count,
        has_executables,
        has_scripts,
        executable_names,
        has_setuid,
    })
}

/// Read a null terminated string from a tar header field
fn read_tar_string(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).trim().to_string()
}

/// Parse an octal ASCII string to u64
fn parse_octal(s: &str) -> Option<u64> {
    let trimmed = s.trim().trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(trimmed, 8).ok()
}

/// Check if data looks like a valid tar header using heuristics
fn has_valid_tar_header(data: &[u8]) -> bool {
    if data.len() < 512 {
        return false;
    }

    // Name field (0-100): should contain printable chars (or nulls after the name)
    let name_end = data[0..100].iter().position(|&b| b == 0).unwrap_or(100);
    if name_end == 0 {
        return false;
    }
    let name_valid = data[0..name_end].iter().all(|&b| (0x20..0x7F).contains(&b));
    if !name_valid {
        return false;
    }

    // Mode field (100-108): should look like an octal string
    let mode_end = data[100..108]
        .iter()
        .position(|&b| b == 0 || b == b' ')
        .unwrap_or(8);
    if mode_end == 0 {
        return false;
    }

    data[100..100 + mode_end]
        .iter()
        .all(|&b| (b'0'..=b'7').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_tar() {
        assert!(detect_tar_analysis(b"Not a tar file").is_none());
    }

    #[test]
    fn test_ustar_magic() {
        let mut data = vec![0u8; 1024];
        // Name field
        let name = b"readme.txt";
        data[0..name.len()].copy_from_slice(name);
        // Mode
        data[100..107].copy_from_slice(b"0000644");
        // Size (10 bytes as octal)
        data[124..135].copy_from_slice(b"00000000012");
        // Typeflag: regular file
        data[156] = b'0';
        // ustar magic
        data[257..262].copy_from_slice(USTAR_MAGIC);

        let r = detect_tar_analysis(&data).unwrap();
        assert_eq!(r.file_count, 1);
        assert!(!r.has_executables);
    }

    #[test]
    fn test_tar_with_executable() {
        let mut data = vec![0u8; 1024];
        let name = b"payload.exe";
        data[0..name.len()].copy_from_slice(name);
        data[100..107].copy_from_slice(b"0000755");
        data[124..135].copy_from_slice(b"00000000012");
        data[156] = b'0';
        data[257..262].copy_from_slice(USTAR_MAGIC);

        let r = detect_tar_analysis(&data).unwrap();
        assert!(r.has_executables);
        assert!(r.executable_names.contains(&"payload.exe".to_string()));
    }

    #[test]
    fn test_tar_with_script() {
        let mut data = vec![0u8; 1024];
        let name = b"deploy.sh";
        data[0..name.len()].copy_from_slice(name);
        data[100..107].copy_from_slice(b"0000755");
        data[124..135].copy_from_slice(b"00000000012");
        data[156] = b'0';
        data[257..262].copy_from_slice(USTAR_MAGIC);

        let r = detect_tar_analysis(&data).unwrap();
        assert!(r.has_scripts);
    }

    #[test]
    fn test_tar_with_setuid() {
        let mut data = vec![0u8; 1024];
        let name = b"suid_binary";
        data[0..name.len()].copy_from_slice(name);
        // Mode 4755 (setuid)
        data[100..107].copy_from_slice(b"0004755");
        data[124..135].copy_from_slice(b"00000000012");
        data[156] = b'0';
        data[257..262].copy_from_slice(USTAR_MAGIC);

        let r = detect_tar_analysis(&data).unwrap();
        assert!(r.has_setuid);
    }

    #[test]
    fn test_parse_octal() {
        assert_eq!(parse_octal("0000644"), Some(0o644));
        assert_eq!(parse_octal("0"), Some(0));
        assert_eq!(parse_octal(""), Some(0));
        assert_eq!(parse_octal("0004755"), Some(0o4755));
    }

    #[test]
    fn test_read_tar_string() {
        let mut field = [0u8; 100];
        field[0..5].copy_from_slice(b"hello");
        assert_eq!(read_tar_string(&field), "hello");
    }

    #[test]
    fn test_heuristic_tar_detection() {
        let mut data = vec![0u8; 512];
        let name = b"test.txt";
        data[0..name.len()].copy_from_slice(name);
        data[100..107].copy_from_slice(b"0000644");
        // No ustar magic, but valid heuristic
        assert!(has_valid_tar_header(&data));
    }
}
