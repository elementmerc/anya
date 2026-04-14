// GZIP compressed file analysis
// Parses GZIP headers to extract original filename and detect executable content.
// No external decompression library is used; inner content is not decompressed.

use crate::output::GzipAnalysis;
use anya_scoring::detection_patterns::EXECUTABLE_EXTENSIONS;

/// GZIP magic bytes
const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];

/// GZIP compression method: deflate
const CM_DEFLATE: u8 = 0x08;

/// GZIP header flags
const FTEXT: u8 = 0x01;
const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;

/// Analyse file bytes as a GZIP compressed file. Returns None if not valid GZIP.
pub fn detect_gzip_analysis(data: &[u8]) -> Option<GzipAnalysis> {
    // Minimum GZIP header is 10 bytes
    if data.len() < 10 {
        return None;
    }

    if data[0..2] != GZIP_MAGIC {
        return None;
    }

    let _compression_method = data[2];
    let flags = data[3];
    // Bytes 4-7: modification time (u32 LE)
    // Byte 8: extra flags
    // Byte 9: OS

    let mut offset = 10;

    // FEXTRA: skip extra field
    if flags & FEXTRA != 0 {
        if offset + 2 > data.len() {
            return Some(minimal_result(data.len() as u64));
        }
        let xlen = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + xlen;
    }

    // FNAME: read original filename (null terminated)
    let original_filename = if flags & FNAME != 0 {
        if offset >= data.len() {
            None
        } else {
            let name_start = offset;
            while offset < data.len() && data[offset] != 0 {
                offset += 1;
            }
            let name = String::from_utf8_lossy(&data[name_start..offset]).to_string();
            if offset < data.len() {
                offset += 1; // Skip null terminator
            }
            if name.is_empty() { None } else { Some(name) }
        }
    } else {
        None
    };

    // FCOMMENT: skip comment (null terminated)
    if flags & FCOMMENT != 0 {
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }
        if offset < data.len() {
            offset += 1;
        }
    }

    // FHCRC: skip 2 byte CRC16
    if flags & FHCRC != 0 {
        offset += 2;
    }

    // Mark offset and constants as intentionally consumed
    let _ = offset;
    let _ = FTEXT;
    let _ = CM_DEFLATE;

    // Check if original filename has an executable extension
    let mut has_executable_content = false;
    if let Some(ref name) = original_filename {
        let lower = name.to_lowercase();
        for ext in EXECUTABLE_EXTENSIONS.iter() {
            let dotted = format!(".{ext}");
            if lower.ends_with(&dotted) {
                has_executable_content = true;
                break;
            }
        }
    }

    // Try to detect inner format by checking if the original filename
    // suggests a known archive format
    let inner_format = detect_inner_format(&original_filename);

    Some(GzipAnalysis {
        original_filename,
        compressed_size: data.len() as u64,
        has_executable_content,
        inner_format,
    })
}

/// Detect inner format from the original filename extension
fn detect_inner_format(filename: &Option<String>) -> Option<String> {
    let name = filename.as_ref()?;
    let lower = name.to_lowercase();

    if lower.ends_with(".tar") {
        Some("TAR Archive".to_string())
    } else if lower.ends_with(".exe") || lower.ends_with(".dll") {
        Some("PE Executable".to_string())
    } else if lower.ends_with(".elf") {
        Some("ELF Binary".to_string())
    } else if lower.ends_with(".zip") {
        Some("ZIP Archive".to_string())
    } else if lower.ends_with(".iso") {
        Some("ISO 9660".to_string())
    } else {
        None
    }
}

fn minimal_result(size: u64) -> GzipAnalysis {
    GzipAnalysis {
        original_filename: None,
        compressed_size: size,
        has_executable_content: false,
        inner_format: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_gzip() {
        assert!(detect_gzip_analysis(b"Not a gzip file").is_none());
    }

    #[test]
    fn test_minimal_gzip() {
        let mut data = vec![0u8; 20];
        data[0] = 0x1F;
        data[1] = 0x8B;
        data[2] = 0x08; // deflate
        data[3] = 0x00; // no flags
        let r = detect_gzip_analysis(&data).unwrap();
        assert!(r.original_filename.is_none());
        assert!(!r.has_executable_content);
    }

    #[test]
    fn test_gzip_with_filename() {
        let mut data = vec![0u8; 64];
        data[0] = 0x1F;
        data[1] = 0x8B;
        data[2] = 0x08;
        data[3] = FNAME; // FNAME flag set
        // Original filename at offset 10
        let name = b"archive.tar\0";
        data[10..10 + name.len()].copy_from_slice(name);
        let r = detect_gzip_analysis(&data).unwrap();
        assert_eq!(r.original_filename, Some("archive.tar".to_string()));
        assert_eq!(r.inner_format, Some("TAR Archive".to_string()));
        assert!(!r.has_executable_content);
    }

    #[test]
    fn test_gzip_with_executable_filename() {
        let mut data = vec![0u8; 64];
        data[0] = 0x1F;
        data[1] = 0x8B;
        data[2] = 0x08;
        data[3] = FNAME;
        let name = b"payload.exe\0";
        data[10..10 + name.len()].copy_from_slice(name);
        let r = detect_gzip_analysis(&data).unwrap();
        assert!(r.has_executable_content);
        assert_eq!(r.inner_format, Some("PE Executable".to_string()));
    }

    #[test]
    fn test_gzip_with_extra_field() {
        let mut data = vec![0u8; 64];
        data[0] = 0x1F;
        data[1] = 0x8B;
        data[2] = 0x08;
        data[3] = FEXTRA | FNAME;
        // Extra field: length 2
        data[10] = 2;
        data[11] = 0;
        // Extra data (2 bytes)
        data[12] = 0xAA;
        data[13] = 0xBB;
        // FNAME starts at offset 14
        let name = b"test.tar\0";
        data[14..14 + name.len()].copy_from_slice(name);
        let r = detect_gzip_analysis(&data).unwrap();
        assert_eq!(r.original_filename, Some("test.tar".to_string()));
    }

    #[test]
    fn test_detect_inner_format() {
        assert_eq!(
            detect_inner_format(&Some("file.tar".to_string())),
            Some("TAR Archive".to_string())
        );
        assert_eq!(detect_inner_format(&Some("readme.txt".to_string())), None);
        assert_eq!(detect_inner_format(&None), None);
    }
}
