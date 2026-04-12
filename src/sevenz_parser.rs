// 7-Zip archive analysis
// Parses the 7z start header to extract version and metadata.
// Full file listing requires decompressing the header stream, which is deferred.

use crate::output::SevenZipAnalysis;

/// 7z signature: "7z\xBC\xAF\x27\x1C"
const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Analyse file bytes as a 7-Zip archive. Returns None if not valid 7z.
pub fn detect_sevenz_analysis(data: &[u8]) -> Option<SevenZipAnalysis> {
    // 7z start header is 32 bytes:
    //   0-5:   Signature (6 bytes)
    //   6:     Major version
    //   7:     Minor version
    //   8-11:  Start header CRC (4 bytes)
    //   12-19: Next header offset (8 bytes LE)
    //   20-27: Next header size (8 bytes LE)
    //   28-31: Next header CRC (4 bytes)
    if data.len() < 32 {
        return None;
    }

    if data[0..6] != SEVENZ_MAGIC {
        return None;
    }

    let version_major = data[6];
    let version_minor = data[7];

    let next_header_size = u64::from_le_bytes([
        data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
    ]);

    Some(SevenZipAnalysis {
        version_major,
        version_minor,
        header_size: next_header_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_7z() {
        assert!(detect_sevenz_analysis(b"Not a 7z file").is_none());
    }

    #[test]
    fn test_too_short() {
        let mut data = vec![0u8; 10];
        data[0..6].copy_from_slice(&SEVENZ_MAGIC);
        assert!(detect_sevenz_analysis(&data).is_none());
    }

    #[test]
    fn test_valid_7z_header() {
        let mut data = vec![0u8; 64];
        data[0..6].copy_from_slice(&SEVENZ_MAGIC);
        data[6] = 0; // Major version
        data[7] = 4; // Minor version
        // Next header size = 256
        data[20..28].copy_from_slice(&256u64.to_le_bytes());
        let r = detect_sevenz_analysis(&data).unwrap();
        assert_eq!(r.version_major, 0);
        assert_eq!(r.version_minor, 4);
        assert_eq!(r.header_size, 256);
    }

    #[test]
    fn test_7z_version_extraction() {
        let mut data = vec![0u8; 32];
        data[0..6].copy_from_slice(&SEVENZ_MAGIC);
        data[6] = 2;
        data[7] = 3;
        let r = detect_sevenz_analysis(&data).unwrap();
        assert_eq!(r.version_major, 2);
        assert_eq!(r.version_minor, 3);
    }
}
