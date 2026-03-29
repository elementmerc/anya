// Image file metadata and steganography indicator analysis
// Detects trailing data, suspicious metadata, and embedded URLs

use crate::output::ImageAnalysis;

/// PNG end marker
const PNG_IEND: &[u8] = b"IEND";
/// JPEG end marker
const JPEG_EOI: [u8; 2] = [0xFF, 0xD9];

/// Analyse image file bytes for trailing data, metadata anomalies, and
/// embedded content. Returns None if no suspicious indicators found.
pub fn detect_image_analysis(data: &[u8]) -> Option<ImageAnalysis> {
    if data.len() < 8 {
        return None;
    }

    let mut has_trailing_data = false;
    let mut trailing_data_size: usize = 0;
    let mut has_suspicious_metadata = false;
    let mut metadata_strings: Vec<String> = Vec::new();
    let mut has_embedded_urls = false;

    // ── Trailing data detection ─────────────────────────────────────────
    // PNG: data after IEND chunk
    if data.starts_with(b"\x89PNG") {
        if let Some(iend_pos) = find_bytes(data, PNG_IEND) {
            // IEND chunk is 12 bytes: 4-byte length (0) + 4 "IEND" + 4 CRC
            let end_of_png = iend_pos + 4 + 4; // IEND + CRC
            if end_of_png < data.len() {
                trailing_data_size = data.len() - end_of_png;
                if trailing_data_size > 16 {
                    has_trailing_data = true;
                }
            }
        }
        // Check PNG text chunks for suspicious content
        check_png_text_chunks(data, &mut metadata_strings, &mut has_embedded_urls);
    }
    // JPEG: data after FFD9 marker
    else if data.starts_with(&[0xFF, 0xD8]) {
        // Search backwards for the last FFD9
        for i in (1..data.len()).rev() {
            if data[i - 1] == JPEG_EOI[0] && data[i] == JPEG_EOI[1] {
                let end_of_jpeg = i + 1;
                if end_of_jpeg < data.len() {
                    trailing_data_size = data.len() - end_of_jpeg;
                    if trailing_data_size > 16 {
                        has_trailing_data = true;
                    }
                }
                break;
            }
        }
        // Check EXIF comments
        check_jpeg_comments(data, &mut metadata_strings, &mut has_embedded_urls);
    }
    // BMP: check if file size exceeds BMP declared size
    else if data.starts_with(b"BM") && data.len() >= 6 {
        let declared_size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
        if declared_size > 0 && declared_size < data.len() {
            trailing_data_size = data.len() - declared_size;
            if trailing_data_size > 16 {
                has_trailing_data = true;
            }
        }
    }

    // ── General metadata string scan ────────────────────────────────────
    // Look for URLs and suspicious strings in the metadata area
    // (first 64KB typically contains headers/metadata)
    let scan_range = data.len().min(65536);
    let scan_area = &data[..scan_range];
    let text_view = String::from_utf8_lossy(scan_area);

    // URLs in metadata
    if text_view.contains("http://") || text_view.contains("https://") {
        has_embedded_urls = true;
        // Extract URLs from metadata
        for word in text_view.split_whitespace() {
            if (word.starts_with("http://") || word.starts_with("https://"))
                && metadata_strings.len() < 10
            {
                metadata_strings.push(word.chars().take(200).collect());
            }
        }
    }

    // Suspicious metadata content
    if text_view.contains("cmd.exe")
        || text_view.contains("powershell")
        || text_view.contains("eval(")
        || text_view.contains("<script")
    {
        has_suspicious_metadata = true;
        if text_view.contains("cmd.exe") {
            metadata_strings.push("cmd.exe reference in metadata".into());
        }
        if text_view.contains("powershell") {
            metadata_strings.push("PowerShell reference in metadata".into());
        }
        if text_view.contains("<script") {
            metadata_strings.push("Script tag in metadata".into());
        }
    }

    if !has_trailing_data && !has_suspicious_metadata && !has_embedded_urls {
        return None;
    }

    Some(ImageAnalysis {
        has_trailing_data,
        trailing_data_size,
        has_suspicious_metadata,
        metadata_strings,
        has_embedded_urls,
    })
}

/// Check PNG tEXt, zTXt, and iTXt chunks for suspicious content
fn check_png_text_chunks(data: &[u8], strings: &mut Vec<String>, has_urls: &mut bool) {
    let chunk_types: &[&[u8]] = &[b"tEXt", b"zTXt", b"iTXt"];
    for ct in chunk_types {
        let mut offset = 8; // Skip PNG signature
        while offset + 12 < data.len() {
            if offset + 4 > data.len() {
                break;
            }
            let chunk_len = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            if offset + 4 + 4 > data.len() {
                break;
            }
            let chunk_type = &data[offset + 4..offset + 8];
            if chunk_type == *ct {
                let chunk_data_end = (offset + 8 + chunk_len).min(data.len());
                let chunk_data = &data[offset + 8..chunk_data_end];
                let text = String::from_utf8_lossy(chunk_data);
                if text.contains("http://") || text.contains("https://") {
                    *has_urls = true;
                    if strings.len() < 10 {
                        strings.push(format!("PNG {}: URL found", String::from_utf8_lossy(ct)));
                    }
                }
            }
            // Move to next chunk: length + type(4) + data + CRC(4)
            offset += 4 + 4 + chunk_len + 4;
            if chunk_len > data.len() {
                break; // Malformed chunk
            }
        }
    }
}

/// Check JPEG COM (comment) markers for suspicious content
fn check_jpeg_comments(data: &[u8], strings: &mut Vec<String>, has_urls: &mut bool) {
    let mut offset = 2; // Skip SOI
    while offset + 4 < data.len() {
        if data[offset] != 0xFF {
            break;
        }
        let marker = data[offset + 1];
        // COM marker = 0xFE
        if marker == 0xFE {
            let seg_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let seg_end = (offset + 2 + seg_len).min(data.len());
            let comment = String::from_utf8_lossy(&data[offset + 4..seg_end]);
            if comment.contains("http://") || comment.contains("https://") {
                *has_urls = true;
                if strings.len() < 10 {
                    strings.push("JPEG comment: URL found".into());
                }
            }
        }
        // Skip to next marker
        if marker == 0xDA {
            break; // Start of scan — no more metadata
        }
        if offset + 3 >= data.len() {
            break;
        }
        let seg_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 2 + seg_len;
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_image() {
        assert!(detect_image_analysis(b"Not an image").is_none());
    }

    #[test]
    fn test_clean_png_stub() {
        // Minimal PNG-like header without trailing data
        let mut data = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        // Add IEND chunk
        data.extend_from_slice(&[0, 0, 0, 0]); // length
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]); // CRC
        assert!(detect_image_analysis(&data).is_none());
    }

    #[test]
    fn test_png_with_trailing_data() {
        let mut data = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        data.extend_from_slice(&[0, 0, 0, 0]); // length
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]); // CRC
        // Add significant trailing data
        data.extend_from_slice(&[0u8; 1024]);
        let r = detect_image_analysis(&data).unwrap();
        assert!(r.has_trailing_data);
        assert!(r.trailing_data_size > 0);
    }
}
