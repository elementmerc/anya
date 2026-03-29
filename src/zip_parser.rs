// ZIP archive deep analysis
// Detection patterns loaded from private scoring crate.

use crate::output::ZipAnalysis;
use anya_scoring::detection_patterns::EXECUTABLE_EXTENSIONS;
use std::io::Cursor;

/// Extensions that look like documents but could hide executables
const DOCUMENT_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "jpg", "jpeg", "png", "gif",
    "bmp",
];

/// Analyse file bytes as ZIP archive. Returns None if not a valid ZIP
/// or no suspicious content found.
pub fn detect_zip_analysis(data: &[u8]) -> Option<ZipAnalysis> {
    // Quick check for ZIP magic (PK\x03\x04)
    if data.len() < 22 || !(data[0] == b'P' && data[1] == b'K') {
        return None;
    }

    let cursor = Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return None,
    };

    let entry_count = archive.len();
    let mut has_executables = false;
    let mut executable_names: Vec<String> = Vec::new();
    let mut has_encrypted_entries = false;
    let mut has_double_extensions = false;
    let mut has_path_traversal = false;
    let mut suspicious_entries: Vec<String> = Vec::new();
    let mut total_compressed: u64 = 0;
    let mut total_uncompressed: u64 = 0;

    for i in 0..entry_count {
        let file = match archive.by_index_raw(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let name = file.name().to_string();

        total_compressed += file.compressed_size();
        total_uncompressed += file.size();

        // Encrypted entry check
        if file.encrypted() {
            has_encrypted_entries = true;
        }

        // Path traversal check
        if name.contains("../") || name.contains("..\\") {
            has_path_traversal = true;
            suspicious_entries.push(format!("Path traversal: {name}"));
        }

        // Extract extension
        let lower_name = name.to_lowercase();
        let ext = lower_name.rsplit('.').next().unwrap_or("");

        // Executable check using private extension list
        if EXECUTABLE_EXTENSIONS.iter().any(|e| e == ext) {
            has_executables = true;
            if executable_names.len() < 20 {
                executable_names.push(name.clone());
            }
        }

        // Double extension check (e.g., invoice.pdf.exe)
        let parts: Vec<&str> = lower_name.rsplitn(3, '.').collect();
        if parts.len() >= 3 {
            let ext1 = parts[0]; // last extension
            let ext2 = parts[1]; // second-to-last
            if EXECUTABLE_EXTENSIONS.iter().any(|e| e == ext1) && DOCUMENT_EXTS.contains(&ext2) {
                has_double_extensions = true;
                suspicious_entries.push(format!("Double extension: {name}"));
            }
        }

        // Nested archive check
        let nested_archive_exts = ["zip", "rar", "7z", "tar", "gz", "cab", "iso"];
        if nested_archive_exts.contains(&ext) {
            suspicious_entries.push(format!("Nested archive: {name}"));
        }

        // Hidden file check
        if name.starts_with('.') && !name.starts_with("./") {
            suspicious_entries.push(format!("Hidden file: {name}"));
        }
    }

    // Compression ratio (bomb detection)
    let compression_ratio = if total_compressed > 0 {
        total_uncompressed as f64 / total_compressed as f64
    } else {
        0.0
    };

    if compression_ratio > 100.0 {
        suspicious_entries.push(format!(
            "Compression bomb indicator: {compression_ratio:.0}x ratio"
        ));
    }

    if !has_executables
        && !has_encrypted_entries
        && !has_double_extensions
        && !has_path_traversal
        && suspicious_entries.is_empty()
    {
        return None;
    }

    Some(ZipAnalysis {
        entry_count,
        has_executables,
        executable_names,
        has_encrypted_entries,
        compression_ratio,
        has_double_extensions,
        has_path_traversal,
        suspicious_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let buf = Vec::new();
        let cursor = Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, content) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn test_non_zip() {
        assert!(detect_zip_analysis(b"Not a ZIP").is_none());
    }

    #[test]
    fn test_clean_zip() {
        let data = make_zip(&[("readme.txt", b"Hello World")]);
        assert!(detect_zip_analysis(&data).is_none());
    }

    #[test]
    fn test_zip_with_exe() {
        let data = make_zip(&[("payload.exe", b"MZ fake exe")]);
        let r = detect_zip_analysis(&data).unwrap();
        assert!(r.has_executables);
        assert!(r.executable_names.contains(&"payload.exe".to_string()));
    }

    #[test]
    fn test_double_extension() {
        let data = make_zip(&[("invoice.pdf.exe", b"MZ fake")]);
        let r = detect_zip_analysis(&data).unwrap();
        assert!(r.has_double_extensions);
        assert!(r.has_executables);
    }

    #[test]
    fn test_path_traversal() {
        let data = make_zip(&[("../../../etc/passwd", b"root:x:0:0")]);
        let r = detect_zip_analysis(&data).unwrap();
        assert!(r.has_path_traversal);
    }
}
