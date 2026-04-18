// Anya — .NET CLR Metadata Parser
//
// Parses the CLR header, metadata streams, and table structures from .NET assemblies
// to detect obfuscation, suspicious patterns, and known obfuscator fingerprints.
//
// Reference: ECMA-335 (Common Language Infrastructure) specification.
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use serde::{Deserialize, Serialize};

/// Results from .NET metadata analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotNetMetadata {
    /// Module initializer (.cctor) detected
    pub has_module_initializer: bool,
    /// Ratio of type/method names that contain unprintable or single characters
    pub obfuscated_names_ratio: f64,
    /// References to reflection APIs (Assembly.Load, Activator.CreateInstance)
    pub reflection_usage: bool,
    /// Number of P/Invoke (DllImport) declarations
    pub pinvoke_count: usize,
    /// P/Invoke to suspicious DLLs (ntdll, kernel32 suspicious APIs)
    pub pinvoke_suspicious: bool,
    /// High-entropy data in #Blob stream (encrypted payloads)
    pub high_entropy_blob: bool,
    /// Detected obfuscator name (ConfuserEx, .NET Reactor, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_obfuscator: Option<String>,
    /// Number of managed resources
    pub resource_count: usize,
    /// High-entropy managed resources (encrypted data)
    pub encrypted_resources: bool,
    /// Total type definitions
    pub type_count: usize,
    /// Total method definitions
    pub method_count: usize,
    /// CLR version string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clr_version: Option<String>,
}

// ── ECMA-335 constants ──────────────────────────────────────────────────────

const METADATA_SIGNATURE: &[u8] = b"\x42\x53\x4A\x42"; // BSJB
const STREAM_TILDE: &str = "#~";
const STREAM_STRINGS: &str = "#Strings";
const STREAM_BLOB: &str = "#Blob";
#[allow(dead_code)]
const STREAM_US: &str = "#US";

// Metadata table indices (ECMA-335 §II.22)
#[allow(dead_code)]
const TABLE_MODULE: usize = 0x00;
const TABLE_TYPEDEF: usize = 0x02;
const TABLE_METHODDEF: usize = 0x06;
#[allow(dead_code)]
const TABLE_MEMBERREF: usize = 0x0A;
const TABLE_IMPLMAP: usize = 0x1C; // P/Invoke map

/// Parse .NET metadata from PE file data.
/// Returns None if the file is not a valid .NET assembly or parsing fails.
pub fn analyse_dotnet(
    data: &[u8],
    _clr_rva: u32,
    _section_rva_base: u32,
    _section_raw_offset: u32,
) -> Option<DotNetMetadata> {
    // Find the BSJB metadata signature in the raw data
    let metadata_offset = find_metadata_root(data)?;

    let mut result = DotNetMetadata {
        has_module_initializer: false,
        obfuscated_names_ratio: 0.0,
        reflection_usage: false,
        pinvoke_count: 0,
        pinvoke_suspicious: false,
        high_entropy_blob: false,
        known_obfuscator: None,
        resource_count: 0,
        encrypted_resources: false,
        type_count: 0,
        method_count: 0,
        clr_version: None,
    };

    // Parse metadata root header
    let root = data.get(metadata_offset..)?;
    if root.len() < 16 {
        return Some(result);
    }

    // Skip signature (4 bytes) + major/minor version (4 bytes) + reserved (4 bytes)
    let version_len = u32::from_le_bytes(root.get(12..16)?.try_into().ok()?) as usize;
    let header_end = 16usize.checked_add(version_len)?.checked_add(4)?;
    if root.len() < header_end {
        return Some(result);
    }

    // Extract CLR version string
    let version_bytes = &root[16..16 + version_len];
    let version_str = std::str::from_utf8(version_bytes)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();
    if !version_str.is_empty() {
        result.clr_version = Some(version_str);
    }

    // Parse stream headers (after version string + flags + streams count)
    let streams_offset = 16 + version_len;
    if root.len() < streams_offset + 4 {
        return Some(result);
    }
    // Flags (2 bytes) + Streams count (2 bytes)
    let sc_start = streams_offset.checked_add(2)?;
    let sc_end = sc_start.checked_add(2)?;
    let num_streams = u16::from_le_bytes(root.get(sc_start..sc_end)?.try_into().ok()?) as usize;

    let mut cursor = streams_offset + 4;
    let mut strings_offset = 0usize;
    let mut strings_size = 0usize;
    let mut blob_offset = 0usize;
    let mut blob_size = 0usize;
    let mut tilde_offset = 0usize;
    let mut tilde_size = 0usize;

    for _ in 0..num_streams.min(8) {
        if cursor.checked_add(8).is_none_or(|end| end > root.len()) {
            break;
        }
        let offset = u32::from_le_bytes(root.get(cursor..cursor + 4)?.try_into().ok()?) as usize;
        let size = u32::from_le_bytes(root.get(cursor + 4..cursor + 8)?.try_into().ok()?) as usize;
        cursor += 8;

        // Read stream name (null-terminated, 4-byte aligned)
        let name_start = cursor;
        while cursor < root.len() && root[cursor] != 0 {
            cursor += 1;
        }
        let name = std::str::from_utf8(&root[name_start..cursor]).unwrap_or("");
        cursor += 1; // skip null
        cursor = (cursor + 3) & !3; // align to 4 bytes

        match name {
            STREAM_STRINGS => {
                strings_offset = metadata_offset + offset;
                strings_size = size;
            }
            STREAM_BLOB => {
                blob_offset = metadata_offset + offset;
                blob_size = size;
            }
            STREAM_TILDE => {
                tilde_offset = metadata_offset + offset;
                tilde_size = size;
            }
            _ => {}
        }
    }

    // Analyse #Strings stream for obfuscated names
    if strings_size > 0 && strings_offset + strings_size <= data.len() {
        let strings_data = &data[strings_offset..strings_offset + strings_size];
        analyse_strings_stream(strings_data, &mut result);
    }

    // Analyse #Blob stream for high entropy (encrypted data)
    if blob_size > 0 && blob_offset + blob_size <= data.len() {
        let blob_data = &data[blob_offset..blob_offset + blob_size];
        analyse_blob_stream(blob_data, &mut result);
    }

    // Analyse #~ (tilde) stream for table counts
    if tilde_size > 0 && tilde_offset + tilde_size <= data.len() {
        let tilde_data = &data[tilde_offset..tilde_offset + tilde_size];
        analyse_tilde_stream(tilde_data, &mut result);
    }

    // Single-pass detection of obfuscators, reflection, and P/Invoke patterns
    detect_dotnet_patterns(data, &mut result);

    Some(result)
}

fn find_metadata_root(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == METADATA_SIGNATURE)
}

fn analyse_strings_stream(data: &[u8], result: &mut DotNetMetadata) {
    // The #Strings stream is a null-terminated string heap.
    // Count names and check for obfuscation (unprintable chars, single-char names).
    let mut total_names = 0usize;
    let mut obfuscated_names = 0usize;
    let mut i = 1; // Skip the first null byte

    while i < data.len() {
        let start = i;
        while i < data.len() && data[i] != 0 {
            i += 1;
        }
        let name = &data[start..i];
        i += 1; // skip null

        if name.is_empty() {
            continue;
        }

        total_names += 1;

        // Obfuscation detection: a name is suspicious if it contains non-printable
        // chars OR is a single non-alphabetic character (e.g. `_`, `\u0001`).
        // Short alphabetic names like `get`, `set`, `Add`, `Main` are legitimate.
        let has_non_printable = name.iter().any(|&b| !(0x20..=0x7E).contains(&b));
        let is_single_nonalpha = name.len() == 1 && !name[0].is_ascii_alphabetic();
        let is_obfuscated = has_non_printable || is_single_nonalpha;

        if is_obfuscated {
            obfuscated_names += 1;
        }

        // Check for module initializer
        if name == b".cctor" {
            result.has_module_initializer = true;
        }
    }

    if total_names > 0 {
        result.obfuscated_names_ratio = obfuscated_names as f64 / total_names as f64;
    }
}

fn analyse_blob_stream(data: &[u8], result: &mut DotNetMetadata) {
    // Check overall entropy of the blob stream
    if data.len() > 256 {
        let entropy = calculate_entropy(data);
        result.high_entropy_blob = entropy > 7.0;
    }
}

fn analyse_tilde_stream(data: &[u8], result: &mut DotNetMetadata) {
    // #~ stream header: reserved(4) + major/minor(2) + heap_sizes(1) + reserved(1) + valid(8) + sorted(8)
    if data.len() < 24 {
        return;
    }

    let valid_tables = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8]));

    // Count rows for each present table
    let mut row_counts = [0u32; 64];
    let mut offset = 24; // After header
    for (i, count) in row_counts.iter_mut().enumerate() {
        if valid_tables & (1u64 << i) != 0 && offset + 4 <= data.len() {
            *count = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
            offset += 4;
        }
    }

    result.type_count = row_counts[TABLE_TYPEDEF] as usize;
    result.method_count = row_counts[TABLE_METHODDEF] as usize;
    result.pinvoke_count = row_counts[TABLE_IMPLMAP] as usize;
    result.resource_count = row_counts[0x28] as usize; // ManifestResource table
}

/// All .NET detection patterns in a single pass using Aho-Corasick.
/// Replaces 14+ separate linear scans with 1 automaton scan.
fn detect_dotnet_patterns(data: &[u8], result: &mut DotNetMetadata) {
    use aho_corasick::AhoCorasick;

    // Pattern categories: (pattern_bytes, category)
    // Categories: "obf:Name" for obfuscators, "ref" for reflection, "pin" for P/Invoke DLLs
    let patterns: &[(&[u8], &str)] = &[
        // Obfuscators
        (b"ConfusedBy", "obf:ConfuserEx"),
        (b"ConfuserEx", "obf:ConfuserEx"),
        (b"CosturaAssembly", "obf:.NET Reactor"),
        (b"SmartAssembly", "obf:SmartAssembly"),
        (b"PoweredByAttribute", "obf:SmartAssembly"),
        (b"DotfuscatorAttribute", "obf:Dotfuscator"),
        (b"PreEmptive", "obf:Dotfuscator"),
        (b"BabelAttribute", "obf:Babel Obfuscator"),
        (b"CryptoObfuscator", "obf:Crypto Obfuscator"),
        (b"EazObfuscator", "obf:Eazfuscator.NET"),
        // Reflection APIs
        (b"Assembly.Load", "ref"),
        (b"Assembly.LoadFrom", "ref"),
        (b"Activator.CreateInstance", "ref"),
        (b"MethodInfo.Invoke", "ref"),
        (b"Type.InvokeMember", "ref"),
        (b"Assembly.GetType", "ref"),
        // Suspicious P/Invoke DLLs
        (b"ntdll", "pin"),
        (b"kernel32", "pin"),
        (b"advapi32", "pin"),
        (b"user32", "pin"),
    ];

    let needles: Vec<&[u8]> = patterns.iter().map(|(p, _)| *p).collect();
    let ac = match AhoCorasick::new(&needles) {
        Ok(ac) => ac,
        Err(_) => return,
    };

    for mat in ac.find_iter(data) {
        let (_, category) = patterns[mat.pattern().as_usize()];
        if let Some(obf_name) = category.strip_prefix("obf:") {
            if result.known_obfuscator.is_none() {
                result.known_obfuscator = Some(obf_name.to_string());
            }
        } else if category == "ref" {
            result.reflection_usage = true;
        } else if category == "pin" && result.pinvoke_count > 0 {
            result.pinvoke_suspicious = true;
        }
    }
}

/// Delegates to the canonical implementation in lib.rs
fn calculate_entropy(data: &[u8]) -> f64 {
    crate::calculate_entropy(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_metadata_root() {
        let data = b"\x00\x00\x42\x53\x4A\x42\x01\x00";
        assert_eq!(find_metadata_root(data), Some(2));
    }

    #[test]
    fn test_find_metadata_root_not_found() {
        let data = b"\x00\x00\x00\x00";
        assert_eq!(find_metadata_root(data), None);
    }

    #[test]
    fn test_detect_obfuscator() {
        // ConfuserEx should be detected from raw bytes
        let data = b"\x00\x00ConfuserEx\x00\x00";
        let mut result = DotNetMetadata {
            has_module_initializer: false,
            obfuscated_names_ratio: 0.0,
            reflection_usage: false,
            pinvoke_count: 0,
            pinvoke_suspicious: false,
            high_entropy_blob: false,
            known_obfuscator: None,
            resource_count: 0,
            encrypted_resources: false,
            type_count: 0,
            method_count: 0,
            clr_version: None,
        };
        detect_dotnet_patterns(data, &mut result);
        assert_eq!(result.known_obfuscator.as_deref(), Some("ConfuserEx"));
    }

    #[test]
    fn test_calculate_entropy() {
        // All same bytes = 0 entropy
        assert_eq!(calculate_entropy(&[0u8; 256]), 0.0);
        // Uniform distribution = ~8.0
        let mut data = vec![0u8; 256];
        for (i, slot) in data.iter_mut().enumerate().take(256) {
            *slot = i as u8;
        }
        let ent = calculate_entropy(&data);
        assert!(ent > 7.9 && ent <= 8.0);
    }
}
