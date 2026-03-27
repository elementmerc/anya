// Ányá - Malware Analysis Platform
// Copyright (C) 2026 Daniel Iwugo
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// For commercial licensing, contact: daniel@themalwarefiles.com

//! `anya hash-check` subcommand — check whether a file's hash appears in a
//! user-supplied plaintext hash list.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use colored::Colorize;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Returns `true` when `s` is a plausible hex-encoded hash (MD5 = 32, SHA1 = 40,
/// SHA256 = 64 hex characters).
fn is_hex_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Determine the hash type name from the length of a hex string.
fn hash_type_label(len: usize) -> &'static str {
    match len {
        32 => "md5",
        40 => "sha1",
        64 => "sha256",
        _ => "unknown",
    }
}

/// Load a hash list from `path`, skipping blank lines and comments (`#`).
/// All entries are normalised to lowercase.  Returns the set and its size.
fn load_hash_list(path: &Path) -> Result<(HashSet<String>, usize)> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read hash list: {}", path.display()))?;

    let set: HashSet<String> = contents
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_lowercase())
        .collect();

    let count = set.len();
    Ok((set, count))
}

/// Format an integer with thousands separators (e.g. `1247` → `"1,247"`).
fn fmt_thousands(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

// ─── Core ────────────────────────────────────────────────────────────────────

/// Run the `hash-check` subcommand.
///
/// * `target` — either a path to a file on disk **or** a raw hex hash string.
/// * `against` — path to a plaintext hash list (one hash per line).
/// * `json` — when `true`, emit machine-readable JSON instead of coloured text.
///
/// Returns `Ok(true)` when the hash is found in the list, `Ok(false)` otherwise.
pub fn run(target: &str, against: &Path, json: bool) -> Result<bool> {
    let (hash_set, list_entries) = load_hash_list(against).context("Could not load hash list")?;

    let list_name = against
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| against.display().to_string());

    // Determine whether `target` is a file or a raw hash string.
    let target_path = Path::new(target);
    if target_path.is_file() {
        // ── File target ──────────────────────────────────────────────────
        let data = std::fs::read(target_path)
            .with_context(|| format!("Failed to read target file: {}", target_path.display()))?;

        let sha256_hex = format!("{:x}", Sha256::digest(&data));
        let sha1_hex = format!("{:x}", Sha1::digest(&data));
        let md5_hex = format!("{:x}", Md5::digest(&data));

        let file_display = target_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| target.to_string());

        // Check SHA256 first, then SHA1, then MD5.
        let (matched, matched_hash, matched_type) = if hash_set.contains(&sha256_hex) {
            (true, sha256_hex.clone(), "sha256")
        } else if hash_set.contains(&sha1_hex) {
            (true, sha1_hex.clone(), "sha1")
        } else if hash_set.contains(&md5_hex) {
            (true, md5_hex.clone(), "md5")
        } else {
            (false, sha256_hex.clone(), "sha256")
        };

        if json {
            print_json(matched, &matched_hash, matched_type, list_entries);
        } else {
            print_terminal(
                matched,
                &file_display,
                &matched_hash,
                matched_type,
                &list_name,
                list_entries,
            );
        }

        Ok(matched)
    } else if is_hex_hash(target) {
        // ── Direct hash string ───────────────────────────────────────────
        let normalised = target.to_lowercase();
        let hash_type = hash_type_label(normalised.len());
        let matched = hash_set.contains(&normalised);

        if json {
            print_json(matched, &normalised, hash_type, list_entries);
        } else {
            print_terminal(
                matched,
                target,
                &normalised,
                hash_type,
                &list_name,
                list_entries,
            );
        }

        Ok(matched)
    } else {
        bail!("Target doesn't look like a file path or hash string.");
    }
}

// ─── Output helpers ──────────────────────────────────────────────────────────

fn print_terminal(
    matched: bool,
    display_name: &str,
    hash: &str,
    hash_type: &str,
    list_name: &str,
    list_entries: usize,
) {
    let hash_label = hash_type.to_uppercase();
    let list_info = format!("{} ({} entries)", list_name, fmt_thousands(list_entries));

    if matched {
        println!("{}", "MATCH FOUND".red().bold());
    } else {
        println!("{}", "NO MATCH".green().bold());
    }
    println!("  File:      {}", display_name);
    println!("  {}:    {}", hash_label, hash);
    println!("  List:      {}", list_info);
}

fn print_json(matched: bool, hash: &str, hash_type: &str, list_entries: usize) {
    println!(
        "{{\"match\":{},\"hash\":\"{}\",\"hash_type\":\"{}\",\"list_entries\":{}}}",
        matched, hash, hash_type, list_entries,
    );
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_is_hex_hash() {
        // MD5 — 32 hex chars
        assert!(is_hex_hash("d41d8cd98f00b204e9800998ecf8427e"));
        // SHA1 — 40 hex chars
        assert!(is_hex_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        // SHA256 — 64 hex chars
        assert!(is_hex_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        // Upper-case hex should also be recognised
        assert!(is_hex_hash("D41D8CD98F00B204E9800998ECF8427E"));

        // Too short / too long / non-hex
        assert!(!is_hex_hash("abc123"));
        assert!(!is_hex_hash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")); // 32 non-hex
        assert!(!is_hex_hash("")); // empty
    }

    #[test]
    fn test_load_hash_list() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "# This is a comment").unwrap();
        writeln!(tmp,).unwrap();
        writeln!(tmp, "D41D8CD98F00B204E9800998ECF8427E").unwrap();
        writeln!(tmp, "  da39a3ee5e6b4b0d3255bfef95601890afd80709  ").unwrap();
        writeln!(tmp, "# another comment").unwrap();
        writeln!(
            tmp,
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        )
        .unwrap();
        tmp.flush().unwrap();

        let (set, count) = load_hash_list(tmp.path()).unwrap();
        assert_eq!(count, 3);

        // All entries should be lowercased
        assert!(set.contains("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(set.contains("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assert!(set.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

        // Comments and blank lines must not appear
        assert!(!set.contains("# This is a comment"));
        assert!(!set.contains(""));
    }
}
