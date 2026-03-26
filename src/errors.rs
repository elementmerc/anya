//! Plain-English error suggestions for common failures.
//! Designed so a 15-year-old can understand what went wrong and what to do.

/// Given an error message, return a helpful suggestion or None.
pub fn suggest(error: &str) -> Option<&'static str> {
    let lower = error.to_lowercase();

    // File not found
    if lower.contains("no such file")
        || lower.contains("not found")
        || lower.contains("does not exist")
    {
        return Some("That file doesn't exist. Double-check the path — did you spell it right?");
    }

    // Permission denied
    if lower.contains("permission denied") || lower.contains("access denied") {
        return Some(
            "Anya can't read that file. Try running with sudo, or check the file's permissions.",
        );
    }

    // File too large / out of memory
    if lower.contains("out of memory")
        || lower.contains("too large")
        || lower.contains("allocation")
    {
        return Some(
            "That file is too large to analyse. Try a smaller file, or increase your system's available memory.",
        );
    }

    // Corrupt / invalid binary
    if lower.contains("corrupt")
        || lower.contains("truncated")
        || lower.contains("invalid magic")
        || lower.contains("bad magic")
    {
        return Some(
            "This file looks damaged or isn't a valid binary. It might be corrupted or incomplete.",
        );
    }

    // Config errors
    if lower.contains("config")
        && (lower.contains("invalid") || lower.contains("parse") || lower.contains("toml"))
    {
        return Some(
            "Your config file has a mistake in it. Delete it and run `anya --init-config` to start fresh.",
        );
    }

    // Empty file
    if lower.contains("empty") {
        return Some("That file is empty (0 bytes). There's nothing to analyse.");
    }

    // Timeout
    if lower.contains("timeout") || lower.contains("took too long") {
        return Some("That file is too big or too complex to analyse in time. Try a smaller file.");
    }

    // IO errors
    if lower.contains("broken pipe") || lower.contains("io error") {
        return Some(
            "Something went wrong reading the file. Check that the disk isn't full and the file isn't locked by another program.",
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_not_found() {
        assert!(suggest("No such file or directory").is_some());
        assert!(suggest("file not found").is_some());
    }

    #[test]
    fn test_permission_denied() {
        assert!(suggest("Permission denied (os error 13)").is_some());
    }

    #[test]
    fn test_corrupt_binary() {
        assert!(suggest("This file has an ELF signature but the header appears corrupt").is_some());
    }

    #[test]
    fn test_config_error() {
        assert!(suggest("Failed to parse config TOML").is_some());
    }

    #[test]
    fn test_empty_file() {
        assert!(suggest("File is empty").is_some());
    }

    #[test]
    fn test_no_match() {
        assert!(suggest("everything is fine").is_none());
    }
}
