// Ányá - Malware Analysis Platform
// IOC (Indicator of Compromise) detection module
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use crate::output::{ExtractedString, IocSummary, IocType};
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

struct IocPattern {
    ioc_type: IocType,
    regex: Regex,
}

// Compile all IOC regexes once on first use. Order matters: first match wins.
static IOC_PATTERNS: LazyLock<Vec<IocPattern>> = LazyLock::new(|| {
    vec![
        IocPattern {
            ioc_type: IocType::Ipv4,
            regex: Regex::new(
                r"^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$",
            )
            .expect("ipv4 regex"),
        },
        IocPattern {
            ioc_type: IocType::Ipv6,
            regex: Regex::new(r"(?i)^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$").expect("ipv6 regex"),
        },
        IocPattern {
            ioc_type: IocType::Url,
            regex: Regex::new(r"(?i)^https?://\S{4,}$").expect("url regex"),
        },
        IocPattern {
            ioc_type: IocType::Email,
            regex: Regex::new(r"(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")
                .expect("email regex"),
        },
        IocPattern {
            ioc_type: IocType::RegistryKey,
            regex: Regex::new(r"^HKEY_[A-Z_]+(?:\\\S+)+$").expect("registry regex"),
        },
        IocPattern {
            ioc_type: IocType::WindowsPath,
            regex: Regex::new(r"^[A-Za-z]:\\[^\s]+$").expect("winpath regex"),
        },
        IocPattern {
            ioc_type: IocType::LinuxPath,
            regex: Regex::new(r"^/(?:etc|tmp|var|usr|home|proc|sys)/\S{2,}$")
                .expect("linpath regex"),
        },
        IocPattern {
            ioc_type: IocType::Mutex,
            regex: Regex::new(r"(?i)(?:mutex|mtx|lock)\S{0,40}$").expect("mutex regex"),
        },
        IocPattern {
            ioc_type: IocType::Domain,
            regex: Regex::new(
                r"(?i)^(?:[a-zA-Z0-9\-]{1,63}\.)+(?:com|net|org|io|ru|cn|tk|top|xyz|onion)$",
            )
            .expect("domain regex"),
        },
        IocPattern {
            ioc_type: IocType::Base64Blob,
            regex: Regex::new(r"^[A-Za-z0-9+/]{40,}={0,2}$").expect("base64 regex"),
        },
    ]
});

/// Classify a single string against IOC patterns. Returns first match.
pub fn classify_ioc(s: &str) -> Option<IocType> {
    if s.len() < 4 {
        return None;
    }
    for pattern in IOC_PATTERNS.iter() {
        if pattern.regex.is_match(s) {
            return Some(pattern.ioc_type.clone());
        }
    }
    None
}

/// Map an IocType to the legacy category string used by ClassifiedString.
pub fn ioc_type_to_category(ioc: &IocType) -> String {
    match ioc {
        IocType::Ipv4 | IocType::Ipv6 => "IP".to_string(),
        IocType::Url => "URL".to_string(),
        IocType::Domain => "URL".to_string(),
        IocType::Email => "URL".to_string(),
        IocType::RegistryKey => "Registry".to_string(),
        IocType::WindowsPath | IocType::LinuxPath => "Path".to_string(),
        IocType::Mutex => "Command".to_string(),
        IocType::Base64Blob => "Base64".to_string(),
    }
}

/// Run IOC classification on a list of extracted strings with offsets.
pub fn extract_iocs(strings: &[(String, usize)]) -> IocSummary {
    let mut ioc_strings = Vec::new();
    let mut ioc_counts: HashMap<String, usize> = HashMap::new();

    for (value, offset) in strings {
        if let Some(ioc) = classify_ioc(value) {
            *ioc_counts.entry(ioc.to_string()).or_insert(0) += 1;
            ioc_strings.push(ExtractedString {
                value: value.clone(),
                offset: *offset,
                ioc_type: Some(ioc),
            });
        }
    }

    IocSummary {
        ioc_strings,
        ioc_counts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4() {
        assert_eq!(classify_ioc("192.168.1.1"), Some(IocType::Ipv4));
        assert_eq!(classify_ioc("10.0.0.255"), Some(IocType::Ipv4));
        assert_eq!(classify_ioc("999.999.999.999"), None); // Invalid octets
    }

    #[test]
    fn test_ipv6() {
        assert_eq!(
            classify_ioc("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            Some(IocType::Ipv6)
        );
    }

    #[test]
    fn test_url() {
        assert_eq!(
            classify_ioc("https://evil.com/payload"),
            Some(IocType::Url)
        );
        assert_eq!(classify_ioc("http://10.0.0.1/cmd"), Some(IocType::Url));
    }

    #[test]
    fn test_domain() {
        assert_eq!(classify_ioc("evil.onion"), Some(IocType::Domain));
        assert_eq!(classify_ioc("c2.malware.xyz"), Some(IocType::Domain));
    }

    #[test]
    fn test_email() {
        assert_eq!(classify_ioc("attacker@evil.com"), Some(IocType::Email));
    }

    #[test]
    fn test_registry() {
        assert_eq!(
            classify_ioc("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft"),
            Some(IocType::RegistryKey)
        );
    }

    #[test]
    fn test_windows_path() {
        assert_eq!(
            classify_ioc("C:\\Windows\\System32\\cmd.exe"),
            Some(IocType::WindowsPath)
        );
    }

    #[test]
    fn test_linux_path() {
        assert_eq!(classify_ioc("/etc/passwd"), Some(IocType::LinuxPath));
        assert_eq!(classify_ioc("/tmp/malware.sh"), Some(IocType::LinuxPath));
    }

    #[test]
    fn test_base64() {
        let b64 = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUk=";
        assert_eq!(classify_ioc(b64), Some(IocType::Base64Blob));
    }

    #[test]
    fn test_no_match() {
        assert_eq!(classify_ioc("hello world"), None);
        assert_eq!(classify_ioc("ab"), None); // too short
    }

    #[test]
    fn test_extract_iocs() {
        let strings = vec![
            ("192.168.1.1".to_string(), 100),
            ("hello world".to_string(), 200),
            ("https://evil.com/payload".to_string(), 300),
        ];
        let summary = extract_iocs(&strings);
        assert_eq!(summary.ioc_strings.len(), 2);
        assert_eq!(summary.ioc_counts.get("ipv4"), Some(&1));
        assert_eq!(summary.ioc_counts.get("url"), Some(&1));
    }
}
