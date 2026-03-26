// Ányá - Malware Analysis Platform
// IOC (Indicator of Compromise) detection module
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later
//
// The implementation now lives in the anya-scoring crate.
// This module re-exports everything for backward compatibility.

pub use anya_scoring::ioc::{classify_ioc, extract_iocs, ioc_type_to_category};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::IocType;

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
        assert_eq!(classify_ioc("https://evil.com/payload"), Some(IocType::Url));
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
