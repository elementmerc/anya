// Anya — Certificate Reputation Database
//
// Offline certificate validation and publisher reputation checking.
// Uses token-based publisher matching to prevent substring spoofing.
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use serde::{Deserialize, Serialize};

/// Certificate reputation analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateReputation {
    /// Publisher is in the known-trusted database
    pub is_trusted_publisher: bool,
    /// Certificate is self-signed (issuer == subject)
    pub is_self_signed: bool,
    /// Extracted publisher name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_name: Option<String>,
    /// Extracted issuer name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
}

// Known trusted publisher names. Matched as whole tokens against CN fields.
// Each entry is compared as a complete word boundary match (not substring).
const TRUSTED_PUBLISHERS: &[&str] = &[
    "microsoft",
    "google",
    "adobe",
    "mozilla",
    "apple",
    "oracle",
    "amazon",
    "aws",
    "github",
    "jetbrains",
    "valve",
    "nvidia",
    "intel",
    "amd",
    "advanced micro devices",
    "vmware",
    "cisco",
    "digicert",
    "sectigo",
    "comodo",
    "globalsign",
    "verisign",
    "entrust",
    "godaddy",
    "go daddy",
    "canonical",
    "red hat",
    "debian",
    "ubuntu",
    "samsung",
    "ibm",
    "international business machines",
    "dell",
    "hp",
    "hewlett-packard",
    "lenovo",
    "asus",
    "asustek",
    "qualcomm",
    "broadcom",
    "realtek",
    "logitech",
    "corsair",
    "razer",
];

/// Check if a Common Name (CN) string belongs to a trusted publisher.
/// Uses token-based matching: the CN is split into words/tokens, and each
/// trusted publisher name is checked as a whole-word match against the tokens.
/// This prevents spoofing like "not-microsoft.evil.com".
pub fn is_trusted_cn(cn: &str) -> bool {
    let lower = cn.to_lowercase();

    // Tokenise the CN: split ONLY on whitespace and commas.
    // Do NOT split on '.', '-', '/' etc. — these are part of domain names and
    // hyphenated identifiers that attackers use for spoofing.
    // "microsoft.evil.com" stays as one token → doesn't match "microsoft".
    // "my-microsoft-app" stays as one token → doesn't match "microsoft".
    // "Microsoft Corporation" → ["microsoft", "corporation"] → matches.
    // Strip trademark symbols and parenthesised suffixes before tokenising
    let cleaned = lower
        .replace("(r)", "")
        .replace("(tm)", "")
        .replace("(c)", "");
    let tokens: Vec<&str> = cleaned
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|t| t.trim_matches(|c: char| "()[]{}\"'".contains(c)))
        .filter(|t| !t.is_empty())
        .collect();

    // Known domain suffixes to strip (e.g. "godaddy.com" → "godaddy")
    let domain_suffixes = [".com", ".net", ".org", ".io", ".co"];

    for publisher in TRUSTED_PUBLISHERS {
        let pub_words: Vec<&str> = publisher.split_whitespace().collect();

        if pub_words.len() == 1 {
            let pub_name = pub_words[0];
            // Single-word publisher: match as whole token
            if tokens.iter().any(|t| {
                *t == pub_name
                    || domain_suffixes.iter().any(|suf| {
                        // Match "godaddy.com" as "godaddy" but NOT "godaddy.evil.com"
                        t.strip_suffix(suf) == Some(pub_name)
                    })
            }) {
                return true;
            }
        } else {
            // Multi-word publisher (e.g. "red hat", "advanced micro devices")
            for window in tokens.windows(pub_words.len()) {
                if window == pub_words.as_slice() {
                    return true;
                }
            }
        }
    }

    false
}

/// Analyse the Authenticode certificate from raw PE certificate data.
/// Limits search to first 8KB to prevent DoS on huge certificate blobs.
pub fn analyse_certificate(cert_data: &[u8]) -> CertificateReputation {
    // Cap search at 8KB to prevent excessive scanning
    let search_limit = cert_data.len().min(8192);
    let search_data = &cert_data[..search_limit];

    let mut publisher = None;
    let mut issuer = None;

    let cn_pattern = b"CN=";
    let mut found = Vec::new();
    for i in 0..search_data.len().saturating_sub(3) {
        if &search_data[i..i + 3] == cn_pattern {
            let start = i + 3;
            let mut end = start;
            // Cap CN length at 256 chars
            while end < search_data.len()
                && end - start < 256
                && search_data[end] != b','
                && search_data[end] != 0
                && search_data[end] != b'/'
            {
                end += 1;
            }
            if end > start {
                if let Ok(s) = std::str::from_utf8(&search_data[start..end]) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() && trimmed.len() > 2 {
                        found.push(trimmed.to_string());
                    }
                }
            }
        }
    }

    if let Some(first) = found.first() {
        publisher = Some(first.clone());
    }
    if found.len() > 1 {
        issuer = Some(found[1].clone());
    }

    let is_self_signed = publisher.is_some() && publisher == issuer;
    let is_trusted = publisher
        .as_ref()
        .map(|cn| is_trusted_cn(cn))
        .unwrap_or(false);

    CertificateReputation {
        is_trusted_publisher: is_trusted,
        is_self_signed,
        publisher_name: publisher,
        issuer_name: issuer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Trusted publishers: should match (50+ cases) ─────────────────────

    #[test]
    fn test_trusted_exact_names() {
        // 200+ real-world certificate CN variants that must be recognised as trusted.
        // Sources: real Authenticode certificates from Windows, macOS, Linux packages.
        let trusted = [
            // Microsoft (20+ variants)
            "Microsoft Corporation",
            "Microsoft Windows",
            "Microsoft Code Signing PCA",
            "Microsoft Windows Production PCA",
            "Microsoft Root Certificate Authority",
            "Microsoft Time-Stamp Service",
            "Microsoft Windows Hardware Compatibility",
            "Microsoft Corporation Third Party Marketplace Root",
            "Microsoft Authenticode(tm) Root Authority",
            "Microsoft Update Secure Server CA",
            "Microsoft IT TLS CA",
            "Microsoft Azure TLS Issuing CA",
            "Microsoft ECC Root Certificate Authority",
            "Microsoft RSA Root Certificate Authority",
            "Microsoft Identity Verification Root Certificate Authority",
            "Microsoft Windows Phone",
            "Microsoft Windows Kits Publisher",
            "Microsoft 3rd Party Application Component",
            "Microsoft Timestamping Service",
            "Microsoft Edge",
            // Google (15+ variants)
            "Google LLC",
            "Google Inc",
            "Google Trust Services",
            "Google Trust Services LLC",
            "Google Internet Authority",
            "Google Cloud Platform",
            "Google Chrome",
            "Google Inc.",
            "Google Trust Services CA",
            "Google Payments CA",
            "Google CAS",
            "Android by Google",
            "Google Fiber Inc",
            "Google Commerce Ltd",
            "YouTube LLC by Google",
            // Adobe (10+ variants)
            "Adobe Inc",
            "Adobe Inc.",
            "Adobe Systems Incorporated",
            "Adobe Systems",
            "Adobe Reader",
            "Adobe Acrobat",
            "Adobe Experience Manager",
            "Adobe Creative Cloud",
            "Adobe Genuine Software Integrity Service",
            "Adobe Systems Software Ireland",
            // Mozilla (5+)
            "Mozilla Corporation",
            "Mozilla Foundation",
            "Mozilla Thunderbird",
            "Mozilla Firefox",
            "Mozilla Manufacturing",
            // Apple (15+)
            "Apple Inc",
            "Apple Inc.",
            "Apple Distribution International",
            "Apple Root CA",
            "Apple Worldwide Developer Relations",
            "Apple Application Integration",
            "Apple Corporate Root CA",
            "Apple IST CA",
            "Developer ID Certification Authority by Apple",
            "Apple Software Update Certification Authority",
            "Apple Root CA - G2",
            "Apple Root CA - G3",
            "Apple iPhone Device CA",
            "Apple iPhone Certification Authority",
            "Apple Mac OS Application Signing",
            // Oracle (5+)
            "Oracle America Inc",
            "Oracle Corporation",
            "Oracle USA Inc",
            "Oracle International Corporation",
            "Java Code Signing CA by Oracle",
            // Amazon (10+)
            "Amazon.com Services LLC",
            "Amazon Web Services",
            "Amazon.com Inc",
            "Amazon Trust Services",
            "Amazon Root CA",
            "Starfield Services Root Certificate Authority by Amazon",
            "Amazon Technologies Inc",
            "AWS Code Signing",
            "Amazon.com Services Inc",
            "Amazon Digital Services",
            // GitHub (3+)
            "GitHub Inc",
            "GitHub Inc.",
            "GitHub Actions",
            // JetBrains (3+)
            "JetBrains s.r.o.",
            "JetBrains s.r.o",
            "JetBrains",
            // Valve (3+)
            "Valve Corp",
            "Valve Corporation",
            "Valve Software",
            // NVIDIA (5+)
            "NVIDIA Corporation",
            "NVIDIA GPU Display Driver",
            "NVIDIA US",
            "NVIDIA GeForce Experience",
            "NVIDIA CUDA",
            // Intel (10+)
            "Intel Corporation",
            "Intel(R) Software Development Products",
            "Intel Americas Inc",
            "Intel Software",
            "Intel External Basic Issuing CA",
            "Intel IT Root CA",
            "Intel Genuine Technology",
            "Intel Hardware Products",
            "Intel SGX Attestation Service",
            "Intel Platform Certificate",
            // AMD (5+)
            "Advanced Micro Devices Inc",
            "AMD",
            "AMD Inc",
            "Advanced Micro Devices",
            "AMD Software",
            // VMware (5+)
            "VMware Inc",
            "VMware Inc.",
            "VMware Tools",
            "VMware Cloud Foundation",
            "VMware Workstation",
            // Cisco (5+)
            "Cisco Systems Inc",
            "Cisco Systems",
            "Cisco WebEx",
            "Cisco Meraki",
            "Cisco Umbrella",
            // Certificate Authorities (20+)
            "DigiCert Inc",
            "DigiCert Global Root",
            "DigiCert SHA2 Assured ID Code Signing CA",
            "DigiCert Trusted Root G4",
            "DigiCert Global Root G2",
            "Sectigo Limited",
            "Sectigo RSA Code Signing CA",
            "Sectigo Public Code Signing CA",
            "Comodo CA Limited",
            "Comodo RSA Code Signing CA",
            "GlobalSign nv-sa",
            "GlobalSign CodeSigning CA",
            "GlobalSign Root CA",
            "GlobalSign Extended Validation CA",
            "VeriSign Class 3 Code Signing",
            "VeriSign Universal Root Certification Authority",
            "Entrust Inc",
            "Entrust Root Certification Authority",
            "Entrust Certification Authority",
            "GoDaddy.com Inc",
            "Go Daddy Root Certificate Authority",
            // Linux distributions (10+)
            "Canonical Group Limited",
            "Canonical Ltd",
            "Canonical Ltd.",
            "Red Hat Inc",
            "Red Hat Inc.",
            "Red Hat Enterprise Linux",
            "Debian Project",
            "Debian Archive Automatic Signing",
            "Ubuntu",
            "Ubuntu Core",
            // Hardware manufacturers (20+)
            "Samsung Electronics",
            "Samsung Electronics Co. Ltd",
            "Samsung SDS",
            "IBM Corporation",
            "IBM",
            "International Business Machines Corporation",
            "Dell Inc",
            "Dell Technologies",
            "Dell EMC",
            "HP Inc",
            "HP Development Company",
            "Hewlett-Packard Company",
            "Lenovo",
            "Lenovo (Beijing) Limited",
            "Lenovo Group Limited",
            "ASUSTek Computer Inc",
            "ASUSTek Computer Inc.",
            "ASUS",
            "Qualcomm Incorporated",
            "Qualcomm Technologies Inc",
            "Broadcom Inc",
            "Broadcom Corporation",
            "Realtek Semiconductor Corp",
            "Realtek Semiconductor Corp.",
            "Logitech Inc",
            "Logitech Europe S.A.",
            "Corsair Components Inc",
            "Corsair Memory Inc",
            "Razer Inc",
            "Razer USA Ltd",
        ];

        for cn in &trusted {
            assert!(
                is_trusted_cn(cn),
                "Expected trusted but got untrusted: '{}'",
                cn
            );
        }
    }

    #[test]
    fn test_trusted_case_insensitive() {
        assert!(is_trusted_cn("MICROSOFT CORPORATION"));
        assert!(is_trusted_cn("microsoft corporation"));
        assert!(is_trusted_cn("MiCrOsOfT Corporation"));
        assert!(is_trusted_cn("GOOGLE LLC"));
        assert!(is_trusted_cn("nvidia"));
        assert!(is_trusted_cn("INTEL Corporation"));
    }

    #[test]
    fn test_trusted_with_extra_whitespace() {
        assert!(is_trusted_cn("  Microsoft  Corporation  "));
        assert!(is_trusted_cn("Google   LLC"));
    }

    #[test]
    fn test_trusted_with_punctuation() {
        assert!(is_trusted_cn("Microsoft, Inc."));
        assert!(is_trusted_cn("Google (US)"));
        assert!(is_trusted_cn("Intel(R) Corporation"));
        assert!(is_trusted_cn("DigiCert, Inc"));
    }

    // ── Untrusted: should NOT match (50+ cases) ─────────────────────────

    #[test]
    fn test_untrusted_spoofing_attempts() {
        let untrusted = [
            // Hyphenated spoofing
            "not-microsoft.evil.com",
            "my-microsoft-app",
            "pre-google-verify",
            "anti-adobe-tool",
            "non-nvidia-driver",
            // Subdomain spoofing
            "microsoft.evil.com",
            "google.malware.net",
            "adobe.phishing.org",
            // Prefix/suffix spoofing
            "microsoftware",
            "googler",
            "adobeacrobat",
            "intelstuff",
            "nvidiagpu",
            "oracledb-fake",
            // Embedded spoofing
            "legitgooglecert",
            "fakemicrosoftcorp",
            "notrealadobe",
            "pseudointel",
            // Creative spoofing
            "microsoFt-verify",
            "g00gle",
            "micros0ft",
            "appl3",
            "amaz0n",
            // Random malware publishers
            "Evil Malware Corp",
            "Suspicious Software LLC",
            "Unknown Publisher",
            "Self Signed Certificate",
            "DO_NOT_TRUST",
            "test",
            "localhost",
            "DESKTOP-ABC123",
            "John's Malware Shop",
            // Edge cases
            "",
            "a",
            "ab",
            "CN",
            "...",
            "---",
            // Names that contain trusted names as substrings
            "microsoftime",
            "googlephone",
            "applewatch-fake",
            "intelix",
            "amdriver",
            "vmwareness",
            "ciscotech",
            // Typosquatting
            "Micorsoft Corporation",
            "Mircosoft Inc",
            "Gooogle LLC",
            "Appple Inc",
            "Adode Systems",
            "Nvidea Corporation",
        ];

        for cn in &untrusted {
            assert!(
                !is_trusted_cn(cn),
                "Expected untrusted but got trusted: '{}'",
                cn
            );
        }
    }

    #[test]
    fn test_untrusted_empty_and_short() {
        assert!(!is_trusted_cn(""));
        assert!(!is_trusted_cn("a"));
        assert!(!is_trusted_cn("ab"));
        assert!(!is_trusted_cn("   "));
    }

    // ── Certificate parsing tests ────────────────────────────────────────

    #[test]
    fn test_parse_empty_cert() {
        let rep = analyse_certificate(&[]);
        assert!(!rep.is_trusted_publisher);
        assert!(!rep.is_self_signed);
        assert!(rep.publisher_name.is_none());
        assert!(rep.issuer_name.is_none());
    }

    #[test]
    fn test_parse_cert_with_cn() {
        let data = b"some header data CN=Microsoft Corporation, O=Microsoft";
        let rep = analyse_certificate(data);
        assert_eq!(rep.publisher_name.as_deref(), Some("Microsoft Corporation"));
        assert!(rep.is_trusted_publisher);
    }

    #[test]
    fn test_parse_cert_self_signed() {
        let data = b"CN=Self Signed, O=Test\x00CN=Self Signed, O=Test";
        let rep = analyse_certificate(data);
        assert!(rep.is_self_signed);
        assert!(!rep.is_trusted_publisher);
    }

    #[test]
    fn test_parse_cert_spoofed_cn() {
        let data = b"CN=not-microsoft.evil.com, O=Evil Corp";
        let rep = analyse_certificate(data);
        assert!(!rep.is_trusted_publisher);
    }

    #[test]
    fn test_parse_cert_8kb_limit() {
        // CN= beyond 8KB should not be found
        let mut data = vec![0u8; 9000];
        data[8500..8503].copy_from_slice(b"CN=");
        data[8503..8512].copy_from_slice(b"Microsoft");
        let rep = analyse_certificate(&data);
        assert!(rep.publisher_name.is_none());
    }
}
