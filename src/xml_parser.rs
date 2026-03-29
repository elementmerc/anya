// XML / SVG file static analysis
// Detects XXE, external entities, XSLT scripts, and SVG code injection

use crate::output::XmlAnalysis;
use regex::Regex;
use std::sync::LazyLock;

static RE_DTD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<!DOCTYPE\s").unwrap());
static RE_SYSTEM_ENTITY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<!ENTITY\s+\w+\s+SYSTEM\s").unwrap());
static RE_PUBLIC_ENTITY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<!ENTITY\s+\w+\s+PUBLIC\s").unwrap());
static RE_PARAMETER_ENTITY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<!ENTITY\s+%\s+\w+\s+SYSTEM\s").unwrap());
static RE_XSLT_SCRIPT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<(xsl|msxsl):script[\s>]").unwrap());
static RE_XSL_STYLESHEET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<xsl:stylesheet[\s>]").unwrap());
static RE_XINCLUDE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<xi:include[\s>]").unwrap());
static RE_SVG_SCRIPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<script[\s>]").unwrap());
static RE_SVG_ONLOAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bonload\s*=").unwrap());
static RE_SVG_FOREIGN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<foreignObject[\s>]").unwrap());
static RE_SVG_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<svg[\s>]").unwrap());

/// Analyse file bytes as XML/SVG. Returns None if no suspicious content.
pub fn detect_xml_analysis(data: &[u8]) -> Option<XmlAnalysis> {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return None,
    };

    // Must look like XML
    let trimmed = text.trim_start();
    if !trimmed.starts_with("<?xml")
        && !trimmed.starts_with("<!DOCTYPE")
        && !trimmed.starts_with('<')
    {
        return None;
    }

    let has_dtd = RE_DTD.is_match(text);
    let has_external_entities = RE_SYSTEM_ENTITY.is_match(text)
        || RE_PUBLIC_ENTITY.is_match(text)
        || RE_PARAMETER_ENTITY.is_match(text);
    let has_xslt_scripts = RE_XSLT_SCRIPT.is_match(text)
        || (RE_XSL_STYLESHEET.is_match(text) && text.contains("script"));

    // SVG-specific checks
    let is_svg = RE_SVG_TAG.is_match(text);
    let is_svg_with_code = is_svg
        && (RE_SVG_SCRIPT.is_match(text)
            || RE_SVG_ONLOAD.is_match(text)
            || RE_SVG_FOREIGN.is_match(text));

    let mut suspicious: Vec<String> = Vec::new();

    if has_external_entities {
        suspicious.push("External entity declaration (XXE indicator)".into());
    }
    if RE_PARAMETER_ENTITY.is_match(text) {
        suspicious.push("Parameter entity (advanced XXE)".into());
    }
    if has_xslt_scripts {
        suspicious.push("XSLT with embedded scripts".into());
    }
    if RE_XINCLUDE.is_match(text) {
        suspicious.push("XInclude reference".into());
    }
    if is_svg_with_code {
        if RE_SVG_SCRIPT.is_match(text) {
            suspicious.push("SVG with embedded script".into());
        }
        if RE_SVG_ONLOAD.is_match(text) {
            suspicious.push("SVG with onload handler".into());
        }
        if RE_SVG_FOREIGN.is_match(text) {
            suspicious.push("SVG with foreignObject (HTML injection)".into());
        }
    }

    if suspicious.is_empty() {
        return None;
    }

    Some(XmlAnalysis {
        has_dtd,
        has_external_entities,
        has_xslt_scripts,
        is_svg_with_code,
        suspicious_elements: suspicious,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_xml() {
        let xml = b"<?xml version=\"1.0\"?><root><item>Hello</item></root>";
        assert!(detect_xml_analysis(xml).is_none());
    }

    #[test]
    fn test_xxe_detection() {
        let xml = br#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#;
        let r = detect_xml_analysis(xml).unwrap();
        assert!(r.has_external_entities);
        assert!(r.has_dtd);
    }

    #[test]
    fn test_svg_with_script() {
        let svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>";
        let r = detect_xml_analysis(svg).unwrap();
        assert!(r.is_svg_with_code);
    }

    #[test]
    fn test_xslt_script() {
        let xml = br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:script>code</xsl:script></xsl:stylesheet>"#;
        let r = detect_xml_analysis(xml).unwrap();
        assert!(r.has_xslt_scripts);
    }
}
