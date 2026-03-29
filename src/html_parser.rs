// HTML / HTA file static analysis
// Detection patterns loaded from private scoring crate.

use crate::output::HtmlAnalysis;
use anya_scoring::detection_patterns::HTML_SUSPICIOUS_PATTERNS;
use regex::Regex;
use std::sync::LazyLock;

/// Pattern indices matching HTML_SUSPICIOUS_PATTERNS order
const IDX_SCRIPT_TAG: usize = 0;
const IDX_VBSCRIPT: usize = 1;
const IDX_EVENT_HANDLER: usize = 2;
const IDX_HIDDEN_IFRAME: usize = 3;
const IDX_OBJECT_EMBED: usize = 4;
const IDX_FORM_ACTION: usize = 5;
const IDX_META_REFRESH: usize = 6;
const IDX_DATA_URI: usize = 7;
const IDX_MSHTA: usize = 8;
const IDX_ACTIVEX: usize = 9;

static HTML_COMPILED: LazyLock<Vec<Option<Regex>>> = LazyLock::new(|| {
    HTML_SUSPICIOUS_PATTERNS
        .iter()
        .map(|pat| Regex::new(pat).ok())
        .collect()
});

fn matches(idx: usize, text: &str) -> bool {
    HTML_COMPILED
        .get(idx)
        .and_then(|r| r.as_ref())
        .is_some_and(|r| r.is_match(text))
}

fn count_matches(idx: usize, text: &str) -> usize {
    match HTML_COMPILED.get(idx).and_then(|r| r.as_ref()) {
        Some(r) => r.find_iter(text).count(),
        None => 0,
    }
}

/// Analyse file bytes as HTML/HTA.
pub fn detect_html_analysis(data: &[u8]) -> Option<HtmlAnalysis> {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return None,
    };

    // Require HTML-like content
    let lower = text.to_lowercase();
    if !lower.contains("<html")
        && !lower.contains("<script")
        && !lower.contains("<!doctype")
        && !lower.contains("<head")
        && !lower.contains("<body")
        && !lower.contains("<hta:")
    {
        return None;
    }

    let script_count = count_matches(IDX_SCRIPT_TAG, text);
    let has_event_handlers = matches(IDX_EVENT_HANDLER, text);
    let has_hidden_iframes = matches(IDX_HIDDEN_IFRAME, text);
    let has_embedded_objects = matches(IDX_OBJECT_EMBED, text) || matches(IDX_ACTIVEX, text);
    let has_form_actions = matches(IDX_FORM_ACTION, text);
    let has_meta_refresh = matches(IDX_META_REFRESH, text);
    let has_data_uris = matches(IDX_DATA_URI, text);

    let mut suspicious: Vec<String> = Vec::new();

    if script_count > 0 {
        suspicious.push(format!("{script_count} script tag(s)"));
    }
    if matches(IDX_VBSCRIPT, text) {
        suspicious.push("VBScript block".into());
    }
    if has_event_handlers {
        suspicious.push("Inline event handlers".into());
    }
    if has_hidden_iframes {
        suspicious.push("Hidden iframe".into());
    }
    if has_embedded_objects {
        suspicious.push("Embedded object/ActiveX".into());
    }
    if has_form_actions {
        suspicious.push("Form with action target".into());
    }
    if has_meta_refresh {
        suspicious.push("Meta refresh redirect".into());
    }
    if has_data_uris {
        suspicious.push("Base64 data: URI".into());
    }
    if matches(IDX_MSHTA, text) {
        suspicious.push("MSHTA reference".into());
    }

    if suspicious.is_empty() {
        return None;
    }

    Some(HtmlAnalysis {
        script_count,
        has_event_handlers,
        has_hidden_iframes,
        has_embedded_objects,
        has_form_actions,
        has_meta_refresh,
        has_data_uris,
        suspicious_elements: suspicious,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_html() {
        let html = b"<html><body><p>Hello World</p></body></html>";
        assert!(detect_html_analysis(html).is_none());
    }

    #[test]
    fn test_html_with_script() {
        let html = b"<html><body><script>alert(1)</script></body></html>";
        let r = detect_html_analysis(html).unwrap();
        assert_eq!(r.script_count, 1);
    }

    #[test]
    fn test_hidden_iframe() {
        let html =
            b"<html><body><iframe src='http://evil.com' width=0 height=0></iframe></body></html>";
        let r = detect_html_analysis(html).unwrap();
        assert!(r.has_hidden_iframes);
    }

    #[test]
    fn test_event_handler() {
        let html = b"<html><body onload='alert(1)'></body></html>";
        let r = detect_html_analysis(html).unwrap();
        assert!(r.has_event_handlers);
    }
}
