// Python script static analysis
// Detection patterns loaded from private scoring crate.

use crate::output::PythonAnalysis;
use anya_scoring::detection_patterns::PYTHON_SUSPICIOUS_PATTERNS;
use regex::Regex;
use std::sync::LazyLock;

/// Pattern indices matching PYTHON_SUSPICIOUS_PATTERNS order
const IDX_EXEC: usize = 0;
const IDX_DUNDER_IMPORT: usize = 1;
const IDX_SUBPROCESS: usize = 2;
const IDX_SOCKET: usize = 3;
const IDX_URLLIB: usize = 4;
const IDX_CTYPES: usize = 5;
const IDX_B64_DECODE: usize = 6;
const IDX_MARSHAL: usize = 7;

static PY_COMPILED: LazyLock<Vec<Option<Regex>>> = LazyLock::new(|| {
    PYTHON_SUSPICIOUS_PATTERNS
        .iter()
        .map(|pat| Regex::new(pat).ok())
        .collect()
});

fn matches(idx: usize, text: &str) -> bool {
    PY_COMPILED
        .get(idx)
        .and_then(|r| r.as_ref())
        .is_some_and(|r| r.is_match(text))
}

/// Analyse file bytes as Python script.
pub fn detect_python_analysis(data: &[u8]) -> Option<PythonAnalysis> {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let has_exec_eval = matches(IDX_EXEC, text) || matches(IDX_DUNDER_IMPORT, text);
    let has_subprocess = matches(IDX_SUBPROCESS, text);
    let has_network = matches(IDX_SOCKET, text) || matches(IDX_URLLIB, text);
    let has_native_code = matches(IDX_CTYPES, text);

    let mut obf: Vec<String> = Vec::new();
    let mut imports: Vec<String> = Vec::new();

    if matches(IDX_B64_DECODE, text) && has_exec_eval {
        obf.push("Base64 decode + exec".into());
    }
    if matches(IDX_MARSHAL, text) {
        obf.push("marshal/pickle deserialization".into());
    }

    if has_subprocess {
        imports.push("subprocess".into());
    }
    if has_native_code {
        imports.push("ctypes".into());
    }
    if has_network {
        imports.push("network".into());
    }

    if !has_exec_eval && !has_subprocess && !has_network && !has_native_code && obf.is_empty() {
        return None;
    }

    Some(PythonAnalysis {
        has_exec_eval,
        has_subprocess,
        has_network,
        has_native_code,
        obfuscation_indicators: obf,
        suspicious_imports: imports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_python() {
        let code = "def hello():\n    print('Hello World')\nhello()";
        assert!(detect_python_analysis(code.as_bytes()).is_none());
    }

    #[test]
    fn test_exec_eval() {
        let code = "import base64\nexec(base64.b64decode('cHJpbnQoJ2hlbGxvJyk='))";
        let r = detect_python_analysis(code.as_bytes()).unwrap();
        assert!(r.has_exec_eval);
    }

    #[test]
    fn test_subprocess() {
        let code = b"import subprocess\nsubprocess.Popen(['cmd', '/c', 'calc'])";
        let r = detect_python_analysis(code).unwrap();
        assert!(r.has_subprocess);
    }

    #[test]
    fn test_socket_network() {
        let code = b"import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)";
        let r = detect_python_analysis(code).unwrap();
        assert!(r.has_network);
    }
}
