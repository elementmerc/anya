// Detection patterns and signature lists.

use std::sync::LazyLock;

// Packer byte signatures
pub static PACKER_SIGNATURE_PATTERNS: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    vec![
        b"UPX0".to_vec(),
        b"UPX1".to_vec(),
        b"UPX!".to_vec(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ]
});

pub const SIG_UPX0: usize = 0;
pub const SIG_UPX1: usize = 1;
pub const SIG_UPX_BANG: usize = 2;
pub const SIG_ASPACK: usize = 3;
pub const SIG_THEMIDA: usize = 4;
pub const SIG_VMPROTECT: usize = 5;
pub const SIG_GO_BUILDID: usize = 6;
pub const SIG_RUST_UNWIND: usize = 7;
pub const SIG_RUST_UNWIND2: usize = 8;
pub const SIG_MEIPASS2: usize = 9;
pub const SIG_PYINSTALLER: usize = 10;
pub const SIG_EMBARCADERO: usize = 11;
pub const SIG_BORLAND: usize = 12;
pub const SIG_GCC: usize = 13;

pub static PACKER_SECTION_NAMES: LazyLock<Vec<(&'static str, &'static str)>> =
    LazyLock::new(|| vec![("UPX0", "UPX"), ("UPX1", "UPX")]);

// Anti-analysis API detection
pub static VM_DETECTION_APIS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["IsDebuggerPresent".to_string()]);
pub static DEBUGGER_DETECTION_APIS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["IsDebuggerPresent".to_string()]);
pub static TIMING_APIS: LazyLock<Vec<String>> = LazyLock::new(|| vec!["GetTickCount".to_string()]);

pub static ELF_SUSPICIOUS_FUNCTIONS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["ptrace".to_string()]);
pub static ELF_EXPLOIT_FUNCTIONS: LazyLock<Vec<String>> = LazyLock::new(Vec::new);
pub static ELF_STANDARD_INTERP_PREFIXES: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["/lib".to_string()]);
pub static ELF_SUSPICIOUS_RPATH_PATTERNS: LazyLock<Vec<String>> = LazyLock::new(Vec::new);
pub static ELF_STANDARD_SECTION_PREFIXES: LazyLock<Vec<String>> =
    LazyLock::new(|| vec![".".to_string()]);

pub static COMMAND_KEYWORDS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["cmd.exe".to_string(), "powershell".to_string()]);
pub static REGISTRY_KEYWORDS: LazyLock<Vec<String>> = LazyLock::new(|| vec!["HKEY_".to_string()]);

// Entropy thresholds
pub const ENTROPY_VERY_HIGH: f64 = 7.99;
pub const ENTROPY_HIGH: f64 = 7.95;
pub const ENTROPY_MODERATE_HIGH: f64 = 7.8;
pub const ENTROPY_MODERATE: f64 = 7.5;
pub const OVERLAY_HIGH_ENTROPY_THRESHOLD: f64 = 7.9;
pub const SECTION_SUSPICIOUS_ENTROPY: f64 = 7.8;
pub const PACKER_ENTROPY_EXEC: f64 = 7.95;
pub const PACKER_ENTROPY_ALL: f64 = 7.9;

pub fn is_vm_detection_api(name: &str) -> bool {
    name == "IsDebuggerPresent"
}
pub fn is_debugger_detection_api(name: &str) -> bool {
    name == "IsDebuggerPresent"
}
pub fn is_timing_api(name: &str) -> bool {
    name == "GetTickCount"
}
pub fn is_elf_suspicious_function(name: &str) -> bool {
    name == "ptrace"
}
pub fn is_elf_exploit_function(_name: &str) -> bool {
    false
}
pub fn is_standard_elf_interpreter(path: &str) -> bool {
    path.starts_with("/lib")
}
pub fn is_suspicious_rpath(_path: &str) -> bool {
    false
}
pub fn is_standard_elf_section(name: &str) -> bool {
    name.starts_with('.')
}

// Packed score weights
pub fn packed_weight_virtual_raw_ratio() -> u32 {
    2
}
pub fn packed_weight_empty_import_table() -> u32 {
    1
}
pub fn packed_weight_zero_imports() -> u32 {
    1
}
pub fn packed_weight_ep_in_last_section() -> u32 {
    1
}
pub fn packed_weight_ep_outside_sections() -> u32 {
    2
}
pub fn packed_weight_zero_size_of_code() -> u32 {
    1
}
pub fn packed_weight_raw_zero_virtual_large() -> u32 {
    1
}
pub fn packed_weight_few_sections() -> u32 {
    1
}
pub fn packed_weight_timestamp_anomaly() -> u32 {
    1
}
pub fn packed_weight_missing_rich_header() -> u32 {
    1
}
pub fn packed_weight_entropy_classic_pack() -> u32 {
    2
}
pub fn packed_weight_entropy_uniform_moderate() -> u32 {
    1
}

// Script parser patterns
pub static JS_SUSPICIOUS_PATTERNS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["eval(".to_string()]);
pub static JS_OBFUSCATION_PATTERNS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["\\x".to_string()]);
pub static PS_SUSPICIOUS_PATTERNS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["-EncodedCommand".to_string()]);
pub static VBS_SUSPICIOUS_KEYWORDS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["CreateObject".to_string()]);
pub static SHELL_SUSPICIOUS_PATTERNS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["curl".to_string()]);
pub static PYTHON_SUSPICIOUS_PATTERNS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["exec(".to_string()]);
pub static OLE_MACRO_STREAM_NAMES: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| vec![b"VBA".to_vec()]);
pub static OLE_AUTO_EXECUTE_NAMES: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["AutoOpen".to_string()]);
pub static OLE_SUSPICIOUS_KEYWORDS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["Shell".to_string()]);
pub static HTML_SUSPICIOUS_PATTERNS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["<script".to_string()]);
pub static LNK_SUSPICIOUS_TARGETS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["cmd.exe".to_string()]);
pub static MSI_SUSPICIOUS_PATTERNS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["CustomAction".to_string()]);
pub static EXECUTABLE_EXTENSIONS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["exe".to_string(), "dll".to_string()]);
