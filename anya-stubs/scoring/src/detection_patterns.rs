// Stub — real detection patterns are in the private anya-proprietary repository.

use std::sync::LazyLock;

pub static PACKER_SIGNATURE_PATTERNS: LazyLock<Vec<Vec<u8>>> = LazyLock::new(Vec::new);

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
    LazyLock::new(Vec::new);

pub static VM_DETECTION_APIS: LazyLock<Vec<String>> = LazyLock::new(Vec::new);
pub static DEBUGGER_DETECTION_APIS: LazyLock<Vec<String>> = LazyLock::new(Vec::new);
pub static TIMING_APIS: LazyLock<Vec<String>> = LazyLock::new(Vec::new);

pub static ELF_SUSPICIOUS_FUNCTIONS: LazyLock<Vec<String>> = LazyLock::new(Vec::new);
pub static ELF_EXPLOIT_FUNCTIONS: LazyLock<Vec<String>> = LazyLock::new(Vec::new);
pub static ELF_STANDARD_INTERP_PREFIXES: LazyLock<Vec<String>> = LazyLock::new(Vec::new);
pub static ELF_SUSPICIOUS_RPATH_PATTERNS: LazyLock<Vec<String>> = LazyLock::new(Vec::new);
pub static ELF_STANDARD_SECTION_PREFIXES: LazyLock<Vec<String>> = LazyLock::new(Vec::new);

pub static COMMAND_KEYWORDS: LazyLock<Vec<String>> = LazyLock::new(Vec::new);
pub static REGISTRY_KEYWORDS: LazyLock<Vec<String>> = LazyLock::new(Vec::new);

pub const ENTROPY_VERY_HIGH: f64 = 0.0;
pub const ENTROPY_HIGH: f64 = 0.0;
pub const ENTROPY_MODERATE_HIGH: f64 = 0.0;
pub const ENTROPY_MODERATE: f64 = 0.0;
pub const OVERLAY_HIGH_ENTROPY_THRESHOLD: f64 = 0.0;
pub const SECTION_SUSPICIOUS_ENTROPY: f64 = 0.0;
pub const PACKER_ENTROPY_EXEC: f64 = 0.0;
pub const PACKER_ENTROPY_ALL: f64 = 0.0;

pub fn is_vm_detection_api(_name: &str) -> bool {
    false
}
pub fn is_debugger_detection_api(_name: &str) -> bool {
    false
}
pub fn is_timing_api(_name: &str) -> bool {
    false
}
pub fn is_elf_suspicious_function(_name: &str) -> bool {
    false
}
pub fn is_elf_exploit_function(_name: &str) -> bool {
    false
}
pub fn is_standard_elf_interpreter(_path: &str) -> bool {
    true
}
pub fn is_suspicious_rpath(_path: &str) -> bool {
    false
}
pub fn is_standard_elf_section(_name: &str) -> bool {
    true
}

// Packed score weights (stubs return 0 — real values in private crate)
pub fn packed_weight_virtual_raw_ratio() -> u32 {
    0
}
pub fn packed_weight_empty_import_table() -> u32 {
    0
}
pub fn packed_weight_zero_imports() -> u32 {
    0
}
pub fn packed_weight_ep_in_last_section() -> u32 {
    0
}
pub fn packed_weight_ep_outside_sections() -> u32 {
    0
}
pub fn packed_weight_zero_size_of_code() -> u32 {
    0
}
pub fn packed_weight_raw_zero_virtual_large() -> u32 {
    0
}
pub fn packed_weight_few_sections() -> u32 {
    0
}
pub fn packed_weight_timestamp_anomaly() -> u32 {
    0
}
pub fn packed_weight_missing_rich_header() -> u32 {
    0
}
pub fn packed_weight_entropy_classic_pack() -> u32 {
    0
}
pub fn packed_weight_entropy_uniform_moderate() -> u32 {
    0
}
