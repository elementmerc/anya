// Anya scoring module.

pub static SUSPICIOUS_APIS_TIER1: &[&str] = &[];
pub static NOTEWORTHY_APIS: &[&str] = &[];

pub fn is_suspicious_api(_name: &str) -> bool {
    false
}
pub fn is_noteworthy_api(_name: &str) -> bool {
    false
}
pub fn categorize_api(_name: &str) -> &'static str {
    "unknown"
}
