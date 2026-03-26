// Stub — real IOC patterns are in the private anya-proprietary repository.

use crate::types::{IocSummary, IocType};

pub fn classify_ioc(_s: &str) -> Option<IocType> {
    None
}
pub fn ioc_type_to_category(_ioc: &IocType) -> String {
    String::new()
}
pub fn extract_iocs(_strings: &[(String, usize)]) -> IocSummary {
    IocSummary {
        ioc_strings: Vec::new(),
        ioc_counts: std::collections::HashMap::new(),
    }
}
