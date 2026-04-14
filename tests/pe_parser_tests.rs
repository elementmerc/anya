/// Integration tests for pe_parser::analyse_pe_data()
///
/// These tests use a handcrafted minimal PE32+ binary so they do not depend on
/// any external sample file and run offline.
mod helpers;

use anya_security_core::pe_parser::analyse_pe_data;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Append `extra` bytes to a PE so the overlay-detection path fires.
fn with_overlay(extra: &[u8]) -> Vec<u8> {
    let mut data = helpers::build_minimal_pe();
    data.extend_from_slice(extra);
    data
}

// ─── Basic parsing ────────────────────────────────────────────────────────────

#[test]
fn test_analyse_pe_data_success() {
    let data = helpers::build_minimal_pe();
    let result = analyse_pe_data(&data);
    assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
}

#[test]
fn test_analyse_pe_rejects_garbage() {
    let garbage = b"This is not a PE file at all".to_vec();
    let result = analyse_pe_data(&garbage);
    assert!(result.is_err(), "Expected Err for garbage input");
}

// ─── Architecture / format ───────────────────────────────────────────────────

#[test]
fn test_pe_architecture_64bit() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert_eq!(pe.architecture, "PE32+ (64-bit)");
    assert!(pe.is_64bit);
}

#[test]
fn test_pe_image_base() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert_eq!(pe.image_base, "0x140000000");
}

#[test]
fn test_pe_entry_point() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert_eq!(pe.entry_point, "0x1000");
}

// ─── File type ───────────────────────────────────────────────────────────────

#[test]
fn test_pe_file_type_exe() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert_eq!(pe.file_type, "EXE");
}

#[test]
fn test_pe_file_type_dll() {
    let pe = analyse_pe_data(&helpers::build_minimal_dll()).unwrap();
    assert_eq!(pe.file_type, "DLL");
}

// ─── Security features ───────────────────────────────────────────────────────

#[test]
fn test_pe_aslr_dep_enabled() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert!(pe.security.aslr_enabled, "ASLR should be enabled");
    assert!(pe.security.dep_enabled, "DEP should be enabled");
}

#[test]
fn test_pe_security_disabled() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe_no_security()).unwrap();
    assert!(!pe.security.aslr_enabled, "ASLR should be disabled");
    assert!(!pe.security.dep_enabled, "DEP should be disabled");
}

// ─── Sections ────────────────────────────────────────────────────────────────

#[test]
fn test_pe_section_count() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert_eq!(pe.sections.len(), 1);
}

#[test]
fn test_pe_section_name() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert_eq!(pe.sections[0].name, ".text");
}

#[test]
fn test_pe_section_not_wx() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert!(!pe.sections[0].is_wx, ".text should not be W+X");
}

#[test]
fn test_pe_section_zero_entropy() {
    // Section data is 512 bytes of zeros, so entropy should be 0
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert_eq!(pe.sections[0].entropy, 0.0);
    assert!(!pe.sections[0].is_suspicious);
}

// ─── Imports ─────────────────────────────────────────────────────────────────

#[test]
fn test_pe_no_imports() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert_eq!(pe.imports.dll_count, 0);
    assert_eq!(pe.imports.total_imports, 0);
    assert_eq!(pe.imports.suspicious_api_count, 0);
    assert!(pe.imports.suspicious_apis.is_empty());
    assert!(pe.imports.libraries.is_empty());
}

#[test]
fn test_pe_no_ordinal_imports() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert!(pe.ordinal_imports.is_empty());
}

#[test]
fn test_pe_imphash_none_when_no_imports() {
    // imphash is None when there are no named imports to hash
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert!(pe.imphash.is_none());
}

// ─── Checksum ────────────────────────────────────────────────────────────────

#[test]
fn test_pe_checksum_zero_stored() {
    // Our PE has CheckSum = 0 (common in user-mode and malware)
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    let cs = pe.checksum.as_ref().expect("checksum field should be Some");
    assert_eq!(cs.stored, 0);
    assert!(
        !cs.stored_nonzero,
        "stored_nonzero should be false when checksum is 0"
    );
}

// ─── Overlay ─────────────────────────────────────────────────────────────────

#[test]
fn test_pe_no_overlay_for_exact_size() {
    // The minimal PE is exactly 1024 bytes; last section ends at 0x400.
    // No overlay should be detected.
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert!(
        pe.overlay.is_none(),
        "No overlay expected for exact-size PE"
    );
}

#[test]
fn test_pe_overlay_detected_when_extra_bytes_appended() {
    let extra = vec![0xAB; 128];
    let data = with_overlay(&extra);
    let pe = analyse_pe_data(&data).unwrap();
    let overlay = pe.overlay.as_ref().expect("Overlay should be detected");
    assert_eq!(overlay.size, 128);
}

// ─── Rich header / TLS / Packers / Anti-analysis ────────────────────────────

#[test]
fn test_pe_no_rich_header_when_e_lfanew_is_small() {
    // e_lfanew = 0x40, which is <= 0x80, so no room for a Rich header
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert!(pe.rich_header.is_none());
}

#[test]
fn test_pe_no_tls_callbacks() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    // TLS directory is zero — no callbacks
    assert!(pe.tls.is_none());
}

#[test]
fn test_pe_no_packers_detected() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert!(
        pe.packers.is_empty(),
        "No packers expected in clean minimal PE"
    );
}

#[test]
fn test_pe_no_anti_analysis_indicators() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert!(
        pe.anti_analysis.is_empty(),
        "No anti-analysis indicators expected (no imports)"
    );
}

// ── Driver detection tests ──────────────────────────────────────────────────

#[test]
fn test_pe_driver_detected_for_native_subsystem() {
    let data = helpers::build_minimal_driver();
    let pe = analyse_pe_data(&data).unwrap();
    assert!(
        pe.driver_analysis.is_some(),
        "Driver analysis should be present for IMAGE_SUBSYSTEM_NATIVE"
    );
    let driver = pe.driver_analysis.unwrap();
    assert!(driver.is_kernel_driver);
}

#[test]
fn test_pe_no_driver_for_console_subsystem() {
    let pe = analyse_pe_data(&helpers::build_minimal_pe()).unwrap();
    assert!(
        pe.driver_analysis.is_none(),
        "Normal console PE should not have driver analysis"
    );
}

#[test]
fn test_pe_driver_no_ntoskrnl_imports() {
    let data = helpers::build_minimal_driver();
    let pe = analyse_pe_data(&data).unwrap();
    let driver = pe.driver_analysis.unwrap();
    // Minimal PE has no imports, so ntoskrnl should not be detected
    assert!(!driver.imports_ntoskrnl);
    assert!(!driver.imports_hal);
    assert!(driver.dangerous_kernel_apis.is_empty());
}

#[test]
fn test_pe_driver_unsigned() {
    let data = helpers::build_minimal_driver();
    let pe = analyse_pe_data(&data).unwrap();
    let driver = pe.driver_analysis.unwrap();
    // Minimal PE has no authenticode, so driver should be unsigned
    assert!(!driver.is_signed);
}
