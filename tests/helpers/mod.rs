/// Minimal valid PE binary builder for integration tests.
/// Produces a 1024-byte PE32+ (AMD64) executable that goblin can parse.
///
/// Layout:
///   0x000  DOS header (64 bytes)          e_lfanew = 0x40
///   0x040  PE signature "PE\0\0"
///   0x044  COFF header (20 bytes)
///   0x058  PE32+ optional header (240 bytes)
///   0x148  Section table: 1 × .text (40 bytes)
///   0x200  Section data: 512 bytes of zeros
fn write_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Build a minimal valid PE32+ (x86-64) EXE with ASLR + DEP enabled.
/// One .text section filled with zeros (entropy = 0, not W+X).
pub fn build_minimal_pe() -> Vec<u8> {
    let mut data = vec![0u8; 0x400];

    // ── DOS header ─────────────────────────────────────────────────────────
    data[0x00] = 0x4D; // 'M'
    data[0x01] = 0x5A; // 'Z'
    write_u32(&mut data, 0x3C, 0x40); // e_lfanew

    // ── PE signature ───────────────────────────────────────────────────────
    data[0x40..0x44].copy_from_slice(b"PE\x00\x00");

    // ── COFF header (at 0x44) ─────────────────────────────────────────────
    write_u16(&mut data, 0x44, 0x8664); // Machine: AMD64
    write_u16(&mut data, 0x46, 0x0001); // NumberOfSections
    write_u16(&mut data, 0x54, 0x00F0); // SizeOfOptionalHeader = 240
    write_u16(&mut data, 0x56, 0x0002); // Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE

    // ── PE32+ optional header (at 0x58) ───────────────────────────────────
    write_u16(&mut data, 0x58, 0x020B); // Magic: PE32+
    write_u32(&mut data, 0x5C, 0x0200); // SizeOfCode
    write_u32(&mut data, 0x68, 0x1000); // AddressOfEntryPoint
    write_u32(&mut data, 0x6C, 0x1000); // BaseOfCode
    write_u64(&mut data, 0x70, 0x140000000); // ImageBase
    write_u32(&mut data, 0x78, 0x1000); // SectionAlignment
    write_u32(&mut data, 0x7C, 0x0200); // FileAlignment
    write_u16(&mut data, 0x80, 0x0006); // MajorOSVersion
    write_u16(&mut data, 0x88, 0x0006); // MajorSubsystemVersion
    write_u32(&mut data, 0x90, 0x2000); // SizeOfImage
    write_u32(&mut data, 0x94, 0x0200); // SizeOfHeaders
    // CheckSum stays 0 at 0x98
    write_u16(&mut data, 0x9C, 0x0003); // Subsystem: console
    write_u16(&mut data, 0x9E, 0x0140); // DllCharacteristics: ASLR(0x40) + DEP(0x100)
    write_u64(&mut data, 0xA0, 0x100000); // SizeOfStackReserve
    write_u64(&mut data, 0xA8, 0x1000); // SizeOfStackCommit
    write_u64(&mut data, 0xB0, 0x100000); // SizeOfHeapReserve
    write_u64(&mut data, 0xB8, 0x1000); // SizeOfHeapCommit
    write_u32(&mut data, 0xC4, 0x10); // NumberOfRvaAndSizes = 16
    // DataDirectory entries (16 × 8 bytes) all stay zero

    // ── Section table: .text (at 0x148) ───────────────────────────────────
    data[0x148..0x150].copy_from_slice(b".text\x00\x00\x00"); // Name
    write_u32(&mut data, 0x150, 0x0010); // VirtualSize
    write_u32(&mut data, 0x154, 0x1000); // VirtualAddress
    write_u32(&mut data, 0x158, 0x0200); // SizeOfRawData
    write_u32(&mut data, 0x15C, 0x0200); // PointerToRawData
    write_u32(&mut data, 0x16C, 0x60000020); // Characteristics: CODE | MEM_READ | MEM_EXEC

    // ── Section data: 512 zeros (already zeroed by vec! initialiser) ───────

    data
}

/// Same as `build_minimal_pe` but with no security flags (ASLR and DEP disabled).
pub fn build_minimal_pe_no_security() -> Vec<u8> {
    let mut data = build_minimal_pe();
    write_u16(&mut data, 0x9E, 0x0000); // DllCharacteristics = 0
    data
}

/// A minimal PE32+ DLL (IMAGE_FILE_DLL bit set in COFF characteristics).
pub fn build_minimal_dll() -> Vec<u8> {
    let mut data = build_minimal_pe();
    // Set IMAGE_FILE_DLL (0x2000) in COFF Characteristics (at 0x56)
    write_u16(&mut data, 0x56, 0x2002); // EXECUTABLE_IMAGE | DLL
    data
}

/// A minimal PE32+ with IMAGE_SUBSYSTEM_NATIVE (kernel driver, value 1).
pub fn build_minimal_driver() -> Vec<u8> {
    let mut data = build_minimal_pe();
    // Set Subsystem = IMAGE_SUBSYSTEM_NATIVE (1) at offset 0x9C
    write_u16(&mut data, 0x9C, 0x0001);
    data
}
