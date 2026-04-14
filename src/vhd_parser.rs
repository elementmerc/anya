// VHD/VHDX disk image analysis
// Detects format version, disk size, and embedded executables

use crate::output::VhdAnalysis;

/// VHD footer cookie at offset 0 (fixed VHD) or last 512 bytes
const VHD_COOKIE: &[u8] = b"conectix";
/// VHDX file signature at offset 0
const VHDX_COOKIE: &[u8] = b"vhdxfile";

/// MZ magic for PE executables
const MZ_MAGIC: [u8; 2] = [0x4D, 0x5A];
/// ELF magic
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// Analyse file bytes as VHD/VHDX disk image. Returns None if not a valid
/// VHD/VHDX or no noteworthy content found.
pub fn detect_vhd_analysis(data: &[u8]) -> Option<VhdAnalysis> {
    if data.len() < 512 {
        return None;
    }

    let is_vhd = data.len() >= 8 && &data[0..8] == VHD_COOKIE;
    let is_vhdx = data.len() >= 8 && &data[0..8] == VHDX_COOKIE;

    // Also check for VHD footer at end of file (dynamic/differencing VHDs
    // have the footer copy at the very end)
    let is_vhd_footer = if !is_vhd && !is_vhdx && data.len() >= 512 {
        let footer_start = data.len() - 512;
        data.len() >= footer_start + 8 && &data[footer_start..footer_start + 8] == VHD_COOKIE
    } else {
        false
    };

    if !is_vhd && !is_vhdx && !is_vhd_footer {
        return None;
    }

    let format_version = if is_vhdx {
        "VHDX".to_string()
    } else {
        "VHD".to_string()
    };

    // Parse disk size from VHD footer
    // VHD footer structure (512 bytes):
    //   Offset 0:  Cookie (8 bytes) "conectix"
    //   Offset 40: Current Size (8 bytes, big endian)
    //   Offset 60: Disk Type (4 bytes, big endian): 2=Fixed, 3=Dynamic, 4=Differencing
    let disk_size_bytes = if is_vhd || is_vhd_footer {
        let footer_start = if is_vhd_footer { data.len() - 512 } else { 0 };
        if footer_start + 48 <= data.len() {
            u64::from_be_bytes([
                data[footer_start + 40],
                data[footer_start + 41],
                data[footer_start + 42],
                data[footer_start + 43],
                data[footer_start + 44],
                data[footer_start + 45],
                data[footer_start + 46],
                data[footer_start + 47],
            ])
        } else {
            0
        }
    } else {
        // VHDX: header at offset 0 is the file type identifier;
        // actual size is in the metadata region which is complex to parse.
        // Report 0 for now.
        0
    };

    // Scan raw bytes for embedded executables (MZ/ELF magic)
    let mut executable_count = 0usize;
    let scan_limit = data.len().min(10 * 1024 * 1024); // Scan up to 10MB
    let mut i = 512; // Skip header
    while i + 4 <= scan_limit {
        if data[i..i + 2] == MZ_MAGIC {
            // Verify this looks like a real PE: check for "PE\0\0" within
            // a reasonable offset (the e_lfanew field at offset 0x3C)
            if i + 0x40 <= scan_limit {
                let e_lfanew = u32::from_le_bytes([
                    data[i + 0x3C],
                    data[i + 0x3D],
                    data[i + 0x3E],
                    data[i + 0x3F],
                ]) as usize;
                if e_lfanew < 0x1000
                    && i + e_lfanew + 4 <= scan_limit
                    && &data[i + e_lfanew..i + e_lfanew + 4] == b"PE\0\0"
                {
                    executable_count += 1;
                }
            }
            i += 512; // Skip ahead
        } else if data[i..i + 4] == ELF_MAGIC {
            executable_count += 1;
            i += 512;
        } else {
            i += 1;
        }
    }

    let has_executables = executable_count > 0;

    Some(VhdAnalysis {
        format_version,
        disk_size_bytes,
        has_executables,
        executable_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_vhd() {
        assert!(detect_vhd_analysis(b"Not a VHD file").is_none());
    }

    #[test]
    fn test_vhd_header() {
        let mut data = vec![0u8; 1024];
        data[0..8].copy_from_slice(VHD_COOKIE);
        // Set disk size to 1GB at offset 40 (big endian)
        let size: u64 = 1024 * 1024 * 1024;
        data[40..48].copy_from_slice(&size.to_be_bytes());
        let r = detect_vhd_analysis(&data).unwrap();
        assert_eq!(r.format_version, "VHD");
        assert_eq!(r.disk_size_bytes, size);
        assert!(!r.has_executables);
    }

    #[test]
    fn test_vhdx_header() {
        let mut data = vec![0u8; 1024];
        data[0..8].copy_from_slice(VHDX_COOKIE);
        let r = detect_vhd_analysis(&data).unwrap();
        assert_eq!(r.format_version, "VHDX");
    }

    #[test]
    fn test_vhd_footer_at_end() {
        let mut data = vec![0u8; 2048];
        // Put the VHD cookie at the last 512 bytes
        let footer_start = data.len() - 512;
        data[footer_start..footer_start + 8].copy_from_slice(VHD_COOKIE);
        let r = detect_vhd_analysis(&data).unwrap();
        assert_eq!(r.format_version, "VHD");
    }

    #[test]
    fn test_vhd_with_embedded_pe() {
        let mut data = vec![0u8; 2048];
        data[0..8].copy_from_slice(VHD_COOKIE);
        // Place a fake PE at offset 512
        data[512] = 0x4D; // M
        data[513] = 0x5A; // Z
        // e_lfanew at offset 0x3C pointing to offset 0x80 within the PE
        let pe_offset: u32 = 0x80;
        data[512 + 0x3C..512 + 0x40].copy_from_slice(&pe_offset.to_le_bytes());
        // PE signature at that offset
        data[512 + 0x80..512 + 0x84].copy_from_slice(b"PE\0\0");
        let r = detect_vhd_analysis(&data).unwrap();
        assert!(r.has_executables);
        assert_eq!(r.executable_count, 1);
    }
}
