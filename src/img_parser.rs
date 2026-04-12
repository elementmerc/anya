// Raw disk image (IMG) analysis
// Detects partition tables, GPT headers, and embedded executables

use crate::output::ImgAnalysis;

/// MBR boot signature at offset 510
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];
/// GPT header signature at offset 512
const GPT_SIGNATURE: &[u8] = b"EFI PART";

/// MZ magic for PE executables
const MZ_MAGIC: [u8; 2] = [0x4D, 0x5A];

/// Analyse file bytes as a raw disk image. Returns None if not a valid
/// disk image format.
pub fn detect_img_analysis(data: &[u8]) -> Option<ImgAnalysis> {
    if data.len() < 1024 {
        return None;
    }

    // Check for MBR signature at offset 510
    let has_mbr = data[510] == MBR_SIGNATURE[0] && data[511] == MBR_SIGNATURE[1];

    // Check for GPT header at offset 512
    let is_gpt = data.len() >= 520 && &data[512..520] == GPT_SIGNATURE;

    if !has_mbr && !is_gpt {
        return None;
    }

    // Parse MBR partition table entries (4 entries at offset 446, 16 bytes each)
    let mut partition_count = 0usize;
    if has_mbr {
        for entry_idx in 0..4 {
            let entry_offset = 446 + entry_idx * 16;
            if entry_offset + 16 > data.len() {
                break;
            }

            // A partition entry is valid if the partition type (byte 4) is non-zero
            let partition_type = data[entry_offset + 4];
            if partition_type != 0 {
                partition_count += 1;
            }
        }
    }

    // For GPT, count partitions from the GPT partition entry array
    if is_gpt && partition_count == 0 {
        // GPT header at offset 512:
        //   Offset 72 (from header start): partition entry start LBA (8 bytes LE)
        //   Offset 80: number of partition entries (4 bytes LE)
        //   Offset 84: size of partition entry (4 bytes LE)
        if data.len() >= 512 + 88 {
            let num_entries = u32::from_le_bytes([
                data[512 + 80],
                data[512 + 81],
                data[512 + 82],
                data[512 + 83],
            ]) as usize;
            let entry_size = u32::from_le_bytes([
                data[512 + 84],
                data[512 + 85],
                data[512 + 86],
                data[512 + 87],
            ]) as usize;

            // Partition entries typically start at LBA 2 (offset 1024)
            let entries_offset = 1024;
            if entry_size > 0 {
                let max_entries = num_entries.min(128); // Cap at 128
                for idx in 0..max_entries {
                    let entry_start = entries_offset + idx * entry_size;
                    if entry_start + 16 > data.len() {
                        break;
                    }
                    // GPT partition entry: first 16 bytes are the partition type GUID
                    // A zero GUID means unused entry
                    let all_zero = data[entry_start..entry_start + 16].iter().all(|&b| b == 0);
                    if !all_zero {
                        partition_count += 1;
                    }
                }
            }
        }
    }

    // Scan for embedded executables at sector boundaries
    let mut executable_count = 0usize;
    let scan_limit = data.len().min(10 * 1024 * 1024); // Scan up to 10MB
    // Start scanning from sector 1 (skip MBR)
    let mut offset = 512;
    while offset + 2 <= scan_limit {
        if data[offset..offset + 2] == MZ_MAGIC {
            // Quick PE validation: check for e_lfanew and PE signature
            if offset + 0x40 <= scan_limit {
                let e_lfanew = u32::from_le_bytes([
                    data[offset + 0x3C],
                    data[offset + 0x3D],
                    data[offset + 0x3E],
                    data[offset + 0x3F],
                ]) as usize;
                if e_lfanew < 0x1000
                    && offset + e_lfanew + 4 <= scan_limit
                    && &data[offset + e_lfanew..offset + e_lfanew + 4] == b"PE\0\0"
                {
                    executable_count += 1;
                }
            }
            offset += 512;
        } else {
            offset += 512; // Scan at sector boundaries
        }
    }

    let has_executables = executable_count > 0;

    Some(ImgAnalysis {
        partition_count,
        has_executables,
        executable_count,
        is_gpt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_img() {
        assert!(detect_img_analysis(b"Not a disk image").is_none());
    }

    #[test]
    fn test_mbr_image() {
        let mut data = vec![0u8; 2048];
        // MBR signature at offset 510
        data[510] = 0x55;
        data[511] = 0xAA;
        // One partition entry at offset 446: set partition type to 0x07 (NTFS)
        data[446 + 4] = 0x07;
        let r = detect_img_analysis(&data).unwrap();
        assert_eq!(r.partition_count, 1);
        assert!(!r.is_gpt);
    }

    #[test]
    fn test_gpt_image() {
        let mut data = vec![0u8; 4096];
        // MBR signature (protective MBR)
        data[510] = 0x55;
        data[511] = 0xAA;
        // GPT header at offset 512
        data[512..520].copy_from_slice(GPT_SIGNATURE);
        // Number of partition entries = 1
        data[512 + 80..512 + 84].copy_from_slice(&1u32.to_le_bytes());
        // Partition entry size = 128
        data[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes());
        // Write a non-zero GUID at the first partition entry (offset 1024)
        data[1024] = 0x01;
        let r = detect_img_analysis(&data).unwrap();
        assert!(r.is_gpt);
        assert_eq!(r.partition_count, 1);
    }

    #[test]
    fn test_img_with_executable() {
        let mut data = vec![0u8; 4096];
        data[510] = 0x55;
        data[511] = 0xAA;
        // Place a fake PE at offset 1024 (sector 2)
        data[1024] = 0x4D; // M
        data[1025] = 0x5A; // Z
        let pe_off: u32 = 0x80;
        data[1024 + 0x3C..1024 + 0x40].copy_from_slice(&pe_off.to_le_bytes());
        data[1024 + 0x80..1024 + 0x84].copy_from_slice(b"PE\0\0");
        let r = detect_img_analysis(&data).unwrap();
        assert!(r.has_executables);
        assert_eq!(r.executable_count, 1);
    }

    #[test]
    fn test_empty_partition_table() {
        let mut data = vec![0u8; 2048];
        data[510] = 0x55;
        data[511] = 0xAA;
        // All partition entries zero
        let r = detect_img_analysis(&data).unwrap();
        assert_eq!(r.partition_count, 0);
    }
}
