// Ányá - Malware Analysis Platform
// Library interface - All testable business logic
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use goblin::Object;
use md5::{Digest, Md5};
use memmap2::Mmap;
use sha1::Sha1;
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use walkdir::WalkDir;

// Process-wide KSD runtime controls. The CLI wires `--no-ksd` and
// `--ksd-threshold` into these so the analysis path can read them without
// adding a parameter to every call site (which would ripple into the Tauri
// IPC and the GUI). Defaults: KSD enabled, distance threshold 150.
//
// The Tauri GUI leaves both at their defaults today; when a future settings
// panel exposes them it can call `set_ksd_enabled` / `set_ksd_threshold`
// directly.
static KSD_ENABLED: AtomicBool = AtomicBool::new(true);
static KSD_THRESHOLD: AtomicU32 = AtomicU32::new(150);

/// Enable or disable KSD (Known Sample Database) matching for subsequent
/// analyses in this process. The default is enabled.
pub fn set_ksd_enabled(enabled: bool) {
    KSD_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Return whether KSD matching is currently enabled.
pub fn is_ksd_enabled() -> bool {
    KSD_ENABLED.load(Ordering::Relaxed)
}

/// Override the TLSH distance threshold used by KSD matching. The default
/// is 150.
pub fn set_ksd_threshold(distance: u32) {
    KSD_THRESHOLD.store(distance, Ordering::Relaxed);
}

/// Return the current KSD TLSH distance threshold.
pub fn ksd_threshold() -> u32 {
    KSD_THRESHOLD.load(Ordering::Relaxed)
}

// Re-export proprietary data constants for IPC access
pub mod proprietary_data {
    pub use anya_data::CATEGORY_EXPLANATIONS_JSON;
    pub use anya_data::DLL_EXPLANATIONS_JSON;
    pub use anya_data::FUNCTION_EXPLANATIONS_JSON;
    pub use anya_data::MITRE_ATTACK_JSON;
    pub use anya_data::TECHNIQUE_EXPLANATIONS_JSON;
}

// Re-export modules
pub mod cab_parser;
pub mod case;
pub mod cert_db;
pub mod confidence;
pub mod config;
pub mod data;
pub mod dotnet_parser;
pub mod elf_parser;
pub mod errors;
pub mod events;
pub mod export;
pub mod guided_output;
pub mod gzip_parser;
pub mod hash_check;
pub mod html_parser;
pub mod image_parser;
pub mod img_parser;
pub mod ioc;
pub mod iso_parser;
pub mod js_parser;
pub mod lnk_parser;
pub mod macho_parser;
pub mod msi_parser;
pub mod ole_parser;
pub mod onenote_parser;
pub mod output;
pub mod parser_registry;
pub mod pe_parser;
pub mod ps_parser;
pub mod python_parser;
pub mod rar_parser;
pub mod report;
pub mod rtf_parser;
pub mod script_parser;
pub mod sevenz_parser;
pub mod tar_parser;
pub mod vbs_parser;
pub mod vhd_parser;
pub mod xml_parser;
pub mod yara;
pub mod zip_parser;

// Scoring engine
pub use anya_scoring;

// Output verbosity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputLevel {
    Quiet,
    Normal,
    Verbose,
}

impl OutputLevel {
    pub fn from_args(verbose: bool, quiet: bool) -> Self {
        if quiet {
            OutputLevel::Quiet
        } else if verbose {
            OutputLevel::Verbose
        } else {
            OutputLevel::Normal
        }
    }

    pub fn should_print_info(&self) -> bool {
        matches!(self, OutputLevel::Normal | OutputLevel::Verbose)
    }

    pub fn should_print_verbose(&self) -> bool {
        matches!(self, OutputLevel::Verbose)
    }
}

/// File analysis result - contains all analysis data
#[derive(Debug, Clone)]
pub struct FileAnalysisResult {
    pub path: PathBuf,
    pub size_bytes: usize,
    pub hashes: output::Hashes,
    pub entropy: output::EntropyInfo,
    pub strings: output::StringsInfo,
    pub file_format: String,
    pub pe_analysis: Option<output::PEAnalysis>,
    pub elf_analysis: Option<output::ELFAnalysis>,
    pub mime_type: Option<String>,
    pub byte_histogram: Option<Vec<u64>>,
    pub file_type_mismatch: Option<output::FileTypeMismatch>,
    pub ioc_summary: Option<output::IocSummary>,
    pub mach_analysis: Option<output::MachoAnalysis>,
    pub pdf_analysis: Option<output::PdfAnalysis>,
    pub office_analysis: Option<output::OfficeAnalysis>,
    // New format-specific analysis fields
    pub javascript_analysis: Option<output::JavaScriptAnalysis>,
    pub powershell_analysis: Option<output::PowerShellAnalysis>,
    pub vbscript_analysis: Option<output::VbScriptAnalysis>,
    pub shell_script_analysis: Option<output::ShellScriptAnalysis>,
    pub python_analysis: Option<output::PythonAnalysis>,
    pub ole_analysis: Option<output::OleAnalysis>,
    pub rtf_analysis: Option<output::RtfAnalysis>,
    pub zip_analysis: Option<output::ZipAnalysis>,
    pub html_analysis: Option<output::HtmlAnalysis>,
    pub xml_analysis: Option<output::XmlAnalysis>,
    pub image_analysis: Option<output::ImageAnalysis>,
    pub lnk_analysis: Option<output::LnkAnalysis>,
    pub iso_analysis: Option<output::IsoAnalysis>,
    pub cab_analysis: Option<output::CabAnalysis>,
    pub msi_analysis: Option<output::MsiAnalysis>,
    pub vhd_analysis: Option<output::VhdAnalysis>,
    pub onenote_analysis: Option<output::OneNoteAnalysis>,
    pub img_analysis: Option<output::ImgAnalysis>,
    pub rar_analysis: Option<output::RarAnalysis>,
    pub gzip_analysis: Option<output::GzipAnalysis>,
    pub sevenz_analysis: Option<output::SevenZipAnalysis>,
    pub tar_analysis: Option<output::TarAnalysis>,
    pub secrets_detected: Option<Vec<output::SecretFinding>>,
    pub yara_matches: Vec<output::YaraMatchResult>,
    /// PE OriginalFilename vs actual filename mismatch (original, actual)
    pub pe_filename_mismatch: Option<(String, String)>,
}

/// Batch analysis summary
#[derive(Debug, Default, Clone)]
pub struct BatchSummary {
    pub total_files: usize,
    pub analysed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub suspicious: usize,
    pub duration: f64,
}

impl BatchSummary {
    pub fn success_rate(&self) -> f64 {
        if self.total_files == 0 {
            0.0
        } else {
            (self.analysed as f64 / self.total_files as f64) * 100.0
        }
    }

    pub fn print_summary(&self) {
        use colored::Colorize;

        println!("\n{}", "═══ Batch Analysis Summary ═══".cyan().bold());
        println!("Total files:     {}", self.total_files);
        println!("Analysed:        {} {}", self.analysed, "✓".green());
        println!(
            "Failed:          {} {}",
            self.failed,
            if self.failed > 0 {
                "✗".red()
            } else {
                "".normal()
            }
        );
        println!("Skipped:         {}", self.skipped);
        println!(
            "Suspicious:      {} {}",
            self.suspicious,
            if self.suspicious > 0 {
                "⚠".yellow()
            } else {
                "".normal()
            }
        );
        println!("Duration:        {:.2}s", self.duration);
        println!("Success rate:    {:.1}%", self.success_rate());
        println!("Analysis rate:   {:.1} files/sec", self.analysis_rate());
    }

    pub fn analysis_rate(&self) -> f64 {
        if self.duration == 0.0 {
            0.0
        } else {
            self.analysed as f64 / self.duration
        }
    }
}

/// Calculate cryptographic hashes for data (parallel via rayon)
pub fn calculate_hashes(data: &[u8]) -> output::Hashes {
    // Compute (md5, sha1) in parallel with (sha256, tlsh)
    let ((md5, sha1), (sha256, tlsh)) = rayon::join(
        || {
            rayon::join(
                || format!("{:x}", Md5::digest(data)),
                || format!("{:x}", Sha1::digest(data)),
            )
        },
        || {
            rayon::join(
                || format!("{:x}", Sha256::digest(data)),
                || calculate_tlsh(data),
            )
        },
    );

    output::Hashes {
        md5,
        sha1,
        sha256,
        tlsh,
    }
}

/// Calculate Shannon entropy and byte histogram in a single pass
pub fn calculate_entropy_and_histogram(data: &[u8]) -> (output::EntropyInfo, Vec<u64>) {
    let mut frequencies = [0u64; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let entropy: f64 = if data.is_empty() {
        0.0
    } else {
        frequencies
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    };

    let (category, is_suspicious) = categorize_entropy(entropy);

    let info = output::EntropyInfo {
        value: entropy,
        category: category.to_string(),
        is_suspicious,
        confidence: None,
    };

    (info, frequencies.to_vec())
}

/// Calculate Shannon entropy (delegates to combined function)
pub fn calculate_file_entropy(data: &[u8]) -> output::EntropyInfo {
    calculate_entropy_and_histogram(data).0
}

/// Calculate Shannon entropy for a byte slice, returning a single f64 value (0.0–8.0).
/// This is the canonical entropy implementation — all parsers should use this
/// instead of maintaining private copies.
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }
    let len = data.len() as f64;
    frequency
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Categorize entropy value
pub fn categorize_entropy(entropy: f64) -> (&'static str, bool) {
    use anya_scoring::detection_patterns::{
        ENTROPY_HIGH, ENTROPY_MODERATE, ENTROPY_MODERATE_HIGH, ENTROPY_VERY_HIGH,
    };
    if entropy > ENTROPY_VERY_HIGH {
        ("Very High", true)
    } else if entropy > ENTROPY_HIGH {
        ("High", true)
    } else if entropy > ENTROPY_MODERATE_HIGH {
        ("Moderate-High", false)
    } else if entropy > ENTROPY_MODERATE {
        ("Moderate", false)
    } else {
        ("Low", false)
    }
}

/// Extract printable ASCII strings with byte offsets (capped at 500)
pub fn extract_strings_with_offsets(
    data: &[u8],
    min_length: usize,
) -> (Vec<(String, usize)>, usize) {
    extract_strings_with_offsets_limit(data, min_length, 500)
}

/// Extract printable ASCII strings with byte offsets, capped at `max_collect`.
pub fn extract_strings_with_offsets_limit(
    data: &[u8],
    min_length: usize,
    max_collect: usize,
) -> (Vec<(String, usize)>, usize) {
    let mut strings = Vec::new();
    let mut total_count: usize = 0;
    let mut current = Vec::new();
    let mut start_offset: usize = 0;

    for (i, &byte) in data.iter().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(byte);
        } else if current.len() >= min_length {
            total_count += 1;
            if strings.len() < max_collect {
                strings.push((String::from_utf8_lossy(&current).to_string(), start_offset));
            }
            current.clear();
        } else {
            current.clear();
        }
    }

    if current.len() >= min_length {
        total_count += 1;
        if strings.len() < max_collect {
            strings.push((String::from_utf8_lossy(&current).to_string(), start_offset));
        }
    }

    (strings, total_count)
}

/// Extract printable ASCII strings (capped collection to limit memory)
pub fn extract_strings_data(data: &[u8], min_length: usize) -> output::StringsInfo {
    let (strings_with_offsets, total_count) = extract_strings_with_offsets(data, min_length);

    let sample_count = 10.min(strings_with_offsets.len());
    let samples: Vec<String> = strings_with_offsets
        .iter()
        .take(sample_count)
        .map(|(s, _)| s.clone())
        .collect();

    let classified = Some(classify_strings(&strings_with_offsets));

    output::StringsInfo {
        min_length,
        total_count,
        samples,
        sample_count,
        classified,
        suppressed_reason: None,
    }
}

/// Check if file should be included in batch analysis.
/// Accepts all files regardless of extension — the analysis engine handles
/// unknown formats gracefully (hashes, entropy, strings still extracted).
pub fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Detect MIME type via magic bytes
fn detect_mime_type(data: &[u8]) -> Option<String> {
    infer::get(data).map(|t| t.mime_type().to_string())
}

/// Map a MIME type to a human-readable format label for files goblin can't parse.
/// Covers 150+ MIME types across archives, documents, images, audio, video,
/// executables, scripts, fonts, ebooks, and more.
fn mime_to_format_label(mime: &str) -> String {
    match mime {
        // ── Archives & Compressed ───────────────────────────────────────
        "application/zip" => "ZIP Archive",
        "application/gzip" | "application/x-gzip" => "GZIP Archive",
        "application/x-bzip2" => "BZIP2 Archive",
        "application/x-xz" => "XZ Archive",
        "application/x-7z-compressed" => "7-Zip Archive",
        "application/x-rar-compressed" | "application/vnd.rar" => "RAR Archive",
        "application/x-tar" => "TAR Archive",
        "application/zstd" | "application/x-zstd" => "Zstandard Archive",
        "application/x-compress" => "Unix Compress Archive",
        "application/x-lzip" => "LZIP Archive",
        "application/x-lzma" => "LZMA Archive",
        "application/x-lz4" => "LZ4 Archive",
        "application/x-cpio" => "CPIO Archive",
        "application/x-unix-archive" => "Unix AR Archive",
        "application/x-arj" => "ARJ Archive",
        "application/x-ace-compressed" => "ACE Archive",
        "application/x-alz-compressed" => "ALZ Archive",
        "application/x-stuffit" => "StuffIt Archive",
        // ── Mobile / JVM / Android ──────────────────────────────────────
        "application/vnd.android.package-archive" => "Android APK",
        "application/java-archive" => "Java JAR",
        "application/java" | "application/x-java-applet" => "Java Class",
        "application/vnd.android.dex" => "Android DEX (Dalvik)",
        "application/vnd.android.dey" => "Android ODEX",
        // ── Documents ───────────────────────────────────────────────────
        "application/pdf" => "PDF Document",
        "application/msword" => "MS Word Document (DOC)",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            "DOCX Document"
        }
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => "XLSX Spreadsheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
            "PPTX Presentation"
        }
        "application/vnd.ms-excel" => "MS Excel Spreadsheet (XLS)",
        "application/vnd.ms-powerpoint" => "MS PowerPoint (PPT)",
        "application/rtf" => "RTF Document",
        "application/vnd.oasis.opendocument.text" => "OpenDocument Text (ODT)",
        "application/vnd.oasis.opendocument.spreadsheet" => "OpenDocument Spreadsheet (ODS)",
        "application/vnd.oasis.opendocument.presentation" => "OpenDocument Presentation (ODP)",
        "application/epub+zip" => "EPUB Ebook",
        "application/x-mobipocket-ebook" => "MOBI Ebook",
        "application/vnd.amazon.ebook" => "Kindle Ebook",
        "application/postscript" => "PostScript Document",
        "application/x-latex" | "application/x-tex" => "LaTeX Document",
        "application/x-ole-storage" => "OLE Compound Document",
        "application/dicom" => "DICOM Medical Image",
        // ── Images ──────────────────────────────────────────────────────
        "image/jpeg" | "image/jpg" => "JPEG Image",
        "image/png" => "PNG Image",
        "image/gif" => "GIF Image",
        "image/bmp" | "image/x-bmp" => "BMP Image",
        "image/webp" => "WebP Image",
        "image/tiff" => "TIFF Image",
        "image/svg+xml" => "SVG Image",
        "image/vnd.adobe.photoshop" => "Photoshop Document (PSD)",
        "image/vnd.microsoft.icon" | "image/x-icon" => "ICO Icon",
        "image/vnd.ms-photo" | "image/jxr" => "JPEG XR Image",
        "image/avif" => "AVIF Image",
        "image/heif" | "image/heic" => "HEIF/HEIC Image",
        "image/jp2" | "image/jpeg2000" => "JPEG 2000 Image",
        "image/jxl" => "JPEG XL Image",
        "image/x-canon-cr2" => "Canon RAW (CR2)",
        "image/x-canon-cr3" => "Canon RAW (CR3)",
        "image/x-nikon-nef" => "Nikon RAW (NEF)",
        "image/x-sony-arw" => "Sony RAW (ARW)",
        "image/x-fuji-raf" => "Fuji RAW (RAF)",
        "image/x-panasonic-rw2" => "Panasonic RAW (RW2)",
        "image/x-olympus-orf" => "Olympus RAW (ORF)",
        "image/x-adobe-dng" => "Adobe DNG RAW",
        "image/vnd.djvu" | "image/x-djvu" => "DjVu Document",
        "image/openraster" => "OpenRaster Image",
        "image/x-pcx" => "PCX Image",
        "image/x-tga" | "image/x-targa" => "TGA Image",
        "image/x-portable-pixmap" | "image/x-portable-anymap" => "PPM/PNM Image",
        "image/x-exr" => "OpenEXR Image",
        // ── Audio ───────────────────────────────────────────────────────
        "audio/mpeg" | "audio/mp3" => "MP3 Audio",
        "audio/ogg" | "audio/vorbis" => "OGG Audio",
        "audio/x-flac" | "audio/flac" => "FLAC Audio",
        "audio/x-wav" | "audio/wav" => "WAV Audio",
        "audio/aac" => "AAC Audio",
        "audio/m4a" | "audio/x-m4a" => "M4A Audio",
        "audio/opus" => "Opus Audio",
        "audio/x-aiff" | "audio/aiff" => "AIFF Audio",
        "audio/midi" | "audio/x-midi" => "MIDI Audio",
        "audio/x-ape" => "APE Audio (Monkey's Audio)",
        "audio/x-dsf" => "DSF Audio (DSD)",
        "audio/x-musepack" | "audio/musepack" => "Musepack Audio",
        "audio/amr" => "AMR Audio",
        "audio/x-wma" | "audio/x-ms-wma" => "WMA Audio",
        "audio/webm" => "WebM Audio",
        // ── Video ───────────────────────────────────────────────────────
        "video/mp4" => "MP4 Video",
        "video/x-matroska" => "MKV Video (Matroska)",
        "video/webm" => "WebM Video",
        "video/x-msvideo" | "video/avi" => "AVI Video",
        "video/quicktime" => "QuickTime Video (MOV)",
        "video/x-ms-wmv" => "WMV Video",
        "video/x-flv" => "FLV Video (Flash)",
        "video/mpeg" => "MPEG Video",
        "video/x-m4v" => "M4V Video",
        "video/3gpp" | "video/3gpp2" => "3GP Video",
        "video/x-ms-asf" => "ASF Video",
        "video/ogg" => "OGG Video",
        "video/mp2t" => "MPEG Transport Stream",
        "video/x-f4v" => "F4V Video (Flash)",
        // ── Executables / Libraries ─────────────────────────────────────
        "application/x-executable" => "Executable",
        "application/x-sharedlib" | "application/x-shared-library-elf" => "Shared Library",
        "application/x-mach-binary" => "macOS Mach-O",
        "application/vnd.microsoft.portable-executable" | "application/x-dosexec" => "Windows PE",
        "application/x-msdownload" => "Windows Executable",
        "application/x-msi" => "Windows Installer (MSI)",
        "application/x-elf" => "Linux ELF",
        "application/x-object" => "Object File",
        "application/x-coredump" => "Core Dump",
        "application/wasm" => "WebAssembly (WASM)",
        "application/x-llvm" => "LLVM Bitcode",
        // ── Package Formats ─────────────────────────────────────────────
        "application/vnd.debian.binary-package" => "Debian Package (DEB)",
        "application/x-rpm" => "RPM Package",
        "application/x-apple-diskimage" => "macOS DMG Image",
        "application/vnd.ms-cab-compressed" => "Windows CAB Archive",
        "application/vnd.snap" => "Snap Package",
        "application/vnd.flatpak" | "application/vnd.flatpak.repo" => "Flatpak Package",
        "application/vnd.appimage" => "AppImage",
        "application/x-xar" => "XAR Archive (macOS pkg)",
        "application/x-chrome-extension" | "application/x-google-chrome-extension" => {
            "Chrome Extension (CRX)"
        }
        // ── Disk Images / Firmware ──────────────────────────────────────
        "application/x-iso9660-image" => "ISO Disk Image",
        "application/x-raw-disk-image" => "Raw Disk Image",
        "application/x-qemu-disk" | "application/x-qcow2" => "QEMU Disk Image",
        "application/x-vmdk" => "VMware Disk Image (VMDK)",
        "application/x-vhd" | "application/x-vhdx" => "Hyper-V Disk Image (VHD)",
        "application/x-virtualbox-vdi" => "VirtualBox Disk Image (VDI)",
        // ── Scripts / Source Code ────────────────────────────────────────
        "text/x-python" | "text/x-script.python" | "application/x-python-code" => "Python Script",
        "text/x-shellscript" | "application/x-shellscript" => "Shell Script",
        "text/x-perl" | "application/x-perl" => "Perl Script",
        "text/x-ruby" | "application/x-ruby" => "Ruby Script",
        "application/javascript" | "text/javascript" => "JavaScript",
        "application/typescript" => "TypeScript",
        "text/x-lua" => "Lua Script",
        "text/x-php" | "application/x-php" => "PHP Script",
        "text/x-java-source" => "Java Source",
        "text/x-c" | "text/x-csrc" => "C Source",
        "text/x-c++" | "text/x-c++src" => "C++ Source",
        "text/x-rust" => "Rust Source",
        "text/x-go" | "text/x-gosrc" => "Go Source",
        "text/x-swift" => "Swift Source",
        "text/x-powershell" | "application/x-powershell" => "PowerShell Script",
        "application/x-bat" | "application/x-msdos-program" => "Batch Script",
        "text/x-asm" | "text/x-nasm" => "Assembly Source",
        // ── Markup / Data ───────────────────────────────────────────────
        "text/html" | "application/xhtml+xml" => "HTML Document",
        "text/xml" | "application/xml" => "XML Document",
        "application/json" => "JSON",
        "application/x-yaml" | "text/yaml" | "text/x-yaml" => "YAML",
        "text/csv" => "CSV Data",
        "text/markdown" | "text/x-markdown" => "Markdown Document",
        "application/x-ndjson" => "NDJSON (Newline-delimited JSON)",
        "application/toml" | "text/x-toml" => "TOML Configuration",
        "application/x-protobuf" => "Protocol Buffers",
        "application/x-plist" => "Apple Property List",
        // ── Fonts ───────────────────────────────────────────────────────
        "font/ttf" | "application/x-font-ttf" => "TrueType Font (TTF)",
        "font/otf" | "application/x-font-otf" | "application/font-sfnt" => "OpenType Font (OTF)",
        "font/woff" | "application/font-woff" => "WOFF Font",
        "font/woff2" | "application/font-woff2" => "WOFF2 Font",
        "application/vnd.ms-fontobject" => "Embedded OpenType Font (EOT)",
        // ── Certificates / Security ─────────────────────────────────────
        "application/x-x509-ca-cert" | "application/x-x509-user-cert" => "X.509 Certificate",
        "application/pkcs7-mime" | "application/x-pkcs7-mime" => "PKCS#7 Signed Data",
        "application/pkcs8" | "application/x-pkcs8" => "PKCS#8 Private Key",
        "application/pkix-cert" => "PKIX Certificate",
        "application/x-pem-file" => "PEM Certificate/Key",
        "application/pgp-signature" => "PGP Signature",
        "application/pgp-keys" => "PGP Public Key",
        "application/pgp-encrypted" => "PGP Encrypted Data",
        // ── Databases ───────────────────────────────────────────────────
        "application/x-sqlite3" | "application/vnd.sqlite3" => "SQLite Database",
        "application/x-dbf" => "dBASE Database",
        // ── Misc / Specialised ──────────────────────────────────────────
        "application/x-shockwave-flash" | "application/x-swf" => "Flash (SWF)",
        "application/x-nintendo-nes-rom" => "NES ROM",
        "application/x-gameboy-rom" => "Game Boy ROM",
        "application/x-sega-genesis-rom" => "Sega Genesis ROM",
        "application/octet-stream" => "Binary Data",
        "application/x-pcap" | "application/vnd.tcpdump.pcap" => "PCAP Network Capture",
        "application/x-pcapng" => "PCAPNG Network Capture",
        "application/x-lnk" | "application/x-ms-shortcut" => "Windows Shortcut (LNK)",
        "application/x-ms-registry" => "Windows Registry Hive",
        // ── Wildcard matches for broad categories ───────────────────────
        m if m.starts_with("image/") => return format!("Image ({})", &m[6..]),
        m if m.starts_with("audio/") => return format!("Audio ({})", &m[6..]),
        m if m.starts_with("video/") => return format!("Video ({})", &m[6..]),
        m if m.starts_with("text/") => return "Text File".to_string(),
        m if m.starts_with("font/") => return format!("Font ({})", &m[5..]),
        // ── Catch-all ───────────────────────────────────────────────────
        other => return format!("Unknown ({})", other),
    }
    .to_string()
}

/// Fallback format detection from file extension when MIME detection fails.
/// Used for text-based formats that `infer` cannot detect from magic bytes.
fn extension_to_format_label(ext: Option<&str>) -> String {
    match ext.map(|e| e.to_ascii_lowercase()).as_deref() {
        Some("py" | "pyw" | "pyx") => "Python Script",
        Some("sh" | "bash") => "Shell Script",
        Some("ps1" | "psm1" | "psd1") => "PowerShell Script",
        Some("bat" | "cmd") => "Batch Script",
        Some("rb") => "Ruby Script",
        Some("pl" | "pm") => "Perl Script",
        Some("lua") => "Lua Script",
        Some("js" | "mjs" | "cjs") => "JavaScript",
        Some("ts" | "mts") => "TypeScript",
        Some("vbs" | "vbe") => "VBScript",
        Some("json") => "JSON",
        Some("xml" | "xsl" | "xslt") => "XML",
        Some("yaml" | "yml") => "YAML",
        Some("toml") => "TOML",
        Some("ini" | "cfg" | "conf") => "Config File",
        Some("csv") => "CSV",
        Some("txt" | "text" | "log") => "Text File",
        Some("md" | "markdown") => "Markdown",
        Some("html" | "htm") => "HTML",
        Some("css") => "CSS",
        Some("sql") => "SQL",
        Some("c" | "h") => "C Source",
        Some("cpp" | "cc" | "cxx" | "hpp") => "C++ Source",
        Some("rs") => "Rust Source",
        Some("go") => "Go Source",
        Some("java") => "Java Source",
        Some("cs") => "C# Source",
        Some("swift") => "Swift Source",
        Some("kt" | "kts") => "Kotlin Source",
        Some("r") => "R Script",
        _ => "Unrecognized",
    }
    .to_string()
}

/// Calculate TLSH fuzzy hash (returns None if file < 50 bytes)
/// Compute TLSH distance between two hex-encoded TLSH strings.
/// Returns None if either string is invalid.
pub fn tlsh_distance(hex1: &str, hex2: &str) -> Option<i32> {
    let h1: tlsh2::Tlsh128_1 = hex1.parse().ok()?;
    let h2: tlsh2::Tlsh128_1 = hex2.parse().ok()?;
    Some(h1.diff(&h2, true))
}

fn calculate_tlsh(data: &[u8]) -> Option<String> {
    if data.len() < 50 {
        return None;
    }
    let mut builder = tlsh2::TlshBuilder128_1::new();
    builder.update(data);
    builder.build().map(|h| {
        let bytes = h.hash();
        bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>()
    })
}

// calculate_byte_histogram is now integrated into calculate_entropy_and_histogram

/// Classify extracted strings into categories (IOC-first, then legacy fallback)
fn classify_strings(strings: &[(String, usize)]) -> Vec<output::ClassifiedString> {
    strings
        .iter()
        .filter(|(s, _)| s.len() >= 8)
        .take(500)
        .map(|(s, offset)| {
            let category = if let Some(ioc) = ioc::classify_ioc(s) {
                ioc::ioc_type_to_category(&ioc)
            } else {
                classify_single_string(s)
            };
            // Mark IOCs matching known benign infrastructure
            let is_benign =
                matches!(category.as_str(), "URL" | "IP") && confidence::is_benign_ioc(s);
            output::ClassifiedString {
                value: s.clone(),
                category,
                offset: Some(format!("0x{:X}", offset)),
                is_benign,
            }
        })
        .collect()
}

/// Aho-Corasick automaton for command/suspicious keyword detection.
/// Keywords are defined in the anya-scoring crate.
static COMMAND_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    let keywords = &*anya_scoring::detection_patterns::COMMAND_KEYWORDS;
    let kw_refs: Vec<&str> = keywords.iter().map(|s| s.as_str()).collect();
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&kw_refs)
        .unwrap_or_else(|_| AhoCorasick::new([""; 0]).unwrap())
});

/// Aho-Corasick automaton for registry key prefix detection.
/// Keywords are defined in the anya-scoring crate.
static REGISTRY_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    let keywords = &*anya_scoring::detection_patterns::REGISTRY_KEYWORDS;
    let kw_refs: Vec<&str> = keywords.iter().map(|s| s.as_str()).collect();
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&kw_refs)
        .unwrap_or_else(|_| AhoCorasick::new([""; 0]).unwrap())
});

fn classify_single_string(s: &str) -> String {
    // URL
    if s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("ftp://")
        || s.contains("://")
    {
        return "URL".to_string();
    }
    // IP address (simple check: 4 groups of 1-3 digits separated by dots)
    if looks_like_ipv4(s) {
        return "IP".to_string();
    }
    // Registry (Aho-Corasick single-pass match)
    if REGISTRY_AC.is_match(s) {
        return "Registry".to_string();
    }
    // Command / suspicious keywords (Aho-Corasick single-pass match)
    if COMMAND_AC.is_match(s) {
        return "Command".to_string();
    }
    // Path
    if (s.starts_with("C:\\")
        || s.starts_with("D:\\")
        || s.starts_with("%")
        || s.starts_with("/home/")
        || s.starts_with("/etc/")
        || s.starts_with("/usr/"))
        || ((s.contains('\\') || s.contains('/'))
            && (s.contains(".exe") || s.contains(".dll") || s.contains(".pdb")))
    {
        return "Path".to_string();
    }
    // Base64 (length >= 20, alphanumeric + /+=, length multiple of 4)
    if s.len() >= 20
        && s.len() % 4 <= 1
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && s.ends_with('=')
    {
        return "Base64".to_string();
    }
    "Plain".to_string()
}

fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 3
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
    })
}

/// Detect mismatch between file extension and detected magic bytes.
/// Cached parsed fragment database — parsed once at first access.
static FRAGMENT_DB: LazyLock<serde_json::Value> =
    LazyLock::new(|| serde_json::from_str(anya_data::FRAGMENT_DB_JSON).unwrap_or_default());

static KNOWN_SAMPLES_DB: LazyLock<serde_json::Value> =
    LazyLock::new(|| serde_json::from_str(anya_data::KNOWN_SAMPLES_DB_JSON).unwrap_or_default());

static FAMILY_ANNOTATIONS_DB: LazyLock<serde_json::Value> = LazyLock::new(|| {
    serde_json::from_str(anya_data::FAMILY_ANNOTATIONS_DB_JSON).unwrap_or_default()
});

/// Look up a SHA256 in the forensic fragment database.
/// Returns a ForensicFragment annotation if matched, None otherwise.
fn lookup_fragment_db(sha256: &str) -> Option<output::ForensicFragment> {
    let fragments = FRAGMENT_DB.get("fragments")?.as_object()?;
    let entry = fragments.get(sha256)?;
    let family = entry.get("family")?.as_str()?;
    let description = entry.get("description")?.as_str()?;
    Some(output::ForensicFragment {
        associated_family: family.to_string(),
        explanation: description.to_string(),
    })
}

/// Look up a SHA256 in the known samples database (tools, PUPs, test files).
/// Returns a KnownSampleMatch if found, which overrides the heuristic verdict.
fn lookup_known_sample(sha256: &str) -> Option<output::KnownSampleMatch> {
    let samples = KNOWN_SAMPLES_DB.get("samples")?.as_object()?;
    let entry = samples.get(sha256)?;
    Some(output::KnownSampleMatch {
        verdict: entry.get("verdict")?.as_str()?.to_string(),
        category: entry.get("category")?.as_str()?.to_string(),
        name: entry.get("name")?.as_str()?.to_string(),
        description: entry.get("description")?.as_str()?.to_string(),
    })
}

/// Look up a malware family in the family annotations database.
/// Strips `sig_` prefix for signature-tagged families.
fn lookup_family_annotation(family: &str) -> Option<output::FamilyAnnotation> {
    let families = FAMILY_ANNOTATIONS_DB.get("families")?.as_object()?;
    let key = family.to_lowercase();
    let key = key.strip_prefix("sig_").unwrap_or(&key);
    // Also handle "agent-tesla" → "agenttesla" style normalisation
    let key_no_dash = key.replace('-', "");
    let entry = families.get(key).or_else(|| families.get(&key_no_dash))?;
    Some(output::FamilyAnnotation {
        name: entry.get("name")?.as_str()?.to_string(),
        category: entry.get("category")?.as_str()?.to_string(),
        description: entry.get("description")?.as_str()?.to_string(),
        aliases: entry
            .get("aliases")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        first_seen: entry
            .get("first_seen")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
    })
}

fn detect_file_type_mismatch(
    data: &[u8],
    extension: Option<&str>,
) -> Option<output::FileTypeMismatch> {
    let ext = extension?;
    let ext_lower = ext.to_lowercase();

    // Map magic bytes → (label, expected extensions)
    let (detected_type, expected): (&str, &[&str]) = if data.starts_with(b"MZ") {
        (
            "PE/MZ executable",
            &["exe", "dll", "sys", "drv", "ocx", "scr", "cpl", "efi"],
        )
    } else if data.starts_with(b"\x7fELF") {
        ("ELF binary", &["elf", "so", "bin", ""])
    } else if data.starts_with(b"%PDF") {
        ("PDF document", &["pdf"])
    } else if data.starts_with(b"PK\x03\x04") {
        (
            "ZIP archive",
            &["zip", "docx", "xlsx", "pptx", "jar", "apk"],
        )
    } else if data.starts_with(b"Rar!") {
        ("RAR archive", &["rar"])
    } else if data.len() >= 4 && data[..4] == [0x37, 0x7A, 0xBC, 0xAF] {
        ("7-Zip archive", &["7z"])
    } else if data.len() >= 2 && data[..2] == [0x1F, 0x8B] {
        ("GZIP archive", &["gz", "tgz"])
    } else if data.starts_with(b"\x89PNG") {
        ("PNG image", &["png"])
    } else if data.len() >= 3 && data[..3] == [0xFF, 0xD8, 0xFF] {
        ("JPEG image", &["jpg", "jpeg"])
    } else {
        return None; // Unrecognised magic — can't compare
    };

    if expected.contains(&ext_lower.as_str()) {
        return None; // Extension matches detected type
    }

    // Determine severity
    let severity = {
        let is_executable_magic =
            detected_type.contains("executable") || detected_type.contains("ELF");
        let is_disguise_ext = matches!(
            ext_lower.as_str(),
            "pdf"
                | "doc"
                | "docx"
                | "xls"
                | "xlsx"
                | "jpg"
                | "jpeg"
                | "png"
                | "txt"
                | "csv"
                | "mp3"
                | "mp4"
                | "zip"
                | "rar"
        );

        if is_executable_magic && is_disguise_ext {
            output::MismatchSeverity::High
        } else if detected_type.contains("archive") && !expected.contains(&ext_lower.as_str()) {
            output::MismatchSeverity::Medium
        } else {
            output::MismatchSeverity::Low
        }
    };

    Some(output::FileTypeMismatch {
        detected_type: detected_type.to_string(),
        claimed_extension: format!(".{}", ext_lower),
        severity,
    })
}

/// Detect dangerous PDF objects via byte-level pattern scanning.
fn detect_pdf_analysis(data: &[u8]) -> Option<output::PdfAnalysis> {
    if !data.starts_with(b"%PDF") {
        return None;
    }

    let mut dangerous_objects: Vec<String> = Vec::new();
    let mut risk_indicators: Vec<String> = Vec::new();

    let has = |pat: &[u8]| data.windows(pat.len()).any(|w| w == pat);

    if has(b"/JavaScript") {
        dangerous_objects.push("Embedded JavaScript".to_string());
        risk_indicators.push(
            "JavaScript code found — can be used for exploit delivery or silent actions on open"
                .to_string(),
        );
    } else {
        // Check short form /JS followed by delimiter
        let js_delimiters: &[&[u8]] = &[
            b"/JS ", b"/JS\n", b"/JS\r", b"/JS\t", b"/JS/", b"/JS>", b"/JS<", b"/JS(",
        ];
        if js_delimiters.iter().any(|d| has(d)) {
            dangerous_objects.push("Embedded JavaScript".to_string());
            risk_indicators.push("JavaScript code found — can be used for exploit delivery or silent actions on open".to_string());
        }
    }

    if has(b"/Launch") {
        dangerous_objects.push("Launch action".to_string());
        risk_indicators.push("/Launch action found — can execute arbitrary system commands when the document is opened".to_string());
    }

    if has(b"/EmbeddedFile") {
        dangerous_objects.push("Embedded file".to_string());
        risk_indicators.push(
            "Embedded file attachment detected — document carries a hidden embedded file"
                .to_string(),
        );
    }

    if has(b"/OpenAction") {
        dangerous_objects.push("Automatic action (OpenAction)".to_string());
        risk_indicators.push(
            "/OpenAction triggers automatically when the PDF is opened without user interaction"
                .to_string(),
        );
    }

    let aa_delimiters: &[&[u8]] = &[
        b"/AA ", b"/AA\n", b"/AA\r", b"/AA\t", b"/AA/", b"/AA>", b"/AA<",
    ];
    if aa_delimiters.iter().any(|d| has(d)) {
        dangerous_objects.push("Automatic action (AA)".to_string());
        risk_indicators.push(
            "/AA (Additional Actions) dictionary can trigger actions on page open/close events"
                .to_string(),
        );
    }

    // AcroForm with JS within 200 bytes
    let acroform = b"/AcroForm";
    for i in 0..data.len().saturating_sub(acroform.len()) {
        if &data[i..i + acroform.len()] == acroform {
            let end = (i + 200).min(data.len());
            let nearby = &data[i..end];
            let has_js = nearby
                .windows(b"/JavaScript".len())
                .any(|w| w == b"/JavaScript")
                || nearby.windows(b"/JS ".len()).any(|w| w == b"/JS ");
            if has_js && !dangerous_objects.contains(&"Form with JavaScript".to_string()) {
                dangerous_objects.push("Form with JavaScript".to_string());
                risk_indicators.push(
                    "AcroForm containing JavaScript — interactive form with embedded script"
                        .to_string(),
                );
            }
            break;
        }
    }

    Some(output::PdfAnalysis {
        dangerous_objects,
        risk_indicators,
    })
}

/// Detect Office macro/embedding indicators in ZIP-based Office documents.
fn detect_office_analysis(data: &[u8], path: &Path) -> Option<output::OfficeAnalysis> {
    let ext = path.extension()?.to_str()?.to_lowercase();
    if !matches!(
        ext.as_str(),
        "docx" | "xlsx" | "xlsm" | "pptm" | "pptx" | "docm"
    ) {
        return None;
    }
    if !data.starts_with(b"PK\x03\x04") {
        return None;
    }

    use std::io::Read;
    let cursor = std::io::Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return None,
    };

    let mut has_macros = false;
    let mut has_embedded_objects = false;
    let mut has_external_links = false;
    let mut suspicious_components: Vec<String> = Vec::new();

    // First pass: collect file names from central directory
    let mut file_names: Vec<String> = Vec::new();
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index_raw(i) {
            file_names.push(file.name().to_string());
        }
    }

    for name in &file_names {
        if name.contains("vbaProject.bin") {
            has_macros = true;
        }
        if name.contains("/embeddings/") {
            has_embedded_objects = true;
        }
    }

    if has_macros {
        suspicious_components.push("VBA macro project detected (vbaProject.bin)".to_string());
    }
    if has_embedded_objects {
        suspicious_components.push("Embedded objects detected".to_string());
    }

    // Second pass: scan .rels files for external link targets
    for i in 0..archive.len() {
        let mut file = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let name = file.name().to_string();
        if !name.ends_with(".rels") {
            continue;
        }
        let mut content = Vec::new();
        if file.read_to_end(&mut content).is_ok() {
            let has_ext = content
                .windows(b"TargetMode=\"External\"".len())
                .any(|w| w == b"TargetMode=\"External\"")
                || content
                    .windows(b"TargetMode='External'".len())
                    .any(|w| w == b"TargetMode='External'");
            if has_ext {
                has_external_links = true;
                break;
            }
        }
    }

    if has_external_links {
        suspicious_components.push("External link references in relationship files".to_string());
    }

    Some(output::OfficeAnalysis {
        has_macros,
        has_embedded_objects,
        has_external_links,
        suspicious_components,
    })
}

/// Metadata about a file being analysed — used by `analyse_bytes()` when the
/// caller already has the raw data (e.g. tests, in-memory pipelines).
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Display path (used for reports and error messages; need not exist on disk)
    pub path: PathBuf,
    /// File extension without the dot (lowercase), e.g. "exe", "js"
    pub extension: String,
    /// MIME type if known externally; None = auto-detect from bytes
    pub mime_type: Option<String>,
}

impl FileMetadata {
    /// Construct from a filesystem path (extracts extension automatically).
    pub fn from_path(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            extension: path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase(),
            mime_type: None,
        }
    }
}

/// Analyze raw bytes with associated metadata.
///
/// This is the core analysis entry point — works on any byte slice, no filesystem
/// required. Use this for in-memory pipelines, tests, and anywhere you
/// already have the data loaded.
///
/// `analyse_file()` is a convenience wrapper that opens + mmaps a file, then
/// delegates here.
pub fn analyse_bytes(
    data: &[u8],
    metadata: &FileMetadata,
    min_string_length: usize,
    depth: config::AnalysisDepth,
) -> Result<FileAnalysisResult> {
    let path = &metadata.path;
    let size_bytes = data.len();

    if size_bytes == 0 {
        anyhow::bail!("Cannot analyse empty data (0 bytes).");
    }

    // Calculate hashes
    let hashes = calculate_hashes(data);

    // Calculate entropy + byte histogram in one pass
    let (entropy, histogram) = calculate_entropy_and_histogram(data);

    // MIME type detection — use externally provided type if available, else auto-detect
    let mime_type = metadata
        .mime_type
        .clone()
        .or_else(|| detect_mime_type(data));
    let is_image = mime_type
        .as_deref()
        .map(|m| m.starts_with("image/"))
        .unwrap_or(false);

    // Extract strings + IOC detection (suppressed for image files and Quick depth)
    // Single-pass: extract strings once, reuse for both StringsInfo and IOC detection
    let skip_strings = is_image || depth == config::AnalysisDepth::Quick;
    let (strings, ioc_summary) = if skip_strings {
        let reason = if is_image {
            "Image file — string extraction not applicable"
        } else {
            "Skipped in quick analysis mode"
        };
        let suppressed = output::StringsInfo {
            min_length: min_string_length,
            total_count: 0,
            samples: vec![],
            sample_count: 0,
            classified: None,
            suppressed_reason: Some(reason.to_string()),
        };
        (suppressed, None)
    } else {
        let max_collect = match depth {
            config::AnalysisDepth::Deep => 2000,
            _ => 500,
        };
        let (strings_with_offsets, total_count) =
            extract_strings_with_offsets_limit(data, min_string_length, max_collect);

        // Build StringsInfo from the shared extraction
        let sample_count = 10.min(strings_with_offsets.len());
        let samples: Vec<String> = strings_with_offsets
            .iter()
            .take(sample_count)
            .map(|(s, _)| s.clone())
            .collect();
        let classified = Some(classify_strings(&strings_with_offsets));
        let s = output::StringsInfo {
            min_length: min_string_length,
            total_count,
            samples,
            sample_count,
            classified,
            suppressed_reason: None,
        };

        // IOC detection from the same extraction
        let ioc = {
            let summary = ioc::extract_iocs(&strings_with_offsets);
            if summary.ioc_strings.is_empty() {
                None
            } else {
                Some(summary)
            }
        };
        (s, ioc)
    };

    // Determine file format and analyse (Quick mode skips deep format parsing)
    let (file_format, pe_analysis, elf_analysis, mach_analysis) =
        if depth == config::AnalysisDepth::Quick {
            // Quick: detect format label only, skip full PE/ELF/Mach-O analysis
            let format_label = match Object::parse(data) {
                Ok(Object::PE(_)) => "Windows PE".to_string(),
                Ok(Object::Elf(_)) => "Linux ELF".to_string(),
                Ok(Object::Mach(_)) => "macOS Mach-O".to_string(),
                Ok(_) | Err(_) => mime_type
                    .as_deref()
                    .map(mime_to_format_label)
                    .unwrap_or_else(|| {
                        extension_to_format_label(path.extension().and_then(|e| e.to_str()))
                    }),
            };
            (format_label, None, None, None)
        } else {
            match Object::parse(data) {
                Ok(Object::PE(_)) => {
                    let pe_data = pe_parser::analyse_pe_data(data).with_context(|| {
                        format!(
                            "PE analysis failed for '{}'. The file may be corrupted or truncated.",
                            path.display()
                        )
                    })?;
                    ("Windows PE".to_string(), Some(pe_data), None, None)
                }
                Ok(Object::Elf(_)) => {
                    let elf_data = elf_parser::analyse_elf_data(data).with_context(|| {
                        format!(
                            "ELF analysis failed for '{}'. The file may be corrupted or truncated.",
                            path.display()
                        )
                    })?;
                    ("Linux ELF".to_string(), None, Some(elf_data), None)
                }
                Ok(Object::Mach(_)) => {
                    let macho = macho_parser::analyse_macho_data(data);
                    ("macOS Mach-O".to_string(), None, None, macho)
                }
                Ok(_) | Err(_) => {
                    // goblin didn't recognise it — use MIME type, then extension fallback
                    let format_label = mime_type
                        .as_deref()
                        .map(mime_to_format_label)
                        .unwrap_or_else(|| {
                            extension_to_format_label(path.extension().and_then(|e| e.to_str()))
                        });
                    (format_label, None, None, None)
                }
            }
        };

    // File type mismatch detection
    let file_type_mismatch =
        detect_file_type_mismatch(data, path.extension().and_then(|e| e.to_str()));

    // ── Format-specific analysis dispatch (via parser registry) ─────────
    // Skipped in Quick mode to keep analysis fast.
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let format_results = if depth == config::AnalysisDepth::Quick {
        Vec::new()
    } else {
        let parse_ctx = parser_registry::ParseContext {
            data,
            extension: &ext,
            format_label: file_format.as_str(),
            mime_type: mime_type.as_deref(),
            path,
            is_image,
        };
        parser_registry::REGISTRY.analyze_all(&parse_ctx)
    };

    let mut result = FileAnalysisResult {
        path: path.to_path_buf(),
        size_bytes,
        hashes,
        entropy,
        strings,
        file_format,
        pe_analysis,
        elf_analysis,
        mime_type,
        byte_histogram: Some(histogram),
        file_type_mismatch,
        ioc_summary,
        mach_analysis,
        // Format-specific fields populated below by the parser registry
        pdf_analysis: None,
        office_analysis: None,
        javascript_analysis: None,
        powershell_analysis: None,
        vbscript_analysis: None,
        shell_script_analysis: None,
        python_analysis: None,
        ole_analysis: None,
        rtf_analysis: None,
        zip_analysis: None,
        html_analysis: None,
        xml_analysis: None,
        image_analysis: None,
        lnk_analysis: None,
        iso_analysis: None,
        cab_analysis: None,
        msi_analysis: None,
        vhd_analysis: None,
        onenote_analysis: None,
        img_analysis: None,
        rar_analysis: None,
        gzip_analysis: None,
        sevenz_analysis: None,
        tar_analysis: None,
        secrets_detected: None,
        yara_matches: Vec::new(),
        pe_filename_mismatch: None,
    };

    // Apply all format-specific parser results
    parser_registry::apply_format_results(format_results, &mut result);

    // YARA scanning
    result.yara_matches = yara::scanner::scan_bytes(data);

    // PE OriginalFilename vs actual filename mismatch check
    if let Some(ref pe) = result.pe_analysis {
        if let Some(ref vi) = pe.version_info {
            if let Some(ref orig) = vi.original_filename {
                let actual = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if !actual.is_empty()
                    && !orig.is_empty()
                    && orig.to_lowercase() != actual.to_lowercase()
                {
                    result.pe_filename_mismatch = Some((orig.clone(), actual));
                }
            }
        }
    }

    Ok(result)
}

/// Analyze a single file from disk. Convenience wrapper around `analyse_bytes()`.
///
/// Opens the file, memory-maps it, then delegates to `analyse_bytes()`.
/// For in-memory analysis (tests, pipelines), call `analyse_bytes()` directly.
pub fn analyse_file(
    path: &Path,
    min_string_length: usize,
    depth: config::AnalysisDepth,
) -> Result<FileAnalysisResult> {
    let file = fs::File::open(path).with_context(|| {
        format!(
            "Couldn't read '{}'. Check that the file exists and you have read permission.",
            path.display()
        )
    })?;
    let file_size = file.metadata()?.len();

    const MAX_FILE_SIZE: u64 = 1_073_741_824; // 1GB
    if file_size > MAX_FILE_SIZE {
        anyhow::bail!(
            "File is too large for analysis ({:.1} GB). Maximum supported size is 1 GB.",
            file_size as f64 / 1_073_741_824.0
        );
    }

    if file_size == 0 {
        anyhow::bail!("This file is empty (0 bytes).");
    }

    let data = unsafe { Mmap::map(&file) }
        .with_context(|| format!("Failed to memory-map '{}'.", path.display()))?;

    let metadata = FileMetadata::from_path(path);
    analyse_bytes(&data, &metadata, min_string_length, depth)
}

/// Run only YARA rules against a file, skipping all other analysis.
///
/// Opens and memory-maps the file, then scans it with the compiled YARA rules.
/// Returns a lightweight result containing just the path, file size, and matches.
pub fn scan_yara_only(path: &Path) -> Result<output::YaraOnlyResult> {
    let file = fs::File::open(path).with_context(|| {
        format!(
            "Couldn't read '{}'. Check that the file exists and you have read permission.",
            path.display()
        )
    })?;
    let file_size = file.metadata()?.len();

    if file_size == 0 {
        return Ok(output::YaraOnlyResult {
            path: path.to_string_lossy().to_string(),
            size_bytes: 0,
            yara_matches: Vec::new(),
        });
    }

    let data = unsafe { Mmap::map(&file) }
        .with_context(|| format!("Failed to memory-map '{}'.", path.display()))?;

    let yara_matches = yara::scanner::scan_bytes(&data);

    Ok(output::YaraOnlyResult {
        path: path.to_string_lossy().to_string(),
        size_bytes: file_size as usize,
        yara_matches,
    })
}

/// Find all executable files in a directory
pub fn find_executable_files(dir_path: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    if !dir_path.exists() {
        anyhow::bail!(
            "Couldn't find the directory at '{}'. Double-check the path and try again.",
            dir_path.display()
        );
    }

    if !dir_path.is_dir() {
        anyhow::bail!(
            "'{}' is not a directory. Provide a directory path for batch scanning.",
            dir_path.display()
        );
    }

    let walker = if recursive {
        WalkDir::new(dir_path)
    } else {
        WalkDir::new(dir_path).max_depth(1)
    };

    let files: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            if !e.file_type().is_file() {
                return false;
            }
            // Reject symlinks to prevent symlink attacks
            match std::fs::symlink_metadata(e.path()) {
                Ok(meta) => !meta.file_type().is_symlink(),
                Err(_) => false,
            }
        })
        .map(|e| e.path().to_path_buf())
        .filter(|path| is_executable_file(path))
        .collect();

    Ok(files)
}

/// Compute a verdict string from analysis results.
/// Returns (verdict_word, full_summary) e.g. ("MALICIOUS", "MALICIOUS — 4 critical indicators, 2 high")
///
/// Delegates to the scoring crate's `score_analysis()`.
pub fn compute_verdict(result: &output::AnalysisResult) -> (String, String) {
    let scoring = confidence::score_analysis(result);
    (scoring.verdict, scoring.verdict_summary)
}

/// Check if a file is suspicious based on analysis
pub fn is_suspicious_file(result: &FileAnalysisResult) -> bool {
    // High entropy
    if result.entropy.is_suspicious {
        return true;
    }

    if let Some(ref pe) = result.pe_analysis {
        // Many suspicious APIs
        if pe.imports.suspicious_api_count > 5 {
            return true;
        }
        // W+X sections
        if pe.sections.iter().any(|s| s.is_wx) {
            return true;
        }
        // TLS callbacks present
        if pe.tls.as_ref().is_some_and(|t| t.callback_count > 0) {
            return true;
        }
        // High-entropy overlay
        if pe.overlay.as_ref().is_some_and(|o| o.high_entropy) {
            return true;
        }
        // Multiple anti-analysis categories
        if pe.anti_analysis.len() >= 2 {
            return true;
        }
        // Packer detected with high confidence
        if pe.packers.iter().any(|p| p.confidence == "High") {
            return true;
        }
        // Ordinal imports from sensitive DLLs
        if pe.ordinal_imports.iter().any(|o| {
            o.dll.eq_ignore_ascii_case("ntdll.dll") || o.dll.eq_ignore_ascii_case("kernel32.dll")
        }) {
            return true;
        }
    }

    if let Some(ref elf) = result.elf_analysis {
        // W+X ELF sections
        if elf.sections.iter().any(|s| s.is_wx) {
            return true;
        }
        // Packer detected
        if !elf.packer_indicators.is_empty() {
            return true;
        }
        // Suspicious function imports
        if !elf.imports.suspicious_functions.is_empty() {
            return true;
        }
    }

    false
}

/// Convert FileAnalysisResult to JSON output format
pub fn to_json_output(result: &FileAnalysisResult) -> output::AnalysisResult {
    let mut out = output::AnalysisResult {
        schema_version: output::ANALYSIS_SCHEMA_VERSION.to_string(),
        file_info: output::FileInfo {
            path: result.path.to_string_lossy().to_string(),
            size_bytes: result.size_bytes as u64,
            size_kb: result.size_bytes as f64 / 1024.0,
            extension: result
                .path
                .extension()
                .map(|e| e.to_string_lossy().to_string()),
            mime_type: result.mime_type.clone(),
        },
        hashes: result.hashes.clone(),
        entropy: result.entropy.clone(),
        strings: result.strings.clone(),
        pe_analysis: result.pe_analysis.clone(),
        elf_analysis: result.elf_analysis.clone(),
        file_format: result.file_format.clone(),
        imphash: result.pe_analysis.as_ref().and_then(|p| p.imphash.clone()),
        checksum_valid: result
            .pe_analysis
            .as_ref()
            .and_then(|p| p.checksum.as_ref().map(|c| !c.stored_nonzero || c.valid)),
        tls_callbacks: result.pe_analysis.as_ref().map_or(vec![], |p| {
            p.tls.as_ref().map_or(vec![], |t| {
                t.callback_rvas
                    .iter()
                    .map(|rva| output::TlsCallback {
                        virtual_address: rva.clone(),
                        raw_offset: 0,
                    })
                    .collect()
            })
        }),
        ordinal_imports: result
            .pe_analysis
            .as_ref()
            .map_or(vec![], |p| p.ordinal_imports.clone()),
        overlay: result.pe_analysis.as_ref().and_then(|p| p.overlay.clone()),
        packer_detections: result.pe_analysis.as_ref().map_or(vec![], |p| {
            p.packers
                .iter()
                .map(|pk| output::PackerDetection {
                    name: pk.name.clone(),
                    confidence: match pk.confidence.as_str() {
                        "Critical" => output::ConfidenceLevel::Critical,
                        "High" => output::ConfidenceLevel::High,
                        "Medium" => output::ConfidenceLevel::Medium,
                        _ => output::ConfidenceLevel::Low,
                    },
                    method: pk.detection_method.clone(),
                    evidence: format!("{} detected via {}", pk.name, pk.detection_method),
                })
                .collect()
        }),
        compiler_detection: result.pe_analysis.as_ref().and_then(|p| {
            p.compiler.as_ref().map(|c| output::CompilerDetection {
                compiler: c.name.clone(),
                language: c.name.clone(),
                confidence: match c.confidence.as_str() {
                    "High" => output::ConfidenceLevel::High,
                    "Medium" => output::ConfidenceLevel::Medium,
                    _ => output::ConfidenceLevel::Low,
                },
                evidence: vec![],
            })
        }),
        anti_analysis_indicators: result.pe_analysis.as_ref().map_or(vec![], |p| {
            p.anti_analysis
                .iter()
                .map(|a| output::AntiAnalysisIndicator {
                    technique: a.category.clone(),
                    evidence: a.indicator.clone(),
                    confidence: output::ConfidenceLevel::High,
                    mitre_technique_id: match a.category.as_str() {
                        "DebuggerDetection" => "T1622".to_string(),
                        "VmDetection" => "T1497.001".to_string(),
                        "TimingCheck" => "T1497.003".to_string(),
                        _ => "T1497".to_string(),
                    },
                })
                .collect()
        }),
        mitre_techniques: {
            // Collect all import names from suspicious APIs and map to MITRE techniques
            let import_names: Vec<&str> = result
                .pe_analysis
                .as_ref()
                .map(|p| {
                    p.imports
                        .suspicious_apis
                        .iter()
                        .map(|a| a.name.as_str())
                        .collect()
                })
                .unwrap_or_default();
            data::mitre_mappings::map_techniques_from_imports(&import_names)
        },
        confidence_scores: {
            let import_names: Vec<&str> = result
                .pe_analysis
                .as_ref()
                .map(|p| {
                    p.imports
                        .suspicious_apis
                        .iter()
                        .map(|a| a.name.as_str())
                        .collect()
                })
                .unwrap_or_default();
            let techniques = data::mitre_mappings::map_techniques_from_imports(&import_names);
            confidence::calculate_confidence(&techniques)
        },
        plain_english_findings: {
            let import_names: Vec<&str> = result
                .pe_analysis
                .as_ref()
                .map(|p| {
                    p.imports
                        .suspicious_apis
                        .iter()
                        .map(|a| a.name.as_str())
                        .collect()
                })
                .unwrap_or_default();
            data::explanations::get_explanation_for_api_combo(&import_names)
        },
        byte_histogram: result.byte_histogram.clone(),
        file_type_mismatch: result.file_type_mismatch.clone(),
        ioc_summary: result.ioc_summary.clone(),
        verdict_summary: None,   // filled below after struct is built
        top_findings: vec![],    // filled below after struct is built
        ksd_match: None,         // filled below after TLSH is available
        forensic_fragment: None, // filled below for sub-100B files
        known_sample: None,      // filled below after SHA256 is available
        family_annotation: None, // filled below after KSD match
        mach_analysis: result.mach_analysis.clone(),
        pdf_analysis: result.pdf_analysis.clone(),
        office_analysis: result.office_analysis.clone(),
        javascript_analysis: result.javascript_analysis.clone(),
        powershell_analysis: result.powershell_analysis.clone(),
        vbscript_analysis: result.vbscript_analysis.clone(),
        shell_script_analysis: result.shell_script_analysis.clone(),
        python_analysis: result.python_analysis.clone(),
        ole_analysis: result.ole_analysis.clone(),
        rtf_analysis: result.rtf_analysis.clone(),
        zip_analysis: result.zip_analysis.clone(),
        html_analysis: result.html_analysis.clone(),
        xml_analysis: result.xml_analysis.clone(),
        image_analysis: result.image_analysis.clone(),
        lnk_analysis: result.lnk_analysis.clone(),
        iso_analysis: result.iso_analysis.clone(),
        cab_analysis: result.cab_analysis.clone(),
        msi_analysis: result.msi_analysis.clone(),
        vhd_analysis: result.vhd_analysis.clone(),
        onenote_analysis: result.onenote_analysis.clone(),
        img_analysis: result.img_analysis.clone(),
        rar_analysis: result.rar_analysis.clone(),
        gzip_analysis: result.gzip_analysis.clone(),
        sevenz_analysis: result.sevenz_analysis.clone(),
        tar_analysis: result.tar_analysis.clone(),
        secrets_detected: None, // filled below after scoring extracts signals
        yara_matches: result.yara_matches.clone(),
    };

    // KSD lookup — find nearest known malware sample by TLSH similarity.
    // Failures are non-fatal: analysis continues without KSD if anything goes wrong.
    // Uses catch_unwind as a last resort since the KSD crate may panic on
    // corrupt overlay files or malformed TLSH values.
    //
    // Process-wide toggle via set_ksd_enabled (wired from the --no-ksd CLI
    // flag in main.rs). Distance threshold via set_ksd_threshold (wired
    // from --ksd-threshold). Both default to enabled / 150 respectively so
    // the existing Tauri GUI path keeps working unchanged.
    if is_ksd_enabled() {
        if let Some(ref tlsh) = out.hashes.tlsh {
            let max_distance = ksd_threshold();
            let ksd_result = std::panic::catch_unwind(|| {
                let ksd_overlay_path =
                    dirs::config_dir().map(|d| d.join("anya").join("known_samples.json"));
                let db = anya_scoring::ksd::KnownSampleDb::load(ksd_overlay_path.as_deref());
                if !db.is_empty() {
                    db.find_nearest(tlsh, max_distance)
                } else {
                    None
                }
            });
            if let Ok(result) = ksd_result {
                out.ksd_match = result;
            }
        }
    }

    // Attach family annotation if KSD matched a family
    if let Some(ref ksd) = out.ksd_match {
        out.family_annotation = lookup_family_annotation(&ksd.family);
    }

    // Forensic fragment annotation — for sub-100B files with KSD or SHA256 association
    if out.file_info.size_bytes < 100
        && out.pe_analysis.is_none()
        && out.elf_analysis.is_none()
        && out.mach_analysis.is_none()
    {
        // Try KSD (TLSH) first — works for files >= 50 bytes
        if let Some(ref ksd) = out.ksd_match {
            out.forensic_fragment = Some(output::ForensicFragment {
                associated_family: ksd.family.clone(),
                explanation: format!(
                    "This file is not independently malicious. It is a {} byte fragment \
                     associated with known malware ({}). It may be part of a malware package, \
                     build system, or delivery mechanism. Investigate surrounding files for context.",
                    out.file_info.size_bytes, ksd.family
                ),
            });
        }
        // For sub-50B files: try SHA256 exact-match against fragment database
        if out.forensic_fragment.is_none() {
            if let Some(frag) = lookup_fragment_db(&out.hashes.sha256) {
                out.forensic_fragment = Some(frag);
            }
        }
    }

    // Check known samples database (tools, PUPs, test files)
    out.known_sample = lookup_known_sample(&out.hashes.sha256);

    // Populate verdict and top findings so all consumers (CLI + GUI) get complete output
    let (verdict_word, verdict_text) = compute_verdict(&out);
    // Retrieve secret findings computed during signal extraction
    out.secrets_detected = confidence::take_secret_findings();
    // Known sample match overrides the heuristic verdict
    if let Some(ref ks) = out.known_sample {
        out.verdict_summary = Some(format!("{} — {}", ks.verdict, ks.name));
    } else {
        out.verdict_summary = Some(verdict_text);
    }
    let _ = verdict_word; // suppress unused warning

    let top = confidence::top_detections(&out, 3);
    out.top_findings = top
        .iter()
        .map(|d| output::TopFinding {
            label: d.description.clone(),
            confidence: d.confidence.clone(),
            technique_id: None,
        })
        .collect();

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_output_level_from_args() {
        assert_eq!(OutputLevel::from_args(false, false), OutputLevel::Normal);
        assert_eq!(OutputLevel::from_args(true, false), OutputLevel::Verbose);
        assert_eq!(OutputLevel::from_args(false, true), OutputLevel::Quiet);
    }

    #[test]
    fn test_output_level_should_print() {
        assert!(OutputLevel::Normal.should_print_info());
        assert!(OutputLevel::Verbose.should_print_info());
        assert!(!OutputLevel::Quiet.should_print_info());

        assert!(OutputLevel::Verbose.should_print_verbose());
        assert!(!OutputLevel::Normal.should_print_verbose());
        assert!(!OutputLevel::Quiet.should_print_verbose());
    }

    #[test]
    fn test_calculate_hashes() {
        let data = b"Hello, World!";
        let hashes = calculate_hashes(data);

        assert_eq!(hashes.md5.len(), 32);
        assert_eq!(hashes.sha1.len(), 40);
        assert_eq!(hashes.sha256.len(), 64);
        assert_eq!(hashes.md5, "65a8e27d8879283831b664bd8b7f0ad4");
    }

    #[test]
    fn test_calculate_entropy_zero() {
        let data = vec![0u8; 100];
        let entropy = calculate_file_entropy(&data);

        assert_eq!(entropy.value, 0.0);
        assert_eq!(entropy.category, "Low");
        assert!(!entropy.is_suspicious);
    }

    #[test]
    fn test_calculate_entropy_high() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = calculate_file_entropy(&data);

        assert!(entropy.value > 7.5);
        assert_eq!(entropy.category, "Very High");
        assert!(entropy.is_suspicious);
    }

    #[test]
    fn test_categorize_entropy() {
        assert_eq!(categorize_entropy(0.0), ("Low", false));
        assert_eq!(categorize_entropy(3.5), ("Low", false));
        assert_eq!(categorize_entropy(5.0), ("Moderate", false));
        assert_eq!(categorize_entropy(6.5), ("Moderate-High", false));
        assert_eq!(categorize_entropy(7.2), ("High", true));
        assert_eq!(categorize_entropy(7.8), ("Very High", true));
    }

    #[test]
    fn test_extract_strings_basic() {
        let data = b"Hello World\x00\x00Test String";
        let strings = extract_strings_data(data, 4);

        assert_eq!(strings.min_length, 4);
        assert_eq!(strings.total_count, 2);
        assert!(strings.samples.contains(&"Hello World".to_string()));
        assert!(strings.samples.contains(&"Test String".to_string()));
    }

    #[test]
    fn test_extract_strings_min_length() {
        let data = b"Hi\x00\x00Hello\x00\x00Greetings";
        let strings = extract_strings_data(data, 5);

        assert_eq!(strings.total_count, 2);
        assert!(strings.samples.contains(&"Hello".to_string()));
        assert!(strings.samples.contains(&"Greetings".to_string()));
    }

    #[test]
    fn test_extract_strings_sample_limit() {
        let mut data = Vec::new();
        for i in 0..20 {
            data.extend_from_slice(format!("String{}", i).as_bytes());
            data.push(0x00);
        }

        let strings = extract_strings_data(&data, 4);
        assert_eq!(strings.total_count, 20);
        assert_eq!(strings.sample_count, 10);
        assert_eq!(strings.samples.len(), 10);
    }

    #[test]
    fn test_is_executable_file() {
        // is_executable_file now accepts any existing regular file (no extension filter)
        use tempfile::NamedTempFile;
        let f = NamedTempFile::new().unwrap();
        assert!(is_executable_file(f.path()));
        // Non-existent paths return false
        assert!(!is_executable_file(&PathBuf::from(
            "/nonexistent/path/test.exe"
        )));
    }

    #[test]
    fn test_is_executable_case_insensitive() {
        // Extension is no longer filtered — any existing file is accepted
        use tempfile::NamedTempFile;
        let f = NamedTempFile::new().unwrap();
        assert!(is_executable_file(f.path()));
    }

    #[test]
    fn test_analyse_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Test file content").unwrap();

        let result = analyse_file(temp_file.path(), 4, config::AnalysisDepth::Standard).unwrap();

        assert_eq!(result.size_bytes, 17);
        assert_eq!(result.hashes.md5.len(), 32);
        assert!(result.strings.total_count > 0);
    }

    #[test]
    fn test_find_executable_files() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        fs::write(temp_dir.path().join("test.exe"), b"exe").unwrap();
        fs::write(temp_dir.path().join("test.dll"), b"dll").unwrap();
        fs::write(temp_dir.path().join("test.txt"), b"txt").unwrap();

        let files = find_executable_files(temp_dir.path(), false).unwrap();
        assert_eq!(files.len(), 3); // All files (no extension filter)
    }

    #[test]
    fn test_find_executable_files_recursive() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        fs::write(temp_dir.path().join("root.exe"), b"root").unwrap();
        fs::write(subdir.join("nested.exe"), b"nested").unwrap();

        // Non-recursive: should find 1
        let files = find_executable_files(temp_dir.path(), false).unwrap();
        assert_eq!(files.len(), 1);

        // Recursive: should find 2
        let files = find_executable_files(temp_dir.path(), true).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_batch_summary() {
        let summary = BatchSummary {
            total_files: 10,
            analysed: 8,
            failed: 2,
            duration: 4.0,
            ..Default::default()
        };

        assert_eq!(summary.success_rate(), 80.0);
        assert_eq!(summary.analysis_rate(), 2.0); // 8 files / 4 seconds
    }

    // ── is_suspicious_file helpers ──────────────────────────────────────────

    fn clean_entropy() -> output::EntropyInfo {
        output::EntropyInfo {
            value: 4.0,
            category: "Moderate".to_string(),
            is_suspicious: false,
            confidence: None,
        }
    }

    fn high_entropy() -> output::EntropyInfo {
        output::EntropyInfo {
            value: 7.8,
            category: "Very High".to_string(),
            is_suspicious: true,
            confidence: None,
        }
    }

    fn baseline_pe() -> output::PEAnalysis {
        output::PEAnalysis {
            architecture: "PE32+ (64-bit)".to_string(),
            is_64bit: true,
            image_base: "0x140000000".to_string(),
            entry_point: "0x1000".to_string(),
            file_type: "EXE".to_string(),
            security: output::SecurityFeatures {
                aslr_enabled: true,
                dep_enabled: true,
            },
            sections: vec![],
            imports: output::ImportAnalysis {
                dll_count: 0,
                total_imports: 0,
                suspicious_api_count: 0,
                suspicious_apis: vec![],
                libraries: vec![],
                imports_per_kb: None,
                import_ratio_suspicious: None,
            },
            exports: None,
            imphash: None,
            checksum: None,
            rich_header: None,
            tls: None,
            overlay: None,
            compiler: None,
            packers: vec![],
            anti_analysis: vec![],
            ordinal_imports: vec![],
            authenticode: None,
            version_info: None,
            debug_artifacts: None,
            weak_crypto: vec![],
            compiler_deps: vec![],
            anomalies: vec![],
            is_dotnet: false,
            packed_score: 0,
            has_delay_imports: false,
            spoofed_imports: vec![],
            resource_has_exe: false,
            resource_high_entropy: false,
            resource_oversized: false,
            overlay_has_exe: false,
            string_density: 0.0,
            dotnet_metadata: None,
            driver_analysis: None,
        }
    }

    fn baseline_result() -> FileAnalysisResult {
        FileAnalysisResult {
            path: PathBuf::from("test.exe"),
            size_bytes: 1024,
            hashes: calculate_hashes(b"test"),
            entropy: clean_entropy(),
            strings: extract_strings_data(b"test", 4),
            file_format: "Windows PE".to_string(),
            pe_analysis: None,
            elf_analysis: None,
            mime_type: None,
            byte_histogram: None,
            file_type_mismatch: None,
            ioc_summary: None,
            mach_analysis: None,
            pdf_analysis: None,
            office_analysis: None,
            javascript_analysis: None,
            powershell_analysis: None,
            vbscript_analysis: None,
            shell_script_analysis: None,
            python_analysis: None,
            ole_analysis: None,
            rtf_analysis: None,
            zip_analysis: None,
            html_analysis: None,
            xml_analysis: None,
            image_analysis: None,
            lnk_analysis: None,
            iso_analysis: None,
            cab_analysis: None,
            msi_analysis: None,
            vhd_analysis: None,
            onenote_analysis: None,
            img_analysis: None,
            rar_analysis: None,
            gzip_analysis: None,
            sevenz_analysis: None,
            tar_analysis: None,
            secrets_detected: None,
            yara_matches: Vec::new(),
            pe_filename_mismatch: None,
        }
    }

    // ── is_suspicious_file tests ─────────────────────────────────────────────

    #[test]
    fn test_is_suspicious_file_high_entropy() {
        let mut result = baseline_result();
        result.entropy = high_entropy();

        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_clean() {
        let result = baseline_result();
        assert!(!is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_wx_section() {
        let mut pe = baseline_pe();
        pe.sections.push(output::SectionInfo {
            name: ".evil".to_string(),
            virtual_size: 0x1000,
            virtual_address: "0x1000".to_string(),
            raw_size: 0x1000,
            entropy: 3.0,
            is_suspicious: false,
            is_wx: true,
            name_anomaly: None,
            md5: None,
            confidence: None,
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_many_suspicious_apis() {
        let mut pe = baseline_pe();
        pe.imports.suspicious_api_count = 6;
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_exactly_five_apis_not_suspicious() {
        let mut pe = baseline_pe();
        pe.imports.suspicious_api_count = 5; // threshold is > 5
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(!is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_high_confidence_packer() {
        let mut pe = baseline_pe();
        pe.packers.push(output::PackerFinding {
            name: "UPX".to_string(),
            confidence: "High".to_string(),
            detection_method: "String".to_string(),
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_medium_confidence_packer_not_suspicious() {
        let mut pe = baseline_pe();
        pe.packers.push(output::PackerFinding {
            name: "unknown packer".to_string(),
            confidence: "Medium".to_string(),
            detection_method: "Entropy".to_string(),
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(!is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_tls_callbacks() {
        let mut pe = baseline_pe();
        pe.tls = Some(output::TlsInfo {
            callback_count: 2,
            callback_rvas: vec!["0x1234".to_string(), "0x5678".to_string()],
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_tls_zero_callbacks_not_suspicious() {
        let mut pe = baseline_pe();
        pe.tls = Some(output::TlsInfo {
            callback_count: 0,
            callback_rvas: vec![],
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(!is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_high_entropy_overlay() {
        let mut pe = baseline_pe();
        pe.overlay = Some(output::OverlayInfo {
            offset: 0x400,
            size: 256,
            entropy: 7.5,
            high_entropy: true,
            overlay_mime_type: None,
            overlay_characterisation: None,
            confidence: None,
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_low_entropy_overlay_not_suspicious() {
        let mut pe = baseline_pe();
        pe.overlay = Some(output::OverlayInfo {
            offset: 0x400,
            size: 256,
            entropy: 3.0,
            high_entropy: false,
            overlay_mime_type: None,
            overlay_characterisation: None,
            confidence: None,
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(!is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_two_anti_analysis_categories() {
        let mut pe = baseline_pe();
        pe.anti_analysis.push(output::AntiAnalysisFinding {
            category: "DebuggerDetection".to_string(),
            indicator: "IsDebuggerPresent".to_string(),
        });
        pe.anti_analysis.push(output::AntiAnalysisFinding {
            category: "TimingCheck".to_string(),
            indicator: "GetTickCount".to_string(),
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_one_anti_analysis_not_suspicious() {
        let mut pe = baseline_pe();
        pe.anti_analysis.push(output::AntiAnalysisFinding {
            category: "DebuggerDetection".to_string(),
            indicator: "IsDebuggerPresent".to_string(),
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(!is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_ntdll_ordinal_import() {
        let mut pe = baseline_pe();
        pe.ordinal_imports.push(output::OrdinalImport {
            dll: "ntdll.dll".to_string(),
            ordinal: 42,
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_kernel32_ordinal_import() {
        let mut pe = baseline_pe();
        pe.ordinal_imports.push(output::OrdinalImport {
            dll: "kernel32.dll".to_string(),
            ordinal: 7,
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_user32_ordinal_not_sensitive() {
        let mut pe = baseline_pe();
        pe.ordinal_imports.push(output::OrdinalImport {
            dll: "user32.dll".to_string(),
            ordinal: 100,
        });
        let mut result = baseline_result();
        result.pe_analysis = Some(pe);
        assert!(!is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_elf_wx_section() {
        let mut result = baseline_result();
        result.file_format = "Linux ELF".to_string();
        result.elf_analysis = Some(output::ELFAnalysis {
            architecture: "x86_64".to_string(),
            is_64bit: true,
            file_type: "Executable".to_string(),
            entry_point: "0x1000".to_string(),
            interpreter: None,
            sections: vec![output::ElfSectionInfo {
                name: ".text".to_string(),
                section_type: "PROGBITS".to_string(),
                size: 0x1000,
                entropy: 3.0,
                is_wx: true,
                is_suspicious: false,
            }],
            imports: output::ElfImportAnalysis {
                library_count: 0,
                libraries: vec![],
                dynamic_symbol_count: 0,
                suspicious_functions: vec![],
            },
            is_pie: true,
            has_nx_stack: true,
            has_relro: true,
            is_stripped: false,
            packer_indicators: vec![],
            got_plt_suspicious: vec![],
            rpath_anomalies: vec![],
            has_dwarf_info: false,
            interpreter_suspicious: false,
            suspicious_section_names: vec![],
            suspicious_libc_calls: vec![],
        });
        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_is_suspicious_file_elf_packer() {
        let mut result = baseline_result();
        result.file_format = "Linux ELF".to_string();
        result.elf_analysis = Some(output::ELFAnalysis {
            architecture: "x86_64".to_string(),
            is_64bit: true,
            file_type: "Executable".to_string(),
            entry_point: "0x1000".to_string(),
            interpreter: None,
            sections: vec![],
            imports: output::ElfImportAnalysis {
                library_count: 0,
                libraries: vec![],
                dynamic_symbol_count: 0,
                suspicious_functions: vec![],
            },
            is_pie: false,
            has_nx_stack: false,
            has_relro: false,
            is_stripped: true,
            packer_indicators: vec![output::PackerFinding {
                name: "UPX".to_string(),
                confidence: "High".to_string(),
                detection_method: "String".to_string(),
            }],
            got_plt_suspicious: vec![],
            rpath_anomalies: vec![],
            has_dwarf_info: false,
            interpreter_suspicious: false,
            suspicious_section_names: vec![],
            suspicious_libc_calls: vec![],
        });
        assert!(is_suspicious_file(&result));
    }

    #[test]
    fn test_to_json_output() {
        let result = FileAnalysisResult {
            path: PathBuf::from("test.exe"),
            size_bytes: 1024,
            hashes: calculate_hashes(b"test"),
            entropy: calculate_file_entropy(b"test"),
            strings: extract_strings_data(b"test", 4),
            file_format: "PE".to_string(),
            pe_analysis: None,
            elf_analysis: None,
            mime_type: None,
            byte_histogram: None,
            file_type_mismatch: None,
            ioc_summary: None,
            mach_analysis: None,
            pdf_analysis: None,
            office_analysis: None,
            javascript_analysis: None,
            powershell_analysis: None,
            vbscript_analysis: None,
            shell_script_analysis: None,
            python_analysis: None,
            ole_analysis: None,
            rtf_analysis: None,
            zip_analysis: None,
            html_analysis: None,
            xml_analysis: None,
            image_analysis: None,
            lnk_analysis: None,
            iso_analysis: None,
            cab_analysis: None,
            msi_analysis: None,
            vhd_analysis: None,
            onenote_analysis: None,
            img_analysis: None,
            rar_analysis: None,
            gzip_analysis: None,
            sevenz_analysis: None,
            tar_analysis: None,
            secrets_detected: None,
            yara_matches: Vec::new(),
            pe_filename_mismatch: None,
        };

        let json = to_json_output(&result);
        assert_eq!(json.file_info.size_bytes, 1024);
        assert_eq!(json.file_format, "PE");
    }
}
