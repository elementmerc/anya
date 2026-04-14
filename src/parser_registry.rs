// Ányá - Malware Analysis Platform
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later
//
// Parser trait and registry.
// Every format parser implements `FormatParser`, and `ParserRegistry` dispatches
// analysis based on file extension, MIME type, and content detection.

use crate::output;

/// The result of a format-specific parser.
/// Each variant wraps the analysis struct from output.rs.
#[derive(Debug, Clone)]
pub enum FormatAnalysis {
    JavaScript(output::JavaScriptAnalysis),
    PowerShell(output::PowerShellAnalysis),
    VbScript(output::VbScriptAnalysis),
    ShellScript(output::ShellScriptAnalysis),
    Python(output::PythonAnalysis),
    Ole(output::OleAnalysis),
    Rtf(output::RtfAnalysis),
    Zip(output::ZipAnalysis),
    Html(output::HtmlAnalysis),
    Xml(output::XmlAnalysis),
    Image(output::ImageAnalysis),
    Lnk(output::LnkAnalysis),
    Iso(output::IsoAnalysis),
    Cab(output::CabAnalysis),
    Msi(output::MsiAnalysis),
    Pdf(output::PdfAnalysis),
    Office(output::OfficeAnalysis),
    Vhd(output::VhdAnalysis),
    OneNote(output::OneNoteAnalysis),
    Img(output::ImgAnalysis),
    Rar(output::RarAnalysis),
    Gzip(output::GzipAnalysis),
    SevenZip(output::SevenZipAnalysis),
    Tar(output::TarAnalysis),
}

/// Context passed to each parser — everything it might need to decide
/// whether to run and what to produce.
pub struct ParseContext<'a> {
    /// Raw file bytes (memory-mapped)
    pub data: &'a [u8],
    /// File extension (lowercase, no dot), empty if none
    pub extension: &'a str,
    /// Format label from goblin/MIME detection (e.g. "JavaScript", "ZIP Archive")
    pub format_label: &'a str,
    /// MIME type if detected, e.g. "application/pdf"
    pub mime_type: Option<&'a str>,
    /// File path (for parsers that need it, e.g. Office OOXML opens sub-files)
    pub path: &'a std::path::Path,
    /// Whether the file was identified as an image by MIME detection
    pub is_image: bool,
}

/// Trait that all format parsers implement.
/// Parsers are stateless — all state lives in the context or the output.
pub trait FormatParser: Send + Sync {
    /// Human-readable name for logging and diagnostics.
    fn name(&self) -> &'static str;

    /// Returns true if this parser should run for the given context.
    /// Checked before `analyze()` — keep this fast.
    fn can_parse(&self, ctx: &ParseContext) -> bool;

    /// Run analysis and return results. Called only if `can_parse()` returned true.
    /// Returns None if the file doesn't contain anything noteworthy for this parser.
    fn analyze(&self, ctx: &ParseContext) -> Option<FormatAnalysis>;
}

/// Registry of all format parsers. Built once at startup, used for every analysis.
pub struct ParserRegistry {
    parsers: Vec<Box<dyn FormatParser>>,
}

impl ParserRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
        }
    }

    /// Register a parser. Order matters — parsers run in registration order.
    pub fn register<P: FormatParser + 'static>(&mut self, parser: P) {
        self.parsers.push(Box::new(parser));
    }

    /// Run all applicable parsers and collect results.
    pub fn analyze_all(&self, ctx: &ParseContext) -> Vec<FormatAnalysis> {
        self.parsers
            .iter()
            .filter(|p| p.can_parse(ctx))
            .filter_map(|p| p.analyze(ctx))
            .collect()
    }

    /// Number of registered parsers.
    pub fn len(&self) -> usize {
        self.parsers.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Built-in parser implementations ──────────────────────────────────────────
// Each wraps the existing detect_*_analysis() function from its parser module.

macro_rules! impl_format_parser {
    ($struct_name:ident, $display_name:expr, $can_parse_fn:expr, $analyze_fn:expr) => {
        pub struct $struct_name;
        impl FormatParser for $struct_name {
            fn name(&self) -> &'static str {
                $display_name
            }
            fn can_parse(&self, ctx: &ParseContext) -> bool {
                ($can_parse_fn)(ctx)
            }
            fn analyze(&self, ctx: &ParseContext) -> Option<FormatAnalysis> {
                ($analyze_fn)(ctx)
            }
        }
    };
}

impl_format_parser!(
    JavaScriptParser,
    "JavaScript",
    |ctx: &ParseContext| {
        ctx.format_label == "JavaScript"
            || ctx.extension == "js"
            || ctx.extension == "jse"
            || ctx.extension == "mjs"
    },
    |ctx: &ParseContext| {
        crate::js_parser::detect_javascript_analysis(ctx.data).map(FormatAnalysis::JavaScript)
    }
);

impl_format_parser!(
    PowerShellParser,
    "PowerShell",
    |ctx: &ParseContext| {
        ctx.extension == "ps1" || ctx.extension == "psm1" || ctx.extension == "psd1"
    },
    |ctx: &ParseContext| {
        crate::ps_parser::detect_powershell_analysis(ctx.data).map(FormatAnalysis::PowerShell)
    }
);

impl_format_parser!(
    VbScriptParser,
    "VBScript",
    |ctx: &ParseContext| {
        ctx.extension == "vbs" || ctx.extension == "vbe" || ctx.extension == "wsf"
    },
    |ctx: &ParseContext| {
        crate::vbs_parser::detect_vbscript_analysis(ctx.data).map(FormatAnalysis::VbScript)
    }
);

impl_format_parser!(
    ShellScriptParser,
    "Shell Script",
    |ctx: &ParseContext| {
        ctx.extension == "bat"
            || ctx.extension == "cmd"
            || ctx.extension == "sh"
            || ctx.extension == "bash"
            || ctx.format_label == "Shell Script"
    },
    |ctx: &ParseContext| {
        crate::script_parser::detect_shell_script_analysis(ctx.data)
            .map(FormatAnalysis::ShellScript)
    }
);

impl_format_parser!(
    PythonParser,
    "Python",
    |ctx: &ParseContext| {
        ctx.extension == "py" || ctx.extension == "pyw" || ctx.format_label == "Python Script"
    },
    |ctx: &ParseContext| {
        crate::python_parser::detect_python_analysis(ctx.data).map(FormatAnalysis::Python)
    }
);

impl_format_parser!(
    OleParser,
    "OLE Compound Document",
    |_ctx: &ParseContext| true, // OLE checks magic bytes internally
    |ctx: &ParseContext| {
        crate::ole_parser::detect_ole_analysis(ctx.data).map(FormatAnalysis::Ole)
    }
);

impl_format_parser!(
    RtfParser,
    "Rich Text Format",
    |_ctx: &ParseContext| true, // RTF checks magic bytes internally
    |ctx: &ParseContext| {
        crate::rtf_parser::detect_rtf_analysis(ctx.data).map(FormatAnalysis::Rtf)
    }
);

impl_format_parser!(
    ZipParser,
    "ZIP Archive",
    |ctx: &ParseContext| ctx.format_label == "ZIP Archive" || ctx.extension == "zip",
    |ctx: &ParseContext| {
        crate::zip_parser::detect_zip_analysis(ctx.data).map(FormatAnalysis::Zip)
    }
);

impl_format_parser!(
    HtmlParser,
    "HTML/HTA",
    |ctx: &ParseContext| {
        ctx.format_label == "HTML Document"
            || ctx.format_label == "HTML"
            || ctx.extension == "html"
            || ctx.extension == "htm"
            || ctx.extension == "hta"
    },
    |ctx: &ParseContext| {
        crate::html_parser::detect_html_analysis(ctx.data).map(FormatAnalysis::Html)
    }
);

impl_format_parser!(
    XmlParser,
    "XML/SVG",
    |ctx: &ParseContext| {
        ctx.format_label == "XML Document"
            || ctx.extension == "xml"
            || ctx.extension == "svg"
            || ctx.extension == "xsl"
    },
    |ctx: &ParseContext| {
        crate::xml_parser::detect_xml_analysis(ctx.data).map(FormatAnalysis::Xml)
    }
);

impl_format_parser!(
    ImageParser,
    "Image",
    |ctx: &ParseContext| ctx.is_image,
    |ctx: &ParseContext| {
        crate::image_parser::detect_image_analysis(ctx.data).map(FormatAnalysis::Image)
    }
);

impl_format_parser!(
    LnkParser,
    "Windows Shortcut",
    |ctx: &ParseContext| ctx.extension == "lnk" || ctx.format_label == "Windows Shortcut",
    |ctx: &ParseContext| {
        crate::lnk_parser::detect_lnk_analysis(ctx.data).map(FormatAnalysis::Lnk)
    }
);

impl_format_parser!(
    IsoParser,
    "ISO 9660",
    |ctx: &ParseContext| ctx.format_label == "ISO 9660" || ctx.extension == "iso",
    |ctx: &ParseContext| {
        crate::iso_parser::detect_iso_analysis(ctx.data).map(FormatAnalysis::Iso)
    }
);

impl_format_parser!(
    CabParser,
    "Windows Cabinet",
    |ctx: &ParseContext| ctx.format_label == "Windows Cabinet" || ctx.extension == "cab",
    |ctx: &ParseContext| {
        crate::cab_parser::detect_cab_analysis(ctx.data).map(FormatAnalysis::Cab)
    }
);

impl_format_parser!(
    MsiParser,
    "MSI Installer",
    |ctx: &ParseContext| ctx.extension == "msi",
    |ctx: &ParseContext| {
        crate::msi_parser::detect_msi_analysis(ctx.data).map(FormatAnalysis::Msi)
    }
);

impl_format_parser!(
    PdfParser,
    "PDF",
    |_ctx: &ParseContext| true, // PDF checks magic bytes internally
    |ctx: &ParseContext| { crate::detect_pdf_analysis(ctx.data).map(FormatAnalysis::Pdf) }
);

impl_format_parser!(
    OfficeParser,
    "Office Document",
    |_ctx: &ParseContext| true, // Office checks magic bytes internally
    |ctx: &ParseContext| {
        crate::detect_office_analysis(ctx.data, ctx.path).map(FormatAnalysis::Office)
    }
);

impl_format_parser!(
    VhdParser,
    "VHD Disk Image",
    |ctx: &ParseContext| {
        ctx.extension == "vhd"
            || ctx.extension == "vhdx"
            || (ctx.data.len() >= 8
                && (&ctx.data[0..8] == b"conectix" || &ctx.data[0..8] == b"vhdxfile"))
    },
    |ctx: &ParseContext| {
        crate::vhd_parser::detect_vhd_analysis(ctx.data).map(FormatAnalysis::Vhd)
    }
);

impl_format_parser!(
    OneNoteParser,
    "OneNote Document",
    |ctx: &ParseContext| {
        ctx.extension == "one"
            || ctx.extension == "onenote"
            || (ctx.data.len() >= 16
                && ctx.data[0..16]
                    == [
                        0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78,
                        0xD0, 0x29, 0x96, 0xD3,
                    ])
    },
    |ctx: &ParseContext| {
        crate::onenote_parser::detect_onenote_analysis(ctx.data).map(FormatAnalysis::OneNote)
    }
);

impl_format_parser!(
    ImgParser,
    "Disk Image",
    |ctx: &ParseContext| {
        ctx.extension == "img" || ctx.extension == "dd" || ctx.extension == "raw"
    },
    |ctx: &ParseContext| {
        crate::img_parser::detect_img_analysis(ctx.data).map(FormatAnalysis::Img)
    }
);

impl_format_parser!(
    RarParser,
    "RAR Archive",
    |ctx: &ParseContext| {
        ctx.extension == "rar" || (ctx.data.len() >= 7 && &ctx.data[0..4] == b"Rar!")
    },
    |ctx: &ParseContext| {
        crate::rar_parser::detect_rar_analysis(ctx.data).map(FormatAnalysis::Rar)
    }
);

impl_format_parser!(
    GzipParser,
    "GZIP Archive",
    |ctx: &ParseContext| {
        ctx.extension == "gz"
            || ctx.extension == "gzip"
            || ctx.extension == "tgz"
            || (ctx.data.len() >= 2 && ctx.data[0] == 0x1F && ctx.data[1] == 0x8B)
    },
    |ctx: &ParseContext| {
        crate::gzip_parser::detect_gzip_analysis(ctx.data).map(FormatAnalysis::Gzip)
    }
);

impl_format_parser!(
    SevenZipParser,
    "7-Zip Archive",
    |ctx: &ParseContext| {
        ctx.extension == "7z"
            || (ctx.data.len() >= 6 && ctx.data[0..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
    },
    |ctx: &ParseContext| {
        crate::sevenz_parser::detect_sevenz_analysis(ctx.data).map(FormatAnalysis::SevenZip)
    }
);

impl_format_parser!(
    TarParser,
    "TAR Archive",
    |ctx: &ParseContext| {
        ctx.extension == "tar"
            || ctx.extension == "tgz"
            || (ctx.data.len() >= 262 && &ctx.data[257..262] == b"ustar")
    },
    |ctx: &ParseContext| {
        crate::tar_parser::detect_tar_analysis(ctx.data).map(FormatAnalysis::Tar)
    }
);

// ── Default registry with all built-in parsers ──────────────────────────────

/// Build the default registry with all 24 format parsers.
/// Called once at startup (or lazily on first analysis).
pub fn default_registry() -> ParserRegistry {
    let mut reg = ParserRegistry::new();
    // Script parsers (extension-gated — fast to skip)
    reg.register(JavaScriptParser);
    reg.register(PowerShellParser);
    reg.register(VbScriptParser);
    reg.register(ShellScriptParser);
    reg.register(PythonParser);
    // Document/archive parsers
    reg.register(OleParser);
    reg.register(RtfParser);
    reg.register(ZipParser);
    // Media/markup parsers
    reg.register(HtmlParser);
    reg.register(XmlParser);
    reg.register(ImageParser);
    reg.register(LnkParser);
    reg.register(IsoParser);
    reg.register(CabParser);
    reg.register(MsiParser);
    // Content-detection parsers (always try, check magic internally)
    reg.register(PdfParser);
    reg.register(OfficeParser);
    // Disk image parsers
    reg.register(VhdParser);
    reg.register(ImgParser);
    // Archive parsers
    reg.register(RarParser);
    reg.register(GzipParser);
    reg.register(SevenZipParser);
    reg.register(TarParser);
    // Document parsers
    reg.register(OneNoteParser);
    reg
}

/// Global registry instance — initialized once, shared across all analyses.
pub static REGISTRY: LazyLock<ParserRegistry> = LazyLock::new(default_registry);

use std::sync::LazyLock;

// ── Helper: apply FormatAnalysis results to FileAnalysisResult ───────────────

/// Merge a list of format analysis results into the main analysis result fields.
pub fn apply_format_results(results: Vec<FormatAnalysis>, result: &mut crate::FileAnalysisResult) {
    for fa in results {
        match fa {
            FormatAnalysis::JavaScript(a) => result.javascript_analysis = Some(a),
            FormatAnalysis::PowerShell(a) => result.powershell_analysis = Some(a),
            FormatAnalysis::VbScript(a) => result.vbscript_analysis = Some(a),
            FormatAnalysis::ShellScript(a) => result.shell_script_analysis = Some(a),
            FormatAnalysis::Python(a) => result.python_analysis = Some(a),
            FormatAnalysis::Ole(a) => result.ole_analysis = Some(a),
            FormatAnalysis::Rtf(a) => result.rtf_analysis = Some(a),
            FormatAnalysis::Zip(a) => result.zip_analysis = Some(a),
            FormatAnalysis::Html(a) => result.html_analysis = Some(a),
            FormatAnalysis::Xml(a) => result.xml_analysis = Some(a),
            FormatAnalysis::Image(a) => result.image_analysis = Some(a),
            FormatAnalysis::Lnk(a) => result.lnk_analysis = Some(a),
            FormatAnalysis::Iso(a) => result.iso_analysis = Some(a),
            FormatAnalysis::Cab(a) => result.cab_analysis = Some(a),
            FormatAnalysis::Msi(a) => result.msi_analysis = Some(a),
            FormatAnalysis::Pdf(a) => result.pdf_analysis = Some(a),
            FormatAnalysis::Office(a) => result.office_analysis = Some(a),
            FormatAnalysis::Vhd(a) => result.vhd_analysis = Some(a),
            FormatAnalysis::OneNote(a) => result.onenote_analysis = Some(a),
            FormatAnalysis::Img(a) => result.img_analysis = Some(a),
            FormatAnalysis::Rar(a) => result.rar_analysis = Some(a),
            FormatAnalysis::Gzip(a) => result.gzip_analysis = Some(a),
            FormatAnalysis::SevenZip(a) => result.sevenz_analysis = Some(a),
            FormatAnalysis::Tar(a) => result.tar_analysis = Some(a),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_all_parsers() {
        let reg = default_registry();
        assert_eq!(
            reg.len(),
            24,
            "Expected 24 format parsers in default registry"
        );
    }

    #[test]
    fn js_parser_matches_extensions() {
        let data = b"var x = 1;";
        let ctx = ParseContext {
            data,
            extension: "js",
            format_label: "",
            mime_type: None,
            path: std::path::Path::new("test.js"),
            is_image: false,
        };
        assert!(JavaScriptParser.can_parse(&ctx));
    }

    #[test]
    fn image_parser_only_for_images() {
        let data = b"\x89PNG";
        let ctx = ParseContext {
            data,
            extension: "png",
            format_label: "PNG Image",
            mime_type: Some("image/png"),
            path: std::path::Path::new("test.png"),
            is_image: true,
        };
        assert!(ImageParser.can_parse(&ctx));

        let ctx2 = ParseContext {
            is_image: false,
            ..ctx
        };
        assert!(!ImageParser.can_parse(&ctx2));
    }

    #[test]
    fn registry_skips_non_matching_parsers() {
        let mut reg = ParserRegistry::new();
        reg.register(JavaScriptParser);
        reg.register(PowerShellParser);

        let data = b"$x = 1";
        let ctx = ParseContext {
            data,
            extension: "ps1",
            format_label: "",
            mime_type: None,
            path: std::path::Path::new("test.ps1"),
            is_image: false,
        };
        // JS parser should not match, PS parser should
        let results = reg.analyze_all(&ctx);
        // Results may be empty if the data doesn't contain enough suspicious content
        // but at least we verified no panics and correct dispatch
        assert!(results.len() <= 1);
    }
}
