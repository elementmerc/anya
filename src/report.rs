// Anya - Malware Analysis Platform
// Report module: generate styled HTML analysis reports
//
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later

use anya_security_core::output;
use printpdf::*;
use std::path::Path;

const CSS: &str = r#"
:root {
    --bg: #1a1b2e;
    --sidebar: #12131f;
    --card: #222340;
    --text: #e0e0e8;
    --text-dim: #888899;
    --accent: #ff6b6b;
    --green: #4ecdc4;
    --yellow: #ffe66d;
    --red: #ff6b6b;
    --cyan: #00d2ff;
    --border: #333355;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', 'SF Pro', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
}
header {
    background: var(--sidebar);
    padding: 2rem 3rem;
    border-bottom: 2px solid var(--accent);
    display: flex;
    justify-content: space-between;
    align-items: center;
}
header h1 {
    font-size: 1.5rem;
    font-weight: 600;
    letter-spacing: 0.05em;
}
header h1 span { color: var(--accent); }
.verdict {
    font-size: 1.2rem;
    font-weight: 700;
    padding: 0.5rem 1.5rem;
    border-radius: 6px;
    text-transform: uppercase;
}
.verdict-malicious { background: rgba(255,107,107,0.2); color: var(--red); border: 1px solid var(--red); }
.verdict-suspicious { background: rgba(255,230,109,0.15); color: var(--yellow); border: 1px solid var(--yellow); }
.verdict-clean { background: rgba(78,205,196,0.15); color: var(--green); border: 1px solid var(--green); }
.verdict-unknown { background: rgba(136,136,153,0.15); color: var(--text-dim); border: 1px solid var(--border); }
main { max-width: 1100px; margin: 2rem auto; padding: 0 2rem; }
.section {
    background: var(--card);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    border: 1px solid var(--border);
}
.section h2 {
    color: var(--cyan);
    font-size: 1.1rem;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
}
table { width: 100%; border-collapse: collapse; }
td, th {
    text-align: left;
    padding: 0.4rem 0.8rem;
    border-bottom: 1px solid var(--border);
}
th { color: var(--text-dim); font-weight: 500; width: 160px; }
.mono { font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.9rem; }
.tag {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 3px;
    font-size: 0.8rem;
    font-weight: 600;
    margin-right: 0.3rem;
}
.tag-critical { background: rgba(255,107,107,0.25); color: var(--red); }
.tag-high { background: rgba(255,230,109,0.2); color: var(--yellow); }
.tag-medium { background: rgba(0,210,255,0.15); color: var(--cyan); }
.tag-low { background: rgba(136,136,153,0.15); color: var(--text-dim); }
.finding-row { display: flex; align-items: center; padding: 0.4rem 0; }
.finding-row .desc { margin-left: 0.5rem; }
footer {
    text-align: center;
    padding: 2rem;
    color: var(--text-dim);
    font-size: 0.85rem;
}
"#;

/// Generate a self-contained HTML report from an AnalysisResult.
pub fn generate_html_report(
    result: &output::AnalysisResult,
    output_path: &Path,
) -> anyhow::Result<()> {
    let filename = &result.file_info.path;

    let verdict_word = result.verdict_summary.as_deref().unwrap_or("UNKNOWN");
    let verdict_class = if verdict_word.contains("MALICIOUS") {
        "verdict-malicious"
    } else if verdict_word.contains("SUSPICIOUS") {
        "verdict-suspicious"
    } else if verdict_word.contains("CLEAN") {
        "verdict-clean"
    } else {
        "verdict-unknown"
    };

    // Top findings HTML
    let findings_html: String = result
        .top_findings
        .iter()
        .map(|f| {
            let conf_str = format!("{}", f.confidence);
            let tag_class = match conf_str.as_str() {
                "Critical" => "tag-critical",
                "High" => "tag-high",
                "Medium" => "tag-medium",
                _ => "tag-low",
            };
            format!(
                r#"<div class="finding-row"><span class="tag {}">{}</span><span class="desc">{}</span></div>"#,
                tag_class, conf_str, escape_html(&f.label)
            )
        })
        .collect();

    // PE sections table rows
    let sections_html: String = result
        .pe_analysis
        .as_ref()
        .map(|pe| {
            pe.sections
                .iter()
                .map(|s| {
                    let flags = format!(
                        "{}{}",
                        if s.is_wx { "W+X " } else { "" },
                        if s.is_suspicious { "Suspicious" } else { "" }
                    );
                    format!(
                        "<tr><td class=\"mono\">{}</td><td>{}</td><td>{:.4}</td><td>{}</td></tr>",
                        escape_html(&s.name),
                        s.virtual_size,
                        s.entropy,
                        escape_html(flags.trim()),
                    )
                })
                .collect::<String>()
        })
        .unwrap_or_default();

    // Suspicious APIs
    let imports_html: String = result
        .pe_analysis
        .as_ref()
        .map(|pe| {
            pe.imports
                .suspicious_apis
                .iter()
                .map(|a| {
                    format!(
                        "<tr><td class=\"mono\">{}</td><td>{}</td></tr>",
                        escape_html(&a.name),
                        escape_html(&a.category)
                    )
                })
                .collect::<String>()
        })
        .unwrap_or_default();

    // Security features
    let security_html: String = result
        .pe_analysis
        .as_ref()
        .map(|pe| {
            format!(
                "<tr><th>ASLR</th><td>{}</td></tr>\
                 <tr><th>DEP/NX</th><td>{}</td></tr>",
                bool_badge(pe.security.aslr_enabled),
                bool_badge(pe.security.dep_enabled),
            )
        })
        .unwrap_or_default();

    // ELF sections table (for ELF files)
    let elf_sections_html: String = result
        .elf_analysis
        .as_ref()
        .map(|elf| {
            elf.sections
                .iter()
                .map(|s| {
                    format!(
                        "<tr><td class=\"mono\">{}</td><td>{}</td><td>{:.4}</td><td>{}</td></tr>",
                        escape_html(&s.name),
                        s.size,
                        s.entropy,
                        escape_html(&s.section_type)
                    )
                })
                .collect::<String>()
        })
        .unwrap_or_default();

    // IOC section
    let ioc_html: String = result
        .ioc_summary
        .as_ref()
        .map(|ioc| {
            ioc.ioc_strings
                .iter()
                .take(20)
                .map(|es| {
                    let ioc_type = es
                        .ioc_type
                        .as_ref()
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "other".to_string());
                    let display = if es.value.len() > 80 {
                        format!("{}...", &es.value[..77])
                    } else {
                        es.value.clone()
                    };
                    format!(
                        "<tr><td>{}</td><td class=\"mono\">{}</td></tr>",
                        escape_html(&ioc_type),
                        escape_html(&display)
                    )
                })
                .collect::<String>()
        })
        .unwrap_or_default();

    // KSD Match
    let ksd_html: String = result
        .ksd_match
        .as_ref()
        .map(|k| {
            format!(
                r#"<div class="section"><h2>Known Sample Match</h2><table>
                <tr><th>Family</th><td>{}</td></tr>
                <tr><th>TLSH Distance</th><td>{}</td></tr>
                <tr><th>Confidence</th><td>{}</td></tr>
                </table></div>"#,
                escape_html(&k.family), k.distance, escape_html(&k.confidence)
            )
        })
        .unwrap_or_default();

    // Forensic Fragment
    let fragment_html: String = result
        .forensic_fragment
        .as_ref()
        .map(|f| {
            format!(
                r#"<div class="section"><h2>Forensic Fragment</h2><p><strong>{}</strong> &mdash; {}</p></div>"#,
                escape_html(&f.associated_family), escape_html(&f.explanation)
            )
        })
        .unwrap_or_default();

    // MITRE ATT&CK techniques
    let mitre_html: String = if !result.mitre_techniques.is_empty() {
        let rows: String = result.mitre_techniques.iter().map(|t| {
            let conf_str = format!("{}", t.confidence);
            format!(
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&t.technique_id), escape_html(&t.technique_name),
                escape_html(&t.tactic), escape_html(&conf_str)
            )
        }).collect();
        format!(
            r#"<div class="section"><h2>MITRE ATT&amp;CK Techniques</h2><table><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Confidence</th></tr>{}</table></div>"#,
            rows
        )
    } else {
        String::new()
    };

    // Plain-English Findings (detailed)
    let findings_detail_html: String = if !result.plain_english_findings.is_empty() {
        let rows: String = result.plain_english_findings.iter().map(|f| {
            let conf_str = format!("{}", f.confidence);
            let tag_class = match conf_str.as_str() {
                "Critical" => "tag-critical",
                "High" => "tag-high",
                "Medium" => "tag-medium",
                _ => "tag-low",
            };
            format!(
                r#"<div class="finding-row"><span class="tag {}">{}</span><strong>{}</strong><p style="margin:4px 0 0;opacity:0.8;font-size:0.9em">{}</p></div>"#,
                tag_class, escape_html(&conf_str), escape_html(&f.title), escape_html(&f.explanation)
            )
        }).collect();
        format!(r#"<div class="section"><h2>Analyst Findings</h2>{}</div>"#, rows)
    } else {
        String::new()
    };

    let packer_html: String = result
        .packer_detections
        .iter()
        .map(|p| format!("<li>{}</li>", escape_html(&p.name)))
        .collect();

    let compiler_html: String = result
        .compiler_detection
        .as_ref()
        .map(|c| {
            format!(
                "{} / {} ({})",
                escape_html(&c.compiler),
                escape_html(&c.language),
                c.confidence
            )
        })
        .unwrap_or_else(|| "Not detected".to_string());

    let tlsh_html = result.hashes.tlsh.as_deref().unwrap_or("N/A");

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anya Analysis Report - {filename}</title>
    <style>{css}</style>
</head>
<body>
    <header>
        <h1><span>Anya</span> Analysis Report</h1>
        <div class="verdict {verdict_class}">{verdict}</div>
    </header>

    <main>
        <!-- Top Findings -->
        <div class="section">
            <h2>Top Findings</h2>
            {findings}
        </div>

        <!-- File Info -->
        <div class="section">
            <h2>File Information</h2>
            <table>
                <tr><th>Name</th><td>{name}</td></tr>
                <tr><th>Size</th><td>{size} bytes</td></tr>
                <tr><th>Format</th><td>{format}</td></tr>
                <tr><th>Compiler</th><td>{compiler}</td></tr>
            </table>
        </div>

        <!-- Hashes -->
        <div class="section">
            <h2>Cryptographic Hashes</h2>
            <table>
                <tr><th>MD5</th><td class="mono">{md5}</td></tr>
                <tr><th>SHA-1</th><td class="mono">{sha1}</td></tr>
                <tr><th>SHA-256</th><td class="mono">{sha256}</td></tr>
                <tr><th>TLSH</th><td class="mono">{tlsh}</td></tr>
            </table>
        </div>

        <!-- Entropy -->
        <div class="section">
            <h2>Entropy Analysis</h2>
            <table>
                <tr><th>Shannon Entropy</th><td>{entropy:.4} / 8.0</td></tr>
                <tr><th>Interpretation</th><td>{entropy_interp}</td></tr>
            </table>
        </div>

        <!-- Strings -->
        <div class="section">
            <h2>Extracted Strings</h2>
            <table>
                <tr><th>Total Count</th><td>{string_count}</td></tr>
                <tr><th>Min Length</th><td>{string_min_len}</td></tr>
            </table>
        </div>

        <!-- Sections (PE or ELF) -->
        {sections_block}

        <!-- Imports -->
        {imports_block}

        <!-- Security -->
        {security_block}

        <!-- KSD Match -->
        {ksd_block}

        <!-- Forensic Fragment -->
        {fragment_block}

        <!-- Analyst Findings (detailed) -->
        {findings_detail_block}

        <!-- MITRE ATT&CK -->
        {mitre_block}

        <!-- Packers -->
        {packer_block}

        <!-- IOCs -->
        {ioc_block}
    </main>

    <footer>
        Generated by Anya Security Platform &mdash; {timestamp}
    </footer>
</body>
</html>"#,
        filename = escape_html(filename),
        css = CSS,
        verdict_class = verdict_class,
        verdict = escape_html(verdict_word),
        findings = findings_html,
        name = escape_html(filename),
        size = result.file_info.size_bytes,
        format = escape_html(&result.file_format),
        compiler = compiler_html,
        md5 = escape_html(&result.hashes.md5),
        sha1 = escape_html(&result.hashes.sha1),
        sha256 = escape_html(&result.hashes.sha256),
        tlsh = escape_html(tlsh_html),
        entropy = result.entropy.value,
        entropy_interp = entropy_interpretation(result.entropy.value),
        string_count = result.strings.total_count,
        string_min_len = result.strings.min_length,
        sections_block = if !sections_html.is_empty() {
            format!(
                r#"<div class="section"><h2>PE Sections</h2><table><tr><th>Name</th><th>Virtual Size</th><th>Entropy</th><th>Characteristics</th></tr>{}</table></div>"#,
                sections_html
            )
        } else if !elf_sections_html.is_empty() {
            format!(
                r#"<div class="section"><h2>ELF Sections</h2><table><tr><th>Name</th><th>Size</th><th>Entropy</th><th>Type</th></tr>{}</table></div>"#,
                elf_sections_html
            )
        } else {
            String::new()
        },
        imports_block = if !imports_html.is_empty() {
            format!(
                r#"<div class="section"><h2>Suspicious Imports</h2><table><tr><th>API</th><th>Category</th></tr>{}</table></div>"#,
                imports_html
            )
        } else {
            String::new()
        },
        security_block = if !security_html.is_empty() {
            format!(
                r#"<div class="section"><h2>Security Features</h2><table>{}</table></div>"#,
                security_html
            )
        } else {
            String::new()
        },
        ksd_block = ksd_html,
        fragment_block = fragment_html,
        findings_detail_block = findings_detail_html,
        mitre_block = mitre_html,
        packer_block = if !packer_html.is_empty() {
            format!(
                r#"<div class="section"><h2>Packer Detections</h2><ul>{}</ul></div>"#,
                packer_html
            )
        } else {
            String::new()
        },
        ioc_block = if !ioc_html.is_empty() {
            format!(
                r#"<div class="section"><h2>IOC Indicators</h2><table><tr><th>Type</th><th>Value</th></tr>{}</table></div>"#,
                ioc_html
            )
        } else {
            String::new()
        },
        timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
    );

    std::fs::write(output_path, html)?;
    tracing::info!("HTML report written to: {}", output_path.display());
    Ok(())
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn bool_badge(val: bool) -> &'static str {
    if val {
        "<span style=\"color: #4ecdc4;\">Enabled</span>"
    } else {
        "<span style=\"color: #ff6b6b;\">Disabled</span>"
    }
}

fn entropy_interpretation(entropy: f64) -> &'static str {
    if entropy > 7.5 {
        "Very high - likely encrypted or packed"
    } else if entropy > 6.5 {
        "High - possibly compressed or obfuscated"
    } else if entropy > 4.0 {
        "Moderate - typical for compiled executables"
    } else {
        "Low - likely plain text or simple data"
    }
}

/// Generate a Markdown analysis report suitable for pasting into tickets.
/// Also used as the file output when `--format text --output` is used.
pub fn generate_markdown_report(
    result: &output::AnalysisResult,
    output_path: &Path,
) -> anyhow::Result<()> {
    let verdict = result.verdict_summary.as_deref().unwrap_or("UNKNOWN");
    let filename = &result.file_info.path;

    let mut md = String::new();
    md.push_str("# Anya Analysis Report\n\n");
    md.push_str(&format!("**File:** `{}`\n\n", filename));
    md.push_str(&format!("## Verdict\n\n**{}**\n\n", verdict));

    // File Info
    md.push_str("## File Information\n\n");
    md.push_str("| Property | Value |\n|---|---|\n");
    md.push_str(&format!(
        "| Size | {} bytes ({:.1} KB) |\n",
        result.file_info.size_bytes, result.file_info.size_kb
    ));
    md.push_str(&format!("| Format | {} |\n", result.file_format));
    if let Some(ref ext) = result.file_info.extension {
        md.push_str(&format!("| Extension | .{} |\n", ext));
    }
    if let Some(ref mime) = result.file_info.mime_type {
        md.push_str(&format!("| MIME Type | {} |\n", mime));
    }
    md.push('\n');

    // Hashes
    md.push_str("## Hashes\n\n");
    md.push_str("| Algorithm | Value |\n|---|---|\n");
    md.push_str(&format!("| MD5 | `{}` |\n", result.hashes.md5));
    md.push_str(&format!("| SHA1 | `{}` |\n", result.hashes.sha1));
    md.push_str(&format!("| SHA256 | `{}` |\n", result.hashes.sha256));
    if let Some(ref tlsh) = result.hashes.tlsh {
        md.push_str(&format!("| TLSH | `{}` |\n", tlsh));
    }
    md.push('\n');

    // Top Findings
    if !result.top_findings.is_empty() {
        md.push_str("## Key Findings\n\n");
        for f in &result.top_findings {
            md.push_str(&format!("- **[{}]** {}\n", f.confidence, f.label));
        }
        md.push('\n');
    }

    // Entropy
    md.push_str("## Entropy Analysis\n\n");
    md.push_str(&format!(
        "- Overall: **{:.4}** ({})\n",
        result.entropy.value, result.entropy.category
    ));
    md.push('\n');

    // MITRE Techniques
    if !result.mitre_techniques.is_empty() {
        md.push_str("## MITRE ATT&CK Techniques\n\n");
        md.push_str("| ID | Name | Tactic | Source |\n|---|---|---|---|\n");
        for t in &result.mitre_techniques {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                t.technique_id, t.technique_name, t.tactic, t.source_indicator
            ));
        }
        md.push('\n');
    }

    // IOCs
    if let Some(ref ioc) = result.ioc_summary {
        if !ioc.ioc_strings.is_empty() {
            md.push_str("## Indicators of Compromise\n\n");
            for es in &ioc.ioc_strings {
                if let Some(ref ioc_type) = es.ioc_type {
                    md.push_str(&format!("- **[{}]** `{}`\n", ioc_type, es.value));
                }
            }
            md.push('\n');
        }
    }

    // KSD Match
    if let Some(ref ksd) = result.ksd_match {
        md.push_str("## Known Sample Match\n\n");
        md.push_str(&format!(
            "- Family: **{}**\n- TLSH Distance: {}\n\n",
            ksd.family, ksd.distance
        ));
    }

    // Forensic Fragment
    if let Some(ref frag) = result.forensic_fragment {
        md.push_str("## Forensic Fragment\n\n");
        md.push_str(&format!("> {}\n\n", frag.explanation));
    }

    // Footer
    md.push_str("---\n\n");
    md.push_str("*Generated by Anya — Privacy-first malware analysis*\n");

    std::fs::write(output_path, md)?;
    Ok(())
}

/// Generate a PDF analysis report.
///
/// Uses printpdf for pure Rust PDF generation — no system dependencies,
/// works offline and air-gapped. Embeds the built-in Helvetica font.
pub fn generate_pdf_report(
    result: &output::AnalysisResult,
    output_path: &Path,
) -> anyhow::Result<()> {
    let verdict = result.verdict_summary.as_deref().unwrap_or("UNKNOWN");
    let filename = &result.file_info.path;

    let (doc, page1, layer1) = PdfDocument::new("Anya Analysis Report", Mm(210.0), Mm(297.0), "Layer 1");
    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_mono = doc.add_builtin_font(BuiltinFont::Courier)?;

    let current_layer = doc.get_page(page1).get_layer(layer1);
    let mut y = 275.0_f32; // Start near top (A4 = 297mm)
    let left = 20.0_f32;
    let line_height = 5.0_f32;

    // Helper closure for writing text
    macro_rules! write_text {
        ($layer:expr, $font:expr, $size:expr, $x:expr, $y:expr, $text:expr) => {
            $layer.use_text($text.to_string(), $size, Mm($x), Mm($y), &$font);
        };
    }

    // Title
    write_text!(current_layer, font_bold, 18.0, left, y, "Anya Analysis Report");
    y -= 8.0;

    // Verdict
    write_text!(current_layer, font_bold, 14.0, left, y, &format!("Verdict: {}", verdict));
    y -= 10.0;

    // File Info section
    write_text!(current_layer, font_bold, 11.0, left, y, "File Information");
    y -= line_height;
    current_layer.add_line(Line {
        points: vec![
            (Point::new(Mm(left), Mm(y + 1.5)), false),
            (Point::new(Mm(190.0), Mm(y + 1.5)), false),
        ],
        is_closed: false,
    });
    y -= line_height;

    let info_rows: Vec<(&str, String)> = vec![
        ("File", filename.clone()),
        ("Size", format!("{} bytes ({:.1} KB)", result.file_info.size_bytes, result.file_info.size_kb)),
        ("Format", result.file_format.clone()),
        ("Entropy", format!("{:.4} ({})", result.entropy.value, result.entropy.category)),
    ];

    for (label, value) in &info_rows {
        write_text!(current_layer, font_bold, 9.0, left, y, label);
        write_text!(current_layer, font_regular, 9.0, left + 30.0, y, value);
        y -= line_height;
    }
    y -= 3.0;

    // Hashes section
    write_text!(current_layer, font_bold, 11.0, left, y, "Hashes");
    y -= line_height;
    current_layer.add_line(Line {
        points: vec![
            (Point::new(Mm(left), Mm(y + 1.5)), false),
            (Point::new(Mm(190.0), Mm(y + 1.5)), false),
        ],
        is_closed: false,
    });
    y -= line_height;

    write_text!(current_layer, font_bold, 8.0, left, y, "MD5");
    write_text!(current_layer, font_mono, 7.0, left + 20.0, y, &result.hashes.md5);
    y -= line_height;
    write_text!(current_layer, font_bold, 8.0, left, y, "SHA1");
    write_text!(current_layer, font_mono, 7.0, left + 20.0, y, &result.hashes.sha1);
    y -= line_height;
    write_text!(current_layer, font_bold, 8.0, left, y, "SHA256");
    write_text!(current_layer, font_mono, 7.0, left + 20.0, y, &result.hashes.sha256);
    y -= line_height;
    if let Some(ref tlsh) = result.hashes.tlsh {
        write_text!(current_layer, font_bold, 8.0, left, y, "TLSH");
        write_text!(current_layer, font_mono, 7.0, left + 20.0, y, tlsh);
        y -= line_height;
    }
    y -= 3.0;

    // Top Findings
    if !result.top_findings.is_empty() {
        write_text!(current_layer, font_bold, 11.0, left, y, "Key Findings");
        y -= line_height;
        current_layer.add_line(Line {
            points: vec![
                (Point::new(Mm(left), Mm(y + 1.5)), false),
                (Point::new(Mm(190.0), Mm(y + 1.5)), false),
            ],
            is_closed: false,
        });
        y -= line_height;

        for f in &result.top_findings {
            let text = format!("[{:?}] {}", f.confidence, f.label);
            write_text!(current_layer, font_regular, 9.0, left + 4.0, y, &text);
            y -= line_height;
            if y < 20.0 {
                break; // Avoid going off-page
            }
        }
        y -= 3.0;
    }

    // Plain English Findings
    if !result.plain_english_findings.is_empty() {
        write_text!(current_layer, font_bold, 11.0, left, y, "Analyst Findings");
        y -= line_height;
        current_layer.add_line(Line {
            points: vec![
                (Point::new(Mm(left), Mm(y + 1.5)), false),
                (Point::new(Mm(190.0), Mm(y + 1.5)), false),
            ],
            is_closed: false,
        });
        y -= line_height;

        for f in &result.plain_english_findings {
            if y < 20.0 { break; }
            write_text!(current_layer, font_bold, 9.0, left + 4.0, y, &format!("[{:?}] {}", f.confidence, f.title));
            y -= line_height;
            // Truncate long explanations for PDF
            let explanation = if f.explanation.len() > 120 {
                format!("{}...", &f.explanation[..117])
            } else {
                f.explanation.clone()
            };
            write_text!(current_layer, font_regular, 8.0, left + 8.0, y, &explanation);
            y -= line_height;
        }
        y -= 3.0;
    }

    // MITRE ATT&CK
    if !result.mitre_techniques.is_empty() && y > 30.0 {
        write_text!(current_layer, font_bold, 11.0, left, y, "MITRE ATT&CK Techniques");
        y -= line_height;
        current_layer.add_line(Line {
            points: vec![
                (Point::new(Mm(left), Mm(y + 1.5)), false),
                (Point::new(Mm(190.0), Mm(y + 1.5)), false),
            ],
            is_closed: false,
        });
        y -= line_height;

        for t in &result.mitre_techniques {
            if y < 20.0 { break; }
            let text = format!("{} — {} ({})", t.technique_id, t.technique_name, t.tactic);
            write_text!(current_layer, font_regular, 8.0, left + 4.0, y, &text);
            y -= line_height;
        }
    }

    // Footer
    write_text!(current_layer, font_regular, 7.0, left, 10.0,
        &format!("Generated by Anya v{} — Privacy-first malware analysis — {}", env!("CARGO_PKG_VERSION"), chrono::Local::now().format("%Y-%m-%d %H:%M")));

    doc.save(&mut std::io::BufWriter::new(std::fs::File::create(output_path)?))?;
    tracing::info!("PDF report written to: {}", output_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_html_angle_brackets() {
        assert_eq!(
            escape_html("<script>alert('xss')</script>"),
            "&lt;script&gt;alert('xss')&lt;/script&gt;"
        );
    }

    #[test]
    fn test_escape_html_ampersand() {
        assert_eq!(escape_html("a & b"), "a &amp; b");
    }

    #[test]
    fn test_escape_html_quotes() {
        assert_eq!(
            escape_html("he said \"hello\""),
            "he said &quot;hello&quot;"
        );
    }

    #[test]
    fn test_escape_html_clean_string() {
        assert_eq!(escape_html("normal text"), "normal text");
    }

    #[test]
    fn test_bool_badge_enabled() {
        assert!(bool_badge(true).contains("Enabled"));
    }

    #[test]
    fn test_bool_badge_disabled() {
        assert!(bool_badge(false).contains("Disabled"));
    }

    #[test]
    fn test_entropy_interpretation_ranges() {
        assert!(entropy_interpretation(7.9).contains("encrypted"));
        assert!(entropy_interpretation(7.0).contains("compressed"));
        assert!(entropy_interpretation(5.0).contains("compiled"));
        assert!(entropy_interpretation(2.0).contains("plain text"));
    }
}
