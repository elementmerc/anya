// Ányá — CLI Guided Mode output
//
// Prints contextual lessons after an analysis when `--guided` is requested.
// Uses the same trigger-evaluation logic as the GUI Teacher Mode sidebar.

use crate::data::lessons::{
    Difficulty, Lesson, TriggerContext, context_from_analysis, get_triggered_lessons,
};
use crate::output::{ELFAnalysis, MitreTechnique, PEAnalysis};
use colored::Colorize;

/// Print all triggered lessons for an analysis result to stdout.
///
/// Lessons are sorted by difficulty (Beginner → Intermediate → Advanced) and
/// formatted for terminal output. Already-completed lessons are NOT tracked in
/// CLI mode (no DB is available) — every relevant lesson is always shown.
pub fn print_guided_output(
    pe: Option<&PEAnalysis>,
    elf: Option<&ELFAnalysis>,
    mitre: &[MitreTechnique],
    risk_score: u32,
) {
    let (file_format, packer_names, import_names, mitre_ids) =
        context_from_analysis(pe, elf, mitre);

    let has_ordinal_imports = pe.is_some_and(|p| !p.ordinal_imports.is_empty());
    let has_tls_callbacks = pe
        .and_then(|p| p.tls.as_ref())
        .is_some_and(|t| t.callback_count > 0);
    let has_high_entropy_overlay = pe
        .and_then(|p| p.overlay.as_ref())
        .is_some_and(|o| o.high_entropy);
    let max_section_entropy = pe
        .map(|p| p.sections.iter().map(|s| s.entropy).fold(0.0_f64, f64::max))
        .unwrap_or(0.0);

    let empty_iocs: Vec<String> = Vec::new();
    let ctx = TriggerContext {
        file_format,
        max_section_entropy,
        packer_names: &packer_names,
        import_names: &import_names,
        has_ordinal_imports,
        mitre_technique_ids: &mitre_ids,
        has_tls_callbacks,
        has_high_entropy_overlay,
        pe_analysis: pe,
        elf_analysis: elf,
        risk_score: Some(risk_score),
        ioc_types: &empty_iocs,
        is_batch: false,
        has_mismatch: false,
        thresholds_customised: false,
        max_confidence: None,
    };

    let lessons = get_triggered_lessons(&ctx);

    if lessons.is_empty() {
        return;
    }

    println!();
    println!(
        "{}",
        "═══ Teacher Mode — Contextual Lessons ═══".cyan().bold()
    );
    println!(
        "  {} lesson{} triggered for this file.\n",
        lessons.len(),
        if lessons.len() == 1 { "" } else { "s" }
    );

    for (i, lesson) in lessons.iter().enumerate() {
        print_lesson(i + 1, lessons.len(), lesson);
    }
}

#[allow(dead_code)]
fn difficulty_label(d: &Difficulty) -> colored::ColoredString {
    match d {
        Difficulty::Beginner => "Beginner".green(),
        Difficulty::Intermediate => "Intermediate".yellow(),
        Difficulty::Advanced => "Advanced".red(),
    }
}

fn print_lesson(index: usize, total: usize, lesson: &Lesson) {
    let header = format!(
        "  [{}/{}] {} [{}]",
        index,
        total,
        lesson.title,
        lesson.difficulty.to_string().as_str().normal()
    );

    println!("{}", header.bold().white());
    println!("  {}", "─".repeat(70).dimmed());

    // Summary
    println!("  {}", lesson.content.summary.italic().bright_black());
    println!();

    // Explanation (word-wrapped to 70 chars)
    for line in wrap_text(&lesson.content.explanation, 70) {
        println!("  {}", line);
    }
    println!();

    // What to look for
    println!("  {} {}", "►".cyan(), "What to look for".cyan().bold());
    for line in wrap_text(&lesson.content.what_to_look_for, 68) {
        println!("    {}", line);
    }
    println!();

    // Next action
    println!("  {} {}", "✓".green(), "Try it now:".green().bold());
    for line in wrap_text(&lesson.content.next_action, 68) {
        println!("    {}", line);
    }

    // Glossary (compact, one line per term)
    if !lesson.content.glossary.is_empty() {
        println!();
        println!("  {}", "Glossary".dimmed().bold());
        for term in &lesson.content.glossary {
            println!("    {} — {}", term.term.bold(), term.definition.dimmed());
        }
    }

    println!();
}

/// Very simple word-wrap: splits at word boundaries, max `width` chars per line.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current.clone());
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

// Implement Display for Difficulty so we can use it in format strings
impl std::fmt::Display for Difficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Difficulty::Beginner => write!(f, "Beginner"),
            Difficulty::Intermediate => write!(f, "Intermediate"),
            Difficulty::Advanced => write!(f, "Advanced"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wrap_text;

    #[test]
    fn test_wrap_text_short() {
        let lines = wrap_text("Hello world", 80);
        assert_eq!(lines, vec!["Hello world"]);
    }

    #[test]
    fn test_wrap_text_wraps() {
        let lines = wrap_text("Hello world this is a long sentence", 15);
        // Each line should be ≤ 15 chars
        for line in &lines {
            assert!(line.len() <= 15, "Line too long: {line:?}");
        }
    }

    #[test]
    fn test_wrap_text_empty() {
        let lines = wrap_text("", 80);
        assert!(lines.is_empty());
    }
}
