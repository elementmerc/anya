// Ányá — Teacher Mode lesson definitions
// Embeds lessons_data.json at compile time; provides trigger evaluation.

use crate::output::{ELFAnalysis, MitreTechnique, PEAnalysis};
use std::collections::HashMap;
use std::sync::OnceLock;

static LESSONS_JSON: &str = include_str!("lessons_data.json");

// ── Serde types (1:1 with JSON schema) ────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum Difficulty {
    Beginner,
    Intermediate,
    Advanced,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum LessonCategory {
    Fundamentals,
    PeStructure,
    ElfStructure,
    Entropy,
    Imports,
    AntiAnalysis,
    MitreAttack,
    Workflow,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum LessonTrigger {
    /// Always show this lesson (context-independent introductory content).
    Always,
    /// Show when the analysed file is the given format.
    FileFormat { format: FileFormat },
    /// Show when any section entropy exceeds `threshold`.
    HighEntropy { threshold: f64 },
    /// Show when a packer was detected (optionally filter by name).
    PackerDetected {
        #[serde(default)]
        name: Option<String>,
    },
    /// Show when ALL of the listed APIs appear in the import table.
    ApiComboPresent { apis: Vec<String> },
    /// Show when ordinal-based imports are present.
    OrdinalImportsPresent,
    /// Show when a specific MITRE technique was detected.
    MitreDetected { technique_id: String },
    /// Show when a particular API is present in the import table.
    SuspiciousApiPresent { api: String },
    /// Show when a TLS callback is detected.
    TlsCallbacksPresent,
    /// Show when an overlay with high entropy is detected.
    HighEntropyOverlay,
    /// Show when any overlay data is present (regardless of entropy).
    OverlayPresent,
    /// Show when ELF security mitigations are absent.
    ElfSecurityMissing,
    /// Show when a specific PE/ELF security flag is disabled.
    SecurityFlagDisabled { flag: String },
    /// Show when the risk score exceeds `threshold`.
    RiskScoreAbove { threshold: u32 },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum FileFormat {
    Pe,
    Elf,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GlossaryTerm {
    pub term: String,
    pub definition: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LessonContent {
    pub summary: String,
    pub explanation: String,
    pub what_to_look_for: String,
    pub real_world_example: String,
    pub next_action: String,
    #[serde(default)]
    pub glossary: Vec<GlossaryTerm>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Lesson {
    pub id: String,
    pub title: String,
    pub category: LessonCategory,
    pub trigger: LessonTrigger,
    pub difficulty: Difficulty,
    pub content: LessonContent,
    #[serde(default)]
    pub next_steps: Vec<String>,
}

// ── Static lesson map ──────────────────────────────────────────────────────────

fn build_lesson_map() -> HashMap<String, Lesson> {
    let raw: Vec<Lesson> =
        serde_json::from_str(LESSONS_JSON).expect("lessons_data.json is malformed");
    raw.into_iter().map(|l| (l.id.clone(), l)).collect()
}

static LESSONS: OnceLock<HashMap<String, Lesson>> = OnceLock::new();

fn get_map() -> &'static HashMap<String, Lesson> {
    LESSONS.get_or_init(build_lesson_map)
}

/// Return all lessons in the lesson map.
pub fn all_lessons() -> Vec<&'static Lesson> {
    get_map().values().collect()
}

/// Return a single lesson by ID, or `None` if not found.
pub fn get_lesson(id: &str) -> Option<&'static Lesson> {
    get_map().get(id)
}

// ── Trigger context (passed in by the caller) ─────────────────────────────────

/// Everything needed to evaluate lesson triggers for one analysis result.
pub struct TriggerContext<'a> {
    /// Whether the file is a PE (true) or ELF (false) or unknown (None).
    pub file_format: Option<FileFormat>,
    /// Maximum section entropy across all sections (PE or ELF).
    pub max_section_entropy: f64,
    /// All named packers detected (empty if none).
    pub packer_names: &'a [String],
    /// All import names (lowercase) present in the file.
    pub import_names: &'a [String],
    /// Whether ordinal imports were found.
    pub has_ordinal_imports: bool,
    /// All MITRE technique IDs detected.
    pub mitre_technique_ids: &'a [String],
    /// Whether TLS callbacks were detected.
    pub has_tls_callbacks: bool,
    /// Whether a high-entropy overlay was detected.
    pub has_high_entropy_overlay: bool,
    /// Raw PE analysis (for deeper checks).
    pub pe_analysis: Option<&'a PEAnalysis>,
    /// Raw ELF analysis (for ELF-specific checks).
    pub elf_analysis: Option<&'a ELFAnalysis>,
    /// Computed risk score (0–100), if available.
    pub risk_score: Option<u32>,
}

/// Evaluate a single lesson trigger against the provided context.
fn trigger_matches(trigger: &LessonTrigger, ctx: &TriggerContext<'_>) -> bool {
    match trigger {
        LessonTrigger::Always => true,

        LessonTrigger::FileFormat { format } => match (format, &ctx.file_format) {
            (FileFormat::Pe, Some(FileFormat::Pe)) => true,
            (FileFormat::Elf, Some(FileFormat::Elf)) => true,
            _ => false,
        },

        LessonTrigger::HighEntropy { threshold } => ctx.max_section_entropy >= *threshold,

        LessonTrigger::PackerDetected { name } => {
            if ctx.packer_names.is_empty() {
                return false;
            }
            match name {
                None => true,
                Some(n) => ctx
                    .packer_names
                    .iter()
                    .any(|p| p.to_lowercase() == n.to_lowercase()),
            }
        }

        LessonTrigger::ApiComboPresent { apis } => {
            let lower: Vec<String> = apis.iter().map(|a| a.to_lowercase()).collect();
            lower.iter().all(|a| ctx.import_names.contains(a))
        }

        LessonTrigger::OrdinalImportsPresent => ctx.has_ordinal_imports,

        LessonTrigger::MitreDetected { technique_id } => {
            ctx.mitre_technique_ids.contains(technique_id)
        }

        LessonTrigger::SuspiciousApiPresent { api } => {
            let api_lower = api.to_lowercase();
            ctx.import_names.contains(&api_lower)
        }

        LessonTrigger::TlsCallbacksPresent => ctx.has_tls_callbacks,

        LessonTrigger::HighEntropyOverlay => ctx.has_high_entropy_overlay,

        LessonTrigger::OverlayPresent => {
            // True if an overlay exists (high entropy or not)
            ctx.has_high_entropy_overlay
                || ctx
                    .pe_analysis
                    .and_then(|p| p.overlay.as_ref())
                    .is_some()
        }

        LessonTrigger::ElfSecurityMissing => {
            if let Some(elf) = ctx.elf_analysis {
                !elf.is_pie || !elf.has_nx_stack || !elf.has_relro
            } else {
                false
            }
        }

        LessonTrigger::SecurityFlagDisabled { flag } => {
            if let Some(pe) = ctx.pe_analysis {
                match flag.to_uppercase().as_str() {
                    "ASLR" => !pe.security.aslr_enabled,
                    "DEP" | "NX" => !pe.security.dep_enabled,
                    _ => false,
                }
            } else {
                false
            }
        }

        // RiskScoreAbove requires a risk score in context; if not provided, never trigger.
        LessonTrigger::RiskScoreAbove { threshold } => {
            // Risk score is computed externally; caller can filter these out
            // or pass a pre-computed score. Default: do not trigger.
            ctx.risk_score
                .map(|s| s >= *threshold)
                .unwrap_or(false)
        }
    }
}

/// Return all lessons whose trigger matches the provided context, sorted
/// by difficulty (Beginner → Intermediate → Advanced).
pub fn get_triggered_lessons(ctx: &TriggerContext<'_>) -> Vec<&'static Lesson> {
    let mut lessons: Vec<&'static Lesson> = get_map()
        .values()
        .filter(|l| trigger_matches(&l.trigger, ctx))
        .collect();

    lessons.sort_by_key(|l| match l.difficulty {
        Difficulty::Beginner => 0u8,
        Difficulty::Intermediate => 1,
        Difficulty::Advanced => 2,
    });
    lessons
}

/// Build a `TriggerContext` from the top-level analysis results.
/// This is a convenience wrapper so callers don't have to compute fields manually.
pub fn context_from_analysis(
    pe: Option<&PEAnalysis>,
    elf: Option<&ELFAnalysis>,
    mitre: &[MitreTechnique],
) -> (
    Option<FileFormat>,
    Vec<String>, // packer_names
    Vec<String>, // import_names (lowercase)
    Vec<String>, // mitre_technique_ids
) {
    let file_format = if pe.is_some() {
        Some(FileFormat::Pe)
    } else if elf.is_some() {
        Some(FileFormat::Elf)
    } else {
        None
    };

    let packer_names: Vec<String> = pe
        .map(|p| p.packers.iter().map(|pk| pk.name.clone()).collect())
        .unwrap_or_default();

    // Collect all import names from the suspicious_apis list (these are the
    // flagged imports; the full import list is not stored in PEAnalysis).
    let import_names: Vec<String> = pe
        .map(|p| {
            p.imports
                .suspicious_apis
                .iter()
                .map(|f| f.name.to_lowercase())
                .collect()
        })
        .unwrap_or_default();

    let mitre_ids: Vec<String> = mitre.iter().map(|t| t.technique_id.clone()).collect();

    (file_format, packer_names, import_names, mitre_ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_lessons_loads() {
        let lessons = all_lessons();
        assert!(lessons.len() >= 15, "expected at least 15 lessons, got {}", lessons.len());
    }

    #[test]
    fn test_get_lesson_by_id() {
        let lesson = get_lesson("what_is_static_analysis");
        assert!(lesson.is_some());
        assert_eq!(lesson.unwrap().title, "What Is Static Analysis?");
    }

    #[test]
    fn test_get_lesson_unknown_returns_none() {
        assert!(get_lesson("nonexistent_lesson_id").is_none());
    }

    #[test]
    fn test_trigger_always_matches() {
        let ctx = TriggerContext {
            file_format: None,
            max_section_entropy: 0.0,
            packer_names: &[],
            import_names: &[],
            has_ordinal_imports: false,
            mitre_technique_ids: &[],
            has_tls_callbacks: false,
            has_high_entropy_overlay: false,
            pe_analysis: None,
            elf_analysis: None,
            risk_score: None,
        };
        let trigger = LessonTrigger::Always;
        assert!(trigger_matches(&trigger, &ctx));
    }

    #[test]
    fn test_trigger_file_format_pe_matches() {
        let ctx = TriggerContext {
            file_format: Some(FileFormat::Pe),
            max_section_entropy: 0.0,
            packer_names: &[],
            import_names: &[],
            has_ordinal_imports: false,
            mitre_technique_ids: &[],
            has_tls_callbacks: false,
            has_high_entropy_overlay: false,
            pe_analysis: None,
            elf_analysis: None,
            risk_score: None,
        };
        assert!(trigger_matches(&LessonTrigger::FileFormat { format: FileFormat::Pe }, &ctx));
        assert!(!trigger_matches(&LessonTrigger::FileFormat { format: FileFormat::Elf }, &ctx));
    }

    #[test]
    fn test_trigger_high_entropy() {
        let mut ctx = TriggerContext {
            file_format: None,
            max_section_entropy: 6.0,
            packer_names: &[],
            import_names: &[],
            has_ordinal_imports: false,
            mitre_technique_ids: &[],
            has_tls_callbacks: false,
            has_high_entropy_overlay: false,
            pe_analysis: None,
            elf_analysis: None,
            risk_score: None,
        };
        assert!(!trigger_matches(&LessonTrigger::HighEntropy { threshold: 6.5 }, &ctx));
        ctx.max_section_entropy = 7.2;
        assert!(trigger_matches(&LessonTrigger::HighEntropy { threshold: 6.5 }, &ctx));
    }

    #[test]
    fn test_trigger_packer_detected_any() {
        let packers = vec!["UPX".to_string()];
        let ctx = TriggerContext {
            file_format: None,
            max_section_entropy: 0.0,
            packer_names: &packers,
            import_names: &[],
            has_ordinal_imports: false,
            mitre_technique_ids: &[],
            has_tls_callbacks: false,
            has_high_entropy_overlay: false,
            pe_analysis: None,
            elf_analysis: None,
            risk_score: None,
        };
        assert!(trigger_matches(&LessonTrigger::PackerDetected { name: None }, &ctx));
        assert!(trigger_matches(
            &LessonTrigger::PackerDetected { name: Some("upx".to_string()) },
            &ctx
        ));
        assert!(!trigger_matches(
            &LessonTrigger::PackerDetected { name: Some("themida".to_string()) },
            &ctx
        ));
    }

    #[test]
    fn test_trigger_api_combo_all_required() {
        let imports = vec![
            "virtualallocex".to_string(),
            "writeprocessmemory".to_string(),
            "createremotethread".to_string(),
        ];
        let ctx = TriggerContext {
            file_format: None,
            max_section_entropy: 0.0,
            packer_names: &[],
            import_names: &imports,
            has_ordinal_imports: false,
            mitre_technique_ids: &[],
            has_tls_callbacks: false,
            has_high_entropy_overlay: false,
            pe_analysis: None,
            elf_analysis: None,
            risk_score: None,
        };
        assert!(trigger_matches(
            &LessonTrigger::ApiComboPresent {
                apis: vec![
                    "VirtualAllocEx".to_string(),
                    "WriteProcessMemory".to_string(),
                    "CreateRemoteThread".to_string(),
                ]
            },
            &ctx
        ));
        // Missing one → false
        assert!(!trigger_matches(
            &LessonTrigger::ApiComboPresent {
                apis: vec!["VirtualAllocEx".to_string(), "CreateToolhelp32Snapshot".to_string()]
            },
            &ctx
        ));
    }

    #[test]
    fn test_trigger_mitre_detected() {
        let techniques = vec!["T1055".to_string(), "T1622".to_string()];
        let ctx = TriggerContext {
            file_format: None,
            max_section_entropy: 0.0,
            packer_names: &[],
            import_names: &[],
            has_ordinal_imports: false,
            mitre_technique_ids: &techniques,
            has_tls_callbacks: false,
            has_high_entropy_overlay: false,
            pe_analysis: None,
            elf_analysis: None,
            risk_score: None,
        };
        assert!(trigger_matches(
            &LessonTrigger::MitreDetected { technique_id: "T1622".to_string() },
            &ctx
        ));
        assert!(!trigger_matches(
            &LessonTrigger::MitreDetected { technique_id: "T1003".to_string() },
            &ctx
        ));
    }

    #[test]
    fn test_triggered_lessons_sorted_by_difficulty() {
        let ctx = TriggerContext {
            file_format: Some(FileFormat::Pe),
            max_section_entropy: 7.5,
            packer_names: &[],
            import_names: &[],
            has_ordinal_imports: false,
            mitre_technique_ids: &[],
            has_tls_callbacks: false,
            has_high_entropy_overlay: false,
            pe_analysis: None,
            elf_analysis: None,
            risk_score: None,
        };
        let lessons = get_triggered_lessons(&ctx);
        // All beginner lessons must come before any intermediate
        let mut found_intermediate = false;
        for lesson in &lessons {
            match lesson.difficulty {
                Difficulty::Beginner => assert!(!found_intermediate, "beginner after intermediate"),
                Difficulty::Intermediate | Difficulty::Advanced => {
                    found_intermediate = true;
                }
            }
        }
    }

    #[test]
    fn test_ordinal_trigger() {
        let ctx = TriggerContext {
            file_format: None,
            max_section_entropy: 0.0,
            packer_names: &[],
            import_names: &[],
            has_ordinal_imports: true,
            mitre_technique_ids: &[],
            has_tls_callbacks: false,
            has_high_entropy_overlay: false,
            pe_analysis: None,
            elf_analysis: None,
            risk_score: None,
        };
        assert!(trigger_matches(&LessonTrigger::OrdinalImportsPresent, &ctx));
    }
}
