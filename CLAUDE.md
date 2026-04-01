# Anya — Claude Code Instructions
<!-- Sprint: V2 — Detection Inflection -->

## Current version: v2.0.0
## Active sprint: V2 — Detection Inflection

---

## V1 — Foundation (SHIPPED)

- PE/ELF/Mach-O analysis engine, MITRE ATT&CK mapping, Teacher Mode (35 lessons)
- IOC detection, confidence scoring, plain-English findings
- Authenticode, overlay, packer/compiler detection, TLS callbacks
- Rich header, ordinal imports, checksum validation, version info
- Batch analysis CLI + GUI, case management CLI + GUI
- anya watch, anya compare, HTML report export
- Guided tour, toast notifications, skeleton loaders, pin findings
- Private repo (anya-proprietary submodule), stub crates
- Splash screen, installer, uninstaller, Bible verse bar, SQLite history
- Keyboard shortcuts, compare view, drag-and-drop tab reorder
- 15 format parsers (JS, PS, VBS, Batch, Python, OLE, RTF, ZIP, HTML, XML, Image, LNK, ISO, CAB, MSI)
- TLSH Known Sample Database (KSD), .NET IL metadata parser, certificate reputation
- Compiler/toolchain fingerprinting, string entropy profiling, import behavioural clustering
- Per-format statistical baselines, forensic fragment annotation + SHA256 fragment DB
- Known-product suppression (MinGW/GCC, Mono/.NET, Node.js, Wine)
- Scoring engine calibration: 99.6% detection, 0.7% FP on 6,864 samples

## What is in scope NOW

- **YARA integration** — add yara-rust crate; load rules from
  `~/.config/anya/rules/`; bundle Florian Roth signature-base as the
  default ruleset (MIT licensed); surface match results in the GUI.
  **Implement last in this phase.**
- **Known-product suppression signals** — version info product name matching,
  debug info presence (DWARF/PDB), export function patterns (COM, JNI, NAPI)
- **Structural similarity clustering** — cluster files by section layout +
  import fingerprint for family detection without exact hash matches
- **Entropy distribution analysis** — byte histogram shape analysis for
  packed/encrypted/legitimate classification
- **Cross-reference IOC validation** — suppress IOCs matching known benign
  infrastructure (CDNs, cloud providers, package registries)
- **Resource language analysis** — detect language ID mismatches between
  PE resources and version info (repackaging indicator)
- **Timestamp plausibility** — flag PE timestamps from the future, before 2000,
  or zeroed (tamper indicator)
- **Dataset-calibrated heuristics** — iterate scoring weights against
  1,693 malware + 5,390 benign sample set
- **Public launch preparation** — README rewrite, social preview image,
  CHANGELOG for v2.0.0

## What is explicitly deferred — do not implement

- YARA IDE / rule editor (V3)
- CAPA-style capability detection (V3)
- Capstone disassembly (V3)
- Plugin trait API design (V3)
- ML model training (V5)
- REST API (V4)
- Cuckoo/CAPE sandbox bridge (V4)
- Multi-tenant SaaS (V5)
- Federated learning (V6)
- Anya Genome (V4/V6)
- Any feature not in the scope list above

## New dependency allowed this sprint

- `yara-rust` — confirm licence compatibility before adding to Cargo.toml

---

## Codebase orientation

```
src/                    Rust analysis engine (anya-security-core)
src-tauri/src/          Tauri IPC commands
ui/                     React + TypeScript frontend
ui/components/tabs/     One file per analysis tab
ui/lib/tauri-bridge.ts  All invoke() wrappers live here
ui/types/analysis.ts    Shared TypeScript types
anya-stubs/             Stub crates (public repo)
anya-proprietary/       Git submodule → real private crates (authorised only)
.cargo/config.toml      Path override: stubs → submodule (gitignored)
tests/                  Integration tests
ARCHITECTURE.md         Source of truth for data flow and schema
```

Read ARCHITECTURE.md before touching any data structures or IPC commands.

---

## Product standard

Anya is a commercial-grade software product, not a hobby project. Hold all
work to the highest known standards in software engineering: thorough testing,
clean architecture, comprehensive documentation, security-conscious code, and
professional-quality UX. Every change should be production-ready.

When fixing issues, prefer the thorough solution over the simple workaround.
If something requires a more complex but reliable approach, do that first
rather than applying band-aid fixes that create technical debt.

## Non-negotiable principles

1. **Privacy first** — zero outbound network calls. No exceptions. Ever.
   Network is disabled at the OS permission layer in Tauri capabilities.
   Do not add any network permission, fetch call, or external API request
   without explicit written instruction from the user in this chat.

2. **Both surfaces** — every user-facing feature must exist in both CLI and GUI.
   If a prompt only mentions one, implement both unless explicitly told otherwise.

3. **Surgical edits only** — do not touch code outside the scope of the prompt.
   Do not reformat, restructure, or refactor anything not directly related
   to the task. If something looks broken outside scope, note it as a comment
   and move on. Do not fix it silently.

4. **False positive rate is first-class** — calibration matters more than coverage.
   A Microsoft-signed Notepad.exe must reach CLEAN. When in doubt, rate lower.

5. **Test coverage** — maintain ≥90% line coverage on all changed files.
   Never comment out or delete existing tests without documenting why.

6. **Light and dark mode** — every UI change must work in both themes.
   Use existing CSS variables and Tailwind dark: variants only.
   Never hardcode colours.

7. **Private repo** — anya-proprietary is private. Never commit real scoring
   content to the public repo (elementmerc/anya). The stub crates in
   anya-stubs/ must remain as stubs. In ALL public-facing content (code
   comments, doc comments, README, ARCHITECTURE.md, CHANGELOG, commit
   messages), write as if the proprietary crate doesn't exist. Do not
   describe internal methodologies, scoring weights, detection patterns,
   calibration data, or the contents of the private/ directory. Do not
   mention that information is being deliberately withheld — the software
   should appear naturally complete, not like it has hidden parts.

8. **Detection metrics** — always report real detection rate (heuristic +
   signature) separately from forensic fragment annotations. The goal is
   always 100% detection and 0% FP. Forensic fragments count toward 100%
   but must be reported as a distinct percentage.

9. **No future plans in public docs** — never mention future versions,
   roadmap items, planned features, or the existence of a roadmap in any
   public-facing file (README, ARCHITECTURE.md, CHANGELOG, code comments,
   doc comments). Present everything as what it IS, not what it WILL BE.
   Do not reference V3, V4, plugin plans, SARIF/STIX plans, REST API plans,
   or any unreleased capability. The goal is to present the software as
   complete and polished at every version, not as a work-in-progress.

10. **Changelog discipline** — changelog entries should list only major
    user-facing features and fixes. Consolidate minor items under
    "Bug fixes and improvements." Do not list internal refactors,
    architectural changes, or implementation details that users don't see.

---

## Architecture rules

- Analysis logic lives in anya-security-core (Rust). Never duplicate in TS.
- All IPC goes through tauri-bridge.ts typed wrappers. Never call invoke() directly.
- All shared types live in ui/types/analysis.ts. Do not define types elsewhere.
- config.rs is the single source of truth for threshold defaults.
- SQLite schema changes require a migration note in ARCHITECTURE.md.
- Detection patterns (keywords, regex, thresholds) belong in
  `anya-proprietary/scoring/src/detection_patterns.rs`, NOT in public parsers.
- Public parsers (`src/*_parser.rs`) import patterns from the private crate.

---

## Roadmap guardrails

Before implementing anything, check:

| Signal | Action |
|---|---|
| Feature belongs to a future version | Flag it, ask before proceeding |
| Contradicts ARCHITECTURE.md | Flag before proceeding |
| Adds a new dependency | Flag and confirm intentional |
| Changes a public struct/enum/IPC command | Flag as breaking change |
| Requires network access | Stop. Do not proceed without instruction |
| Would duplicate existing CLI or GUI feature | Flag the duplication |

---

## Key files — read before touching

| Task | Read first |
|---|---|
| Any analysis engine change | src/pe_parser.rs, src/elf_parser.rs, src/lib.rs |
| Any IPC command | src-tauri/src/lib.rs, ui/lib/tauri-bridge.ts |
| Any config/threshold change | src/config.rs, ui/components/SettingsModal.tsx |
| Any tab UI change | The specific tab file + ui/types/analysis.ts |
| Any scoring change | src/confidence.rs, anya-proprietary/scoring/src/confidence.rs |
| Any new data structure | src/output.rs, ui/types/analysis.ts |
| Any MITRE change | src/data/mitre_mappings.rs, ui/data/mitre_attack.json |
| Any parser change | The specific src/*_parser.rs + anya-proprietary detection_patterns.rs |
| Any format support | src/lib.rs (analyse_file format dispatch) |

---

## Test requirements

- `cargo test -p anya-security-core` must pass before any session ends
- `npm test` (Vitest) must pass
- New functions: ≥90% branch coverage
- Never use `#[ignore]` without a documented reason in the test file

---

## Commit hygiene

- Update ARCHITECTURE.md if any IPC command, data structure, or module changes
- Update ROADMAP.md if a feature is added, deferred, or reprioritised
- Do not bump the version number without explicit instruction
- Do not modify .github/workflows/ without explicit instruction
- **IP check before every push:** Always verify that no scoring thresholds,
  detection weights, verdict logic, packed_score values, detection patterns,
  calibration data, social media plans, book content, or private methodology
  details have leaked into the public codebase (`src/`, `anya-stubs/`, `docs/`,
  `ui/`, `README.md`). All such content belongs in `anya-proprietary/` or
  `private/`. Run `cargo fmt`, `cargo clippy`, and a quick grep for hardcoded
  values before committing. Remind the user to check if unsure.

---

## Code style

- Rust: follow rustfmt and clippy. Fix all warnings before finishing.
- TypeScript: strict mode. No `any`. No non-null assertions without a comment.
- No `console.log` left in production paths.
- Comments: explain why, not what.
- Error messages shown to users must be plain English, not raw Rust error strings.

---

## Verification and testing

When asked to verify, simulate, or test that something works:

1. **Actually run real checks** — write test scripts, check library source code,
   grep for actual behavior. Do not theorize about what should happen and present
   it as verification.
2. **If live testing is impossible** (requires a running browser/Tauri app), say so
   explicitly and describe what you verified statically vs what needs manual testing.
3. **If thorough testing will take significant time**, inform the user before
   proceeding and let them decide whether to invest the time.
4. **Never present a theoretical walkthrough as an actual test.**

---

## If you are unsure about scope

Ask: "This touches [X]. Is that in scope for this session?"
Do not assume. Do not expand scope silently.

Even in Edit automatically mode, pause and ask the user questions when
something is unclear, when a design decision has multiple valid paths,
or when a mistake could be expensive to fix later. A 30-second question
saves 30 minutes of rework.
