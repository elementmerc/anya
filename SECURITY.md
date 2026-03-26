# Security Policy

## What Counts as a Security Issue

A security issue in Anya is a flaw that could harm users of the software, expose data
they did not intend to expose, or allow an attacker to use Anya as a vector. Examples:

- **Parser vulnerabilities** — a malformed PE or ELF file causes Anya to panic, corrupt
  memory, write outside its intended output path, or otherwise behave incorrectly in a
  way that is exploitable.
- **Path traversal** — a crafted file path in a sample causes Anya to read or write files
  outside the intended directories.
- **Denial of service via malformed input** — a crafted input causes unbounded memory
  allocation or CPU consumption that makes the host system unusable.
- **Privilege escalation** (if dynamic analysis is added in a future version) — any
  sandbox escape that allows analysed code to affect the host environment.
- **Data leakage** — any code path that transmits user data, file contents, or analysis
  results to a remote endpoint without explicit user consent.
- **GUI injection** — any crafted file that causes the Tauri WebView to execute
  unintended JavaScript, load external resources, or escape the application sandbox.
- **Case directory traversal** — a crafted case name or file path that writes case
  data outside the intended cases directory.

## Out of Scope

The following are **not** security issues in Anya:

- **False negatives** — Anya reports a malicious file as clean, or assigns it a low risk
  score. Anya is a **static analysis aid**, not an antivirus engine. It cannot guarantee
  detection of all threats. A low risk score means Anya found no indicators it was looking
  for; it does not mean a file is safe. Never make trust decisions based solely on Anya's
  output.
- **False positives** — Anya flags a legitimate file as suspicious. This is an analysis
  quality issue, not a security vulnerability. Report it as a regular bug.
- **UI cosmetic issues** in the desktop GUI.
- **Vulnerabilities in third-party dependencies** that have upstream fixes available —
  please update your dependencies via `cargo update` and open a regular issue if Anya has
  not yet adopted the fix.
- **Reverse-engineering the compiled binary** to extract detection logic or scoring
  weights. The binary is distributed under AGPL-3.0 and reverse-engineering for
  interoperability is permitted. This is not a security vulnerability.

## How to Report

**Preferred method — GitHub private Security Advisory:**

1. Go to <https://github.com/elementmerc/anya/security/advisories>
2. Click **"New draft security advisory"**
3. Fill in the details (see below for what to include)
4. Submit the draft — only you and the maintainer can see it until it is published

**Alternative — Email:**

Email daniel@themalwarefiles.com with subject line `[SECURITY] Anya — <brief description>`.

Reports can be sent via email. Encryption is not currently required.

For the love of everything on God's green earth, do not post security issues publicly (GitHub Issues, social media, forums) until a fix
has been released and you have been notified.

## What to Include in a Report

A good report helps us reproduce and fix the issue quickly. Please include:

- **Affected version** — run `anya --version` to find out
- **Operating system and architecture** — e.g. Ubuntu 24.04 x86_64, Windows 11 ARM64
- **Reproduction steps** — the minimal command or action that triggers the issue
- **Sample file** (if applicable) — a crafted file that triggers the vulnerability.
  If the file is itself dangerous, describe its structure rather than attaching it, or
  share it via a private channel agreed with the maintainer.
- **Impact assessment** — what an attacker could do if they exploited this

## Response Timeline

| Milestone | Target |
|---|---|
| Acknowledge receipt | Within 72 hours |
| Confirm whether the report is a valid security issue | Within 7 days |
| Publish a patch for critical vulnerabilities | Within 30 days of confirmation |
| Publish a patch for high/medium vulnerabilities | Within 60 days of confirmation |

If we cannot meet these timelines for a confirmed issue, we will tell you and explain why.

These are targets, not guarantees. Anya is maintained by a small team. We take security
seriously but cannot offer service-level commitments.

## Safe Harbour

We consider security research conducted in good faith to be a welcome and legitimate
activity. We will **not** pursue legal action against researchers who:

- Report issues to us privately before any public disclosure.
- Do not access, modify, or exfiltrate data belonging to other users.
- Do not intentionally cause harm to users or infrastructure.
- Act in accordance with this policy.

We ask that you give us reasonable time to respond and remediate before disclosing
publicly.

## Credit

We will credit researchers who report valid security issues in the relevant release notes
and CHANGELOG entry, unless they prefer to remain anonymous. Please indicate your
preference when submitting the report.

## Bug Bounty

There is currently **no bug bounty programme**. We are a small open-source project and
cannot offer financial rewards. We offer recognition, our gratitude, and the knowledge
that you have helped protect users of a privacy-focused security tool.
