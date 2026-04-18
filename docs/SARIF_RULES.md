# Anya SARIF rule catalogue

The canonical reference for every rule Anya emits in its SARIF 2.1.0 output. When a SARIF consumer sees a `ruleId` value like `ANYA-H007`, the `helpUri` for that rule points at the matching section below.

The catalogue is versioned alongside Anya releases. Rule IDs are stable across releases; adding a rule always bumps the catalogue rather than renumbering an existing entry. Descriptions may be refined over time; IDs and semantics do not change.

**Catalogue size as of v2.0.5: 15 rules.**

- **`ANYA-V*`** — verdict carrier rule. Emitted for every scan so the SARIF log is a complete scan-of-record, not a findings-only list.
- **`ANYA-H*`** — heuristic signals. Produced by the static analysis heuristics running over parsed file structure.
- **`ANYA-P*`** — parser-level signals. Produced by the format parsers during file inspection.
- **`ANYA-D*`** — detection database matches. Produced by the known-sample database and the known-similar-digest (KSD) fuzzy-hash lookup.

Every finding carries a colon-prefixed tag vocabulary under `properties.tags[]`:

- `verdict:<clean|suspicious|malicious|test|tool|pup|unknown>`
- `mitre:<technique_id>` (e.g. `mitre:T1055.001`)
- `family:<slug>` (canonical family slug from `family_slug()` normalisation)
- `confidence:<critical|high|medium|low>`
- `signal:<short-name>` (e.g. `signal:packer-upx`, `signal:imphash-cluster`)
- `format:<pe|elf|macho|pdf|office|script|other>`

---

## ANYA-V001

**Name:** Overall verdict

**Category:** Verdict carrier (always emitted)

**SARIF level mapping:**

- MALICIOUS → `error`
- SUSPICIOUS → `warning`
- CLEAN, TOOL, PUP, TEST, UNKNOWN → `note`

**Short description:** The file received an overall Anya verdict.

**Full description:** Every Anya scan emits this result, even for clean files. The level reflects the top-level verdict; the message text is the human-readable verdict summary; the tags carry the verdict and format namespaces. Downstream SIEM ingestion uses this result as the scan-of-record anchor.

**Example tags:** `verdict:suspicious`, `format:pe`, `family:agenttesla` (if the file also matched a family), `signal:known-sample-pup` (if the verdict came from a known-sample override).

---

## ANYA-H001

**Name:** Packer or protector detected

**Category:** Heuristic

**Short description:** A known packer or protector signature was matched in the file.

**Full description:** Packers and protectors compress or encrypt the real payload, forcing static analysis tools to reason over a thin loader layer. The presence of a packer is not itself malicious — plenty of legitimate commercial software ships packed — but it raises the prior probability of malicious intent, especially when combined with high entropy or suspicious imports.

**Source field:** `packer_detections[]` in the AnalysisResult.

**Example tags:** `signal:packer`, `signal:packer-upx`, `confidence:high`, `format:pe`.

---

## ANYA-H002

**Name:** High or suspicious entropy

**Category:** Heuristic

**Short description:** The file's Shannon entropy is at or above the suspicious threshold.

**Full description:** Shannon entropy above roughly 7.5 indicates compressed, encrypted, or packed content. Benign installers and legitimate compressed archives can reach this range, but it is also the default state of packed malware. Anya reports entropy alongside the context that explains it.

**Source field:** `entropy.is_suspicious` boolean on the AnalysisResult.

**Example tags:** `signal:entropy-high`, `confidence:high`, `format:pe`.

---

## ANYA-H003

**Name:** Anti-analysis: debugger detection

**Category:** Heuristic

**Short description:** The file contains indicators consistent with detecting an attached debugger.

**Full description:** Code that probes for the presence of a debugger typically does so to alter behaviour when under analysis, a pattern strongly associated with malicious intent. Legitimate software rarely needs this defence. Common API calls include `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and various PEB field probes.

**Source field:** `anti_analysis_indicators[].technique == "DebuggerDetection"`.

**Example tags:** `signal:anti-analysis-debugger-detection`, `mitre:T1622`, `confidence:high`, `format:pe`.

---

## ANYA-H004

**Name:** Anti-analysis: virtual machine detection

**Category:** Heuristic

**Short description:** The file contains indicators consistent with detecting a virtualised environment.

**Full description:** VM detection routines read CPU features, registry keys, driver names, and device signatures characteristic of VirtualBox, VMware, QEMU, or Hyper-V. Malware uses them to stay dormant inside sandboxes. Benign software rarely has a reason to detect a hypervisor.

**Source field:** `anti_analysis_indicators[].technique == "VmDetection"`.

**Example tags:** `signal:anti-analysis-vm-detection`, `mitre:T1497.001`, `confidence:high`, `format:pe`.

---

## ANYA-H005

**Name:** Anti-analysis: timing evasion

**Category:** Heuristic

**Short description:** The file contains indicators consistent with timing-based evasion of sandboxes.

**Full description:** Sleep loops, time delta checks, and delayed payload execution defeat automated sandboxes that give each sample a fixed budget. The presence of such routines alongside other indicators is a strong malicious signal.

**Source field:** `anti_analysis_indicators[].technique == "TimingEvasion"`.

**Example tags:** `signal:anti-analysis-timing-evasion`, `mitre:T1497.003`, `confidence:medium`, `format:pe`.

---

## ANYA-H006

**Name:** Anti-analysis: sandbox detection

**Category:** Heuristic

**Short description:** The file contains indicators consistent with detecting a sandbox environment.

**Full description:** Checks for cursor movement, screen resolution, installed applications, recent documents, and uptime are used to distinguish a real user workstation from an analysis sandbox. Often paired with timing evasion.

**Source field:** `anti_analysis_indicators[].technique == "SandboxDetection"`.

**Example tags:** `signal:anti-analysis-sandbox-detection`, `mitre:T1497`, `confidence:medium`, `format:pe`.

---

## ANYA-H007

**Name:** Suspicious imports: process injection

**Category:** Heuristic

**Short description:** The file imports functions associated with injecting code into another process.

**Full description:** APIs such as `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, and `NtMapViewOfSection` are the building blocks of process injection and hollowing techniques. Their presence does not prove injection, but it narrows the intent considerably.

**Source field:** `mitre_techniques[]` entries with technique ID in {T1055, T1106, T1057, T1134}.

**Example tags:** `signal:import-process-injection`, `mitre:T1055.001`, `confidence:high`, `format:pe`.

---

## ANYA-H008

**Name:** Suspicious imports: cryptographic API

**Category:** Heuristic

**Short description:** The file imports cryptographic primitives consistent with payload obfuscation or ransomware behaviour.

**Full description:** Symmetric key setup, key derivation, and bulk encryption APIs appear in legitimate software, but also form the backbone of ransomware and payload obfuscation. Anya reports this signal for analyst review, not as a standalone verdict.

**Source field:** `mitre_techniques[]` entries with technique ID in {T1027, T1140, T1486}.

**Example tags:** `signal:import-crypto`, `mitre:T1027.007`, `confidence:medium`, `format:pe`.

---

## ANYA-H009

**Name:** Suspicious imports: registry persistence

**Category:** Heuristic

**Short description:** The file imports registry APIs consistent with persistence through Run keys or services.

**Full description:** APIs that create or modify HKCU / HKLM Run keys, service entries, or scheduled tasks are the standard persistence mechanism for Windows malware. Legitimate installers also use them; context in the calling code matters.

**Source field:** `mitre_techniques[]` entries with technique ID in {T1547, T1112, T1543, T1053}.

**Example tags:** `signal:import-registry-persistence`, `mitre:T1547.001`, `confidence:medium`, `format:pe`.

---

## ANYA-H010

**Name:** Suspicious imports: networking

**Category:** Heuristic

**Short description:** The file imports networking APIs consistent with command and control or data exfiltration.

**Full description:** WinInet, WinHTTP, and Winsock APIs power legitimate updaters and malicious command and control channels alike. The suspicious qualifier reflects the clustering of networking calls with other indicators, not networking by itself.

**Source field:** `mitre_techniques[]` entries with technique ID in {T1071, T1095, T1105, T1571, T1041}.

**Example tags:** `signal:import-networking`, `mitre:T1071.001`, `confidence:medium`, `format:pe`.

---

## ANYA-P001

**Name:** File type mismatch

**Category:** Parser

**Short description:** The detected magic bytes of the file do not match the claimed extension.

**Full description:** A file that presents as a PDF but is a PE, or as an image but is a script, is a common social engineering vehicle. Anya flags the mismatch as a standalone rule so SIEM correlation can weight it explicitly.

**SARIF level mapping by severity:**

- Critical → `error`
- High → `warning`
- Medium → `warning`
- Low → `note`

**Source field:** `file_type_mismatch` on the AnalysisResult.

**Example tags:** `signal:file-type-mismatch`, `confidence:high`, `format:pe`.

---

## ANYA-P002

**Name:** IOC artifacts present

**Category:** Parser

**Short description:** Indicators of compromise (URLs, IPs, hashes, or domains) were extracted from the file.

**Full description:** Indicator presence is informational on its own. Paired with other signals it reinforces a verdict; in isolation it mostly provides pivots for SOC hunting. Anya emits the per-category counts (URLs, IPs, hashes, domains) in the result message.

**Source field:** `ioc_summary.ioc_counts` map on the AnalysisResult.

**Example tags:** `signal:ioc-artifacts`, `confidence:medium`, `format:pe`.

---

## ANYA-D001

**Name:** Known sample database match

**Category:** Detection

**Short description:** The file matched an entry in Anya's curated known-samples database (tool, PUP, or test file).

**Full description:** Known-sample matches override the heuristic verdict so legitimate dual-use tools (reverse engineering utilities, forensic binaries, test files) are not misclassified as malicious. The subtype (tool / PUP / test) is emitted in the tags. Common matches include the EICAR anti-malware test file and widely-used analysis tooling like FLOSS and Ghidra.

**SARIF level:** always `note`. Known-sample matches are informational.

**Source field:** `known_sample` on the AnalysisResult.

**Example tags:** `signal:known-sample-tool`, `family:floss`, `confidence:critical`, `format:pe`.

---

## ANYA-D002

**Name:** Known similar digest (KSD) match

**Category:** Detection

**Short description:** The file's TLSH fuzzy hash is within the configured threshold of a known malware sample.

**Full description:** TLSH provides locality-sensitive similarity so packed variants of a family retain a similar hash. A KSD match is strong evidence of family relationship; combined with independent signals it produces a high-confidence verdict. The message carries the resolved family name and the TLSH distance.

**SARIF level:** `warning`.

**Source field:** `ksd_match` on the AnalysisResult.

**Example tags:** `signal:ksd-match`, `family:emotet`, `confidence:high`, `format:pe`.

---

## Versioning

| Version | Rules added | Rules removed |
|---|---|---|
| v2.0.5 | V001, H001-H010, P001-P002, D001-D002 (initial catalogue) | — |

Rule IDs are append-only. An ID retired from active detection will be marked deprecated in future releases but its slot is never reused for a different rule. This guarantees that any SARIF consumer that encodes a rule-ID-based filter keeps working across Anya upgrades.
