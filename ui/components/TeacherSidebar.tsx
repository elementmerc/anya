/**
 * TeacherSidebar — contextual explanation panel for Teacher Mode.
 *
 * Rendered as a flex sibling to the main tab content area. It transitions
 * its width between 0 (hidden) and the current sidebar width (visible)
 * so the rest of the layout shrinks/grows — it never overlaps content.
 *
 * The left edge is draggable to resize the sidebar (min 280px, max 50vw).
 * The X button disables teacher mode entirely (synced with Settings toggle).
 */
import { useState, useRef, useCallback, useEffect } from "react";
import { GraduationCap, X, ExternalLink, BookOpen } from "lucide-react";
import { useTeacherMode, type TeacherFocusItem } from "@/hooks/useTeacherMode";
import mitreData from "@/data/mitre_attack.json";
import explanations from "@/data/technique_explanations.json";
import { getApiDescription } from "@/lib/apiDescriptions";

// ── Data look-up helpers ─────────────────────────────────────────────────────

interface MitreTechniqueEntry {
  id: string;
  name: string;
  tactic: string;
  description: string;
  subtechniques: { id: string; name: string; description: string }[];
}

const techniqueMap = new Map<string, MitreTechniqueEntry>();
for (const t of (mitreData as { techniques: MitreTechniqueEntry[] }).techniques) {
  techniqueMap.set(t.id, t);
  for (const sub of t.subtechniques) {
    techniqueMap.set(sub.id, { ...sub, tactic: t.tactic, subtechniques: [] });
  }
}

const explanationMap = explanations as Record<string, { simple: string; real_world_example?: string }>;

function getSimpleExplanation(techniqueId: string): string | null {
  const exact = explanationMap[techniqueId]?.simple;
  if (exact) return exact;
  return explanationMap[techniqueId.split(".")[0]]?.simple ?? null;
}

function getTechniqueData(techniqueId: string): { simple: string; real_world_example?: string } | null {
  const exact = explanationMap[techniqueId];
  if (exact) return exact;
  return explanationMap[techniqueId.split(".")[0]] ?? null;
}

function getTechniqueDescription(techniqueId: string): string | null {
  return techniqueMap.get(techniqueId)?.description ?? null;
}

// ── Simple explanation card ──────────────────────────────────────────────────

function SimpleExplanationCard({ text, fallback }: { text: string | null; fallback?: string }) {
  return (
    <>
      <div
        style={{
          margin: "14px 0 10px",
          paddingTop: 14,
          borderTop: "1px solid var(--border-subtle)",
          display: "flex",
          alignItems: "center",
          gap: 5,
        }}
      >
        <GraduationCap size={11} style={{ color: "var(--text-muted)" }} />
        <span style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 600, letterSpacing: "0.04em", textTransform: "uppercase" }}>
          Simple explanation
        </span>
      </div>
      <div
        style={{
          background: "rgba(99,102,241,0.06)",
          border: "1px solid rgba(99,102,241,0.2)",
          borderRadius: "var(--radius)",
          padding: "12px 14px",
        }}
      >
        <p className="selectable" style={{ margin: 0, fontSize: "var(--font-size-xs)", color: text ? "var(--text-primary)" : "var(--text-muted)", lineHeight: 1.7, fontStyle: text ? "normal" : "italic" }}>
          {text ?? fallback ?? "No simplified explanation available yet."}
        </p>
      </div>
    </>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div
      data-testid="sidebar-default-prompt"
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "32px 20px",
        gap: 12,
        textAlign: "center",
      }}
    >
      <div
        style={{
          width: 40, height: 40, borderRadius: "50%",
          background: "rgba(99,102,241,0.1)",
          display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
        }}
      >
        <BookOpen size={18} style={{ color: "rgb(129,140,248)" }} />
      </div>
      <p style={{ margin: 0, fontSize: "var(--font-size-sm)", fontWeight: 500, color: "var(--text-primary)" }}>
        Teacher Mode
      </p>
      <p style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.6 }}>
        Click or hover any flagged item — a MITRE badge, suspicious API, or
        detection card — to get an explanation here.
      </p>
    </div>
  );
}

// ── MITRE focus content ───────────────────────────────────────────────────────

function MitreFocusContent({ item }: { item: Extract<TeacherFocusItem, { type: "mitre" }> }) {
  const techDescription = getTechniqueDescription(item.techniqueId);
  const simpleExplanation = getSimpleExplanation(item.techniqueId);
  const attackUrl = `https://attack.mitre.org/techniques/${item.techniqueId.replace(".", "/")}/`;

  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <span
          data-testid="sidebar-technique-id"
          style={{
            fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", fontWeight: 700,
            padding: "2px 7px", borderRadius: 4,
            background: "rgba(99,102,241,0.15)", color: "rgb(129,140,248)",
            border: "1px solid rgba(99,102,241,0.3)", flexShrink: 0,
          }}
        >
          {item.techniqueId}
        </span>
        <a
          href={attackUrl} target="_blank" rel="noopener noreferrer"
          title="View on MITRE ATT&CK"
          style={{ color: "var(--text-muted)", display: "flex", alignItems: "center", flexShrink: 0 }}
          onClick={(e) => e.stopPropagation()}
        >
          <ExternalLink size={11} />
        </a>
      </div>

      <h3 style={{ margin: "0 0 6px", fontSize: "var(--font-size-sm)", fontWeight: 600, color: "var(--text-primary)", lineHeight: 1.3 }}>
        {item.techniqueName}
      </h3>
      <span style={{ display: "inline-block", marginBottom: 14, fontSize: 10, padding: "1px 6px", borderRadius: 999, background: "var(--bg-elevated)", color: "var(--text-muted)", border: "1px solid var(--border)" }}>
        {item.tactic}
      </span>

      {techDescription && (
        <div style={{ marginBottom: 14 }}>
          <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            What it does
          </p>
          <p className="selectable" style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.6 }}>
            {techDescription}
          </p>
        </div>
      )}

      {item.detectedSubs && item.detectedSubs.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Subtechniques detected
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {item.detectedSubs.map((sub) => (
              <div key={sub.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 8px", borderRadius: "var(--radius-sm)", background: "var(--bg-elevated)" }}>
                <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", fontWeight: 700, color: "rgb(251,191,36)", flexShrink: 0 }}>{sub.id}</span>
                <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-secondary)" }}>{sub.name}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {item.indicators && item.indicators.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Detected via
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
            {item.indicators.map((ind, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 8px", borderRadius: "var(--radius-sm)", background: "var(--bg-elevated)" }}>
                <span style={{ flex: 1, fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>{ind.source}</span>
                <span style={{ fontSize: 10, color: "var(--text-muted)", flexShrink: 0 }}>{ind.confidence}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <SimpleExplanationCard text={simpleExplanation} />

      {(() => {
        const techniqueData = getTechniqueData(item.techniqueId);
        return techniqueData?.real_world_example ? (
          <div style={{ marginTop: 12 }}>
            <h4 style={{ fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", margin: "0 0 6px" }}>
              Real-World Attack
            </h4>
            <div style={{
              padding: "10px 14px",
              borderRadius: "var(--radius)",
              background: "rgba(234,179,8,0.06)",
              border: "1px solid rgba(234,179,8,0.15)",
              fontSize: "var(--font-size-sm)",
              color: "var(--text-primary)",
              lineHeight: 1.55,
            }}>
              {techniqueData.real_world_example}
            </div>
          </div>
        ) : null;
      })()}
    </div>
  );
}

// ── API focus content ─────────────────────────────────────────────────────────

function ApiFocusContent({ item }: { item: Extract<TeacherFocusItem, { type: "api" }> }) {
  const techDesc = getApiDescription(item.name);
  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
      <h3 style={{ margin: "0 0 6px", fontSize: "var(--font-size-sm)", fontWeight: 600, fontFamily: "var(--font-mono)", color: "var(--text-primary)", wordBreak: "break-all" }}>
        {item.name}
      </h3>
      {item.category && (
        <span style={{ display: "inline-block", marginBottom: 14, fontSize: 10, padding: "1px 6px", borderRadius: 999, background: "rgba(249,115,22,0.12)", color: "var(--risk-high)", border: "1px solid rgba(249,115,22,0.2)" }}>
          {item.category}
        </span>
      )}
      {techDesc && (
        <div style={{ marginBottom: 0 }}>
          <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Why it&apos;s suspicious
          </p>
          <p style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.6 }}>
            {techDesc}
          </p>
        </div>
      )}
      <SimpleExplanationCard
        text={techDesc ?? null}
        fallback="This API is flagged as suspicious based on its category. Hover a MITRE badge for full technique context."
      />
    </div>
  );
}

// ── DLL focus content ─────────────────────────────────────────────────────────

const DLL_TEACHER_EXPLANATIONS: Record<string, string> = {
  "KERNEL32.dll": "This is like the main toolbox Windows uses for basic tasks — opening files, managing memory, starting programs. If Windows were a phone, this would be the operating system itself. Almost every program uses it, so seeing it is totally normal.",
  "NTDLL.dll": "The deepest layer of Windows that talks directly to the hardware — like the engine under a car's hood that most people never see. Malware sometimes calls this directly to bypass security software watching the normal route.",
  "USER32.dll": "Handles everything you see and click on screen — windows, buttons, menus, keyboard input. Like the part of your phone that makes the touchscreen work. Normal for most apps, but keyloggers abuse it to record what you type.",
  "ADVAPI32.dll": "Windows' security and settings toolkit — manages passwords, the registry (Windows' settings database), and system services. Malware uses it to create services that start automatically or to mess with security settings.",
  "WS2_32.dll": "Handles all internet and network connections — this is what lets programs send and receive data online, like a browser loading a webpage. If a program you don't expect to go online imports this, that's worth investigating.",
  "WININET.dll": "A higher-level internet toolkit built on top of WS2_32 — provides ready-made functions for HTTP requests and FTP transfers. Malware uses it to download payloads or send stolen data to the attacker's server.",
  "CRYPT32.dll": "Windows' encryption and certificate toolkit — it handles the padlock you see in your browser's address bar. Malware might use it to encrypt files (ransomware) or to verify fake certificates.",
  "SHELL32.dll": "Controls Windows Explorer features — file operations, desktop shortcuts, the recycle bin. Like the home screen on your phone. Malware uses it to run programs or manage files without you noticing.",
  "GDI32.dll": "The drawing toolkit — renders text, shapes, and images on screen. Like a program's paintbrush. Mostly harmless, but screen-capture malware uses it to take screenshots of your desktop.",
  "OLEAUT32.dll": "Handles automation and scripting in Windows — lets programs control other programs. Like a universal remote control. Malware uses it to automate attacks through Office macros or scripts.",
  "MSVCRT.dll": "The C programming language's standard toolkit for Windows — basic math, text handling, file operations. Almost every program written in C or C++ needs it. Completely normal to see.",
  "PSAPI.dll": "Lets programs inspect what other programs are running — process names, memory usage, loaded modules. Like a task manager for code. Malware uses it to find and target specific running programs.",
  "IPHLPAPI.dll": "Provides network configuration info — IP addresses, network adapters, routing tables. Like checking your phone's Wi-Fi settings. Malware uses it to map out the network it landed on.",
  "WINTRUST.dll": "Verifies digital signatures — checks if a file was actually made by who it claims. Like checking the seal on a package. Malware sometimes uses it to appear legitimate or to bypass signature checks.",
  "DBGHELP.dll": "A debugging toolkit — reads program crash dumps and symbol files. Like a mechanic's diagnostic tool. Malware uses it to dump passwords from memory (like the famous Mimikatz tool).",
  "SHLWAPI.dll": "Shell utility functions — URL parsing, file path handling, string operations. A helper toolkit for Windows Explorer features. Generally harmless, commonly seen in normal software.",
  "COMCTL32.dll": "Provides common Windows controls — toolbars, progress bars, list views, tree views. The building blocks of a Windows app's interface. Completely normal, no security concerns.",
  "COMDLG32.dll": "Provides the standard 'Open File' and 'Save File' dialog boxes you see in every Windows app. Completely normal — every app that lets you open or save files uses this.",
  "WINMM.dll": "Handles multimedia — sound playback, MIDI, timers. Like the audio player on your phone. Rarely suspicious unless combined with screen recording.",
  "WINSPOOL.DRV": "Manages printer communication — sending documents to printers, managing print queues. Normal for any app that can print. Very rarely seen in malware.",
};

function DllFocusContent({ item }: { item: Extract<TeacherFocusItem, { type: "dll" }> }) {
  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
      <h3 style={{ margin: "0 0 6px", fontSize: "var(--font-size-sm)", fontWeight: 600, fontFamily: "var(--font-mono)", color: "var(--text-primary)", wordBreak: "break-all" }}>
        {item.name}
      </h3>
      <span style={{ display: "inline-block", marginBottom: 14, fontSize: 10, padding: "1px 6px", borderRadius: 999, background: "var(--bg-elevated)", color: "var(--text-muted)", border: "1px solid var(--border)" }}>
        Dynamic-Link Library
      </span>
      <SimpleExplanationCard text={DLL_TEACHER_EXPLANATIONS[item.name] ?? item.description ?? null} />
    </div>
  );
}

// ── IOC focus content ──────────────────────────────────────────────────────────

const IOC_DESCRIPTIONS: Record<string, { label: string; description: string; falsePositiveGuidance: string }> = {
  url: {
    label: "URLs (Web Addresses)",
    description: "Attackers hide website addresses in malware so it knows where to phone home — like a spy with a secret radio frequency. Finding URLs in a program that shouldn't need the internet is a major red flag. The URL often points to a command-and-control server where the attacker sends instructions.",
    falsePositiveGuidance: "Legitimate software often contains URLs too — update servers, documentation links, crash reporting endpoints. Check if the domain is from a known company.",
  },
  ip: {
    label: "IP Addresses",
    description: "Raw IP addresses are like GPS coordinates that point directly to a specific server. Malware uses these instead of domain names because IP addresses can't be blocked by DNS filters — it's like knowing someone's exact home address instead of just their name.",
    falsePositiveGuidance: "Private IP ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x) and localhost (127.0.0.1) are almost always harmless internal references.",
  },
  registry: {
    label: "Registry Keys",
    description: "The Windows Registry is like a giant settings notebook that controls how your computer behaves. Malware writes entries here to start itself every time you turn on your computer — like secretly adding itself to your morning alarm. Common targets are the 'Run' keys that auto-start programs.",
    falsePositiveGuidance: "Most legitimate software writes to the registry too — for settings, file associations, and installation info. Suspicious keys are ones under Run/RunOnce or that modify security settings.",
  },
  base64: {
    label: "Base64 Encoded Data",
    description: "Base64 is a way to disguise binary data or text as random-looking characters — like writing a message in code that only looks like gibberish. Attackers use it to hide commands, URLs, or stolen data so antivirus software can't easily read it.",
    falsePositiveGuidance: "Base64 is also used legitimately for embedding images, certificates, and configuration data. Long Base64 strings (100+ characters) in unexpected places are more suspicious.",
  },
  filepath: {
    label: "File Paths",
    description: "File paths show where on the computer the malware reads from or writes to. Paths to system folders (like Windows\\System32) or temp directories are common targets — malware drops files there because they're trusted locations that users rarely check.",
    falsePositiveGuidance: "Normal software also references system paths. Suspicious paths are ones in temp folders combined with random-looking filenames, or paths to other users' directories.",
  },
  path: {
    label: "File Paths",
    description: "File paths show where on the computer the malware reads from or writes to. Paths to system folders (like Windows\\System32) or temp directories are common targets — malware drops files there because they're trusted locations that users rarely check.",
    falsePositiveGuidance: "Normal software also references system paths. Suspicious paths are ones in temp folders combined with random-looking filenames, or paths to other users' directories.",
  },
  suspicious: {
    label: "Suspicious Strings",
    description: "These are strings that match patterns commonly seen in malware — command-line tools (cmd.exe, powershell), script interpreters, or known malicious keywords. They suggest the program might be trying to run commands or scripts on your computer.",
    falsePositiveGuidance: "System administration tools, installers, and development software legitimately reference these. Context matters — a text editor referencing cmd.exe is normal, a PDF reader doing so is not.",
  },
  command: {
    label: "Command Strings",
    description: "Commands that could be executed on the system — like someone typing instructions into a terminal. Malware uses these to download files, delete evidence, disable security, or spread to other computers. Think of it as finding a to-do list of malicious actions.",
    falsePositiveGuidance: "Build tools, package managers, and IT administration software naturally contain command strings. Look for commands that download files, modify security settings, or delete logs.",
  },
  crypto: {
    label: "Cryptographic Strings",
    description: "References to encryption algorithms or crypto libraries. Malware uses encryption to hide its communications (so network monitors can't read them) or to encrypt your files for ransom. It's like finding lock-picking tools in someone's bag.",
    falsePositiveGuidance: "Legitimate software uses encryption extensively — HTTPS, password storage, file protection. Suspicious when combined with file enumeration (ransomware) or network activity (C2).",
  },
};

function IocFocusContent({ item }: { item: Extract<TeacherFocusItem, { type: "ioc" }> }) {
  const info = IOC_DESCRIPTIONS[item.iocType] ?? {
    label: item.iocType.toUpperCase(),
    description: `An indicator of type "${item.iocType}" was found in the binary's strings. This may be relevant to understanding the file's behaviour and intent.`,
    falsePositiveGuidance: "Evaluate this indicator in the context of the file's apparent purpose. Not all indicators of a given type are malicious.",
  };

  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
      <h3 style={{ margin: "0 0 6px", fontSize: "var(--font-size-sm)", fontWeight: 600, color: "var(--text-primary)" }}>
        {info.label}
      </h3>
      <span style={{ display: "inline-block", marginBottom: 14, fontSize: 10, padding: "1px 6px", borderRadius: 999, background: "rgba(239,68,68,0.12)", color: "var(--risk-critical)", border: "1px solid rgba(239,68,68,0.2)" }}>
        IOC
      </span>

      {item.value && (
        <div style={{ marginBottom: 14, padding: "8px 10px", borderRadius: "var(--radius-sm)", background: "var(--bg-elevated)", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", wordBreak: "break-all" }}>
          {item.value}
        </div>
      )}

      <div style={{ marginBottom: 14 }}>
        <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          What this means
        </p>
        <p className="selectable" style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.6 }}>
          {info.description}
        </p>
      </div>

      <div style={{ marginBottom: 0 }}>
        <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          False positive guidance
        </p>
        <p className="selectable" style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.6 }}>
          {info.falsePositiveGuidance}
        </p>
      </div>

      <SimpleExplanationCard text={`This ${info.label} indicator was extracted from the file's embedded strings. Evaluate it alongside other findings to determine if it supports a malicious interpretation.`} />
    </div>
  );
}

// ── Security focus content ────────────────────────────────────────────────────

const SECURITY_EXPLANATIONS: Record<string, { title: string; explanation: string; good: string; bad: string }> = {
  aslr: {
    title: "ASLR (Address Space Layout Randomisation)",
    explanation: "Randomises where the program is loaded in memory each time it runs — like shuffling room numbers in a hotel so an intruder can't find the right room. This makes it much harder for attackers to exploit memory bugs.",
    good: "Enabled — the program uses memory randomisation, making exploitation harder.",
    bad: "Disabled — the program always loads at the same memory address, making it easier for attackers to write reliable exploits.",
  },
  dep: {
    title: "DEP / NX (Data Execution Prevention)",
    explanation: "Marks data areas of memory as non-executable — like putting a 'no entry' sign on a storage room. Even if an attacker manages to inject code into memory, the CPU refuses to run it.",
    good: "Enabled — injected code in data areas will be blocked by the CPU.",
    bad: "Disabled — an attacker who gets code into memory can run it directly.",
  },
  authenticode: {
    title: "Authenticode (Digital Signature)",
    explanation: "Microsoft's way of proving a file was made by who it claims — like a wax seal on a letter. The publisher's identity is verified by a trusted certificate authority, and any tampering breaks the seal.",
    good: "Present and valid — the file was signed by a verified publisher and hasn't been modified.",
    bad: "Absent or self-signed — there's no proof of who made this file. Self-signed means anyone could have created the signature.",
  },
  checksum: {
    title: "PE Checksum",
    explanation: "A mathematical fingerprint stored in the file header that should match the actual file contents — like a tamper-evident seal on a medicine bottle. If someone modifies the file, the checksum won't match.",
    good: "Match — the stored checksum matches the computed one. The file hasn't been tampered with (or was correctly rebuilt).",
    bad: "Mismatch — the file was modified after the checksum was set. This could be tampering, or just a tool that didn't update the checksum.",
  },
  overlay: {
    title: "Overlay Data",
    explanation: "Extra data appended after the end of the normal executable — like a secret compartment taped to the bottom of a suitcase. Legitimate software sometimes stores resources here, but malware uses it to hide payloads, configuration, or stolen data.",
    good: "No overlay, or overlay is part of a valid Authenticode signature.",
    bad: "Overlay present without a valid signature — could be hiding additional malicious content.",
  },
  entropy: {
    title: "Section Entropy",
    explanation: "Measures how random a section's data is, on a scale of 0 (completely predictable, like all zeros) to 8 (perfectly random, like encrypted data). Normal code sits around 5-6. Anything above 7 is suspicious.",
    good: "Sections have normal entropy (below 7.0) — the code isn't packed or encrypted.",
    bad: "High entropy sections (above 7.0) — the code is likely packed, encrypted, or compressed to hide its true contents.",
  },
  debug_artifacts: {
    title: "Debug Artifacts",
    explanation: "Leftover breadcrumbs from when the program was being developed — like finding a rough draft mixed in with a finished essay. PDB paths reveal the developer's file system, and zeroed timestamps suggest deliberate tampering.",
    good: "PDB path looks legitimate (e.g., a known company's build server). Timestamp is present and reasonable.",
    bad: "PDB path contains suspicious usernames or paths. Timestamp is zeroed (deliberately hidden) or set to an impossible date.",
  },
  weak_crypto: {
    title: "Weak Cryptography Indicators",
    explanation: "Signs that the program uses outdated or broken encryption — like using a combination lock with only 2 digits. Malware authors sometimes implement their own weak encryption to hide strings or communications.",
    good: "No weak crypto constants found — the program likely uses standard, strong encryption libraries.",
    bad: "Weak crypto constants detected (like RC4 S-box or XOR keys) — could indicate custom encryption used to hide malicious strings or payloads.",
  },
  version_info: {
    title: "Version Info",
    explanation: "Metadata embedded in the executable describing what it is — company name, product name, version number, copyright. Like the label on a jar. Legitimate software always fills this in; malware often fakes it or leaves it empty.",
    good: "Version info is present and matches a known publisher.",
    bad: "Version info is missing, blank, or claims to be from a well-known company but doesn't match the file's other characteristics.",
  },
  pie: {
    title: "PIE (Position Independent Executable)",
    explanation: "The ELF equivalent of ASLR — the program can be loaded at any memory address. Like ASLR for Linux programs. Makes memory exploitation significantly harder.",
    good: "Enabled — the program supports address randomisation.",
    bad: "Disabled — the program always loads at a fixed address, making exploitation easier.",
  },
  nx: {
    title: "NX Stack (Non-Executable Stack)",
    explanation: "Marks the stack (a temporary memory area) as non-executable — the Linux equivalent of DEP. Prevents the classic 'stack buffer overflow to code execution' attack.",
    good: "Enabled — stack-based code execution is blocked.",
    bad: "Disabled — an attacker exploiting a stack overflow can directly execute injected code.",
  },
  relro: {
    title: "RELRO (Relocation Read-Only)",
    explanation: "Protects critical memory tables from being overwritten after the program starts — like locking the control panel after the machine is running. Prevents attackers from redirecting function calls.",
    good: "Full RELRO — the GOT (Global Offset Table) is locked down after startup. Best protection.",
    bad: "Partial or no RELRO — an attacker can overwrite function pointers in memory to hijack program flow.",
  },
  toolchain: {
    title: "Compiler / Toolchain Detection",
    explanation: "Identifies which programming language and compiler built the executable — like recognising a car manufacturer from the engine and body style. Each toolchain (MSVC, GCC, Go, Rust, Delphi) leaves distinctive fingerprints in the binary's structure, imports, and section layout.",
    good: "Recognised, common toolchain — consistent with legitimate software development.",
    bad: "Unknown toolchain or suspicious compiler (e.g., AutoIt, PyInstaller wrapping a single script) — may indicate a script-based dropper or packer.",
  },
  rich_header: {
    title: "Rich Header",
    explanation: "An undocumented metadata block that Microsoft's MSVC linker embeds in every PE file it builds. It records which compiler tools and versions were used — like a receipt from the factory. It's XOR-encrypted with a checksum, and most tools don't know to fake it.",
    good: "Present — confirms the file was built with Microsoft's toolchain. Entries can be cross-referenced to identify the exact Visual Studio version.",
    bad: "Absent — the file wasn't built with MSVC (could be GCC, Go, Delphi, or a packer), or the header was deliberately stripped to hide build information.",
  },
  cert_reputation: {
    title: "Certificate Reputation",
    explanation: "Evaluates the trust level of the code-signing certificate — like checking if a passport was issued by a real government. Microsoft-signed binaries are the most trusted. Self-signed certificates offer no third-party verification.",
    good: "Signed by a trusted publisher (Microsoft, known vendor) — strong indicator of legitimacy.",
    bad: "Self-signed or unknown publisher — anyone can create a self-signed certificate, so it proves nothing about the file's origin.",
  },
  ksd_match: {
    title: "Known Sample Match (TLSH)",
    explanation: "Compares the file's structural fingerprint (TLSH hash) against a database of known malware. TLSH is a fuzzy hash — it measures similarity rather than exact matches. Think of it like facial recognition for malware: even if the file is slightly modified, it can still be matched to a known family.",
    good: "No match — the file doesn't resemble any known malware in the database.",
    bad: "Close match — the file's structure is similar to known malware. The closer the match (higher percentage), the more likely it's a variant of that family.",
  },
  dotnet: {
    title: ".NET Assembly Metadata",
    explanation: ".NET executables contain a rich metadata layer describing every class, method, and reference — like a complete blueprint attached to a building. This metadata reveals obfuscation tools, suspicious P/Invoke calls to native code, and reflection usage that can load code dynamically.",
    good: "Clean metadata — standard type names, no obfuscation detected, legitimate P/Invoke usage.",
    bad: "Obfuscated names, suspicious P/Invoke (calls to process injection APIs), or known obfuscator detected — strong indicators of malicious intent.",
  },
  stripped: {
    title: "Symbol Stripping",
    explanation: "Symbols are like a phonebook for a program's functions — they map memory addresses to human-readable names. Stripping removes this phonebook, making reverse engineering harder. Like removing all the labels from a circuit board.",
    good: "Symbols present — easier to analyse, common in debug builds and open-source software.",
    bad: "Symbols stripped — harder to analyse. Normal for release builds, but combined with other suspicious indicators, may suggest deliberate obfuscation.",
  },
  yara: {
    title: "YARA Rule Matches",
    explanation: "YARA rules are pattern-matching signatures written by security researchers to identify specific malware families, tools, or techniques — like a field guide for identifying species of malware. Each rule describes a unique combination of strings, byte patterns, or structural features.",
    good: "No matches — the file doesn't trigger any known detection rules.",
    bad: "Rule matched — a security researcher's signature identified something in this file. Check the rule name and description for details on what was found.",
  },
  graph: {
    title: "Relationship Graph",
    explanation: "A visual map of connections between evidence found in the file — imported DLLs, suspicious APIs, IOCs (URLs, IPs, domains), and behavioral categories. In batch mode, it shows structural similarity (TLSH distance) between files. Hover any node to spotlight its connections; drag to rearrange; click to select.",
    good: "Few connections, mostly benign infrastructure — the graph is sparse with clean verdicts and no suspicious API clusters.",
    bad: "Dense web of suspicious APIs connected to dangerous DLLs, IOCs pointing to external infrastructure, and multiple behavioral categories flagged — indicates sophisticated malicious capability.",
  },
};

function SecurityFocusContent({ item }: { item: { type: "security"; feature: string } }) {
  const data = SECURITY_EXPLANATIONS[item.feature];
  if (!data) return null;
  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
      <h3 style={{ fontSize: "var(--font-size-base)", fontWeight: 600, color: "var(--text-primary)", margin: "0 0 4px" }}>
        {data.title}
      </h3>
      <SimpleExplanationCard text={data.explanation} />
      <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 8 }}>
        <div style={{ padding: "8px 12px", borderRadius: "var(--radius)", background: "rgba(34,197,94,0.06)", border: "1px solid rgba(34,197,94,0.15)", fontSize: "var(--font-size-sm)", color: "var(--text-secondary)" }}>
          <strong style={{ color: "#22c55e" }}>Good:</strong> {data.good}
        </div>
        <div style={{ padding: "8px 12px", borderRadius: "var(--radius)", background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.15)", fontSize: "var(--font-size-sm)", color: "var(--text-secondary)" }}>
          <strong style={{ color: "#ef4444" }}>Bad:</strong> {data.bad}
        </div>
      </div>
    </div>
  );
}

// ── Batch focus content ───────────────────────────────────────────────────────

function BatchFocusContent({ item }: { item: Extract<TeacherFocusItem, { type: "batch" }> }) {
  const isDashboard = item.context === "dashboard";
  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
      <h3 style={{ margin: "0 0 6px", fontSize: "var(--font-size-sm)", fontWeight: 600, color: "var(--text-primary)" }}>
        Batch Analysis
      </h3>
      <span style={{ display: "inline-block", marginBottom: 14, fontSize: 10, padding: "1px 6px", borderRadius: 999, background: "rgba(99,102,241,0.12)", color: "rgb(129,140,248)", border: "1px solid rgba(99,102,241,0.2)" }}>
        {isDashboard ? "Dashboard" : "File Detail"}
      </span>

      <div style={{ marginBottom: 14 }}>
        <p style={{ margin: "0 0 5px", fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          {isDashboard ? "Reading the dashboard" : "Viewing a file in batch context"}
        </p>
        <p className="selectable" style={{ margin: 0, fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.6 }}>
          {isDashboard
            ? "The batch dashboard shows an overview of all analysed files. Use the verdict distribution to identify outliers, sort by risk score to prioritise your review, and look for patterns across files that might indicate a coordinated attack. Files in the High and Critical categories should be examined first."
            : "You are viewing a single file from a batch analysis. All the same analysis tabs are available. When you finish reviewing this file, return to the batch dashboard to continue triaging the remaining files. Look for IOCs that also appear in other files from the same batch — shared indicators suggest related threats."}
        </p>
      </div>

      <SimpleExplanationCard
        text={isDashboard
          ? "Batch analysis processes multiple files at once and aggregates the results. Start with the highest-risk files and work your way down. Look for shared indicators across files to identify campaigns."
          : "This file is part of a larger batch. Compare its findings with other files in the batch. Shared C2 addresses, packer signatures, or import patterns can link files to the same threat actor or campaign."}
      />
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

const MIN_WIDTH = 280;
const MAX_WIDTH_RATIO = 0.5;

export default function TeacherSidebar() {
  const { enabled, setEnabled, focusedItem } = useTeacherMode();
  const [sidebarWidth, setSidebarWidth] = useState(MIN_WIDTH);
  const [isDragging, setIsDragging] = useState(false);
  const dragRef = useRef(false);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    dragRef.current = true;
    setIsDragging(true);

    const onMouseMove = (ev: MouseEvent) => {
      if (!dragRef.current) return;
      const newWidth = window.innerWidth - ev.clientX;
      const clamped = Math.max(MIN_WIDTH, Math.min(newWidth, window.innerWidth * MAX_WIDTH_RATIO));
      setSidebarWidth(clamped);
    };

    const onMouseUp = () => {
      dragRef.current = false;
      setIsDragging(false);
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }, []);

  // Reset width when sidebar is disabled
  useEffect(() => {
    if (!enabled) setSidebarWidth(MIN_WIDTH);
  }, [enabled]);

  return (
    <div
      data-testid="teacher-sidebar"
      style={{
        width: enabled ? sidebarWidth : 0,
        minWidth: enabled ? sidebarWidth : 0,
        flexShrink: 0,
        overflow: "hidden",
        transition: isDragging ? "none" : "width 250ms ease-out, min-width 250ms ease-out",
        position: "relative",
      }}
    >
      {/* Drag handle */}
      {enabled && (
        <div
          onMouseDown={handleMouseDown}
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            width: 4,
            height: "100%",
            cursor: "col-resize",
            zIndex: 10,
            background: isDragging ? "var(--accent)" : "transparent",
            transition: "background 150ms ease",
          }}
          onMouseEnter={(e) => {
            if (!isDragging) (e.currentTarget as HTMLDivElement).style.background = "var(--border)";
          }}
          onMouseLeave={(e) => {
            if (!isDragging) (e.currentTarget as HTMLDivElement).style.background = "transparent";
          }}
        />
      )}

      {/* Inner container — fills to current width */}
      <div
        style={{
          width: sidebarWidth,
          height: "100%",
          background: "var(--bg-surface)",
          borderLeft: "1px solid var(--border)",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Header */}
        <div
          style={{
            flexShrink: 0,
            padding: "10px 14px",
            borderBottom: "1px solid var(--border-subtle)",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <GraduationCap size={14} style={{ color: "rgb(129,140,248)", flexShrink: 0 }} />
          <span style={{ flex: 1, fontSize: "var(--font-size-xs)", fontWeight: 600, color: "var(--text-primary)", whiteSpace: "nowrap" }}>
            Teacher Mode
          </span>
          <button
            onClick={() => setEnabled(false)}
            title="Disable Teacher Mode"
            style={{
              background: "none", border: "none", cursor: "pointer",
              color: "var(--text-muted)", padding: 2, display: "flex",
              alignItems: "center", borderRadius: "var(--radius-sm)", flexShrink: 0,
            }}
          >
            <X size={13} />
          </button>
        </div>

        {/* Content area */}
        {!focusedItem && <EmptyState />}
        {focusedItem?.type === "mitre" && <MitreFocusContent item={focusedItem} />}
        {focusedItem?.type === "api" && <ApiFocusContent item={focusedItem} />}
        {focusedItem?.type === "dll" && <DllFocusContent item={focusedItem} />}
        {focusedItem?.type === "ioc" && <IocFocusContent item={focusedItem} />}
        {focusedItem?.type === "security" && <SecurityFocusContent item={focusedItem} />}
        {focusedItem?.type === "batch" && <BatchFocusContent item={focusedItem} />}
      </div>
    </div>
  );
}
