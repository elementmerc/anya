import { useState, useMemo } from "react";
import { ChevronRight, AlertTriangle, Search } from "lucide-react";
import { getApiDescription } from "@/lib/apiDescriptions";
import { useTeacherFocus } from "@/hooks/useTeacherMode";
import type { AnalysisResult } from "@/types/analysis";

interface Props {
  result: AnalysisResult;
  /** Called when a MITRE badge is clicked; navigates to MITRE tab and highlights the card. */
  onMitreNavigate?: (techId: string) => void;
}

interface DllEntry {
  dll: string;
  functions: string[];
  suspiciousCount: number;
}

function Highlight({ text, query }: { text: string; query: string }) {
  if (!query) return <>{text}</>;
  const idx = text.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return <>{text}</>;
  return (
    <>
      {text.slice(0, idx)}
      <mark style={{ background: "rgba(250,204,21,0.3)", color: "inherit", borderRadius: 2 }}>
        {text.slice(idx, idx + query.length)}
      </mark>
      {text.slice(idx + query.length)}
    </>
  );
}

// Build a map of API name (lowercase) → first MITRE technique (full object)
function buildMitreMap(techniques: Props["result"]["mitre_techniques"]) {
  const map = new Map<string, { id: string; name: string; tactic: string }>();
  if (techniques) {
    for (const t of techniques) {
      const key = t.source_indicator.toLowerCase();
      if (!map.has(key)) {
        map.set(key, {
          id: t.technique_id,
          name: t.technique_name,
          tactic: t.tactic,
        });
      }
    }
  }
  return map;
}

export default function ImportsTab({ result, onMitreNavigate }: Props) {
  const pe = result.pe_analysis;
  const { teacherEnabled, focus, blur } = useTeacherFocus();
  const mitreMap = buildMitreMap(result.mitre_techniques);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [tooltip, setTooltip] = useState<{ fn: string; x: number; y: number } | null>(null);

  if (!pe) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <p style={{ color: "var(--text-muted)" }}>No PE import data available.</p>
      </div>
    );
  }

  const suspiciousSet = new Set(pe.imports.suspicious_apis.map((a) => a.name.toLowerCase()));

  const dllMap = useMemo<DllEntry[]>(() => {
    const suspApiNames = pe.imports.suspicious_apis.map((a) => a.name);

    const knownHosts: Record<string, string[]> = {
      "kernel32.dll":   ["CreateRemoteThread","WriteProcessMemory","VirtualAllocEx","CreateService","StartService","DeleteFile","MoveFile","CopyFile"],
      "kernelbase.dll": ["VirtualAllocEx","OpenProcess","OpenProcessToken","AdjustTokenPrivileges"],
      "ntdll.dll":      ["NtQueueApcThread","RtlCreateUserThread","NtCreateThreadEx","NtMapViewOfSection","NtQueryInformationProcess","ZwSetInformationThread","NtSetInformationThread"],
      "user32.dll":     ["SetWindowsHookEx","SetWindowsHookExA","SetWindowsHookExW","GetAsyncKeyState"],
      "wininet.dll":    ["InternetOpen","InternetOpenUrl","URLDownloadToFile"],
      "winhttp.dll":    ["WinHttpOpen"],
      "advapi32.dll":   ["RegSetValueEx","RegCreateKeyEx","CryptEncrypt","CryptDecrypt","CryptAcquireContext"],
      "ws2_32.dll":     ["WSAStartup","socket","connect"],
    };

    const assigned = new Set<string>();
    const entries: DllEntry[] = [];

    for (const dll of pe.imports.libraries) {
      const hostFns = knownHosts[dll.toLowerCase()] ?? [];
      const fns = suspApiNames.filter((n) => {
        if (assigned.has(n)) return false;
        if (hostFns.some((h) => h.toLowerCase() === n.toLowerCase())) { assigned.add(n); return true; }
        return false;
      });
      entries.push({ dll, functions: fns, suspiciousCount: fns.length });
    }

    const unassigned = suspApiNames.filter((n) => !assigned.has(n));
    if (unassigned.length > 0 && entries.length > 0) {
      entries[0].functions.push(...unassigned);
      entries[0].suspiciousCount += unassigned.length;
    }

    return entries;
  }, [pe]);

  function toggle(dll: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(dll) ? next.delete(dll) : next.add(dll);
      return next;
    });
  }

  const lSearch = search.toLowerCase();

  const filtered = useMemo(() =>
    dllMap.filter((e) => {
      if (suspiciousOnly && e.suspiciousCount === 0) return false;
      if (!lSearch) return true;
      return e.dll.toLowerCase().includes(lSearch) || e.functions.some((f) => f.toLowerCase().includes(lSearch));
    }),
    [dllMap, lSearch, suspiciousOnly]
  );

  const effectiveExpanded = useMemo(() => {
    if (!lSearch) return expanded;
    const next = new Set(expanded);
    for (const e of filtered) {
      if (e.functions.some((f) => f.toLowerCase().includes(lSearch))) next.add(e.dll);
    }
    return next;
  }, [lSearch, filtered, expanded]);

  return (
    <div
      style={{ height: "100%", overflow: "hidden", display: "flex", flexDirection: "column" }}
      onClick={() => setTooltip(null)}
    >
      {/* Toolbar */}
      <div style={{ flexShrink: 0, padding: "16px 24px 12px", background: "var(--bg-base)", borderBottom: "1px solid var(--border-subtle)" }}>
        <div style={{ maxWidth: 1600, margin: "0 auto", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 200, display: "flex", alignItems: "center", gap: 8, padding: "0 12px", height: 36, borderRadius: "var(--radius)", background: "var(--bg-surface)", border: "1px solid var(--border)" }}>
            <Search size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
            <input
              type="text"
              placeholder="Search DLLs and functions…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ flex: 1, background: "transparent", border: "none", outline: "none", fontSize: "var(--font-size-sm)", color: "var(--text-primary)" }}
            />
          </div>
          <button
            onClick={() => setSuspiciousOnly((v) => !v)}
            aria-pressed={suspiciousOnly}
            style={{ height: 36, padding: "0 14px", display: "flex", alignItems: "center", gap: 6, fontSize: "var(--font-size-xs)", fontWeight: 500, borderRadius: "var(--radius)", border: "1px solid var(--border)", background: suspiciousOnly ? "rgba(249,115,22,0.15)" : "var(--bg-surface)", color: suspiciousOnly ? "var(--risk-high)" : "var(--text-secondary)", cursor: "pointer", transition: "all 150ms ease-out", flexShrink: 0, whiteSpace: "nowrap" }}
          >
            <AlertTriangle size={13} />
            Suspicious only
          </button>
          <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", whiteSpace: "nowrap", flexShrink: 0 }}>
            {pe.imports.dll_count} DLLs &nbsp;·&nbsp; {pe.imports.total_imports} functions
            {pe.imports.suspicious_api_count > 0 && (
              <span style={{ color: "var(--risk-high)" }}> &nbsp;·&nbsp; {pe.imports.suspicious_api_count} suspicious</span>
            )}
          </span>
        </div>
      </div>

      {/* Tree */}
      <div style={{ flex: 1, overflowY: "auto", padding: "16px 24px 24px" }}>
        <div style={{ maxWidth: 1600, margin: "0 auto" }}>
          <div style={{ borderRadius: 8, overflow: "hidden", background: "var(--bg-surface)", border: "1px solid var(--border)" }}>
            {filtered.length === 0 ? (
              <p style={{ padding: "32px 16px", textAlign: "center", fontSize: "var(--font-size-base)", color: "var(--text-muted)" }}>
                No imports match the current filter.
              </p>
            ) : filtered.map((entry, idx) => {
              const isOpen = effectiveExpanded.has(entry.dll);
              return (
                <div key={entry.dll} style={{ borderTop: idx > 0 ? "1px solid var(--border-subtle)" : undefined }}>
                  <button
                    onClick={() => toggle(entry.dll)}
                    aria-expanded={isOpen}
                    style={{ width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "0 16px", height: 40, background: "transparent", border: "none", cursor: "pointer", transition: "background 150ms ease-out", textAlign: "left" }}
                    onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "var(--bg-elevated)"; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "transparent"; }}
                  >
                    <ChevronRight size={14} style={{ color: "var(--text-muted)", flexShrink: 0, transform: isOpen ? "rotate(90deg)" : "rotate(0)", transition: "transform 150ms ease-out" }} />
                    <span style={{ flex: 1, fontSize: "var(--font-size-sm)", fontFamily: "var(--font-mono)", color: "var(--text-primary)", fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      <Highlight text={entry.dll} query={search} />
                    </span>
                    {entry.suspiciousCount > 0 && (
                      <span style={{ display: "flex", alignItems: "center", gap: 4, fontSize: "var(--font-size-xs)", padding: "2px 8px", borderRadius: 999, background: "rgba(249,115,22,0.12)", color: "var(--risk-high)", flexShrink: 0 }}>
                        <AlertTriangle size={10} />{entry.suspiciousCount}
                      </span>
                    )}
                  </button>

                  {isOpen && entry.functions.length > 0 && (
                    <div style={{ background: "var(--bg-base)", borderTop: "1px solid var(--border-subtle)" }}>
                      {entry.functions.map((fn) => {
                        const isSusp = suspiciousSet.has(fn.toLowerCase());
                        const category = pe.imports.suspicious_apis.find((a) => a.name.toLowerCase() === fn.toLowerCase())?.category;
                        const hasDesc = !!getApiDescription(fn);
                        const mitreTech = mitreMap.get(fn.toLowerCase());
                        return (
                          <div
                            key={fn}
                            style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 16px 0 40px", height: 36, background: isSusp ? "var(--suspicious-bg)" : "transparent" }}
                            onMouseEnter={() => {
                              if (teacherEnabled && isSusp) {
                                if (mitreTech) {
                                  focus({ type: "mitre", techniqueId: mitreTech.id, techniqueName: mitreTech.name, tactic: mitreTech.tactic });
                                } else {
                                  focus({ type: "api", name: fn, category: category ?? undefined });
                                }
                              }
                            }}
                            onMouseLeave={() => {
                              if (teacherEnabled) blur();
                            }}
                          >
                            {isSusp && <AlertTriangle size={12} style={{ color: "var(--risk-high)", flexShrink: 0 }} />}
                            <span className="selectable" style={{ flex: 1, fontSize: "var(--font-size-sm)", fontFamily: "var(--font-mono)", color: isSusp ? "var(--risk-high)" : "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              <Highlight text={fn} query={search} />
                            </span>
                            {category && (
                              <span style={{ fontSize: "var(--font-size-xs)", padding: "2px 7px", borderRadius: 999, background: "rgba(249,115,22,0.12)", color: "var(--risk-high)", flexShrink: 0, whiteSpace: "nowrap" }}>
                                {category}
                              </span>
                            )}
                            {isSusp && mitreTech && (
                              <button
                                title={`MITRE ATT&CK ${mitreTech.id} — click to view in MITRE tab`}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  if (onMitreNavigate) {
                                    onMitreNavigate(mitreTech.id);
                                  }
                                }}
                                style={{
                                  fontSize: "var(--font-size-xs)",
                                  padding: "2px 6px",
                                  borderRadius: 4,
                                  background: "rgba(99,102,241,0.15)",
                                  color: "rgb(129,140,248)",
                                  border: "1px solid rgba(99,102,241,0.3)",
                                  flexShrink: 0,
                                  whiteSpace: "nowrap",
                                  cursor: "pointer",
                                  fontFamily: "var(--font-mono)",
                                  fontWeight: 600,
                                }}
                              >
                                {mitreTech.id}
                              </button>
                            )}
                            {hasDesc && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  const r = e.currentTarget.getBoundingClientRect();
                                  setTooltip({ fn, x: r.left, y: r.bottom + 4 });
                                }}
                                style={{ background: "none", border: "1px solid var(--border)", padding: "1px 6px", fontSize: "var(--font-size-xs)", color: "var(--text-muted)", cursor: "pointer", flexShrink: 0, borderRadius: "var(--radius-sm)", lineHeight: 1.4 }}
                              >
                                why?
                              </button>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="animate-tooltip-in"
          style={{ position: "fixed", top: Math.min(tooltip.y, window.innerHeight - 120), left: Math.min(tooltip.x, window.innerWidth - 320), zIndex: 50, maxWidth: 300, padding: "10px 14px", borderRadius: "var(--radius)", background: "var(--bg-elevated)", border: "1px solid var(--border)", fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", lineHeight: 1.5, boxShadow: "0 4px 16px rgba(0,0,0,0.3)" }}
        >
          <p style={{ margin: "0 0 4px", fontWeight: 600, color: "var(--text-primary)", fontSize: "var(--font-size-sm)" }}>{tooltip.fn}</p>
          <p style={{ margin: 0 }}>{getApiDescription(tooltip.fn)}</p>
        </div>
      )}
    </div>
  );
}
