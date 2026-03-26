import { useState, useEffect } from "react";
import { Briefcase, ChevronRight, ChevronDown, Trash2 } from "lucide-react";
import { listCases, getCase, deleteCase } from "@/lib/tauri-bridge";
import { useToast } from "@/components/Toast";
import type { CaseSummary, CaseDetail } from "@/types/analysis";

interface Props {
  onPickFile: (filePath: string) => void;
}

export default function CaseBrowser({ onPickFile }: Props) {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [expandedCase, setExpandedCase] = useState<string | null>(null);
  const [caseDetail, setCaseDetail] = useState<CaseDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState<string | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    listCases().then(setCases).catch(() => setCases([]));
  }, []);

  async function handleExpand(name: string) {
    if (expandedCase === name) {
      setExpandedCase(null);
      setCaseDetail(null);
      return;
    }
    setExpandedCase(name);
    setLoadingDetail(true);
    try {
      const detail = await getCase(name);
      setCaseDetail(detail);
    } catch {
      setCaseDetail(null);
    } finally {
      setLoadingDetail(false);
    }
  }

  function handleDeleteClick(e: React.MouseEvent, name: string) {
    e.stopPropagation();
    setConfirmingDelete(name);
  }

  async function handleDeleteConfirm(e: React.MouseEvent, name: string) {
    e.stopPropagation();
    setConfirmingDelete(null);
    try {
      await deleteCase(name);
      setCases((prev) => prev.filter((c) => c.name !== name));
      if (expandedCase === name) {
        setExpandedCase(null);
        setCaseDetail(null);
      }
      toast(`Case "${name}" deleted`, "success");
    } catch (err) {
      toast(`Failed to delete: ${err}`, "error");
    }
  }

  if (cases.length === 0) return null;

  const verdictColor = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case "malicious": return "var(--risk-critical)";
      case "suspicious": return "var(--risk-medium)";
      case "clean": return "var(--text-muted)";
      default: return "var(--text-muted)";
    }
  };

  return (
    <div
      style={{
        marginTop: 20,
        width: "100%",
        maxWidth: 360,
        animation: "batch-fade-in 300ms ease-out",
      }}
      onClick={(e) => e.stopPropagation()}
    >
      <p
        style={{
          fontSize: "var(--font-size-xs)",
          color: "var(--text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          margin: "0 0 8px",
          textAlign: "center",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 6,
        }}
      >
        <Briefcase size={12} />
        Cases ({cases.length})
      </p>
      {cases.map((c) => (
        <div key={c.name}>
          <button
            onClick={() => void handleExpand(c.name)}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              width: "100%",
              padding: "6px 10px",
              border: "none",
              background: expandedCase === c.name ? "var(--bg-surface)" : "transparent",
              borderRadius: 4,
              color: "var(--text-secondary)",
              fontSize: "var(--font-size-sm)",
              cursor: "pointer",
              transition: "background 100ms ease",
              textAlign: "left",
            }}
            onMouseEnter={(e) => {
              if (expandedCase !== c.name) e.currentTarget.style.background = "var(--bg-surface)";
            }}
            onMouseLeave={(e) => {
              if (expandedCase !== c.name) e.currentTarget.style.background = "transparent";
            }}
          >
            <span style={{ display: "flex", alignItems: "center", gap: 6, overflow: "hidden" }}>
              {expandedCase === c.name ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {c.name}
              </span>
            </span>
            <span style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
              {confirmingDelete === c.name ? (
                <>
                  <span
                    onClick={(e) => void handleDeleteConfirm(e, c.name)}
                    style={{ fontSize: "var(--font-size-xs)", color: "var(--risk-critical)", cursor: "pointer", padding: "1px 4px" }}
                  >
                    Delete
                  </span>
                  <span
                    onClick={(e) => { e.stopPropagation(); setConfirmingDelete(null); }}
                    style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", cursor: "pointer", padding: "1px 4px" }}
                  >
                    Cancel
                  </span>
                </>
              ) : (
                <>
                  <span style={{ fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                    {c.file_count} files
                  </span>
                  <span
                    onClick={(e) => handleDeleteClick(e, c.name)}
                    style={{ display: "flex", alignItems: "center", padding: 2, borderRadius: 3, color: "var(--text-muted)", cursor: "pointer", transition: "color 100ms ease" }}
                    onMouseEnter={(e) => (e.currentTarget.style.color = "var(--risk-critical)")}
                    onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-muted)")}
                  >
                    <Trash2 size={12} />
                  </span>
                </>
              )}
            </span>
          </button>

          {expandedCase === c.name && (
            <div style={{ paddingLeft: 24, paddingBottom: 4 }}>
              {loadingDetail ? (
                <p style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", margin: "4px 0" }}>
                  Loading...
                </p>
              ) : caseDetail ? (
                <>
                  <p style={{
                    fontSize: "var(--font-size-xs)", color: "var(--text-muted)",
                    margin: "2px 0 4px", fontFamily: "var(--font-mono)",
                  }}>
                    {caseDetail.status} &middot; updated {caseDetail.updated.slice(0, 10)}
                  </p>
                  {caseDetail.files.map((f, i) => (
                    <button
                      key={i}
                      onClick={() => onPickFile(f.path)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        width: "100%",
                        padding: "4px 8px",
                        border: "none",
                        background: "transparent",
                        borderRadius: 4,
                        color: "var(--text-secondary)",
                        fontSize: "var(--font-size-xs)",
                        cursor: "pointer",
                        transition: "background 100ms ease",
                        textAlign: "left",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-elevated)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >
                      <span style={{
                        overflow: "hidden", textOverflow: "ellipsis",
                        whiteSpace: "nowrap", maxWidth: 200,
                        fontFamily: "var(--font-mono)",
                      }}>
                        {f.path.split(/[\\/]/).pop() ?? f.path}
                      </span>
                      <span
                        style={{
                          fontSize: "var(--font-size-xs)",
                          fontFamily: "var(--font-mono)",
                          color: verdictColor(f.verdict),
                          padding: "1px 6px",
                          borderRadius: 3,
                          background: `color-mix(in srgb, ${verdictColor(f.verdict)} 10%, transparent)`,
                          flexShrink: 0,
                          marginLeft: 8,
                        }}
                      >
                        {f.verdict}
                      </span>
                    </button>
                  ))}
                </>
              ) : (
                <p style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)", margin: "4px 0" }}>
                  Could not load case details
                </p>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
