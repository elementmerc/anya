import { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { Search } from "lucide-react";
import type { AnalysisResult, StringType } from "@/types/analysis";

interface Props {
  result: AnalysisResult;
}

// ── String classification ─────────────────────────────────────────────────────
const URL_RE      = /^https?:\/\/\S+/i;
const IP_RE       = /^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$/;
const PATH_RE     = /^[A-Za-z]:\\|^\/[A-Za-z]/;
const REG_RE      = /^HKEY_|^HKLM\\|^HKCU\\|^HKCR\\/i;
const SUSP_RE     = /cmd\.exe|powershell|mshta|wscript|cscript|regsvr32|rundll32|schtasks|certutil|bitsadmin|CreateObject|WScript\.Shell|Shell\.Application/i;

function classifyString(s: string): StringType {
  if (URL_RE.test(s))  return "url";
  if (IP_RE.test(s))   return "ip";
  if (REG_RE.test(s))  return "registry";
  if (PATH_RE.test(s)) return "path";
  if (SUSP_RE.test(s)) return "suspicious";
  return "default";
}

const TYPE_STYLE: Record<StringType, { bg: string; color: string; label: string }> = {
  url:        { bg: "rgba(96,165,250,0.12)",  color: "#60a5fa", label: "URL" },
  ip:         { bg: "rgba(34,211,238,0.12)",  color: "#22d3ee", label: "IP" },
  path:       { bg: "rgba(250,204,21,0.12)",  color: "#facc15", label: "Path" },
  registry:   { bg: "rgba(167,139,250,0.12)", color: "#a78bfa", label: "Registry" },
  suspicious: { bg: "rgba(239,68,68,0.12)",   color: "#ef4444", label: "Suspicious" },
  default:    { bg: "transparent",            color: "transparent", label: "" },
};

const ALL_TYPES: StringType[] = ["url", "ip", "path", "registry", "suspicious"];

const ROW_HEIGHT = 32;

interface StringRow {
  value: string;
  type: StringType;
  index: number;
}

// ── Virtual list ──────────────────────────────────────────────────────────────
function VirtualList({ items, expandedIdx, onExpand }: {
  items: StringRow[];
  expandedIdx: number | null;
  onExpand: (idx: number | null) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(400);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setContainerHeight(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const BUFFER = 8;
  const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - BUFFER);
  const end   = Math.min(items.length - 1, Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + BUFFER);

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop((e.target as HTMLDivElement).scrollTop);
  }, []);

  return (
    <div
      ref={containerRef}
      onScroll={handleScroll}
      style={{ flex: 1, overflowY: "auto", position: "relative" }}
    >
      <div style={{ height: items.length * ROW_HEIGHT, position: "relative" }}>
        {items.slice(start, end + 1).map((item, localIdx) => {
          const absIdx = start + localIdx;
          const isExpanded = expandedIdx === absIdx;
          const ts = TYPE_STYLE[item.type];
          const showBadge = item.type !== "default";

          return (
            <div
              key={item.index}
              onClick={() => onExpand(isExpanded ? null : absIdx)}
              style={{
                position: "absolute",
                top: absIdx * ROW_HEIGHT,
                left: 0,
                right: 0,
                height: isExpanded ? "auto" : ROW_HEIGHT,
                minHeight: ROW_HEIGHT,
                display: "flex",
                alignItems: isExpanded ? "flex-start" : "center",
                gap: 12,
                padding: "0 16px",
                cursor: "pointer",
                borderBottom: "1px solid var(--border-subtle)",
                background: item.type === "suspicious" ? "var(--suspicious-bg)" : "transparent",
                transition: "background 100ms ease-out",
                paddingTop: isExpanded ? 8 : 0,
                paddingBottom: isExpanded ? 8 : 0,
                zIndex: isExpanded ? 1 : 0,
              }}
              onMouseEnter={(e) => {
                if (item.type !== "suspicious") {
                  (e.currentTarget as HTMLDivElement).style.background = "var(--bg-elevated)";
                }
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLDivElement).style.background =
                  item.type === "suspicious" ? "var(--suspicious-bg)" : "transparent";
              }}
            >
              {/* Type badge */}
              <span
                style={{
                  width: 80,
                  flexShrink: 0,
                  fontSize: "var(--font-size-xs)",
                  fontWeight: 600,
                  padding: "2px 6px",
                  borderRadius: 4,
                  textAlign: "center",
                  background: showBadge ? ts.bg : "transparent",
                  color: showBadge ? ts.color : "transparent",
                  fontFamily: "var(--font-mono)",
                  overflow: "hidden",
                  whiteSpace: "nowrap",
                  textOverflow: "ellipsis",
                }}
              >
                {showBadge ? ts.label : ""}
              </span>

              {/* Value */}
              <span
                style={{
                  flex: 1,
                  fontSize: "var(--font-size-xs)",
                  fontFamily: "var(--font-mono)",
                  color: item.type === "suspicious" ? "#ef4444" : "var(--text-secondary)",
                  overflow: isExpanded ? "visible" : "hidden",
                  textOverflow: isExpanded ? "unset" : "ellipsis",
                  whiteSpace: isExpanded ? "pre-wrap" : "nowrap",
                  wordBreak: isExpanded ? "break-all" : "normal",
                }}
              >
                {item.value}
              </span>

              {/* Offset placeholder (backend doesn't provide offsets) */}
              <span style={{ fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", color: "var(--text-muted)", flexShrink: 0 }}>
                —
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function StringsTab({ result }: Props) {
  const [search, setSearch] = useState("");
  const [activeTypes, setActiveTypes] = useState<Set<StringType>>(new Set());
  const [minLength, setMinLength] = useState(4);
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  const rawStrings: string[] = result.strings?.samples ?? [];

  const classified = useMemo<StringRow[]>(() => {
    return rawStrings.map((s, i) => ({
      value: s,
      type: classifyString(s),
      index: i,
    }));
  }, [rawStrings]);

  const filtered = useMemo<StringRow[]>(() => {
    const lSearch = search.toLowerCase();
    return classified.filter((row) => {
      if (row.value.length < minLength) return false;
      if (activeTypes.size > 0 && !activeTypes.has(row.type)) return false;
      if (lSearch && !row.value.toLowerCase().includes(lSearch)) return false;
      return true;
    });
  }, [classified, search, minLength, activeTypes]);

  function toggleType(t: StringType) {
    setActiveTypes((prev) => {
      const next = new Set(prev);
      next.has(t) ? next.delete(t) : next.add(t);
      return next;
    });
  }

  return (
    <div style={{ height: "100%", overflow: "hidden", display: "flex", flexDirection: "column" }}>
      {/* Sticky toolbar */}
      <div
        style={{
          flexShrink: 0,
          padding: "16px 24px 12px",
          background: "var(--bg-base)",
          borderBottom: "1px solid var(--border-subtle)",
        }}
      >
        <div style={{ maxWidth: 1600, margin: "0 auto", display: "flex", flexDirection: "column", gap: 10 }}>
          {/* Search + length */}
          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <div
              style={{
                flex: 1,
                minWidth: 200,
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "0 12px",
                height: 36,
                borderRadius: "var(--radius)",
                background: "var(--bg-surface)",
                border: "1px solid var(--border)",
              }}
            >
              <Search size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
              <input
                type="text"
                placeholder="Search strings…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ flex: 1, background: "transparent", border: "none", outline: "none", fontSize: "var(--font-size-sm)", color: "var(--text-primary)" }}
              />
            </div>

            <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "var(--font-size-xs)", color: "var(--text-muted)", flexShrink: 0, whiteSpace: "nowrap" }}>
              Min length: <strong style={{ color: "var(--text-primary)", minWidth: 18 }}>{minLength}</strong>
              <input
                type="range"
                min={4}
                max={20}
                value={minLength}
                onChange={(e) => setMinLength(Number(e.target.value))}
                style={{ width: 80, accentColor: "var(--accent)" }}
              />
            </label>
          </div>

          {/* Type filter pills */}
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <button
              onClick={() => setActiveTypes(new Set())}
              style={{
                height: 26,
                padding: "0 10px",
                fontSize: "var(--font-size-xs)",
                fontWeight: 500,
                borderRadius: 999,
                border: "1px solid var(--border)",
                background: activeTypes.size === 0 ? "var(--bg-elevated)" : "transparent",
                color: activeTypes.size === 0 ? "var(--text-primary)" : "var(--text-muted)",
                cursor: "pointer",
                transition: "all 150ms ease-out",
              }}
            >
              All
            </button>
            {ALL_TYPES.map((t) => {
              const ts = TYPE_STYLE[t];
              const active = activeTypes.has(t);
              return (
                <button
                  key={t}
                  onClick={() => toggleType(t)}
                  style={{
                    height: 26,
                    padding: "0 10px",
                    fontSize: "var(--font-size-xs)",
                    fontWeight: 500,
                    borderRadius: 999,
                    border: `1px solid ${active ? ts.color + "66" : "var(--border)"}`,
                    background: active ? ts.bg : "transparent",
                    color: active ? ts.color : "var(--text-muted)",
                    cursor: "pointer",
                    transition: "all 150ms ease-out",
                  }}
                >
                  {ts.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Column headers */}
      <div
        style={{
          flexShrink: 0,
          display: "flex",
          gap: 12,
          padding: "6px 16px",
          background: "var(--bg-surface)",
          borderBottom: "1px solid var(--border-subtle)",
        }}
      >
        <span style={{ width: 80, flexShrink: 0, fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--text-muted)" }}>Type</span>
        <span style={{ flex: 1, fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--text-muted)" }}>Value</span>
        <span style={{ fontSize: "var(--font-size-xs)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--text-muted)", flexShrink: 0 }}>Offset</span>
      </div>

      {/* Virtual list fills remaining space */}
      {filtered.length === 0 ? (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <p style={{ color: "var(--text-muted)", fontSize: "var(--font-size-base)" }}>No strings match the current filter.</p>
        </div>
      ) : (
        <VirtualList items={filtered} expandedIdx={expandedIdx} onExpand={setExpandedIdx} />
      )}

      {/* Footer */}
      <div
        style={{
          flexShrink: 0,
          padding: "8px 16px",
          borderTop: "1px solid var(--border-subtle)",
          fontSize: "var(--font-size-xs)",
          color: "var(--text-muted)",
          background: "var(--bg-surface)",
        }}
      >
        Showing {filtered.length} of {rawStrings.length} strings
      </div>
    </div>
  );
}
