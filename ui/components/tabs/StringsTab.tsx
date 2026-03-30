import { useState, useMemo, useRef, useEffect, useContext } from "react";
import { Search, Pin } from "lucide-react";
import type { AnalysisResult } from "@/types/analysis";
import { TeacherModeContext } from "@/hooks/useTeacherMode";
type StringType = "url" | "ip" | "path" | "registry" | "suspicious" | "default";

interface PinnedFinding {
  type: string;
  label: string;
  detail: string;
}

interface Props {
  result: AnalysisResult;
  onPin?: (finding: PinnedFinding) => void;
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

// Extended category styles for backend-classified strings
const CATEGORY_STYLE: Record<string, { bg: string; color: string; label: string }> = {
  URL:      TYPE_STYLE.url,
  IP:       TYPE_STYLE.ip,
  Path:     TYPE_STYLE.path,
  Registry: TYPE_STYLE.registry,
  Command:  { bg: "rgba(239,68,68,0.12)", color: "#ef4444", label: "Command" },
  Base64:   { bg: "rgba(251,146,60,0.12)", color: "#fb923c", label: "Base64" },
  Crypto:   { bg: "rgba(168,85,247,0.12)", color: "#a855f7", label: "Crypto" },
  Plain:    { bg: "transparent", color: "transparent", label: "" },
};

const ROW_HEIGHT = 32;

interface StringRow {
  value: string;
  type: StringType;
  category?: string; // backend category if available
  offset?: string;
  index: number;
  isBenign?: boolean;
}

// ── Virtual scroll hook ───────────────────────────────────────────────────────
function useVirtualScroll(
  itemCount: number,
  itemHeight: number,
  containerRef: React.RefObject<HTMLDivElement | null>,
) {
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(0);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const observer = new ResizeObserver((entries) => {
      setContainerHeight(entries[0].contentRect.height);
    });
    observer.observe(el);

    const onScroll = () => setScrollTop(el.scrollTop);
    el.addEventListener("scroll", onScroll, { passive: true });

    return () => {
      observer.disconnect();
      el.removeEventListener("scroll", onScroll);
    };
  }, [containerRef]);

  const overscan = 5;
  const startIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
  const endIndex = Math.min(itemCount, Math.ceil((scrollTop + containerHeight) / itemHeight) + overscan);
  const offsetY = startIndex * itemHeight;
  const totalHeight = itemCount * itemHeight;

  return { startIndex, endIndex, offsetY, totalHeight };
}

// ── Virtual list ──────────────────────────────────────────────────────────────
function VirtualList({ items, expandedIdx, onExpand, onPin }: {
  items: StringRow[];
  expandedIdx: number | null;
  onExpand: (idx: number | null) => void;
  onPin?: (finding: PinnedFinding) => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const { startIndex, endIndex, offsetY, totalHeight } = useVirtualScroll(
    items.length, ROW_HEIGHT, scrollRef,
  );

  return (
    <div
      ref={scrollRef}
      style={{ flex: 1, overflowY: "auto" }}
    >
      <div style={{ height: totalHeight, position: "relative" }}>
        <div style={{ transform: `translateY(${offsetY}px)` }}>
          {items.slice(startIndex, endIndex).map((item, localIdx) => {
            const absIdx = startIndex + localIdx;
            const isExpanded = expandedIdx === absIdx;
            const ts = TYPE_STYLE[item.type];
            const showBadge = item.type !== "default";

            return (
              <div
                key={item.index}
                onClick={() => onExpand(isExpanded ? null : absIdx)}
                style={{
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
                {/* Type badge — use backend category if available */}
                {(() => {
                  // Show "Benign" badge for known-safe IOCs
                  if (item.isBenign) {
                    return (
                      <span style={{
                        width: 80, flexShrink: 0, fontSize: "var(--font-size-xs)", fontWeight: 600,
                        padding: "2px 6px", borderRadius: 4, textAlign: "center",
                        background: "rgba(74,222,128,0.08)", color: "var(--risk-low)",
                        fontFamily: "var(--font-mono)", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis",
                      }}>
                        Benign
                      </span>
                    );
                  }
                  const catStyle = item.category ? (CATEGORY_STYLE[item.category] ?? CATEGORY_STYLE.Plain) : null;
                  const useCat = catStyle && item.category !== "Plain";
                  const badge = useCat ? catStyle : (showBadge ? ts : null);
                  return (
                    <span
                      style={{
                        width: 80,
                        flexShrink: 0,
                        fontSize: "var(--font-size-xs)",
                        fontWeight: 600,
                        padding: "2px 6px",
                        borderRadius: 4,
                        textAlign: "center",
                        background: badge ? badge.bg : "transparent",
                        color: badge ? badge.color : "transparent",
                        fontFamily: "var(--font-mono)",
                        overflow: "hidden",
                        whiteSpace: "nowrap",
                        textOverflow: "ellipsis",
                      }}
                    >
                      {badge ? badge.label : ""}
                    </span>
                  );
                })()}

                {/* Value */}
                <span
                  className="selectable"
                  style={{
                    flex: 1,
                    fontSize: "var(--font-size-xs)",
                    fontFamily: "var(--font-mono)",
                    color: item.isBenign ? "var(--text-muted)" : item.type === "suspicious" ? "#ef4444" : "var(--text-secondary)",
                    opacity: item.isBenign ? 0.5 : 1,
                    textDecoration: item.isBenign ? "line-through" : "none",
                    overflow: isExpanded ? "visible" : "hidden",
                    textOverflow: isExpanded ? "unset" : "ellipsis",
                    whiteSpace: isExpanded ? "pre-wrap" : "nowrap",
                    wordBreak: isExpanded ? "break-all" : "normal",
                  }}
                >
                  {item.value}
                </span>

                {/* Offset */}
                <span style={{ fontSize: "var(--font-size-xs)", fontFamily: "var(--font-mono)", color: "var(--text-muted)", flexShrink: 0, minWidth: 60, textAlign: "right" }}>
                  {item.offset ?? "—"}
                </span>

                {/* Pin button for suspicious strings */}
                {item.type !== "default" && onPin && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onPin({ type: "string", label: item.value.slice(0, 60), detail: `${item.category ?? item.type} string` }); }}
                    style={{ opacity: 0.4, cursor: "pointer", background: "transparent", border: "none", color: "var(--text-muted)", padding: 2, flexShrink: 0 }}
                    title="Pin to Overview"
                  >
                    <Pin size={11} />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function StringsTab({ result, onPin }: Props) {
  const teacherMode = useContext(TeacherModeContext);
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const [minLength, setMinLength] = useState(4);
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  // Debounce search input — filter runs 200ms after user stops typing
  useEffect(() => {
    const id = setTimeout(() => setDebouncedSearch(search), 200);
    return () => clearTimeout(id);
  }, [search]);

  const rawStrings: string[] = result.strings?.samples ?? [];

  const backendClassified = result.strings?.classified;

  const classified = useMemo<StringRow[]>(() => {
    // If backend provides classified strings, use those
    if (backendClassified && backendClassified.length > 0) {
      return backendClassified.map((cs, i) => {
        // Map backend category to frontend StringType for backwards compat
        const catLower = cs.category.toLowerCase();
        let type: StringType = "default";
        if (catLower === "url") type = "url";
        else if (catLower === "ip") type = "ip";
        else if (catLower === "path") type = "path";
        else if (catLower === "registry") type = "registry";
        else if (catLower === "command") type = "suspicious";
        return { value: cs.value, type, category: cs.category, offset: cs.offset, index: i, isBenign: cs.is_benign };
      });
    }
    // Fallback to frontend classification
    return rawStrings.map((s, i) => ({
      value: s,
      type: classifyString(s),
      index: i,
    }));
  }, [rawStrings, backendClassified]);

  const iocCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const row of classified) {
      const cat = row.category ?? "Plain";
      if (cat !== "Plain" && cat !== "default") {
        counts[cat] = (counts[cat] ?? 0) + 1;
      }
    }
    return counts;
  }, [classified]);

  const filtered = useMemo<StringRow[]>(() => {
    const lSearch = debouncedSearch.toLowerCase();
    return classified.filter((row) => {
      if (row.value.length < minLength) return false;
      if (activeCategory && (row.category ?? "Plain") !== activeCategory) return false;
      if (lSearch && !row.value.toLowerCase().includes(lSearch)) return false;
      return true;
    });
  }, [classified, debouncedSearch, minLength, activeCategory]);

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

          {/* IOC filter blocks */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
            {(["URL", "IP", "Path", "Registry", "Suspicious", "Base64", "Crypto", "Command"] as const).map((cat) => {
              const count = iocCounts[cat] ?? 0;
              const isActive = activeCategory === cat;
              return (
                <button
                  key={cat}
                  onClick={() => {
                    setActiveCategory(isActive ? null : cat);
                    if (teacherMode?.enabled) {
                      teacherMode.focus({ type: "ioc", iocType: cat.toLowerCase(), value: "" });
                    }
                  }}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    justifyContent: "center",
                    padding: "8px 4px",
                    borderRadius: "var(--radius)",
                    border: `1px solid ${isActive ? "var(--accent)" : count > 0 ? "var(--border)" : "var(--border-subtle)"}`,
                    background: isActive ? "var(--bg-elevated)" : count > 0 ? "var(--bg-surface)" : "transparent",
                    color: isActive ? "var(--text-primary)" : count > 0 ? "var(--text-secondary)" : "var(--text-muted)",
                    cursor: "pointer",
                    transition: "all 150ms ease-out",
                    opacity: count === 0 && !isActive ? 0.5 : 1,
                  }}
                >
                  <span style={{ fontSize: "var(--font-size-lg)", fontWeight: 700, fontFamily: "var(--font-mono)" }}>
                    {count}
                  </span>
                  <span style={{ fontSize: "var(--font-size-xs)", marginTop: 2 }}>
                    {cat}
                  </span>
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
          <p style={{ color: "var(--text-muted)", fontSize: "var(--font-size-base)" }}>{activeCategory ? `No ${activeCategory} strings found` : "No strings match the current filter."}</p>
        </div>
      ) : (
        <VirtualList items={filtered} expandedIdx={expandedIdx} onExpand={setExpandedIdx} onPin={onPin} />
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
        Showing {filtered.length} of {classified.length} strings
      </div>
    </div>
  );
}
