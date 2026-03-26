import { useRef, useState, useEffect, useCallback } from "react";
import {
  LayoutDashboard,
  Activity,
  GitBranch,
  Layers,
  AlignLeft,
  Shield,
  Crosshair,
} from "lucide-react";
import type { TabName } from "@/types/analysis";

interface TabDef {
  id: TabName;
  label: string;
  Icon: React.ElementType;
}

const DEFAULT_TABS: TabDef[] = [
  { id: "overview",  label: "Overview",  Icon: LayoutDashboard },
  { id: "entropy",   label: "Entropy",   Icon: Activity },
  { id: "imports",   label: "Imports",   Icon: GitBranch },
  { id: "sections",  label: "Sections",  Icon: Layers },
  { id: "strings",   label: "Strings",   Icon: AlignLeft },
  { id: "security",  label: "Security",  Icon: Shield },
  { id: "mitre",     label: "MITRE",     Icon: Crosshair },
];

const TAB_MAP = new Map(DEFAULT_TABS.map((t) => [t.id, t]));

interface Props {
  active: TabName;
  onChange: (tab: TabName) => void;
  badges: (id: TabName) => boolean;
  disabled?: boolean;
  /** Controlled tab order — if provided, tabs render in this order */
  tabOrder?: TabName[];
  onTabOrderChange?: (order: TabName[]) => void;
}

export default function TabNav({ active, onChange, badges, disabled, tabOrder, onTabOrderChange }: Props) {
  const navRef = useRef<HTMLElement>(null);
  const tabRefs = useRef<Map<TabName, HTMLButtonElement>>(new Map());
  const [indicator, setIndicator] = useState<{ left: number; width: number } | null>(null);
  const [dragIdx, setDragIdx] = useState<number | null>(null);
  const [dragOverIdx, setDragOverIdx] = useState<number | null>(null);

  const orderedTabs: TabDef[] = tabOrder
    ? tabOrder.map((id) => TAB_MAP.get(id)).filter(Boolean) as TabDef[]
    : DEFAULT_TABS;

  const updateIndicator = useCallback(() => {
    const nav = navRef.current;
    const btn = tabRefs.current.get(active);
    if (!nav || !btn) return;
    const navRect = nav.getBoundingClientRect();
    const btnRect = btn.getBoundingClientRect();
    setIndicator({
      left: btnRect.left - navRect.left + 8,
      width: btnRect.width - 16,
    });
  }, [active]);

  useEffect(() => {
    updateIndicator();
  }, [updateIndicator, tabOrder]);

  // Update on resize in case tab widths change
  useEffect(() => {
    window.addEventListener("resize", updateIndicator);
    return () => window.removeEventListener("resize", updateIndicator);
  }, [updateIndicator]);

  return (
    <nav
      ref={navRef}
      role="tablist"
      aria-label="Analysis sections"
      data-tour="tab-nav"
      style={{
        position: "relative",
        height: 40,
        flexShrink: 0,
        display: "flex",
        alignItems: "stretch",
        padding: "0 16px",
        background: "var(--bg-surface)",
        borderBottom: "1px solid var(--border-subtle)",
        gap: 0,
        overflowX: "auto",
      }}
    >
      {orderedTabs.map(({ id, label, Icon }, i) => {
        const isActive = active === id;
        const hasBadge = badges(id);
        const isDragOver = dragOverIdx === i && dragIdx !== null && dragIdx !== i;
        return (
          <button
            key={id}
            ref={(el) => { if (el) tabRefs.current.set(id, el); }}
            role="tab"
            aria-selected={isActive}
            aria-controls={`panel-${id}`}
            {...(id === "imports" ? { "data-tour": "tab-imports" } : {})}
            draggable={disabled ? "false" : "true"}
            onDragStart={(e) => {
              setDragIdx(i);
              e.dataTransfer.effectAllowed = "move";
            }}
            onDragOver={(e) => {
              e.preventDefault();
              e.dataTransfer.dropEffect = "move";
              setDragOverIdx(i);
            }}
            onDragLeave={() => {
              if (dragOverIdx === i) setDragOverIdx(null);
            }}
            onDrop={(e) => {
              e.preventDefault();
              if (dragIdx === null || !onTabOrderChange) { setDragIdx(null); setDragOverIdx(null); return; }
              const currentOrder = tabOrder ?? DEFAULT_TABS.map((t) => t.id);
              const newOrder = [...currentOrder];
              const [moved] = newOrder.splice(dragIdx, 1);
              newOrder.splice(i, 0, moved);
              onTabOrderChange(newOrder);
              setDragIdx(null);
              setDragOverIdx(null);
            }}
            onDragEnd={() => {
              setDragIdx(null);
              setDragOverIdx(null);
            }}
            onClick={() => onChange(id)}
            style={{
              position: "relative",
              display: "flex",
              alignItems: "center",
              gap: 6,
              height: "100%",
              padding: "0 16px",
              fontSize: "var(--font-size-sm)",
              fontWeight: isActive ? 500 : 400,
              color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
              background: "transparent",
              border: "none",
              cursor: disabled ? "default" : dragIdx !== null ? "grabbing" : "grab",
              whiteSpace: "nowrap",
              transition: "color 150ms ease-out, padding-left 120ms ease, opacity 150ms ease-out",
              outline: "none",
              paddingLeft: isDragOver ? 28 : 16,
              ...(disabled ? { opacity: 0.35, pointerEvents: "none" as const } : {}),
              ...(dragIdx === i ? { opacity: 0.4 } : {}),
            }}
            onMouseEnter={(e) => {
              if (!isActive) (e.currentTarget as HTMLButtonElement).style.color = "var(--text-primary)";
            }}
            onMouseLeave={(e) => {
              if (!isActive) (e.currentTarget as HTMLButtonElement).style.color = "var(--text-secondary)";
            }}
          >
            <Icon size={14} />
            {/* Hide label below 640px */}
            <span className="hidden sm:inline">{label}</span>

            {/* Warning badge */}
            {hasBadge && (
              <span
                aria-label="has findings"
                style={{
                  position: "absolute",
                  top: 8,
                  right: 6,
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "var(--risk-critical)",
                }}
              />
            )}
          </button>
        );
      })}

      {/* Sliding active underline */}
      {indicator && !disabled && (
        <span
          style={{
            position: "absolute",
            bottom: 0,
            left: indicator.left,
            width: indicator.width,
            height: 2,
            background: "var(--accent)",
            borderRadius: "1px 1px 0 0",
            transition: "left 250ms cubic-bezier(0.4,0,0.2,1), width 250ms cubic-bezier(0.4,0,0.2,1)",
            pointerEvents: "none",
          }}
        />
      )}
    </nav>
  );
}
