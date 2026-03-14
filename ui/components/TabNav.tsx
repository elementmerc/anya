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

const TABS: TabDef[] = [
  { id: "overview",  label: "Overview",  Icon: LayoutDashboard },
  { id: "entropy",   label: "Entropy",   Icon: Activity },
  { id: "imports",   label: "Imports",   Icon: GitBranch },
  { id: "sections",  label: "Sections",  Icon: Layers },
  { id: "strings",   label: "Strings",   Icon: AlignLeft },
  { id: "security",  label: "Security",  Icon: Shield },
  { id: "mitre",     label: "MITRE",     Icon: Crosshair },
];

interface Props {
  active: TabName;
  onChange: (tab: TabName) => void;
  badges: (id: TabName) => boolean;
}

export default function TabNav({ active, onChange, badges }: Props) {
  const navRef = useRef<HTMLElement>(null);
  const tabRefs = useRef<Map<TabName, HTMLButtonElement>>(new Map());
  const [indicator, setIndicator] = useState<{ left: number; width: number } | null>(null);

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
  }, [updateIndicator]);

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
      {TABS.map(({ id, label, Icon }) => {
        const isActive = active === id;
        const hasBadge = badges(id);
        return (
          <button
            key={id}
            ref={(el) => { if (el) tabRefs.current.set(id, el); }}
            role="tab"
            aria-selected={isActive}
            aria-controls={`panel-${id}`}
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
              cursor: "pointer",
              whiteSpace: "nowrap",
              transition: "color 150ms ease-out",
              outline: "none",
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
      {indicator && (
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
