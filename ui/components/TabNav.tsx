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
  return (
    <nav
      role="tablist"
      aria-label="Analysis sections"
      style={{
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

            {/* Active underline */}
            {isActive && (
              <span
                style={{
                  position: "absolute",
                  bottom: 0,
                  left: 8,
                  right: 8,
                  height: 2,
                  background: "var(--accent)",
                  borderRadius: "1px 1px 0 0",
                }}
              />
            )}

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
    </nav>
  );
}
