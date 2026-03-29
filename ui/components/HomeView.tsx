import { useEffect, useState } from "react";
import { Clock, FileSearch, ChevronRight } from "lucide-react";
import { getRecentAnalysisSummaries } from "@/lib/db";
import { getRiskColor } from "@/lib/risk";

interface RecentScan {
  file_path: string;
  file_name: string;
  risk_score: number;
  timestamp: string;
}

interface Props {
  onOpenFile: (path: string) => void;
  isLoading: boolean;
}

function verdictLabel(score: number): string {
  if (score >= 70) return "MALICIOUS";
  if (score >= 40) return "SUSPICIOUS";
  return "CLEAN";
}

function timeAgo(timestamp: string): string {
  const now = Date.now();
  const then = new Date(timestamp).getTime();
  const diff = Math.max(0, now - then);
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(timestamp).toLocaleDateString();
}

export default function HomeView({ onOpenFile, isLoading }: Props) {
  const [recents, setRecents] = useState<RecentScan[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    getRecentAnalysisSummaries(5)
      .then(setRecents)
      .catch(() => {})
      .finally(() => setLoaded(true));
  }, []);

  if (!loaded || isLoading) return null;
  if (recents.length === 0) return null; // No history — let DropZone show

  return (
    <div
      className="animate-in fade-in duration-300"
      style={{
        padding: "24px 32px 0",
        maxWidth: 720,
        margin: "0 auto",
        width: "100%",
      }}
    >
      {/* Recent Scans */}
      <div style={{ marginBottom: 20 }}>
        <div style={{
          display: "flex", alignItems: "center", gap: 8,
          marginBottom: 12,
        }}>
          <Clock size={14} style={{ color: "var(--text-muted)" }} />
          <h3 style={{
            margin: 0, fontSize: "var(--font-size-xs)", fontWeight: 600,
            textTransform: "uppercase", letterSpacing: "0.08em",
            color: "var(--text-muted)",
          }}>
            Recent Scans
          </h3>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {recents.map((scan, i) => {
            const verdict = verdictLabel(scan.risk_score);
            const color = getRiskColor(scan.risk_score);
            return (
              <button
                key={`${scan.file_path}-${i}`}
                onClick={() => onOpenFile(scan.file_path)}
                style={{
                  display: "flex", alignItems: "center", gap: 12,
                  padding: "10px 14px", borderRadius: "var(--radius)",
                  background: "var(--bg-surface)", border: "1px solid var(--border)",
                  cursor: "pointer", textAlign: "left", width: "100%",
                  transition: "background 150ms, border-color 150ms",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "var(--bg-elevated)";
                  e.currentTarget.style.borderColor = "var(--accent)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "var(--bg-surface)";
                  e.currentTarget.style.borderColor = "var(--border)";
                }}
              >
                <FileSearch size={16} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
                <span style={{
                  flex: 1, fontSize: "var(--font-size-sm)", color: "var(--text-primary)",
                  fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}>
                  {scan.file_name}
                </span>
                <span style={{
                  fontSize: "var(--font-size-xs)", fontWeight: 600,
                  padding: "2px 8px", borderRadius: 999,
                  background: `${color}1a`, color, border: `1px solid ${color}44`,
                  flexShrink: 0,
                }}>
                  {verdict}
                </span>
                <span style={{
                  fontSize: "var(--font-size-xs)", color: "var(--text-muted)",
                  minWidth: 60, textAlign: "right", flexShrink: 0,
                }}>
                  {timeAgo(scan.timestamp)}
                </span>
                <ChevronRight size={12} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
