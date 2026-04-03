/**
 * SingleFileGraph — IOC/Import evidence web for single-file analysis.
 *
 * Uses vanilla `force-graph` (kapsule) directly instead of react-force-graph-2d.
 * This gives us direct access to fg.width()/fg.height() for responsive resizing
 * without fighting React's prop reconciliation.
 */

import { useEffect, useRef, useState, useMemo } from "react";
import { RotateCcw, GraduationCap, ChevronDown, ChevronUp } from "lucide-react";
import type { AnalysisResult } from "@/types/analysis";
import AnimatedEmptyState from "@/components/AnimatedEmptyState";
import GraphSettingsPanel, { type GraphSettings, DEFAULT_SETTINGS } from "@/components/GraphSettingsPanel";
import { useTeacherFocus } from "@/hooks/useTeacherMode";

// ── Types ───────────────────────────────────────────────────────────────────

interface Props {
  result: AnalysisResult;
  theme: "dark" | "light";
}

interface EvidenceNode {
  id: string;
  label: string;
  type: "file" | "dll" | "api" | "ioc" | "category";
  group?: string;
  color: string;
  val: number;
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
}

interface EvidenceLink {
  source: string | EvidenceNode;
  target: string | EvidenceNode;
  label: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

const TYPE_COLORS = {
  file: "#22c55e",
  dll: "#a78bfa",
  api: "#f97316",
  ioc: "#ef4444",
  category: "#3b82f6",
};

const IOC_COLORS: Record<string, string> = {
  url: "#ef4444", domain: "#f59e0b", ipv4: "#f97316", ipv6: "#f97316",
  email: "#ec4899", registry_key: "#6366f1", windows_path: "#6b7280",
  linux_path: "#6b7280", base64_blob: "#8b5cf6", mutex: "#6b7280",
  script_obfuscation: "#ef4444",
};

const PHYSICS = {
  alphaDecay: 0.008,
  alphaMin: 0.001,
  velocityDecay: 0.35,
  warmupTicks: 0,
  cooldownTicks: 999999,
  reheatInterval: 4000,
};

// ── Build graph data ────────────────────────────────────────────────────────

function buildGraphData(result: AnalysisResult): { nodes: EvidenceNode[]; links: EvidenceLink[] } {
  const nodes: EvidenceNode[] = [];
  const links: EvidenceLink[] = [];
  const nodeIds = new Set<string>();
  const addNode = (n: EvidenceNode) => { if (!nodeIds.has(n.id)) { nodeIds.add(n.id); nodes.push(n); } };

  const fileName = result.file_info.path.split(/[\\/]/).pop() ?? "file";
  const fileColor = result.verdict_summary?.includes("MALICIOUS") ? "#ef4444"
    : result.verdict_summary?.includes("SUSPICIOUS") ? "#eab308" : "#22c55e";
  addNode({ id: "file", label: fileName, type: "file", color: fileColor, val: 8 });

  const libraries = result.pe_analysis?.imports?.libraries ?? result.elf_analysis?.imports?.libraries ?? [];
  for (const lib of libraries) {
    const id = `dll:${lib}`;
    addNode({ id, label: lib, type: "dll", color: TYPE_COLORS.dll, val: 3 });
    links.push({ source: "file", target: id, label: "imports" });
  }

  const apis = result.pe_analysis?.imports?.suspicious_apis ?? result.elf_analysis?.imports?.suspicious_functions ?? [];
  const categories = new Set<string>();
  for (const api of apis) {
    const id = `api:${api.name}`;
    addNode({ id, label: api.name, type: "api", group: api.category, color: TYPE_COLORS.api, val: 2 });
    if (api.dll && nodeIds.has(`dll:${api.dll}`)) {
      links.push({ source: `dll:${api.dll}`, target: id, label: "exports" });
    } else {
      links.push({ source: "file", target: id, label: "uses" });
    }
    if (api.category) { categories.add(api.category); links.push({ source: id, target: `cat:${api.category}`, label: "categorised" }); }
  }
  for (const cat of categories) addNode({ id: `cat:${cat}`, label: cat, type: "category", color: TYPE_COLORS.category, val: 2.5 });

  const classified = result.strings?.classified ?? [];
  const iocEntries: { value: string; type: string }[] = [];
  for (const cs of classified) {
    if (cs.category && cs.category !== "Plain" && !cs.is_benign) iocEntries.push({ value: cs.value, type: cs.category.toLowerCase() });
  }
  const typePriority: Record<string, number> = { url: 0, ipv4: 1, ipv6: 1, domain: 2, email: 3, script_obfuscation: 4 };
  iocEntries.sort((a, b) => (typePriority[a.type] ?? 9) - (typePriority[b.type] ?? 9));
  for (const ioc of iocEntries.slice(0, 50)) {
    const truncated = ioc.value.length > 40 ? ioc.value.slice(0, 37) + "..." : ioc.value;
    const id = `ioc:${ioc.value.slice(0, 60)}`;
    if (nodeIds.has(id)) continue;
    addNode({ id, label: truncated, type: "ioc", group: ioc.type, color: IOC_COLORS[ioc.type] ?? "#ef4444", val: 1.5 });
    links.push({ source: "file", target: id, label: ioc.type });
  }

  return { nodes, links };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type FgInstance = any;

// ── Component ───────────────────────────────────────────────────────────────

export default function SingleFileGraph({ result, theme }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<FgInstance>(null);
  const [ready, setReady] = useState(false);
  const [graphSettings, setGraphSettings] = useState<GraphSettings>({ ...DEFAULT_SETTINGS });
  const { teacherEnabled, focus: teacherFocus } = useTeacherFocus();
  const [teacherExpanded, setTeacherExpanded] = useState(true);
  const settingsRef = useRef(graphSettings);
  settingsRef.current = graphSettings;
  const teacherFocusRef = useRef(teacherFocus);
  teacherFocusRef.current = teacherFocus;
  const teacherEnabledRef = useRef(teacherEnabled);
  teacherEnabledRef.current = teacherEnabled;

  const graphData = useMemo(() => buildGraphData(result), [result]);
  const bgColor = theme === "dark" ? "#1a1a1a" : "#f5f5f5";
  const themeRef = useRef(theme);
  themeRef.current = theme;

  // Update background color on theme change without remounting
  useEffect(() => {
    const fg = graphRef.current;
    if (fg?.backgroundColor) fg.backgroundColor(bgColor);
  }, [bgColor]);

  // Apply settings changes to the live graph instance
  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    fg.d3Force("charge")?.strength(graphSettings.repulsion);
    if (graphSettings.frozen) {
      // Kill simulation energy but keep render loop alive (so drag repaints)
      fg.d3AlphaDecay(1);
    } else {
      // Unfreeze: restore physics, clear all pinned nodes, reheat
      fg.d3AlphaDecay(0.008);
      const data = fg.graphData();
      if (data?.nodes) {
        for (const node of data.nodes) { node.fx = undefined; node.fy = undefined; }
      }
      fg.d3ReheatSimulation();
    }
  }, [graphSettings.repulsion, graphSettings.frozen]);

  // Force a repaint when visual-only settings change (labels, node size, link thickness)
  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    if (settingsRef.current.frozen) {
      // Temporarily restore physics just enough to trigger a redraw cycle
      fg.d3AlphaDecay(0.5);
      fg.d3ReheatSimulation();
      // Re-freeze after a few frames have rendered
      setTimeout(() => { if (settingsRef.current.frozen) fg.d3AlphaDecay(1); }, 100);
    }
  }, [graphSettings.showLabels, graphSettings.nodeSize, graphSettings.linkThickness]);

  // Interaction state stored in refs (no re-renders needed for canvas drawing)
  const hoveredNodeId = useRef<string | null>(null);
  const selectedNodeId = useRef<string | null>(null);
  const hoveredLinkRef = useRef<EvidenceLink | null>(null);
  const nodeAlphas = useRef(new Map<string, number>());
  const emergeStart = useRef(performance.now());
  const hasZoomed = useRef(false);
  const EMERGE_DURATION = 1500;
  const EDGE_DELAY = 400;
  const LERP_SPEED = 0.15;

  // Empty state
  if (graphData.nodes.length <= 1) {
    return <AnimatedEmptyState icon="network" title="No evidence graph available" subtitle="This file doesn't have enough DLLs, APIs, or IOCs to build a relationship graph." />;
  }

  // ── Mount vanilla force-graph + handle resize ─────────────────────────────
  // eslint-disable-next-line react-hooks/rules-of-hooks
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    let fg: FgInstance = null;
    let destroyed = false;

    // Create a child div for force-graph to own (it wipes innerHTML)
    const graphEl = document.createElement("div");
    graphEl.style.width = "100%";
    graphEl.style.height = "100%";
    el.appendChild(graphEl);

    import("force-graph").then((mod) => {
      if (destroyed) { graphEl.remove(); return; }
      const ForceGraph = mod.default;
      fg = new ForceGraph(graphEl);
      graphRef.current = fg;

      // ── Size ────────────────────────────────────────────────────
      const rect = el.getBoundingClientRect();
      fg.width(Math.floor(rect.width) || window.innerWidth)
        .height(Math.floor(rect.height) || window.innerHeight);

      // ── Physics ─────────────────────────────────────────────────
      fg.d3AlphaDecay(PHYSICS.alphaDecay)
        .d3AlphaMin(PHYSICS.alphaMin)
        .d3VelocityDecay(PHYSICS.velocityDecay)
        .warmupTicks(PHYSICS.warmupTicks)
        .cooldownTicks(PHYSICS.cooldownTicks)
        .backgroundColor(bgColor);

      // ── Node rendering ──────────────────────────────────────────
      fg.nodeCanvasObject((node: EvidenceNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const isActive = hoveredNodeId.current ?? selectedNodeId.current;
        const neighborSet = new Set<string>();
        if (isActive) {
          neighborSet.add(isActive);
          for (const l of graphData.links) {
            const s = typeof l.source === "object" ? (l.source as EvidenceNode).id : l.source;
            const t = typeof l.target === "object" ? (l.target as EvidenceNode).id : l.target;
            if (s === isActive || t === isActive) { neighborSet.add(s as string); neighborSet.add(t as string); }
          }
        }
        const isNeighbor = !isActive || neighborSet.has(node.id);
        const isHovered = node.id === hoveredNodeId.current;
        const isSelected = node.id === selectedNodeId.current;

        let targetAlpha = isActive && !isNeighbor ? 0.08 : 1;
        const elapsed = performance.now() - emergeStart.current;
        targetAlpha *= Math.min(elapsed / EMERGE_DURATION, 1);
        const prev = nodeAlphas.current.get(node.id) ?? 0;
        const alpha = prev + (targetAlpha - prev) * LERP_SPEED;
        nodeAlphas.current.set(node.id, alpha);

        const scale = isHovered ? 1.5 : (isSelected || (isActive && isNeighbor)) ? 1.2 : 1;
        const r = node.val * 1.2 * scale * settingsRef.current.nodeSize / globalScale * 4;

        ctx.globalAlpha = alpha;
        if (isHovered || isSelected) { ctx.shadowColor = node.color; ctx.shadowBlur = 12 / globalScale; }
        ctx.beginPath();
        ctx.arc(node.x!, node.y!, r, 0, Math.PI * 2);
        ctx.fillStyle = node.color;
        ctx.fill();
        ctx.shadowBlur = 0;

        if (settingsRef.current.showLabels && (globalScale > 0.8 || isHovered || isSelected || node.type === "file")) {
          const fontSize = Math.max((node.type === "file" ? 12 : 9) / globalScale, 2);
          ctx.font = `${node.type === "file" ? "bold " : ""}${fontSize}px Geist Mono, monospace`;
          ctx.textAlign = "center";
          ctx.textBaseline = "top";
          ctx.fillStyle = themeRef.current === "dark" ? `rgba(240,240,240,${alpha})` : `rgba(26,26,26,${alpha})`;
          ctx.fillText(node.label, node.x!, node.y! + r + 2 / globalScale);
        }
        ctx.globalAlpha = 1;
      });

      fg.nodePointerAreaPaint((node: EvidenceNode, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const r = node.val * 1.2 * 1.5 / globalScale * 4;
        ctx.beginPath(); ctx.arc(node.x!, node.y!, r, 0, Math.PI * 2); ctx.fillStyle = color; ctx.fill();
      });

      // ── Link rendering ──────────────────────────────────────────
      fg.linkCanvasObject((link: EvidenceLink & { source: EvidenceNode; target: EvidenceNode }, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const sx = link.source.x, sy = link.source.y, tx = link.target.x, ty = link.target.y;
        if (sx == null || sy == null || tx == null || ty == null) return;

        const isActive = hoveredNodeId.current ?? selectedNodeId.current;
        let isNeighborLink = false;
        if (isActive) {
          const s = typeof link.source === "object" ? link.source.id : link.source;
          const t = typeof link.target === "object" ? link.target.id : link.target;
          isNeighborLink = s === isActive || t === isActive;
        }
        const edgeElapsed = performance.now() - emergeStart.current - EDGE_DELAY;
        const edgeEmerge = Math.max(0, Math.min(edgeElapsed / EMERGE_DURATION, 1));
        const opacity = isActive ? (isNeighborLink ? 0.7 : 0.03) : 0.2;
        const color = isNeighborLink && isActive
          ? (link.source.type === "ioc" || link.target.type === "ioc" ? "#ef4444" : "#a78bfa")
          : (themeRef.current === "dark" ? "#ffffff" : "#000000");

        ctx.globalAlpha = opacity * edgeEmerge;
        ctx.strokeStyle = color;
        ctx.lineWidth = (isNeighborLink && isActive ? 1.5 : 0.5) * settingsRef.current.linkThickness / globalScale;
        ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(tx, ty); ctx.stroke();
        ctx.globalAlpha = 1;

        // Edge label on hover
        const hl = hoveredLinkRef.current;
        if (hl && hl === link && link.label) {
          const mx = (sx + tx) / 2, my = (sy + ty) / 2;
          const fontSize = Math.max(8 / globalScale, 2);
          ctx.font = `${fontSize}px Geist Mono, monospace`;
          ctx.textAlign = "center"; ctx.textBaseline = "middle";
          const pad = 2 / globalScale;
          const m = ctx.measureText(link.label);
          ctx.fillStyle = themeRef.current === "dark" ? "rgba(36,36,36,0.9)" : "rgba(255,255,255,0.9)";
          ctx.fillRect(mx - m.width / 2 - pad, my - fontSize / 2 - pad, m.width + pad * 2, fontSize + pad * 2);
          ctx.fillStyle = themeRef.current === "dark" ? "#f0f0f0" : "#1a1a1a";
          ctx.fillText(link.label, mx, my);
        }
      });

      fg.linkPointerAreaPaint((link: EvidenceLink & { source: EvidenceNode; target: EvidenceNode }, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const sx = link.source.x, sy = link.source.y, tx = link.target.x, ty = link.target.y;
        if (sx == null || sy == null || tx == null || ty == null) return;
        ctx.strokeStyle = color; ctx.lineWidth = 6 / globalScale;
        ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(tx, ty); ctx.stroke();
      });

      // ── Interactions ────────────────────────────────────────────
      fg.onNodeHover((node: EvidenceNode | null) => {
        hoveredNodeId.current = node?.id ?? null;
        if (el) el.style.cursor = node ? "pointer" : "grab";
      });
      fg.onNodeClick((node: EvidenceNode) => {
        selectedNodeId.current = selectedNodeId.current === node.id ? null : node.id;
        if (node.x != null && node.y != null) fg.centerAt(node.x, node.y, 600);

        // Teacher Mode: focus the sidebar on the clicked node
        if (teacherEnabledRef.current && node.type !== "file") {
          const focus = teacherFocusRef.current;
          if (node.type === "dll") {
            focus({ type: "dll", name: node.label });
          } else if (node.type === "api") {
            focus({ type: "api", name: node.label, category: node.group ?? undefined });
          } else if (node.type === "ioc") {
            focus({ type: "ioc", iocType: node.group ?? "unknown", value: node.label });
          } else if (node.type === "category") {
            focus({ type: "category", name: node.label });
          }
        }
      });
      fg.onNodeDrag((node: EvidenceNode) => { node.fx = node.x; node.fy = node.y; });
      fg.onNodeDragEnd((node: EvidenceNode) => {
        // When frozen, keep node pinned where dropped; when live, release it
        if (!settingsRef.current.frozen) { node.fx = undefined; node.fy = undefined; }
      });
      fg.onLinkHover((link: EvidenceLink | null) => { hoveredLinkRef.current = link; });
      fg.onBackgroundClick(() => { selectedNodeId.current = null; hoveredNodeId.current = null; });

      // ── Zoom to fit after settle ────────────────────────────────
      fg.onRenderFramePost(() => {
        if (!hasZoomed.current) {
          hasZoomed.current = true;
          setTimeout(() => fg?.zoomToFit?.(400, 80), 300);
        }
      });

      // ── Load data ───────────────────────────────────────────────
      fg.graphData(graphData);
      emergeStart.current = performance.now();
      setReady(true);
    });

    // ── Resize handler — direct kapsule call ────────────────────
    const onResize = () => {
      if (!fg) return;
      const rect = el.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        fg.width(Math.floor(rect.width)).height(Math.floor(rect.height));
      }
    };
    window.addEventListener("resize", onResize);

    // ── Alive-when-idle ─────────────────────────────────────────
    const reheat = setInterval(() => { if (!settingsRef.current.frozen) fg?.d3ReheatSimulation?.(); }, PHYSICS.reheatInterval);

    return () => {
      destroyed = true;
      window.removeEventListener("resize", onResize);
      clearInterval(reheat);
      if (fg) { fg.pauseAnimation(); fg._destructor(); }
      graphRef.current = null;
      graphEl.remove();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result]); // theme excluded — uses ref via bgColor closure to avoid remount

  return (
    <div ref={containerRef} style={{ position: "relative", flex: 1, minHeight: 0, overflow: "hidden", background: bgColor }}>
      {/* Loading state before force-graph mounts */}
      {!ready && (
        <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 16, height: 16, borderRadius: "50%", border: "2px solid var(--text-muted)", borderTopColor: "transparent", animation: "spinRing 800ms linear infinite" }} />
            <span style={{ fontSize: "var(--font-size-sm)" }}>Loading graph engine...</span>
          </div>
        </div>
      )}

      {/* Reset camera */}
      <div style={{ position: "absolute", top: 12, right: 12, zIndex: 10 }}>
        <button onClick={() => { graphRef.current?.zoomToFit?.(400, 60); selectedNodeId.current = null; }} title="Reset view" className="ghost-btn"
          style={{ width: 32, height: 32, padding: 0, justifyContent: "center", background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)", backdropFilter: "blur(8px)" }}>
          <RotateCcw size={14} />
        </button>
      </div>

      {/* Settings panel */}
      <GraphSettingsPanel settings={graphSettings} onChange={setGraphSettings} theme={theme} />

      {/* Teacher Mode guidance */}
      {teacherEnabled && (
        <div style={{
          position: "absolute", top: 12, left: 12, zIndex: 10, maxWidth: 320,
          background: theme === "dark" ? "rgba(36,36,36,0.92)" : "rgba(255,255,255,0.92)",
          border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`,
          borderRadius: 8, backdropFilter: "blur(8px)", overflow: "hidden",
        }}>
          <button
            onClick={() => setTeacherExpanded(v => !v)}
            style={{
              display: "flex", alignItems: "center", gap: 6, width: "100%",
              padding: "8px 12px", background: "none", border: "none",
              color: "var(--text-primary)", cursor: "pointer", fontSize: 12, fontWeight: 600,
            }}
          >
            <GraduationCap size={14} style={{ color: "rgb(129,140,248)", flexShrink: 0 }} />
            What am I looking at?
            {teacherExpanded ? <ChevronUp size={12} style={{ marginLeft: "auto" }} /> : <ChevronDown size={12} style={{ marginLeft: "auto" }} />}
          </button>
          {teacherExpanded && (
            <div style={{ padding: "0 12px 10px", fontSize: 12, lineHeight: 1.6, color: "var(--text-secondary)" }}>
              <p style={{ margin: "0 0 6px" }}>The <strong>centre node</strong> is your file. Surrounding nodes show what it connects to.</p>
              <p style={{ margin: "0 0 6px" }}><span style={{ color: TYPE_COLORS.dll }}>Purple nodes</span> are DLLs (libraries the file imports). <span style={{ color: TYPE_COLORS.api }}>Orange nodes</span> are specific API functions it calls. <span style={{ color: TYPE_COLORS.ioc }}>Red nodes</span> are indicators of compromise (suspicious URLs, IPs, domains). <span style={{ color: TYPE_COLORS.category }}>Blue nodes</span> are behaviour categories.</p>
              <p style={{ margin: 0 }}><strong>Click any node</strong> with Teacher Mode on to learn what it does. A file with many red IOC nodes and process manipulation APIs is far more suspicious than one that only imports standard system libraries.</p>
            </div>
          )}
        </div>
      )}

      {/* Legend (permanent) */}
      <div style={{
        position: "absolute", bottom: 12, left: 12, display: "flex", gap: 10, padding: "6px 12px",
        borderRadius: 6, background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)",
        border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`, backdropFilter: "blur(8px)",
        fontSize: 11, zIndex: 10, alignItems: "center",
      }}>
        {[
          { color: TYPE_COLORS.dll, label: "DLL" },
          { color: TYPE_COLORS.api, label: "API" },
          { color: TYPE_COLORS.ioc, label: "IOC" },
          { color: TYPE_COLORS.category, label: "Category" },
        ].map(({ color, label }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: color }} />
            <span style={{ color: theme === "dark" ? "#8a8a8a" : "#6b6b6b" }}>{label}</span>
          </div>
        ))}
      </div>

      {/* Stats */}
      <div style={{
        position: "absolute", bottom: 12, right: 12, padding: "4px 10px", borderRadius: 6,
        background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)",
        border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`, backdropFilter: "blur(8px)",
        fontSize: 10, fontFamily: "'Geist Mono', monospace", color: theme === "dark" ? "#555" : "#aaa", zIndex: 10,
      }}>
        {graphData.nodes.length} nodes · {graphData.links.length} edges
      </div>
    </div>
  );
}
