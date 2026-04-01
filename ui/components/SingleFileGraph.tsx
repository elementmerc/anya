/**
 * SingleFileGraph — IOC/Import evidence web for single-file analysis.
 *
 * Builds a 2D force-directed graph from the AnalysisResult showing
 * DLLs, suspicious APIs, IOCs, and behavioral categories as interconnected
 * nodes. Uses the same Obsidian-style physics as BatchGraph.
 */

import { useEffect, useRef, useState, useMemo, useCallback } from "react";
import { RotateCcw } from "lucide-react";
import type { AnalysisResult } from "@/types/analysis";
import AnimatedEmptyState from "@/components/AnimatedEmptyState";

// ── Props ───────────────────────────────────────────────────────────────────

interface Props {
  result: AnalysisResult;
  theme: "dark" | "light";
}

// ── Node/link types for the evidence graph ──────────────────────────────────

interface EvidenceNode {
  id: string;
  label: string;
  type: "file" | "dll" | "api" | "ioc" | "category";
  color: string;
  val: number;
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
}

interface EvidenceLink {
  source: string;
  target: string;
  label: string;
}

// ── Node colours by type ────────────────────────────────────────────────────

const TYPE_COLORS = {
  file: "#22c55e",
  dll: "#a78bfa",
  api: "#f97316",
  ioc: "#ef4444",
  category: "#3b82f6",
};

const IOC_COLORS: Record<string, string> = {
  url: "#ef4444",
  domain: "#f59e0b",
  ipv4: "#f97316",
  ipv6: "#f97316",
  email: "#ec4899",
  registry_key: "#6366f1",
  windows_path: "#6b7280",
  linux_path: "#6b7280",
  base64_blob: "#8b5cf6",
  mutex: "#6b7280",
  script_obfuscation: "#ef4444",
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type FgInstance = any;

// ── Physics (shared with BatchGraph) ────────────────────────────────────────

const PHYSICS = {
  alphaDecay: 0.008,
  alphaMin: 0.001,
  velocityDecay: 0.35,
  warmupTicks: 0,
  cooldownTicks: 999999,
  chargeStrength: -150,
  linkDistance: 50,
  reheatInterval: 4000,
};

// ── Build graph data from AnalysisResult ────────────────────────────────────

function buildGraphData(result: AnalysisResult): { nodes: EvidenceNode[]; links: EvidenceLink[] } {
  const nodes: EvidenceNode[] = [];
  const links: EvidenceLink[] = [];
  const nodeIds = new Set<string>();

  const addNode = (n: EvidenceNode) => { if (!nodeIds.has(n.id)) { nodeIds.add(n.id); nodes.push(n); } };

  // Center: the file itself
  const fileName = result.file_info.path.split(/[\\/]/).pop() ?? "file";
  const fileColor = result.verdict_summary?.includes("MALICIOUS") ? "#ef4444"
    : result.verdict_summary?.includes("SUSPICIOUS") ? "#eab308" : "#22c55e";
  addNode({ id: "file", label: fileName, type: "file", color: fileColor, val: 8 });

  // DLLs
  const libraries = result.pe_analysis?.imports?.libraries ?? result.elf_analysis?.imports?.libraries ?? [];
  for (const lib of libraries) {
    const id = `dll:${lib}`;
    addNode({ id, label: lib, type: "dll", color: TYPE_COLORS.dll, val: 3 });
    links.push({ source: "file", target: id, label: "imports" });
  }

  // Suspicious APIs
  const apis = result.pe_analysis?.imports?.suspicious_apis ?? result.elf_analysis?.imports?.suspicious_functions ?? [];
  const categories = new Set<string>();
  for (const api of apis) {
    const id = `api:${api.name}`;
    addNode({ id, label: api.name, type: "api", color: TYPE_COLORS.api, val: 2 });
    // DLL → API edge (if dll field is populated)
    if (api.dll) {
      const dllId = `dll:${api.dll}`;
      if (nodeIds.has(dllId)) {
        links.push({ source: dllId, target: id, label: "exports" });
      } else {
        links.push({ source: "file", target: id, label: "uses" });
      }
    } else {
      links.push({ source: "file", target: id, label: "uses" });
    }
    // Category hub
    if (api.category) {
      const catId = `cat:${api.category}`;
      categories.add(api.category);
      links.push({ source: id, target: catId, label: "categorised" });
    }
  }

  // Category hub nodes
  for (const cat of categories) {
    addNode({ id: `cat:${cat}`, label: cat, type: "category", color: TYPE_COLORS.category, val: 2.5 });
  }

  // IOCs from classified strings (capped at 50, prioritised by type)
  const classified = result.strings?.classified ?? [];
  const iocEntries: { value: string; type: string }[] = [];
  for (const cs of classified) {
    if (cs.category && cs.category !== "Plain" && !cs.is_benign) {
      iocEntries.push({ value: cs.value, type: cs.category.toLowerCase() });
    }
  }

  // Priority: non-benign first, then by type
  const typePriority: Record<string, number> = { url: 0, ipv4: 1, ipv6: 1, domain: 2, email: 3, script_obfuscation: 4 };
  iocEntries.sort((a, b) => (typePriority[a.type] ?? 9) - (typePriority[b.type] ?? 9));
  const cappedIocs = iocEntries.slice(0, 50);

  for (const ioc of cappedIocs) {
    const truncated = ioc.value.length > 40 ? ioc.value.slice(0, 37) + "..." : ioc.value;
    const id = `ioc:${ioc.value.slice(0, 60)}`;
    if (nodeIds.has(id)) continue;
    addNode({ id, label: truncated, type: "ioc", color: IOC_COLORS[ioc.type] ?? "#ef4444", val: 1.5 });
    links.push({ source: "file", target: id, label: ioc.type });
  }

  return { nodes, links };
}

// ── Component ───────────────────────────────────────────────────────────────

export default function SingleFileGraph({ result, theme }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<FgInstance>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [hoveredLink, setHoveredLink] = useState<EvidenceLink | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [ForceGraph2D, setForceGraph2D] = useState<any>(null);
  const [loadError, setLoadError] = useState(false);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const [legendVisible, setLegendVisible] = useState(true);

  useEffect(() => {
    import("react-force-graph-2d")
      .then((mod) => setForceGraph2D(() => mod.default))
      .catch(() => setLoadError(true));
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      setDimensions({ width: Math.floor(width), height: Math.floor(height) });
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // Alive-when-idle
  useEffect(() => {
    const interval = setInterval(() => fgRef.current?.d3ReheatSimulation?.(), PHYSICS.reheatInterval);
    return () => clearInterval(interval);
  }, []);

  const graphData = useMemo(() => buildGraphData(result), [result]);

  // ── Staggered node-by-node build animation ──────────────────────────────

  const [visibleCount, setVisibleCount] = useState(0);
  const buildTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    setVisibleCount(0);
    if (graphData.nodes.length === 0) return;
    let count = 0;
    buildTimerRef.current = setInterval(() => {
      count++;
      setVisibleCount(count);
      if (count >= graphData.nodes.length) {
        if (buildTimerRef.current) clearInterval(buildTimerRef.current);
      }
    }, 60);
    return () => { if (buildTimerRef.current) clearInterval(buildTimerRef.current); };
  }, [graphData.nodes.length]);

  const stagedData = useMemo(() => {
    if (visibleCount >= graphData.nodes.length) return graphData;
    const visibleNodes = graphData.nodes.slice(0, visibleCount);
    const visibleIds = new Set(visibleNodes.map((n) => n.id));
    const visibleLinks = graphData.links.filter((l) => {
      const s = typeof l.source === "object" ? (l.source as EvidenceNode).id : l.source;
      const t = typeof l.target === "object" ? (l.target as EvidenceNode).id : l.target;
      return visibleIds.has(s) && visibleIds.has(t);
    });
    return { nodes: visibleNodes, links: visibleLinks };
  }, [graphData, visibleCount]);

  // Neighbor sets
  const { neighborNodes, neighborLinks } = useMemo(() => {
    const nodes = new Set<string>();
    const links = new Set<number>();
    const activeId = hoveredNodeId ?? selectedNodeId;
    if (activeId) {
      nodes.add(activeId);
      graphData.links.forEach((l, i) => {
        const s = typeof l.source === "object" ? (l.source as EvidenceNode).id : l.source;
        const t = typeof l.target === "object" ? (l.target as EvidenceNode).id : l.target;
        if (s === activeId || t === activeId) { links.add(i); nodes.add(s); nodes.add(t); }
      });
    }
    return { neighborNodes: nodes, neighborLinks: links };
  }, [hoveredNodeId, selectedNodeId, graphData.links]);

  const isSpotlight = hoveredNodeId !== null || selectedNodeId !== null;

  // Smooth hover transitions
  const nodeAlphas = useRef(new Map<string, number>());
  const LERP_SPEED = 0.15;

  const handleNodeHover = useCallback((node: EvidenceNode | null) => {
    setHoveredNodeId(node?.id ?? null);
    if (containerRef.current) containerRef.current.style.cursor = node ? "pointer" : "grab";
  }, []);

  const handleNodeClick = useCallback((node: EvidenceNode) => {
    setSelectedNodeId((prev) => (prev === node.id ? null : node.id));
    if (fgRef.current?.centerAt && node.x != null && node.y != null) {
      fgRef.current.centerAt(node.x, node.y, 600);
    }
  }, []);

  const handleNodeDrag = useCallback((node: EvidenceNode) => { node.fx = node.x; node.fy = node.y; }, []);
  const handleNodeDragEnd = useCallback((node: EvidenceNode) => { node.fx = undefined; node.fy = undefined; }, []);

  const hasZoomed = useRef(false);
  useEffect(() => { hasZoomed.current = false; }, [result]);

  const bgColor = theme === "dark" ? "#1a1a1a" : "#f5f5f5";

  // Empty state
  if (graphData.nodes.length <= 1) {
    return <AnimatedEmptyState icon="network" title="No evidence graph available" subtitle="This file doesn't have enough DLLs, APIs, or IOCs to build a relationship graph." />;
  }

  if (loadError) return <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)" }}><p>2D graph unavailable.</p></div>;
  if (!ForceGraph2D) return <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)" }}><div style={{ display: "flex", alignItems: "center", gap: 8 }}><div style={{ width: 16, height: 16, borderRadius: "50%", border: "2px solid var(--text-muted)", borderTopColor: "transparent", animation: "spinRing 800ms linear infinite" }} /><span style={{ fontSize: "var(--font-size-sm)" }}>Loading graph engine...</span></div></div>;

  return (
    <div ref={containerRef} style={{ position: "absolute", inset: 0, overflow: "hidden", background: bgColor }}>
      <ForceGraph2D
        ref={fgRef}
        graphData={stagedData}
        width={dimensions.width}
        height={dimensions.height}
        backgroundColor={bgColor}
        d3AlphaDecay={PHYSICS.alphaDecay}
        d3AlphaMin={PHYSICS.alphaMin}
        d3VelocityDecay={PHYSICS.velocityDecay}
        warmupTicks={PHYSICS.warmupTicks}
        cooldownTicks={PHYSICS.cooldownTicks}

        nodeCanvasObject={(node: EvidenceNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
          const isNeighbor = neighborNodes.has(node.id);
          const isHovered = node.id === hoveredNodeId;
          const isSelected = node.id === selectedNodeId;
          const targetAlpha = isSpotlight && !isNeighbor ? 0.08 : 1;
          const prevAlpha = nodeAlphas.current.get(node.id) ?? 1;
          const alpha = prevAlpha + (targetAlpha - prevAlpha) * LERP_SPEED;
          nodeAlphas.current.set(node.id, alpha);
          const scale = isHovered ? 1.5 : (isSelected || isNeighbor) ? 1.2 : 1;
          const baseR = node.val * 1.2;
          const r = baseR * scale / globalScale * 4;

          ctx.globalAlpha = alpha;
          if (isHovered || isSelected) { ctx.shadowColor = node.color; ctx.shadowBlur = 12 / globalScale; }

          ctx.beginPath();
          ctx.arc(node.x!, node.y!, r, 0, Math.PI * 2);
          ctx.fillStyle = node.color;
          ctx.fill();
          ctx.shadowBlur = 0;

          // Label
          if (globalScale > 0.8 || isHovered || isSelected || node.type === "file") {
            const fontSize = Math.max((node.type === "file" ? 12 : 9) / globalScale, 2);
            ctx.font = `${node.type === "file" ? "bold " : ""}${fontSize}px Geist Mono, monospace`;
            ctx.textAlign = "center";
            ctx.textBaseline = "top";
            ctx.fillStyle = theme === "dark" ? `rgba(240,240,240,${alpha})` : `rgba(26,26,26,${alpha})`;
            ctx.fillText(node.label, node.x!, node.y! + r + 2 / globalScale);
          }
          ctx.globalAlpha = 1;
        }}
        nodePointerAreaPaint={(node: EvidenceNode, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
          const r = node.val * 1.2 * 1.5 / globalScale * 4;
          ctx.beginPath(); ctx.arc(node.x!, node.y!, r, 0, Math.PI * 2); ctx.fillStyle = color; ctx.fill();
        }}

        linkCanvasObject={(link: EvidenceLink & { source: EvidenceNode; target: EvidenceNode }, ctx: CanvasRenderingContext2D, globalScale: number) => {
          const sx = link.source.x; const sy = link.source.y;
          const tx = link.target.x; const ty = link.target.y;
          if (sx == null || sy == null || tx == null || ty == null) return;

          const idx = stagedData.links.indexOf(link);
          const isNeighborLink = neighborLinks.has(idx);
          const opacity = isSpotlight ? (isNeighborLink ? 0.7 : 0.03) : 0.2;
          const color = isNeighborLink && isSpotlight
            ? (link.source.type === "ioc" || link.target.type === "ioc" ? "#ef4444" : "#a78bfa")
            : (theme === "dark" ? "#ffffff" : "#000000");

          ctx.globalAlpha = opacity;
          ctx.strokeStyle = color;
          ctx.lineWidth = (isNeighborLink && isSpotlight ? 1.5 : 0.5) / globalScale;
          ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(tx, ty); ctx.stroke();
          ctx.globalAlpha = 1;

          // Edge label on hover
          if (hoveredLink === link && link.label) {
            const mx = (sx + tx) / 2; const my = (sy + ty) / 2;
            const fontSize = Math.max(8 / globalScale, 2);
            ctx.font = `${fontSize}px Geist Mono, monospace`;
            ctx.textAlign = "center"; ctx.textBaseline = "middle";
            const pad = 2 / globalScale;
            const metrics = ctx.measureText(link.label);
            ctx.fillStyle = theme === "dark" ? "rgba(36,36,36,0.9)" : "rgba(255,255,255,0.9)";
            ctx.fillRect(mx - metrics.width / 2 - pad, my - fontSize / 2 - pad, metrics.width + pad * 2, fontSize + pad * 2);
            ctx.fillStyle = theme === "dark" ? "#f0f0f0" : "#1a1a1a";
            ctx.fillText(link.label, mx, my);
          }
        }}
        linkPointerAreaPaint={(link: EvidenceLink & { source: EvidenceNode; target: EvidenceNode }, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
          const sx = link.source.x; const sy = link.source.y;
          const tx = link.target.x; const ty = link.target.y;
          if (sx == null || sy == null || tx == null || ty == null) return;
          ctx.strokeStyle = color; ctx.lineWidth = 6 / globalScale;
          ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(tx, ty); ctx.stroke();
        }}

        onRenderFramePost={() => {
          if (!hasZoomed.current && fgRef.current?.zoomToFit) {
            hasZoomed.current = true;
            setTimeout(() => fgRef.current?.zoomToFit?.(400, 80), 300);
          }
        }}

        onNodeHover={handleNodeHover}
        onNodeClick={handleNodeClick}
        onNodeDrag={handleNodeDrag}
        onNodeDragEnd={handleNodeDragEnd}
        onLinkHover={(link: EvidenceLink | null) => setHoveredLink(link)}
        onBackgroundClick={() => { setSelectedNodeId(null); setHoveredNodeId(null); }}
      />

      {/* Reset camera */}
      <div style={{ position: "absolute", top: 12, right: 12, zIndex: 10 }}>
        <button onClick={() => { fgRef.current?.zoomToFit?.(400, 60); setSelectedNodeId(null); }} title="Reset view" className="ghost-btn"
          style={{ width: 32, height: 32, padding: 0, justifyContent: "center", background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)", backdropFilter: "blur(8px)" }}>
          <RotateCcw size={14} />
        </button>
      </div>

      {/* Legend */}
      {legendVisible && (
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
          <button onClick={() => setLegendVisible(false)}
            style={{ background: "none", border: "none", color: theme === "dark" ? "#555" : "#aaa", cursor: "pointer", padding: "0 0 0 4px", fontSize: 11 }}>×</button>
        </div>
      )}

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
