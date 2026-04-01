/**
 * BatchGraph — Obsidian-style 2D force-directed relationship graph.
 *
 * Uses vanilla `force-graph` (kapsule) directly for full control over
 * canvas sizing. fg.width()/fg.height() are called imperatively on resize.
 */

import { useEffect, useRef, useState, useMemo } from "react";
import { RotateCcw } from "lucide-react";
import type { GraphData, GraphNode, GraphLink } from "@/types/analysis";
import AnimatedEmptyState from "@/components/AnimatedEmptyState";

// ── Props ───────────────────────────────────────────────────────────────────

interface Props {
  data: GraphData;
  theme: "dark" | "light";
  onNodeClick?: (nodeId: number) => void;
  searchQuery?: string;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const VERDICT_COLORS: Record<string, string> = {
  MALICIOUS: "#ef4444", SUSPICIOUS: "#eab308", CLEAN: "#22c55e", UNKNOWN: "#6b7280",
};
function getNodeColor(verdict: string): string {
  for (const [key, color] of Object.entries(VERDICT_COLORS)) {
    if (verdict.toUpperCase().includes(key)) return color;
  }
  return "#22c55e";
}
function isThreatEdge(link: GraphLink): boolean { return link.strength > 0 && link.label !== "mesh"; }

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type FgInstance = any;
type RuntimeNode = GraphNode & { x?: number; y?: number; fx?: number; fy?: number };
type RuntimeLink = GraphLink & { source: RuntimeNode; target: RuntimeNode };

const PHYSICS = {
  alphaDecay: 0.008, alphaMin: 0.001, velocityDecay: 0.35,
  warmupTicks: 0, cooldownTicks: 999999, reheatInterval: 4000,
};

// ── Convex hull for cluster halos ───────────────────────────────────────────

function convexHull(points: { x: number; y: number }[]): { x: number; y: number }[] {
  if (points.length < 3) return points;
  const sorted = [...points].sort((a, b) => a.x - b.x || a.y - b.y);
  const cross = (o: { x: number; y: number }, a: { x: number; y: number }, b: { x: number; y: number }) =>
    (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
  const lower: { x: number; y: number }[] = [];
  for (const p of sorted) { while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0) lower.pop(); lower.push(p); }
  const upper: { x: number; y: number }[] = [];
  for (const p of sorted.reverse()) { while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0) upper.pop(); upper.push(p); }
  lower.pop(); upper.pop();
  return lower.concat(upper);
}

// ── Component ───────────────────────────────────────────────────────────────

export default function BatchGraph({ data, theme, onNodeClick, searchQuery }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<FgInstance>(null);
  const [ready, setReady] = useState(false);
  const [legendVisible, setLegendVisible] = useState(true);

  const bgColor = theme === "dark" ? "#1a1a1a" : "#f5f5f5";

  // Interaction state in refs (canvas redraws without React re-renders)
  const hoveredNodeId = useRef<number | null>(null);
  const selectedNodeId = useRef<number | null>(null);
  const hoveredLinkRef = useRef<RuntimeLink | null>(null);
  const nodeAlphas = useRef(new Map<number, number>());
  const emergeStart = useRef(performance.now());
  const hasZoomed = useRef(false);
  const searchRef = useRef(searchQuery);
  searchRef.current = searchQuery;
  const EMERGE_DURATION = 1500;
  const EDGE_DELAY = 400;
  const LERP_SPEED = 0.15;

  // Enhance data with mesh edges
  const enhancedData = useMemo<GraphData>(() => {
    const existingEdges = new Set(
      data.links.map((l) => {
        const s = typeof l.source === "object" ? (l.source as GraphNode).id : l.source;
        const t = typeof l.target === "object" ? (l.target as GraphNode).id : l.target;
        return `${Math.min(s as number, t as number)}-${Math.max(s as number, t as number)}`;
      })
    );
    const meshLinks: GraphLink[] = [];
    for (let i = 0; i < data.nodes.length; i++) {
      for (let j = i + 1; j <= Math.min(i + 3, data.nodes.length - 1); j++) {
        const key = `${data.nodes[i].id}-${data.nodes[j].id}`;
        if (!existingEdges.has(key)) meshLinks.push({ source: data.nodes[i].id, target: data.nodes[j].id, distance: 200, strength: 0, label: "mesh" });
      }
    }
    return { nodes: data.nodes, links: [...data.links, ...meshLinks] };
  }, [data]);

  // Precompute degrees
  const nodeDegrees = useMemo(() => {
    const deg = new Map<number, number>();
    for (const link of enhancedData.links) {
      const s = typeof link.source === "object" ? (link.source as GraphNode).id : link.source as number;
      const t = typeof link.target === "object" ? (link.target as GraphNode).id : link.target as number;
      deg.set(s, (deg.get(s) ?? 0) + 1); deg.set(t, (deg.get(t) ?? 0) + 1);
    }
    return deg;
  }, [enhancedData]);

  // Family clusters for halos
  const familyClusters = useMemo(() => {
    const families = new Map<string, GraphNode[]>();
    for (const node of data.nodes) { if (node.family) { const arr = families.get(node.family) ?? []; arr.push(node); families.set(node.family, arr); } }
    return Array.from(families.entries()).filter(([, nodes]) => nodes.length >= 2);
  }, [data.nodes]);

  // Empty state
  if (data.nodes.length === 0) {
    return <AnimatedEmptyState icon="network" title="No relationship data yet" subtitle="Files will appear as they're analysed. TLSH similarity edges connect related files." />;
  }

  // eslint-disable-next-line react-hooks/rules-of-hooks
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    let fg: FgInstance = null;
    let destroyed = false;

    const graphEl = document.createElement("div");
    graphEl.style.width = "100%";
    graphEl.style.height = "100%";
    el.appendChild(graphEl);

    import("force-graph").then((mod) => {
      if (destroyed) { graphEl.remove(); return; }
      const ForceGraph = mod.default;
      fg = new ForceGraph(graphEl);
      graphRef.current = fg;

      const rect = el.getBoundingClientRect();
      fg.width(Math.floor(rect.width) || window.innerWidth)
        .height(Math.floor(rect.height) || window.innerHeight)
        .backgroundColor(bgColor)
        .d3AlphaDecay(PHYSICS.alphaDecay)
        .d3AlphaMin(PHYSICS.alphaMin)
        .d3VelocityDecay(PHYSICS.velocityDecay)
        .warmupTicks(PHYSICS.warmupTicks)
        .cooldownTicks(PHYSICS.cooldownTicks);

      // ── Node rendering ──────────────────────────────────────────
      fg.nodeCanvasObject((node: RuntimeNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const id = node.id;
        const color = getNodeColor(node.verdict);
        const degree = nodeDegrees.get(id) ?? 0;
        const baseR = 3 + Math.sqrt(degree) * 1.5;
        const activeId = hoveredNodeId.current ?? selectedNodeId.current;

        const neighborSet = new Set<number>();
        if (activeId !== null) {
          neighborSet.add(activeId);
          for (const l of enhancedData.links) {
            const s = typeof l.source === "object" ? (l.source as RuntimeNode).id : l.source as number;
            const t = typeof l.target === "object" ? (l.target as RuntimeNode).id : l.target as number;
            if (s === activeId || t === activeId) { neighborSet.add(s); neighborSet.add(t); }
          }
        }

        const isNeighbor = activeId === null || neighborSet.has(id);
        const isHovered = id === hoveredNodeId.current;
        const isSelected = id === selectedNodeId.current;
        const sq = searchRef.current?.trim().toLowerCase();
        const isSearchMatch = sq ? node.name.toLowerCase().includes(sq) : false;

        let targetAlpha = activeId !== null && !isNeighbor ? 0.08 : 1;
        if (sq && !isSearchMatch) targetAlpha = Math.min(targetAlpha, 0.3);
        const elapsed = performance.now() - emergeStart.current;
        targetAlpha *= Math.min(elapsed / EMERGE_DURATION, 1);
        const prev = nodeAlphas.current.get(id) ?? 0;
        const alpha = prev + (targetAlpha - prev) * LERP_SPEED;
        nodeAlphas.current.set(id, alpha);

        let scale = 1;
        if (isHovered) scale = 1.5;
        else if (isSelected || (activeId !== null && isNeighbor)) scale = 1.2;
        const r = baseR * scale / globalScale * 4;

        ctx.globalAlpha = alpha;
        if (isHovered || isSelected) { ctx.shadowColor = color; ctx.shadowBlur = 12 / globalScale; }
        ctx.beginPath(); ctx.arc(node.x!, node.y!, r, 0, Math.PI * 2);
        ctx.fillStyle = color; ctx.fill();

        if (isSearchMatch && sq) {
          const pulse = 1 + Math.sin(performance.now() * 0.005) * 0.3;
          ctx.beginPath(); ctx.arc(node.x!, node.y!, r * pulse * 1.8, 0, Math.PI * 2);
          ctx.strokeStyle = color; ctx.lineWidth = 1.5 / globalScale; ctx.stroke();
        }
        ctx.shadowBlur = 0;

        if (globalScale > 1.5 || isHovered || isSelected || isSearchMatch) {
          const fontSize = Math.max(10 / globalScale, 2);
          ctx.font = `${fontSize}px Geist Mono, monospace`;
          ctx.textAlign = "center"; ctx.textBaseline = "top";
          ctx.fillStyle = theme === "dark" ? `rgba(240,240,240,${alpha})` : `rgba(26,26,26,${alpha})`;
          ctx.fillText(node.name, node.x!, node.y! + r + 2 / globalScale);
        }
        ctx.globalAlpha = 1;
      });

      fg.nodePointerAreaPaint((node: RuntimeNode, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const degree = nodeDegrees.get(node.id) ?? 0;
        const r = (3 + Math.sqrt(degree) * 1.5) * 1.5 / globalScale * 4;
        ctx.beginPath(); ctx.arc(node.x!, node.y!, r, 0, Math.PI * 2); ctx.fillStyle = color; ctx.fill();
      });

      // ── Link rendering ──────────────────────────────────────────
      fg.linkCanvasObject((link: RuntimeLink, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const sx = link.source.x, sy = link.source.y, tx = link.target.x, ty = link.target.y;
        if (sx == null || sy == null || tx == null || ty == null) return;

        const activeId = hoveredNodeId.current ?? selectedNodeId.current;
        const isActive = activeId !== null;
        const srcId = (link.source as RuntimeNode).id ?? link.source;
        const tgtId = (link.target as RuntimeNode).id ?? link.target;
        const isNeighborLink = isActive && (srcId === activeId || tgtId === activeId);
        const threat = isThreatEdge(link);

        const edgeElapsed = performance.now() - emergeStart.current - EDGE_DELAY;
        const edgeEmerge = Math.max(0, Math.min(edgeElapsed / EMERGE_DURATION, 1));

        let opacity: number;
        let color: string;
        if (threat) {
          if (link.label === "near-identical" || link.label === "similar") color = "#ef4444";
          else color = "#eab308";
          opacity = isActive ? (isNeighborLink ? 0.9 : 0.03) : 0.7;
        } else {
          color = theme === "dark" ? "#ffffff" : "#000000";
          opacity = isActive ? (isNeighborLink ? 0.25 : 0.02) : 0.12;
        }

        ctx.globalAlpha = opacity * edgeEmerge;
        ctx.strokeStyle = color;
        ctx.lineWidth = (threat ? 1.5 : 0.5) / globalScale;
        ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(tx, ty); ctx.stroke();
        ctx.globalAlpha = 1;

        const hl = hoveredLinkRef.current;
        if (hl === link && link.label && link.label !== "mesh") {
          const mx = (sx + tx) / 2, my = (sy + ty) / 2;
          const fontSize = Math.max(9 / globalScale, 2);
          ctx.font = `${fontSize}px Geist Mono, monospace`;
          ctx.textAlign = "center"; ctx.textBaseline = "middle";
          const pad = 3 / globalScale;
          const m = ctx.measureText(link.label);
          ctx.fillStyle = theme === "dark" ? "rgba(36,36,36,0.9)" : "rgba(255,255,255,0.9)";
          ctx.fillRect(mx - m.width / 2 - pad, my - fontSize / 2 - pad, m.width + pad * 2, fontSize + pad * 2);
          ctx.fillStyle = theme === "dark" ? "#f0f0f0" : "#1a1a1a";
          ctx.fillText(link.label, mx, my);
        }
      });

      fg.linkPointerAreaPaint((link: RuntimeLink, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const sx = link.source.x, sy = link.source.y, tx = link.target.x, ty = link.target.y;
        if (sx == null || sy == null || tx == null || ty == null) return;
        ctx.strokeStyle = color; ctx.lineWidth = 6 / globalScale;
        ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(tx, ty); ctx.stroke();
      });

      // ── Cluster halos in post-render ────────────────────────────
      fg.onRenderFramePost((ctx: CanvasRenderingContext2D) => {
        if (!hasZoomed.current) { hasZoomed.current = true; setTimeout(() => fg?.zoomToFit?.(400, 60), 300); }
        for (const [, members] of familyClusters) {
          const points = members.map((n) => { const rn = n as RuntimeNode; return rn.x != null && rn.y != null ? { x: rn.x, y: rn.y } : null; }).filter(Boolean) as { x: number; y: number }[];
          if (points.length < 2) continue;
          const hull = convexHull(points);
          if (hull.length < 2) continue;
          const color = getNodeColor(members[0].verdict);
          const cx = points.reduce((s, p) => s + p.x, 0) / points.length;
          const cy = points.reduce((s, p) => s + p.y, 0) / points.length;
          ctx.globalAlpha = 0.06; ctx.fillStyle = color; ctx.beginPath();
          hull.forEach((p, i) => { const dx = p.x - cx, dy = p.y - cy, dist = Math.sqrt(dx * dx + dy * dy) || 1; const ex = p.x + (dx / dist) * 20, ey = p.y + (dy / dist) * 20; if (i === 0) ctx.moveTo(ex, ey); else ctx.lineTo(ex, ey); });
          ctx.closePath(); ctx.fill(); ctx.globalAlpha = 1;
        }
      });

      // ── Interactions ────────────────────────────────────────────
      fg.onNodeHover((node: RuntimeNode | null) => { hoveredNodeId.current = node?.id ?? null; if (el) el.style.cursor = node ? "pointer" : "grab"; });
      fg.onNodeClick((node: RuntimeNode) => {
        selectedNodeId.current = selectedNodeId.current === node.id ? null : node.id;
        onNodeClick?.(node.id);
        if (node.x != null && node.y != null) { fg.centerAt(node.x, node.y, 600); fg.zoom(3, 600); }
      });
      fg.onNodeDrag((node: RuntimeNode) => { node.fx = node.x; node.fy = node.y; });
      fg.onNodeDragEnd((node: RuntimeNode) => { node.fx = undefined; node.fy = undefined; });
      fg.onLinkHover((link: RuntimeLink | null) => { hoveredLinkRef.current = link; });
      fg.onBackgroundClick(() => { selectedNodeId.current = null; hoveredNodeId.current = null; });

      fg.graphData(enhancedData);
      emergeStart.current = performance.now();
      setReady(true);
    });

    // ── Resize — direct kapsule call ────────────────────────────
    const onResize = () => {
      if (!fg) return;
      const rect = el.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        fg.width(Math.floor(rect.width)).height(Math.floor(rect.height));
      }
    };
    window.addEventListener("resize", onResize);
    const reheat = setInterval(() => fg?.d3ReheatSimulation?.(), PHYSICS.reheatInterval);

    return () => {
      destroyed = true;
      window.removeEventListener("resize", onResize);
      clearInterval(reheat);
      if (fg) { fg.pauseAnimation(); fg._destructor(); }
      graphRef.current = null;
      graphEl.remove();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, theme]);

  return (
    <div ref={containerRef} style={{ position: "relative", flex: 1, minHeight: 0, overflow: "hidden", background: bgColor }}>
      {!ready && (
        <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 16, height: 16, borderRadius: "50%", border: "2px solid var(--text-muted)", borderTopColor: "transparent", animation: "spinRing 800ms linear infinite" }} />
            <span style={{ fontSize: "var(--font-size-sm)" }}>Loading graph engine...</span>
          </div>
        </div>
      )}

      <div style={{ position: "absolute", top: 12, right: 12, zIndex: 10 }}>
        <button onClick={() => { graphRef.current?.zoomToFit?.(400, 60); selectedNodeId.current = null; }} title="Reset view" className="ghost-btn"
          style={{ width: 32, height: 32, padding: 0, justifyContent: "center", background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)", backdropFilter: "blur(8px)" }}>
          <RotateCcw size={14} />
        </button>
      </div>

      {legendVisible && (
        <div style={{
          position: "absolute", bottom: 12, left: 12, display: "flex", gap: 12, padding: "6px 12px",
          borderRadius: 6, background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)",
          border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`, backdropFilter: "blur(8px)",
          fontSize: 11, zIndex: 10, alignItems: "center",
        }}>
          {[{ color: "#ef4444", label: "Malicious" }, { color: "#eab308", label: "Suspicious" }, { color: "#22c55e", label: "Clean" }].map(({ color, label }) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, boxShadow: `0 0 4px ${color}` }} />
              <span style={{ color: theme === "dark" ? "#8a8a8a" : "#6b6b6b" }}>{label}</span>
            </div>
          ))}
          <button onClick={() => setLegendVisible(false)} style={{ background: "none", border: "none", color: theme === "dark" ? "#555" : "#aaa", cursor: "pointer", padding: "0 0 0 4px", fontSize: 11 }}>×</button>
        </div>
      )}

      <div style={{
        position: "absolute", bottom: 12, right: 12, padding: "4px 10px", borderRadius: 6,
        background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)",
        border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`, backdropFilter: "blur(8px)",
        fontSize: 10, fontFamily: "'Geist Mono', monospace", color: theme === "dark" ? "#555" : "#aaa", zIndex: 10,
      }}>
        {data.nodes.length} nodes · {data.links.filter(isThreatEdge).length} relationships
      </div>
    </div>
  );
}
