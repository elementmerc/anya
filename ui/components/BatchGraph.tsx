/**
 * BatchGraph — Obsidian-style 2D force-directed relationship graph.
 *
 * Visualizes TLSH similarity between batch-analysed files. Uses canvas 2D
 * rendering via react-force-graph-2d with custom nodeCanvasObject for glow,
 * hover spotlight, cluster halos, and search highlighting.
 *
 * Beyond-Obsidian features: edge labels on hover, threat path tracing,
 * cluster halos by malware family, minimap, and search-to-highlight.
 */

import { useEffect, useRef, useState, useMemo, useCallback } from "react";
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

// ── Verdict colour mapping ──────────────────────────────────────────────────

const VERDICT_COLORS: Record<string, string> = {
  MALICIOUS:  "#ef4444",
  SUSPICIOUS: "#eab308",
  CLEAN:      "#22c55e",
  UNKNOWN:    "#6b7280",
};

function getNodeColor(verdict: string): string {
  for (const [key, color] of Object.entries(VERDICT_COLORS)) {
    if (verdict.toUpperCase().includes(key)) return color;
  }
  return "#22c55e";
}

function isThreatEdge(link: GraphLink): boolean {
  return link.strength > 0 && link.label !== "mesh";
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type FgInstance = any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type RuntimeNode = GraphNode & { x?: number; y?: number; fx?: number; fy?: number; __degree?: number };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type RuntimeLink = GraphLink & { source: any; target: any };

// ── Shared Obsidian-style physics constants ─────────────────────────────────

const PHYSICS = {
  alphaDecay: 0.008,
  alphaMin: 0.001,
  velocityDecay: 0.35,
  warmupTicks: 0,
  cooldownTicks: 999999,
  chargeStrength: -200,
  linkDistance: 40,
  centerStrength: 0.05,
  reheatAlpha: 0.015,
  reheatInterval: 4000,
};

// ── Convex hull for cluster halos ───────────────────────────────────────────

function convexHull(points: { x: number; y: number }[]): { x: number; y: number }[] {
  if (points.length < 3) return points;
  const sorted = [...points].sort((a, b) => a.x - b.x || a.y - b.y);
  const cross = (o: { x: number; y: number }, a: { x: number; y: number }, b: { x: number; y: number }) =>
    (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
  const lower: { x: number; y: number }[] = [];
  for (const p of sorted) {
    while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0) lower.pop();
    lower.push(p);
  }
  const upper: { x: number; y: number }[] = [];
  for (const p of sorted.reverse()) {
    while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0) upper.pop();
    upper.push(p);
  }
  lower.pop();
  upper.pop();
  return lower.concat(upper);
}

// ── Component ───────────────────────────────────────────────────────────────

export default function BatchGraph({ data, theme, onNodeClick, searchQuery }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<FgInstance>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<number | null>(null);
  const [hoveredLink, setHoveredLink] = useState<RuntimeLink | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<number | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [ForceGraph2D, setForceGraph2D] = useState<any>(null);
  const [loadError, setLoadError] = useState(false);
  const [dimensions, setDimensions] = useState({ width: window.innerWidth, height: window.innerHeight });
  const [legendVisible, setLegendVisible] = useState(true);

  // Smooth hover transitions: lerp node alphas toward target each frame
  const nodeAlphas = useRef(new Map<number, number>());
  const LERP_SPEED = 0.15; // ~150ms to reach target at 60fps

  // Lazy-load react-force-graph-2d
  useEffect(() => {
    import("react-force-graph-2d")
      .then((mod) => setForceGraph2D(() => mod.default))
      .catch(() => setLoadError(true));
  }, []);

  // Resize: component remounts on tab switch, so initial size is correct.
  // Only need to handle window resize while the tab is active.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => {
      const rect = el.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        setDimensions({ width: Math.floor(rect.width), height: Math.floor(rect.height) });
      }
    };
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, []);

  // Alive-when-idle: periodic gentle reheat
  useEffect(() => {
    const interval = setInterval(() => {
      fgRef.current?.d3ReheatSimulation?.();
    }, PHYSICS.reheatInterval);
    return () => clearInterval(interval);
  }, []);

  // Zoom-to-fit after initial settle
  const hasZoomed = useRef(false);
  useEffect(() => {
    if (!ForceGraph2D || data.nodes.length === 0) return;
    hasZoomed.current = false;
  }, [ForceGraph2D, data.nodes.length]);

  // ── Constellation emerge: entire graph fades in from darkness ────────────

  const emergeStart = useRef(0);
  const EMERGE_DURATION = 1500; // ms
  const EDGE_DELAY = 400; // edges start fading in after nodes

  useEffect(() => {
    emergeStart.current = performance.now();
  }, [data.nodes.length]);

  // ── Enhance data with mesh edges ──────────────────────────────────────────

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
        if (!existingEdges.has(key)) {
          meshLinks.push({ source: data.nodes[i].id, target: data.nodes[j].id, distance: 200, strength: 0, label: "mesh" });
        }
      }
    }
    return { nodes: data.nodes, links: [...data.links, ...meshLinks] };
  }, [data]);

  // ── Precompute node degrees ───────────────────────────────────────────────

  const nodeDegrees = useMemo(() => {
    const deg = new Map<number, number>();
    for (const link of enhancedData.links) {
      const s = typeof link.source === "object" ? (link.source as GraphNode).id : link.source as number;
      const t = typeof link.target === "object" ? (link.target as GraphNode).id : link.target as number;
      deg.set(s, (deg.get(s) ?? 0) + 1);
      deg.set(t, (deg.get(t) ?? 0) + 1);
    }
    return deg;
  }, [enhancedData]);

  // ── Neighbor sets for hover spotlight ──────────────────────────────────────

  const { neighborNodes, neighborLinks } = useMemo(() => {
    const nodes = new Set<number>();
    const links = new Set<number>();
    const activeId = hoveredNodeId ?? selectedNodeId;
    if (activeId !== null) {
      nodes.add(activeId);
      enhancedData.links.forEach((link, i) => {
        const s = typeof link.source === "object" ? (link.source as RuntimeNode).id : link.source as number;
        const t = typeof link.target === "object" ? (link.target as RuntimeNode).id : link.target as number;
        if (s === activeId || t === activeId) {
          links.add(i);
          nodes.add(s);
          nodes.add(t);
        }
      });
    }
    return { neighborNodes: nodes, neighborLinks: links };
  }, [hoveredNodeId, selectedNodeId, enhancedData.links]);

  // ── Cluster halos (group by family) ───────────────────────────────────────

  const familyClusters = useMemo(() => {
    const families = new Map<string, GraphNode[]>();
    for (const node of data.nodes) {
      if (node.family) {
        const arr = families.get(node.family) ?? [];
        arr.push(node);
        families.set(node.family, arr);
      }
    }
    // Only clusters with 2+ members
    return Array.from(families.entries()).filter(([, nodes]) => nodes.length >= 2);
  }, [data.nodes]);

  // ── Search matching ───────────────────────────────────────────────────────

  const searchMatches = useMemo(() => {
    if (!searchQuery?.trim()) return null;
    const q = searchQuery.toLowerCase();
    return new Set(data.nodes.filter((n) => n.name.toLowerCase().includes(q)).map((n) => n.id));
  }, [searchQuery, data.nodes]);

  // ── Interaction handlers ──────────────────────────────────────────────────

  const handleNodeHover = useCallback((node: RuntimeNode | null) => {
    setHoveredNodeId(node?.id ?? null);
    if (containerRef.current) containerRef.current.style.cursor = node ? "pointer" : "grab";
  }, []);

  const handleNodeClick = useCallback((node: RuntimeNode) => {
    setSelectedNodeId((prev) => (prev === node.id ? null : node.id));
    onNodeClick?.(node.id);
    const fg = fgRef.current;
    if (fg?.centerAt && node.x !== undefined && node.y !== undefined) {
      fg.centerAt(node.x, node.y, 600);
      fg.zoom(3, 600);
    }
  }, [onNodeClick]);

  const handleNodeDrag = useCallback((node: RuntimeNode) => {
    node.fx = node.x;
    node.fy = node.y;
  }, []);

  const handleNodeDragEnd = useCallback((node: RuntimeNode) => {
    node.fx = undefined;
    node.fy = undefined;
  }, []);

  const handleLinkHover = useCallback((link: RuntimeLink | null) => {
    setHoveredLink(link);
  }, []);

  const resetCamera = useCallback(() => {
    fgRef.current?.zoomToFit?.(400, 60);
    setSelectedNodeId(null);
    setHoveredNodeId(null);
  }, []);

  // ── Render timing for search pulse ────────────────────────────────────────
  const animFrame = useRef(0);
  useEffect(() => {
    if (!searchMatches) return;
    let running = true;
    const tick = () => { animFrame.current++; if (running) requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
    return () => { running = false; };
  }, [searchMatches]);

  // ── Scene colours ─────────────────────────────────────────────────────────

  const bgColor = theme === "dark" ? "#1a1a1a" : "#f5f5f5";
  const isSpotlight = hoveredNodeId !== null || selectedNodeId !== null;

  // ── Empty / loading / error states ────────────────────────────────────────

  if (data.nodes.length === 0) {
    return <AnimatedEmptyState icon="network" title="No relationship data yet" subtitle="Files will appear as they're analysed. TLSH similarity edges connect related files." />;
  }
  if (loadError) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)" }}>
        <p style={{ fontSize: "var(--font-size-sm)" }}>2D graph unavailable.</p>
      </div>
    );
  }
  if (!ForceGraph2D) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 16, height: 16, borderRadius: "50%", border: "2px solid var(--text-muted)", borderTopColor: "transparent", animation: "spinRing 800ms linear infinite" }} />
          <span style={{ fontSize: "var(--font-size-sm)" }}>Loading graph engine...</span>
        </div>
      </div>
    );
  }

  return (
    <div ref={containerRef} style={{ flex: 1, minHeight: 0, overflow: "hidden", background: bgColor, position: "relative" }}>
      <ForceGraph2D
        ref={fgRef}
        graphData={enhancedData}
        width={dimensions.width}
        height={dimensions.height}
        backgroundColor={bgColor}

        // ── Obsidian physics ────────────────────────────────────────
        d3AlphaDecay={PHYSICS.alphaDecay}
        d3AlphaMin={PHYSICS.alphaMin}
        d3VelocityDecay={PHYSICS.velocityDecay}
        warmupTicks={PHYSICS.warmupTicks}
        cooldownTicks={PHYSICS.cooldownTicks}

        // ── Node rendering (canvas) ─────────────────────────────────
        nodeCanvasObject={(node: RuntimeNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
          const id = node.id;
          const color = getNodeColor(node.verdict);
          const degree = nodeDegrees.get(id) ?? 0;
          const baseR = 3 + Math.sqrt(degree) * 1.5;

          // Spotlight logic with smooth alpha interpolation
          const isNeighbor = neighborNodes.has(id);
          const isHovered = id === hoveredNodeId;
          const isSelected = id === selectedNodeId;
          const isSearchMatch = searchMatches?.has(id) ?? false;

          let targetAlpha = 1;
          let scale = 1;
          if (isSpotlight && !isNeighbor) targetAlpha = 0.08;
          if (isHovered) scale = 1.5;
          else if (isSelected || isNeighbor) scale = 1.2;
          if (searchMatches && !isSearchMatch) targetAlpha = Math.min(targetAlpha, 0.3);

          // Constellation emerge: clamp target alpha by global emerge progress
          const elapsed = performance.now() - emergeStart.current;
          const emergeAlpha = Math.min(elapsed / EMERGE_DURATION, 1);
          targetAlpha *= emergeAlpha;

          // Lerp alpha for smooth transitions
          const prevAlpha = nodeAlphas.current.get(id) ?? 0;
          const alpha = prevAlpha + (targetAlpha - prevAlpha) * LERP_SPEED;
          nodeAlphas.current.set(id, alpha);

          const r = baseR * scale / globalScale * 4;
          ctx.globalAlpha = alpha;

          // Glow on hover/selected
          if (isHovered || isSelected) {
            ctx.shadowColor = color;
            ctx.shadowBlur = 12 / globalScale;
          }

          // Node circle
          ctx.beginPath();
          ctx.arc(node.x!, node.y!, r, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.fill();

          // Search pulse ring
          if (isSearchMatch && searchMatches) {
            const pulse = 1 + Math.sin(animFrame.current * 0.08) * 0.3;
            ctx.beginPath();
            ctx.arc(node.x!, node.y!, r * pulse * 1.8, 0, Math.PI * 2);
            ctx.strokeStyle = color;
            ctx.lineWidth = 1.5 / globalScale;
            ctx.stroke();
          }

          ctx.shadowBlur = 0;
          ctx.globalAlpha = 1;

          // Label (show when zoomed in enough or node is interacted with)
          if (globalScale > 1.5 || isHovered || isSelected || isSearchMatch) {
            const fontSize = Math.max(10 / globalScale, 2);
            ctx.font = `${fontSize}px Geist Mono, monospace`;
            ctx.textAlign = "center";
            ctx.textBaseline = "top";
            ctx.fillStyle = theme === "dark" ? `rgba(240,240,240,${alpha})` : `rgba(26,26,26,${alpha})`;
            ctx.fillText(node.name, node.x!, node.y! + r + 2 / globalScale);
          }
        }}
        nodePointerAreaPaint={(node: RuntimeNode, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
          const degree = nodeDegrees.get(node.id) ?? 0;
          const r = (3 + Math.sqrt(degree) * 1.5) * 1.5 / globalScale * 4;
          ctx.beginPath();
          ctx.arc(node.x!, node.y!, r, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.fill();
        }}

        // ── Link rendering ──────────────────────────────────────────
        linkCanvasObject={(link: RuntimeLink, ctx: CanvasRenderingContext2D, globalScale: number) => {
          const sx = link.source.x;
          const sy = link.source.y;
          const tx = link.target.x;
          const ty = link.target.y;
          if (sx == null || sy == null || tx == null || ty == null) return;

          const idx = enhancedData.links.indexOf(link);
          const isThreat = isThreatEdge(link);
          const isNeighborLink = neighborLinks.has(idx);

          // Edge color and opacity
          const edgeElapsed = performance.now() - emergeStart.current - EDGE_DELAY;
          const edgeEmerge = Math.max(0, Math.min(edgeElapsed / EMERGE_DURATION, 1));

          let opacity: number;
          let color: string;
          if (isThreat) {
            if (link.label === "near-identical") color = "#ef4444";
            else if (link.label === "similar") color = "#ef4444";
            else if (link.label?.startsWith("same family")) color = "#eab308";
            else color = "#eab308";
            opacity = isSpotlight ? (isNeighborLink ? 0.9 : 0.03) : 0.7;
          } else {
            color = theme === "dark" ? "#ffffff" : "#000000";
            opacity = isSpotlight ? (isNeighborLink ? 0.25 : 0.02) : 0.12;
          }

          ctx.globalAlpha = opacity * edgeEmerge;
          ctx.strokeStyle = color;
          ctx.lineWidth = (isThreat ? 1.5 : 0.5) / globalScale;
          ctx.beginPath();
          ctx.moveTo(sx, sy);
          ctx.lineTo(tx, ty);
          ctx.stroke();
          ctx.globalAlpha = 1;

          // Edge label on hover
          if (hoveredLink === link && link.label) {
            const mx = (sx + tx) / 2;
            const my = (sy + ty) / 2;
            const fontSize = Math.max(9 / globalScale, 2);
            ctx.font = `${fontSize}px Geist Mono, monospace`;
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            const text = link.label === "mesh" ? "" : link.label ?? "";
            if (text) {
              const pad = 3 / globalScale;
              const metrics = ctx.measureText(text);
              ctx.fillStyle = theme === "dark" ? "rgba(36,36,36,0.9)" : "rgba(255,255,255,0.9)";
              ctx.fillRect(mx - metrics.width / 2 - pad, my - fontSize / 2 - pad, metrics.width + pad * 2, fontSize + pad * 2);
              ctx.fillStyle = theme === "dark" ? "#f0f0f0" : "#1a1a1a";
              ctx.fillText(text, mx, my);
            }
          }
        }}
        linkPointerAreaPaint={(link: RuntimeLink, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
          const sx = link.source.x;
          const sy = link.source.y;
          const tx = link.target.x;
          const ty = link.target.y;
          if (sx == null || sy == null || tx == null || ty == null) return;
          ctx.strokeStyle = color;
          ctx.lineWidth = 6 / globalScale;
          ctx.beginPath();
          ctx.moveTo(sx, sy);
          ctx.lineTo(tx, ty);
          ctx.stroke();
        }}

        // ── Post-render: cluster halos ──────────────────────────────
        onRenderFramePost={(ctx: CanvasRenderingContext2D) => {
          if (!hasZoomed.current && fgRef.current?.zoomToFit) {
            hasZoomed.current = true;
            setTimeout(() => fgRef.current?.zoomToFit?.(400, 60), 300);
          }
          // Cluster halos
          for (const [, members] of familyClusters) {
            const points = members
              .map((n) => {
                const rn = n as RuntimeNode;
                return rn.x != null && rn.y != null ? { x: rn.x, y: rn.y } : null;
              })
              .filter(Boolean) as { x: number; y: number }[];
            if (points.length < 2) continue;

            const hull = convexHull(points);
            if (hull.length < 2) continue;

            const color = getNodeColor(members[0].verdict);
            ctx.globalAlpha = 0.06;
            ctx.fillStyle = color;
            ctx.beginPath();
            // Expand hull outward by padding
            const cx = points.reduce((s, p) => s + p.x, 0) / points.length;
            const cy = points.reduce((s, p) => s + p.y, 0) / points.length;
            const pad = 20;
            hull.forEach((p, i) => {
              const dx = p.x - cx;
              const dy = p.y - cy;
              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
              const ex = p.x + (dx / dist) * pad;
              const ey = p.y + (dy / dist) * pad;
              if (i === 0) ctx.moveTo(ex, ey);
              else ctx.lineTo(ex, ey);
            });
            ctx.closePath();
            ctx.fill();
            ctx.globalAlpha = 1;
          }
        }}

        // ── Interaction callbacks ────────────────────────────────────
        onNodeHover={handleNodeHover}
        onNodeClick={handleNodeClick}
        onNodeDrag={handleNodeDrag}
        onNodeDragEnd={handleNodeDragEnd}
        onLinkHover={handleLinkHover}
        onBackgroundClick={() => { setSelectedNodeId(null); setHoveredNodeId(null); }}
      />

      {/* Reset camera button */}
      <div style={{ position: "absolute", top: 12, right: 12, zIndex: 10 }}>
        <button
          onClick={resetCamera}
          title="Reset view"
          className="ghost-btn"
          style={{ width: 32, height: 32, padding: 0, justifyContent: "center", background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)", backdropFilter: "blur(8px)" }}
        >
          <RotateCcw size={14} />
        </button>
      </div>

      {/* Legend */}
      {legendVisible && (
        <div
          style={{
            position: "absolute", bottom: 12, left: 12, display: "flex", gap: 12, padding: "6px 12px",
            borderRadius: 6, background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)",
            border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`, backdropFilter: "blur(8px)",
            fontSize: 11, zIndex: 10, alignItems: "center",
          }}
        >
          {[
            { color: "#ef4444", label: "Malicious" },
            { color: "#eab308", label: "Suspicious" },
            { color: "#22c55e", label: "Clean" },
          ].map(({ color, label }) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, boxShadow: `0 0 4px ${color}` }} />
              <span style={{ color: theme === "dark" ? "#8a8a8a" : "#6b6b6b" }}>{label}</span>
            </div>
          ))}
          <button
            onClick={() => setLegendVisible(false)}
            style={{ background: "none", border: "none", color: theme === "dark" ? "#555" : "#aaa", cursor: "pointer", padding: "0 0 0 4px", fontSize: 11 }}
          >
            ×
          </button>
        </div>
      )}

      {/* Stats badge */}
      <div
        style={{
          position: "absolute", bottom: 12, right: 12, padding: "4px 10px", borderRadius: 6,
          background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)",
          border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`, backdropFilter: "blur(8px)",
          fontSize: 10, fontFamily: "'Geist Mono', monospace",
          color: theme === "dark" ? "#555" : "#aaa", zIndex: 10,
        }}
      >
        {data.nodes.length} nodes · {data.links.filter(isThreatEdge).length} relationships
      </div>
    </div>
  );
}
