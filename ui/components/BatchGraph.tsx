import { useEffect, useRef, useState, useMemo, useCallback } from "react";
import { Network, RotateCcw } from "lucide-react";
import type { GraphData, GraphNode, GraphLink } from "@/types/analysis";

// ── Types ────────────────────────────────────────────────────────────────────

interface Props {
  /** Graph data from the backend IPC command */
  data: GraphData;
  /** Current theme — needed for Three.js scene colors */
  theme: "dark" | "light";
  /** Called when user clicks a node (file index in batch mode) */
  onNodeClick?: (nodeId: number) => void;
  /** Compact mode for embedding in OverviewTab */
  compact?: boolean;
}

interface HoveredNode {
  node: GraphNode;
  x: number;
  y: number;
}

// ── Verdict colour mapping ───────────────────────────────────────────────────

const VERDICT_GLOW: Record<string, string> = {
  MALICIOUS:  "#ef4444",
  SUSPICIOUS: "#eab308",
  CLEAN:      "#22c55e",
  UNKNOWN:    "#6b7280",
};

function getNodeGlow(verdict: string): string {
  for (const [key, color] of Object.entries(VERDICT_GLOW)) {
    if (verdict.toUpperCase().includes(key)) return color;
  }
  return "#6b7280";
}

// ── Edge colour based on relationship strength ───────────────────────────────

function getEdgeColor(link: GraphLink, theme: "dark" | "light"): string {
  // Threat edges: red for near-identical/similar, yellow for same family
  if (link.label === "near-identical") return "rgba(239, 68, 68, 0.7)";
  if (link.label === "similar") return "rgba(239, 68, 68, 0.5)";
  if (link.label?.startsWith("same family")) return "rgba(234, 179, 8, 0.6)";
  if (link.label === "related") return "rgba(234, 179, 8, 0.3)";
  // Neutral mesh edges
  if (theme === "dark") return "rgba(255, 255, 255, 0.04)";
  return "rgba(0, 0, 0, 0.06)";
}

function isThreatEdge(link: GraphLink): boolean {
  return link.strength > 0 && link.label !== "mesh";
}

// react-force-graph-3d wraps our types at runtime with x/y/z coords.
// Its generic types are deeply nested — use any for callback params.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type FgInstance = any;

// ── Graph component ──────────────────────────────────────────────────────────

export default function BatchGraph({ data, theme, onNodeClick, compact }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<FgInstance>(null);
  const [hoveredNode, setHoveredNode] = useState<HoveredNode | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<number | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [ForceGraph3D, setForceGraph3D] = useState<any>(null);
  const [loadError, setLoadError] = useState(false);
  const [dimensions, setDimensions] = useState({ width: 600, height: 400 });

  // Lazy-load react-force-graph-3d
  useEffect(() => {
    import("react-force-graph-3d")
      .then((mod) => setForceGraph3D(() => mod.default))
      .catch(() => setLoadError(true));
  }, []);

  // Track container size
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

  // Scene colours
  const bgColor = theme === "dark" ? "#1a1a1a" : "#f5f5f5";

  // Enhance graph data with mesh edges (Obsidian-style constellation)
  const enhancedData = useMemo<GraphData>(() => {
    const existingEdges = new Set(
      data.links.map((l) => {
        const s = typeof l.source === "object" ? (l.source as GraphNode).id : l.source;
        const t = typeof l.target === "object" ? (l.target as GraphNode).id : l.target;
        return `${Math.min(s as number, t as number)}-${Math.max(s as number, t as number)}`;
      })
    );

    const meshLinks: GraphLink[] = [];
    // Connect each node to its 2-3 nearest neighbors (by index proximity) for mesh
    for (let i = 0; i < data.nodes.length; i++) {
      for (let j = i + 1; j <= Math.min(i + 3, data.nodes.length - 1); j++) {
        const key = `${data.nodes[i].id}-${data.nodes[j].id}`;
        if (!existingEdges.has(key)) {
          meshLinks.push({
            source: data.nodes[i].id,
            target: data.nodes[j].id,
            distance: 200,
            strength: 0,
            label: "mesh",
          });
        }
      }
    }

    return {
      nodes: data.nodes,
      links: [...data.links, ...meshLinks],
    };
  }, [data]);

  // Node hover — react-force-graph-3d passes (node, prevNode), no MouseEvent
  // We track mouse position separately for the tooltip
  const mousePos = useRef({ x: 0, y: 0 });
  useEffect(() => {
    const handler = (e: MouseEvent) => { mousePos.current = { x: e.clientX, y: e.clientY }; };
    window.addEventListener("mousemove", handler, { passive: true });
    return () => window.removeEventListener("mousemove", handler);
  }, []);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleNodeHover = useCallback((node: any) => {
    if (node) {
      setHoveredNode({ node: node as GraphNode, x: mousePos.current.x, y: mousePos.current.y });
    } else {
      setHoveredNode(null);
    }
    if (containerRef.current) {
      containerRef.current.style.cursor = node ? "pointer" : "grab";
    }
  }, []);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleNodeClick = useCallback((node: any) => {
    const n = node as GraphNode & { x?: number; y?: number; z?: number };
    setSelectedNodeId((prev) => (prev === n.id ? null : n.id));
    onNodeClick?.(n.id);

    // Zoom to node
    const fg = fgRef.current;
    if (fg?.cameraPosition && n.x !== undefined && n.y !== undefined && n.z !== undefined) {
      const distance = 120;
      fg.cameraPosition(
        { x: n.x, y: n.y, z: (n.z ?? 0) + distance },
        { x: n.x, y: n.y, z: n.z },
        1000,
      );
    }
  }, [onNodeClick]);

  // Highlight connected nodes/links when a node is selected
  const { highlightNodes, highlightLinks } = useMemo(() => {
    const nodes = new Set<number>();
    const links = new Set<number>();
    if (selectedNodeId !== null) {
      nodes.add(selectedNodeId);
      data.links.forEach((link, i) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const src = typeof link.source === "object" ? (link.source as any).id : link.source;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const tgt = typeof link.target === "object" ? (link.target as any).id : link.target;
        if (src === selectedNodeId || tgt === selectedNodeId) {
          links.add(i);
          nodes.add(src as number);
          nodes.add(tgt as number);
        }
      });
    }
    return { highlightNodes: nodes, highlightLinks: links };
  }, [selectedNodeId, data.links]);

  // Camera controls
  const resetCamera = useCallback(() => {
    const fg = fgRef.current;
    if (fg?.zoomToFit) {
      fg.zoomToFit(400, 60);
    }
    setSelectedNodeId(null);
  }, []);

  // Empty state
  if (data.nodes.length === 0) {
    return (
      <div
        style={{
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexDirection: "column",
          gap: 12,
          color: "var(--text-muted)",
        }}
      >
        <Network size={32} style={{ opacity: 0.4 }} />
        <p style={{ fontSize: "var(--font-size-sm)", margin: 0 }}>No relationship data available</p>
      </div>
    );
  }

  // Loading / error state for Three.js
  if (loadError) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)" }}>
        <p style={{ fontSize: "var(--font-size-sm)" }}>3D graph unavailable. Run <code style={{ fontFamily: "var(--font-mono)" }}>npm install</code> to enable.</p>
      </div>
    );
  }

  if (!ForceGraph3D) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div
            style={{
              width: 16, height: 16, borderRadius: "50%",
              border: "2px solid var(--text-muted)", borderTopColor: "transparent",
              animation: "spinRing 800ms linear infinite",
            }}
          />
          <span style={{ fontSize: "var(--font-size-sm)" }}>Loading 3D engine...</span>
        </div>
      </div>
    );
  }

  const graphHeight = compact ? Math.min(dimensions.height, 300) : dimensions.height;

  return (
    <div
      ref={containerRef}
      style={{
        position: "relative",
        width: "100%",
        height: "100%",
        minHeight: compact ? 250 : 400,
        overflow: "hidden",
        borderRadius: "var(--radius)",
        background: bgColor,
      }}
    >
      {/* 3D Graph */}
      <ForceGraph3D
        ref={fgRef}
        graphData={enhancedData}
        width={dimensions.width}
        height={graphHeight}
        backgroundColor={bgColor}
        nodeLabel=""
        nodeVal={(node: GraphNode) =>
          selectedNodeId !== null && highlightNodes.has(node.id) ? 2.5 : node.val || 1.2
        }
        nodeColor={(node: GraphNode) => {
          if (selectedNodeId !== null && !highlightNodes.has(node.id)) {
            return theme === "dark" ? "#333333" : "#cccccc";
          }
          return node.color;
        }}
        nodeOpacity={0.9}
        nodeResolution={20}
        linkWidth={(link: GraphLink) => {
          if (!isThreatEdge(link)) return 0.2;
          const i = enhancedData.links.indexOf(link);
          if (selectedNodeId !== null && !highlightLinks.has(i)) return 0.15;
          return Math.max(0.8, link.strength * 4);
        }}
        linkColor={(link: GraphLink) => {
          if (selectedNodeId !== null) {
            const i = enhancedData.links.indexOf(link);
            if (!highlightLinks.has(i)) {
              return theme === "dark" ? "rgba(255,255,255,0.02)" : "rgba(0,0,0,0.02)";
            }
          }
          return getEdgeColor(link, theme);
        }}
        linkOpacity={0.8}
        linkDirectionalParticles={(link: GraphLink) => {
          if (!isThreatEdge(link)) return 0;
          const i = enhancedData.links.indexOf(link);
          return selectedNodeId !== null && highlightLinks.has(i) ? 3 : 0;
        }}
        linkDirectionalParticleWidth={1.5}
        linkDirectionalParticleSpeed={0.004}
        linkDirectionalParticleColor={() => theme === "dark" ? "#ffffff" : "#000000"}
        onNodeHover={handleNodeHover}
        onNodeClick={handleNodeClick}
        onBackgroundClick={() => setSelectedNodeId(null)}
        onEngineStop={() => {
          const fg = fgRef.current;
          if (fg?.zoomToFit) {
            fg.zoomToFit(400, 80);
          }
        }}
        d3AlphaDecay={0.015}
        d3VelocityDecay={0.25}
        warmupTicks={80}
        cooldownTicks={150}
      />

      {/* Floating tooltip */}
      {hoveredNode && (
        <div
          style={{
            position: "fixed",
            left: hoveredNode.x + 12,
            top: hoveredNode.y - 8,
            pointerEvents: "none",
            zIndex: 1000,
            background: theme === "dark" ? "#242424" : "#ffffff",
            border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`,
            borderRadius: 6,
            padding: "8px 12px",
            boxShadow: theme === "dark"
              ? "0 4px 20px rgba(0,0,0,0.5)"
              : "0 4px 20px rgba(0,0,0,0.15)",
            maxWidth: 280,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <span
              style={{
                width: 8, height: 8, borderRadius: "50%",
                background: hoveredNode.node.color,
                boxShadow: `0 0 6px ${getNodeGlow(hoveredNode.node.verdict)}`,
                flexShrink: 0,
              }}
            />
            <span style={{
              fontSize: 12, fontWeight: 600,
              color: theme === "dark" ? "#f0f0f0" : "#1a1a1a",
              fontFamily: "'Geist Mono', monospace",
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}>
              {hoveredNode.node.name}
            </span>
          </div>
          <div style={{ fontSize: 11, color: theme === "dark" ? "#8a8a8a" : "#6b6b6b" }}>
            {hoveredNode.node.verdict}
          </div>
          {hoveredNode.node.family && (
            <div style={{
              fontSize: 11, marginTop: 2,
              color: theme === "dark" ? "#eab308" : "#ca8a04",
              fontStyle: "italic",
            }}>
              Family: {hoveredNode.node.family}
            </div>
          )}
        </div>
      )}

      {/* Controls overlay */}
      {!compact && (
        <div
          style={{
            position: "absolute",
            top: 12,
            right: 12,
            display: "flex",
            flexDirection: "column",
            gap: 4,
            zIndex: 10,
          }}
        >
          <button
            onClick={resetCamera}
            title="Reset view"
            style={{
              width: 32, height: 32,
              display: "flex", alignItems: "center", justifyContent: "center",
              borderRadius: 6,
              background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)",
              border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`,
              color: theme === "dark" ? "#8a8a8a" : "#6b6b6b",
              cursor: "pointer",
              backdropFilter: "blur(8px)",
              transition: "all 150ms ease-out",
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLButtonElement).style.color = theme === "dark" ? "#f0f0f0" : "#1a1a1a";
              (e.currentTarget as HTMLButtonElement).style.borderColor = theme === "dark" ? "#555" : "#bbb";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLButtonElement).style.color = theme === "dark" ? "#8a8a8a" : "#6b6b6b";
              (e.currentTarget as HTMLButtonElement).style.borderColor = theme === "dark" ? "#3a3a3a" : "#d4d4d4";
            }}
          >
            <RotateCcw size={14} />
          </button>
        </div>
      )}

      {/* Legend */}
      <div
        style={{
          position: "absolute",
          bottom: 12,
          left: 12,
          display: "flex",
          gap: 12,
          padding: "6px 12px",
          borderRadius: 6,
          background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)",
          border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`,
          backdropFilter: "blur(8px)",
          fontSize: 11,
          zIndex: 10,
        }}
      >
        {[
          { color: "#ef4444", label: "Malicious" },
          { color: "#eab308", label: "Suspicious" },
          { color: "#22c55e", label: "Clean" },
        ].map(({ color, label }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{
              width: 8, height: 8, borderRadius: "50%",
              background: color, boxShadow: `0 0 4px ${color}`,
            }} />
            <span style={{ color: theme === "dark" ? "#8a8a8a" : "#6b6b6b" }}>{label}</span>
          </div>
        ))}
      </div>

      {/* Stats badge */}
      <div
        style={{
          position: "absolute",
          bottom: 12,
          right: 12,
          padding: "4px 10px",
          borderRadius: 6,
          background: theme === "dark" ? "rgba(36,36,36,0.85)" : "rgba(255,255,255,0.85)",
          border: `1px solid ${theme === "dark" ? "#3a3a3a" : "#d4d4d4"}`,
          backdropFilter: "blur(8px)",
          fontSize: 11,
          color: theme === "dark" ? "#555" : "#a3a3a3",
          fontFamily: "'Geist Mono', monospace",
          zIndex: 10,
        }}
      >
        {data.nodes.length} nodes &middot; {data.links.filter((l) => l.label !== "mesh").length} connections
      </div>
    </div>
  );
}
