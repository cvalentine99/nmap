/*
 * NetworkTopology — Interactive Network Graph Visualization
 * Spectra Command Dark Theme
 * Shows discovered hosts, subnets, and connections as an interactive graph
 */
import { useState, useRef, useEffect, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Network,
  Server,
  Shield,
  Wifi,
  Globe,
  Router,
  Monitor,
  Database,
  ZoomIn,
  ZoomOut,
  Maximize2,
  AlertTriangle,
  Info,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface TopoNode {
  id: string;
  label: string;
  ip: string;
  type: "gateway" | "server" | "workstation" | "database" | "unknown";
  os?: string;
  ports: number;
  vulns: number;
  status: "up" | "filtered";
  x: number;
  y: number;
  subnet: string;
}

interface TopoEdge {
  from: string;
  to: string;
  latency: string;
  type: "direct" | "routed";
}

const nodeTypeConfig: Record<string, { icon: React.ElementType; color: string; bg: string }> = {
  gateway: { icon: Router, color: "#22d3ee", bg: "rgba(34,211,238,0.1)" },
  server: { icon: Server, color: "#a78bfa", bg: "rgba(167,139,250,0.1)" },
  workstation: { icon: Monitor, color: "#4ade80", bg: "rgba(74,222,128,0.1)" },
  database: { icon: Database, color: "#f59e0b", bg: "rgba(245,158,11,0.1)" },
  unknown: { icon: Globe, color: "#6b7280", bg: "rgba(107,114,128,0.1)" },
};

const nodes: TopoNode[] = [
  { id: "gw", label: "Gateway", ip: "192.168.1.1", type: "gateway", os: "OpenWrt", ports: 3, vulns: 0, status: "up", x: 400, y: 80, subnet: "192.168.1.0/24" },
  { id: "web", label: "Web Server", ip: "192.168.1.25", type: "server", os: "Debian 11", ports: 4, vulns: 4, status: "up", x: 200, y: 220, subnet: "192.168.1.0/24" },
  { id: "db", label: "DB Server", ip: "192.168.1.5", type: "database", os: "Ubuntu 22.04", ports: 3, vulns: 1, status: "up", x: 600, y: 220, subnet: "192.168.1.0/24" },
  { id: "ws1", label: "Workstation 01", ip: "192.168.1.10", type: "workstation", os: "Windows 10", ports: 2, vulns: 0, status: "up", x: 120, y: 380, subnet: "192.168.1.0/24" },
  { id: "dns", label: "DNS Server", ip: "192.168.1.50", type: "server", os: "Linux 5.4", ports: 2, vulns: 0, status: "up", x: 400, y: 380, subnet: "192.168.1.0/24" },
  { id: "ws2", label: "Workstation 02", ip: "192.168.1.15", type: "workstation", os: "macOS 14", ports: 1, vulns: 0, status: "up", x: 680, y: 380, subnet: "192.168.1.0/24" },
  { id: "fw", label: "Firewall", ip: "10.0.0.1", type: "gateway", os: "pfSense", ports: 1, vulns: 0, status: "up", x: 400, y: 500, subnet: "10.0.0.0/8" },
  { id: "ext", label: "External DNS", ip: "8.8.8.8", type: "unknown", os: "Unknown", ports: 1, vulns: 0, status: "up", x: 400, y: 620, subnet: "External" },
];

const edges: TopoEdge[] = [
  { from: "gw", to: "web", latency: "0.5ms", type: "direct" },
  { from: "gw", to: "db", latency: "0.3ms", type: "direct" },
  { from: "gw", to: "ws1", latency: "1.2ms", type: "direct" },
  { from: "gw", to: "dns", latency: "0.4ms", type: "direct" },
  { from: "gw", to: "ws2", latency: "0.8ms", type: "direct" },
  { from: "web", to: "db", latency: "0.2ms", type: "direct" },
  { from: "dns", to: "fw", latency: "0.6ms", type: "direct" },
  { from: "fw", to: "ext", latency: "15ms", type: "routed" },
  { from: "gw", to: "fw", latency: "0.5ms", type: "direct" },
];

export default function NetworkTopology() {
  const [selectedNode, setSelectedNode] = useState<TopoNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const svgRef = useRef<SVGSVGElement>(null);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if ((e.target as SVGElement).closest(".topo-node")) return;
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  }, [isDragging, dragStart]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  const getNodePos = (id: string) => {
    const node = nodes.find((n) => n.id === id);
    return node ? { x: node.x, y: node.y } : { x: 0, y: 0 };
  };

  const subnets = Array.from(new Set(nodes.map((n) => n.subnet)));

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <div className="flex items-center gap-2 mb-1">
          <Network className="w-4 h-4 text-purple-400" />
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-purple-400">
            Topology
          </span>
        </div>
        <h2 className="text-2xl font-bold text-foreground font-[Outfit]">Network Topology</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Interactive visualization of {nodes.length} discovered hosts across {subnets.length} subnets.
        </p>
      </motion.div>

      <div className="flex flex-col xl:flex-row gap-4">
        {/* Graph Canvas */}
        <div className="flex-1 min-w-0">
          <Card className="border-border/50 bg-card/80 overflow-hidden">
            {/* Toolbar */}
            <div className="flex items-center justify-between px-4 py-2 border-b border-border/30">
              <div className="flex items-center gap-2">
                {Object.entries(nodeTypeConfig).map(([type, config]) => {
                  const Icon = config.icon;
                  return (
                    <div key={type} className="flex items-center gap-1 text-[10px] text-muted-foreground">
                      <Icon className="w-3 h-3" style={{ color: config.color }} />
                      <span className="capitalize">{type}</span>
                    </div>
                  );
                })}
              </div>
              <div className="flex items-center gap-1">
                <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setZoom((z) => Math.min(z + 0.2, 2))}>
                  <ZoomIn className="w-3.5 h-3.5" />
                </Button>
                <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setZoom((z) => Math.max(z - 0.2, 0.4))}>
                  <ZoomOut className="w-3.5 h-3.5" />
                </Button>
                <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}>
                  <Maximize2 className="w-3.5 h-3.5" />
                </Button>
                <span className="text-[10px] text-muted-foreground ml-2">{Math.round(zoom * 100)}%</span>
              </div>
            </div>

            {/* SVG Canvas */}
            <div className="relative h-[560px] bg-background/50 overflow-hidden cursor-grab active:cursor-grabbing">
              <svg
                ref={svgRef}
                width="100%"
                height="100%"
                viewBox="0 0 800 700"
                className="select-none"
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseUp}
              >
                <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                  {/* Grid pattern */}
                  <defs>
                    <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
                    </pattern>
                    {/* Glow filter */}
                    <filter id="glow">
                      <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                      <feMerge>
                        <feMergeNode in="coloredBlur" />
                        <feMergeNode in="SourceGraphic" />
                      </feMerge>
                    </filter>
                  </defs>
                  <rect width="800" height="700" fill="url(#grid)" />

                  {/* Subnet backgrounds */}
                  <rect x="60" y="40" width="700" height="430" rx="12" fill="rgba(34,211,238,0.02)" stroke="rgba(34,211,238,0.08)" strokeWidth="1" strokeDasharray="6 4" />
                  <text x="80" y="65" fill="rgba(34,211,238,0.3)" fontSize="10" fontFamily="monospace">192.168.1.0/24</text>

                  <rect x="300" y="470" width="200" height="170" rx="12" fill="rgba(167,139,250,0.02)" stroke="rgba(167,139,250,0.08)" strokeWidth="1" strokeDasharray="6 4" />
                  <text x="320" y="495" fill="rgba(167,139,250,0.3)" fontSize="10" fontFamily="monospace">External</text>

                  {/* Edges */}
                  {edges.map((edge, i) => {
                    const from = getNodePos(edge.from);
                    const to = getNodePos(edge.to);
                    const midX = (from.x + to.x) / 2;
                    const midY = (from.y + to.y) / 2;
                    return (
                      <g key={i}>
                        <line
                          x1={from.x}
                          y1={from.y}
                          x2={to.x}
                          y2={to.y}
                          stroke={edge.type === "routed" ? "rgba(167,139,250,0.3)" : "rgba(34,211,238,0.2)"}
                          strokeWidth="1.5"
                          strokeDasharray={edge.type === "routed" ? "6 4" : "none"}
                        />
                        <text x={midX} y={midY - 6} fill="rgba(255,255,255,0.2)" fontSize="8" textAnchor="middle" fontFamily="monospace">
                          {edge.latency}
                        </text>
                      </g>
                    );
                  })}

                  {/* Nodes */}
                  {nodes.map((node) => {
                    const config = nodeTypeConfig[node.type];
                    const isSelected = selectedNode?.id === node.id;
                    const hasVulns = node.vulns > 0;
                    return (
                      <g
                        key={node.id}
                        className="topo-node cursor-pointer"
                        onClick={() => setSelectedNode(isSelected ? null : node)}
                        transform={`translate(${node.x}, ${node.y})`}
                      >
                        {/* Selection ring */}
                        {isSelected && (
                          <circle r="32" fill="none" stroke={config.color} strokeWidth="2" opacity="0.4">
                            <animate attributeName="r" values="30;35;30" dur="2s" repeatCount="indefinite" />
                            <animate attributeName="opacity" values="0.4;0.1;0.4" dur="2s" repeatCount="indefinite" />
                          </circle>
                        )}

                        {/* Vuln indicator ring */}
                        {hasVulns && (
                          <circle r="28" fill="none" stroke="#ef4444" strokeWidth="1.5" strokeDasharray="4 3" opacity="0.6">
                            <animateTransform attributeName="transform" type="rotate" values="0;360" dur="20s" repeatCount="indefinite" />
                          </circle>
                        )}

                        {/* Node circle */}
                        <circle
                          r="22"
                          fill={config.bg}
                          stroke={isSelected ? config.color : "rgba(255,255,255,0.1)"}
                          strokeWidth={isSelected ? 2 : 1}
                          filter={isSelected ? "url(#glow)" : undefined}
                        />

                        {/* Icon placeholder (using text) */}
                        <text
                          textAnchor="middle"
                          dominantBaseline="central"
                          fill={config.color}
                          fontSize="11"
                          fontFamily="monospace"
                          fontWeight="bold"
                        >
                          {node.type === "gateway" ? "GW" : node.type === "server" ? "SV" : node.type === "workstation" ? "WS" : node.type === "database" ? "DB" : "??"}
                        </text>

                        {/* Label */}
                        <text y="36" textAnchor="middle" fill="rgba(255,255,255,0.7)" fontSize="10" fontFamily="sans-serif">
                          {node.label}
                        </text>
                        <text y="48" textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize="9" fontFamily="monospace">
                          {node.ip}
                        </text>

                        {/* Vuln count badge */}
                        {hasVulns && (
                          <g transform="translate(16, -16)">
                            <circle r="8" fill="#ef4444" />
                            <text textAnchor="middle" dominantBaseline="central" fill="white" fontSize="8" fontWeight="bold">
                              {node.vulns}
                            </text>
                          </g>
                        )}
                      </g>
                    );
                  })}
                </g>
              </svg>
            </div>
          </Card>
        </div>

        {/* Detail Panel */}
        <div className="xl:w-80 shrink-0">
          <AnimatePresence mode="wait">
            {selectedNode ? (
              <motion.div
                key={selectedNode.id}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.3 }}
              >
                <Card className="border-border/50 bg-card/80">
                  <CardHeader className="pb-3">
                    <div className="flex items-center gap-2">
                      {(() => {
                        const Icon = nodeTypeConfig[selectedNode.type].icon;
                        return <Icon className="w-4 h-4" style={{ color: nodeTypeConfig[selectedNode.type].color }} />;
                      })()}
                      <CardTitle className="text-base font-[Outfit]">{selectedNode.label}</CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground">IP Address</p>
                        <p className="text-sm font-mono text-foreground">{selectedNode.ip}</p>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Status</p>
                        <Badge className="bg-green-500/10 text-green-400 border border-green-500/30 text-[10px] mt-0.5">
                          {selectedNode.status}
                        </Badge>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground">OS</p>
                        <p className="text-sm text-foreground">{selectedNode.os}</p>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Type</p>
                        <p className="text-sm text-foreground capitalize">{selectedNode.type}</p>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Subnet</p>
                        <p className="text-sm font-mono text-foreground">{selectedNode.subnet}</p>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Open Ports</p>
                        <p className="text-sm font-mono text-cyan-400">{selectedNode.ports}</p>
                      </div>
                    </div>

                    {selectedNode.vulns > 0 && (
                      <>
                        <Separator className="bg-border/30" />
                        <div className="flex items-center gap-2 p-2.5 rounded-md bg-red-500/5 border border-red-500/20">
                          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                          <div>
                            <p className="text-xs text-red-400 font-medium">{selectedNode.vulns} vulnerabilities detected</p>
                            <p className="text-[10px] text-muted-foreground">View host detail for full report</p>
                          </div>
                        </div>
                      </>
                    )}

                    <Separator className="bg-border/30" />

                    {/* Connections */}
                    <div>
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Connections</p>
                      <div className="space-y-1.5">
                        {edges
                          .filter((e) => e.from === selectedNode.id || e.to === selectedNode.id)
                          .map((edge, i) => {
                            const otherId = edge.from === selectedNode.id ? edge.to : edge.from;
                            const other = nodes.find((n) => n.id === otherId);
                            return (
                              <div key={i} className="flex items-center justify-between text-xs p-1.5 rounded bg-background/50">
                                <div className="flex items-center gap-1.5">
                                  <Wifi className="w-3 h-3 text-cyan-400" />
                                  <span className="text-foreground/80">{other?.label}</span>
                                </div>
                                <span className="text-muted-foreground font-mono">{edge.latency}</span>
                              </div>
                            );
                          })}
                      </div>
                    </div>

                    <Button
                      className="w-full bg-cyan-600 hover:bg-cyan-700 text-white text-xs gap-1.5 mt-2"
                      size="sm"
                      onClick={() => window.location.href = "/host/detail"}
                    >
                      <Server className="w-3 h-3" />
                      View Full Host Detail
                    </Button>
                  </CardContent>
                </Card>
              </motion.div>
            ) : (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.3 }}
              >
                <Card className="border-border/50 bg-card/80">
                  <CardContent className="p-6 text-center">
                    <Info className="w-8 h-8 mx-auto mb-3 text-muted-foreground/30" />
                    <p className="text-sm text-muted-foreground">Click a node to view details</p>
                    <p className="text-[10px] text-muted-foreground/60 mt-1">Drag to pan, scroll to zoom</p>
                  </CardContent>
                </Card>

                {/* Summary stats */}
                <Card className="border-border/50 bg-card/80 mt-4">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-semibold font-[Outfit]">Network Summary</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {subnets.map((subnet) => {
                      const subnetNodes = nodes.filter((n) => n.subnet === subnet);
                      const totalVulns = subnetNodes.reduce((s, n) => s + n.vulns, 0);
                      return (
                        <div key={subnet} className="flex items-center justify-between text-xs p-2 rounded bg-background/50">
                          <div>
                            <p className="font-mono text-foreground">{subnet}</p>
                            <p className="text-[10px] text-muted-foreground">{subnetNodes.length} hosts</p>
                          </div>
                          {totalVulns > 0 && (
                            <Badge className="bg-red-500/10 text-red-400 border border-red-500/30 text-[9px]">
                              {totalVulns} vulns
                            </Badge>
                          )}
                        </div>
                      );
                    })}
                  </CardContent>
                </Card>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
