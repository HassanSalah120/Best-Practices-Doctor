import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, GitBranch, Network, Route, SquareFunction, Workflow } from "lucide-react";

import { ApiClient } from "@/lib/api";
import type {
  ProjectExplainerResponse,
  ProjectMapEdge,
  ProjectMapNode,
  ProjectMapResponse,
} from "@/types/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface ProjectIntelligenceMapPanelProps {
  jobId: string;
}

type GuidedMode = "api_flow" | "unused_code" | "big_components";

type TreeItem = {
  id?: string;
  label?: string;
  type?: string;
  children?: TreeItem[];
  [key: string]: unknown;
};

const GRAPH_VIEWBOX_WIDTH = 980;
const GRAPH_VIEWBOX_HEIGHT = 520;

function nodeColor(type: string): string {
  const t = (type || "").toLowerCase();
  if (t === "route") return "#22d3ee";
  if (t === "controller") return "#38bdf8";
  if (t === "service") return "#34d399";
  if (t === "model") return "#f59e0b";
  if (t === "method") return "#a78bfa";
  if (t === "page") return "#f472b6";
  if (t === "component") return "#fb7185";
  if (t === "hook") return "#facc15";
  if (t === "file") return "#94a3b8";
  return "#cbd5e1";
}

function getTreeItems(source: unknown): TreeItem[] {
  if (!Array.isArray(source)) return [];
  return source as TreeItem[];
}

export const ProjectIntelligenceMapPanel: React.FC<ProjectIntelligenceMapPanelProps> = ({ jobId }) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mapData, setMapData] = useState<ProjectMapResponse | null>(null);
  const [explainerResponse, setExplainerResponse] = useState<ProjectExplainerResponse | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [guidedMode, setGuidedMode] = useState<GuidedMode>("api_flow");

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const [mapPayload, explainerPayload] = await Promise.all([
          ApiClient.getProjectMap(jobId),
          ApiClient.getProjectExplainer(jobId, { include_reverse: true }),
        ]);
        if (cancelled) return;
        setMapData(mapPayload);
        setExplainerResponse(explainerPayload);
        const firstRoute = mapPayload.nodes.find((n) => n.type === "route");
        setSelectedNodeId(firstRoute?.id ?? mapPayload.nodes[0]?.id ?? null);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load project intelligence map");
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [jobId]);

  const nodeIndex = useMemo(() => {
    const out: Record<string, ProjectMapNode> = {};
    for (const n of mapData?.nodes ?? []) out[n.id] = n;
    return out;
  }, [mapData?.nodes]);

  const edgeIndex = useMemo(() => {
    const outgoing: Record<string, ProjectMapEdge[]> = {};
    const incoming: Record<string, ProjectMapEdge[]> = {};
    for (const e of mapData?.edges ?? []) {
      (outgoing[e.from] ??= []).push(e);
      (incoming[e.to] ??= []).push(e);
    }
    return { outgoing, incoming };
  }, [mapData?.edges]);

  const selectedNode = selectedNodeId ? nodeIndex[selectedNodeId] : null;

  const selectedDependency = useMemo(() => {
    if (!selectedNodeId) return null;
    return explainerResponse?.explainer?.function_dependency_index?.[selectedNodeId] ?? null;
  }, [explainerResponse?.explainer?.function_dependency_index, selectedNodeId]);

  const warningByNode = useMemo(() => {
    const out: Record<string, Array<{ title: string; severity: string; description: string }>> = {};
    const warnings = mapData?.insights?.warnings ?? [];
    for (const warning of warnings) {
      const nodeId = String(warning.node_id || "");
      if (!nodeId) continue;
      (out[nodeId] ??= []).push({
        title: String(warning.title || ""),
        severity: String(warning.severity || ""),
        description: String(warning.description || ""),
      });
    }
    return out;
  }, [mapData?.insights?.warnings]);

  const subgraph = useMemo(() => {
    const allNodes = mapData?.nodes ?? [];
    const allEdges = mapData?.edges ?? [];
    if (!allNodes.length) return { nodes: [] as ProjectMapNode[], edges: [] as ProjectMapEdge[] };

    const root = selectedNodeId || allNodes[0].id;
    const visited = new Set<string>();
    const queue: Array<{ id: string; depth: number }> = [{ id: root, depth: 0 }];

    while (queue.length > 0 && visited.size < 80) {
      const current = queue.shift()!;
      if (visited.has(current.id)) continue;
      visited.add(current.id);
      if (current.depth >= 1) continue;
      for (const e of edgeIndex.outgoing[current.id] ?? []) {
        if (!visited.has(e.to)) queue.push({ id: e.to, depth: current.depth + 1 });
      }
      for (const e of edgeIndex.incoming[current.id] ?? []) {
        if (!visited.has(e.from)) queue.push({ id: e.from, depth: current.depth + 1 });
      }
    }

    const nodes = allNodes.filter((n) => visited.has(n.id));
    const edges = allEdges.filter((e) => visited.has(e.from) && visited.has(e.to));
    return { nodes, edges };
  }, [edgeIndex.incoming, edgeIndex.outgoing, mapData?.edges, mapData?.nodes, selectedNodeId]);

  const graphLayout = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    const nodes = subgraph.nodes;
    if (!nodes.length) return positions;
    const selected = selectedNodeId && nodes.some((n) => n.id === selectedNodeId) ? selectedNodeId : nodes[0].id;
    const centerX = GRAPH_VIEWBOX_WIDTH / 2;
    const centerY = GRAPH_VIEWBOX_HEIGHT / 2;
    positions[selected] = { x: centerX, y: centerY };

    const others = nodes.filter((n) => n.id !== selected);
    const radius = Math.max(120, Math.min(230, 70 + others.length * 5));
    others.forEach((node, index) => {
      const angle = (2 * Math.PI * index) / Math.max(1, others.length);
      positions[node.id] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
      };
    });
    return positions;
  }, [selectedNodeId, subgraph.nodes]);

  const endpointFlows = explainerResponse?.explainer?.endpoint_flows ?? [];
  const componentFlows = explainerResponse?.explainer?.component_flows ?? [];
  const narrative = explainerResponse?.explainer?.narrative_sections ?? [];

  const biggestComponents = useMemo(() => {
    const candidates = (mapData?.nodes ?? [])
      .filter((n) => n.type === "component" || n.type === "page")
      .map((n) => ({
        id: n.id,
        label: n.label,
        loc: Number((n.metadata?.loc as number | undefined) ?? 0),
      }))
      .sort((a, b) => b.loc - a.loc || a.label.localeCompare(b.label));
    return candidates.slice(0, 8);
  }, [mapData?.nodes]);

  const deadCodePreview = useMemo(() => {
    const dead = mapData?.insights?.dead_code ?? {};
    const methods = Array.isArray(dead.methods) ? dead.methods : [];
    const controllers = Array.isArray(dead.controllers) ? dead.controllers : [];
    const components = Array.isArray(dead.components) ? dead.components : [];
    return { methods, controllers, components };
  }, [mapData?.insights?.dead_code]);

  const renderTreeItems = (items: TreeItem[]) => {
    if (!items.length) {
      return <div className="text-xs text-white/45">No items</div>;
    }
    return (
      <div className="space-y-1">
        {items.map((item) => {
          const id = typeof item.id === "string" ? item.id : "";
          const label = String(item.label ?? id ?? "Unnamed");
          const children = Array.isArray(item.children) ? item.children : [];
          return (
            <div key={`${id}:${label}`} className="rounded-lg border border-white/10 bg-white/[0.03] p-2">
              <button
                onClick={() => id && setSelectedNodeId(id)}
                className={cn(
                  "w-full text-left text-xs font-medium truncate transition-colors",
                  id === selectedNodeId ? "text-cyan-300" : "text-white/80 hover:text-white",
                )}
                title={label}
              >
                {label}
              </button>
              {children.length > 0 ? (
                <div className="mt-2 space-y-1 border-l border-white/10 pl-2">
                  {children.slice(0, 8).map((child) => {
                    const childId = String(child.id ?? "");
                    const childLabel = String(child.label ?? childId);
                    return (
                      <button
                        key={`${childId}:${childLabel}`}
                        onClick={() => childId && setSelectedNodeId(childId)}
                        className={cn(
                          "block w-full truncate text-left text-[11px] transition-colors",
                          childId === selectedNodeId ? "text-cyan-300" : "text-white/65 hover:text-white",
                        )}
                        title={childLabel}
                      >
                        {childLabel}
                      </button>
                    );
                  })}
                  {children.length > 8 ? (
                    <div className="text-[10px] text-white/45">+{children.length - 8} more</div>
                  ) : null}
                </div>
              ) : null}
            </div>
          );
        })}
      </div>
    );
  };

  if (loading) {
    return (
      <Card className="border-white/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="w-4 h-4 text-muted-foreground" />
            Project Intelligence Map
          </CardTitle>
          <CardDescription>Building architecture map and deep explainer...</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  if (error || !mapData || !explainerResponse) {
    return (
      <Card className="border-red-400/20 bg-red-400/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-red-100">
            <AlertTriangle className="w-4 h-4" />
            Project Intelligence Map
          </CardTitle>
          <CardDescription className="text-red-100/80">{error || "Failed to load project map."}</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const backendTree = mapData.hierarchy?.backend ?? {};
  const frontendTree = mapData.hierarchy?.frontend ?? {};

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
      <Card className="xl:col-span-3 border-white/10">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-muted-foreground" />
            Structure Tree
          </CardTitle>
          <CardDescription>Routes, controllers, services, models, pages, components, hooks.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 max-h-[70vh] overflow-auto pr-2">
          <div>
            <div className="text-xs font-semibold text-white/70 mb-2">Backend / Routes</div>
            {renderTreeItems(getTreeItems((backendTree as Record<string, unknown>).routes))}
          </div>
          <div>
            <div className="text-xs font-semibold text-white/70 mb-2">Backend / Controllers</div>
            {renderTreeItems(getTreeItems((backendTree as Record<string, unknown>).controllers))}
          </div>
          <div>
            <div className="text-xs font-semibold text-white/70 mb-2">Backend / Services</div>
            {renderTreeItems(getTreeItems((backendTree as Record<string, unknown>).services))}
          </div>
          <div>
            <div className="text-xs font-semibold text-white/70 mb-2">Frontend / Pages</div>
            {renderTreeItems(getTreeItems((frontendTree as Record<string, unknown>).pages))}
          </div>
          <div>
            <div className="text-xs font-semibold text-white/70 mb-2">Frontend / Components</div>
            {renderTreeItems(getTreeItems((frontendTree as Record<string, unknown>).components))}
          </div>
        </CardContent>
      </Card>

      <Card className="xl:col-span-5 border-white/10">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Network className="w-4 h-4 text-muted-foreground" />
            Focused Relation Graph
          </CardTitle>
          <CardDescription>
            Lazy subgraph view (1-hop, up to 80 nodes). Click any node in tree or panel to refocus.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="rounded-xl border border-white/10 bg-slate-950/50 p-2">
            <svg viewBox={`0 0 ${GRAPH_VIEWBOX_WIDTH} ${GRAPH_VIEWBOX_HEIGHT}`} className="w-full h-[420px]">
              {subgraph.edges.map((edge) => {
                const src = graphLayout[edge.from];
                const dst = graphLayout[edge.to];
                if (!src || !dst) return null;
                return (
                  <line
                    key={`${edge.from}:${edge.to}:${edge.type}`}
                    x1={src.x}
                    y1={src.y}
                    x2={dst.x}
                    y2={dst.y}
                    stroke="rgba(148,163,184,0.35)"
                    strokeWidth={1.5}
                  />
                );
              })}
              {subgraph.nodes.map((node) => {
                const pos = graphLayout[node.id];
                if (!pos) return null;
                const selected = node.id === selectedNodeId;
                return (
                  <g key={node.id} transform={`translate(${pos.x}, ${pos.y})`} onClick={() => setSelectedNodeId(node.id)}>
                    <circle
                      r={selected ? 16 : 12}
                      fill={nodeColor(node.type)}
                      stroke={selected ? "rgba(255,255,255,0.9)" : "rgba(255,255,255,0.35)"}
                      strokeWidth={selected ? 2 : 1}
                    />
                    <text
                      y={selected ? 30 : 24}
                      textAnchor="middle"
                      fontSize={10}
                      fill="rgba(255,255,255,0.9)"
                      style={{ pointerEvents: "none" }}
                    >
                      {node.label.slice(0, 22)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
            <div className="text-xs uppercase tracking-[0.2em] text-white/45 mb-2">Node Inspector</div>
            {selectedNode ? (
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="bg-white/5 border-white/10">{selectedNode.type}</Badge>
                  <span className="font-medium">{selectedNode.label}</span>
                </div>
                {selectedNode.file ? <div className="text-xs text-white/60 font-mono">{selectedNode.file}</div> : null}
                <div className="text-xs text-white/60">
                  Outgoing: {(edgeIndex.outgoing[selectedNode.id] ?? []).length} | Incoming: {(edgeIndex.incoming[selectedNode.id] ?? []).length}
                </div>
                {(warningByNode[selectedNode.id] ?? []).slice(0, 3).map((w) => (
                  <div key={`${selectedNode.id}:${w.title}`} className="rounded-lg border border-amber-400/20 bg-amber-400/10 px-2 py-1 text-xs">
                    <div className="font-semibold text-amber-100">{w.title} ({w.severity})</div>
                    <div className="text-amber-50/80">{w.description}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-sm text-white/55">Select a node to inspect dependencies and warnings.</div>
            )}
          </div>
        </CardContent>
      </Card>

      <Card className="xl:col-span-4 border-white/10">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Workflow className="w-4 h-4 text-muted-foreground" />
            Project Explainer
          </CardTitle>
          <CardDescription>
            Deep static explainer for architecture, endpoint flows, and function/component dependencies.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 max-h-[70vh] overflow-auto pr-2">
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant={guidedMode === "api_flow" ? "default" : "outline"} onClick={() => setGuidedMode("api_flow")}>
              <Route className="w-3.5 h-3.5 mr-1.5" />
              Show API flow
            </Button>
            <Button size="sm" variant={guidedMode === "unused_code" ? "default" : "outline"} onClick={() => setGuidedMode("unused_code")}>
              <AlertTriangle className="w-3.5 h-3.5 mr-1.5" />
              Show unused code
            </Button>
            <Button size="sm" variant={guidedMode === "big_components" ? "default" : "outline"} onClick={() => setGuidedMode("big_components")}>
              <SquareFunction className="w-3.5 h-3.5 mr-1.5" />
              Show biggest components
            </Button>
          </div>

          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
            <div className="text-xs uppercase tracking-[0.2em] text-white/45 mb-2">How this project is structured</div>
            {narrative.slice(0, 1).map((section) => (
              <div key={section.title} className="text-sm text-white/75">{section.body}</div>
            ))}
          </div>

          {guidedMode === "api_flow" ? (
            <div className="space-y-2">
              <div className="text-xs uppercase tracking-[0.2em] text-white/45">API flows (GET/POST/...)</div>
              {(endpointFlows ?? []).slice(0, 12).map((flow) => (
                <button
                  key={`${flow.entry_id}:${flow.start_id}`}
                  onClick={() => setSelectedNodeId(flow.entry_id || flow.start_id || null)}
                  className="w-full rounded-lg border border-white/10 bg-white/[0.03] p-2 text-left hover:bg-white/[0.06] transition-colors"
                >
                  <div className="text-sm font-medium text-white/85">
                    {flow.method} {flow.uri}
                  </div>
                  <div className="text-[11px] text-white/55">
                    {flow.controller}::{flow.action} • depth {flow.depth}
                    {flow.truncated ? " • truncated" : ""}
                  </div>
                </button>
              ))}
              {(endpointFlows ?? []).length === 0 ? <div className="text-xs text-white/50">No endpoint flows available.</div> : null}
            </div>
          ) : null}

          {guidedMode === "unused_code" ? (
            <div className="space-y-2">
              <div className="text-xs uppercase tracking-[0.2em] text-white/45">Potentially unused code</div>
              <div className="rounded-lg border border-white/10 bg-white/[0.03] p-2">
                <div className="text-xs text-white/70 mb-1">Methods ({deadCodePreview.methods.length})</div>
                {(deadCodePreview.methods as Array<Record<string, unknown>>).slice(0, 8).map((m) => (
                  <div key={String(m.id)} className="text-[11px] text-white/55 truncate">{String(m.label ?? m.id)}</div>
                ))}
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.03] p-2">
                <div className="text-xs text-white/70 mb-1">Controllers ({deadCodePreview.controllers.length})</div>
                {(deadCodePreview.controllers as Array<Record<string, unknown>>).slice(0, 8).map((m) => (
                  <div key={String(m.id)} className="text-[11px] text-white/55 truncate">{String(m.label ?? m.id)}</div>
                ))}
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.03] p-2">
                <div className="text-xs text-white/70 mb-1">Components ({deadCodePreview.components.length})</div>
                {(deadCodePreview.components as Array<Record<string, unknown>>).slice(0, 8).map((m) => (
                  <div key={String(m.id)} className="text-[11px] text-white/55 truncate">{String(m.label ?? m.id)}</div>
                ))}
              </div>
            </div>
          ) : null}

          {guidedMode === "big_components" ? (
            <div className="space-y-2">
              <div className="text-xs uppercase tracking-[0.2em] text-white/45">Biggest components by LOC</div>
              {biggestComponents.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setSelectedNodeId(item.id)}
                  className="w-full rounded-lg border border-white/10 bg-white/[0.03] p-2 text-left hover:bg-white/[0.06]"
                >
                  <div className="text-sm text-white/85">{item.label}</div>
                  <div className="text-[11px] text-white/55">~{item.loc} LOC</div>
                </button>
              ))}
            </div>
          ) : null}

          {selectedDependency ? (
            <div className="space-y-2 rounded-xl border border-white/10 bg-white/[0.03] p-3">
              <div className="text-xs uppercase tracking-[0.2em] text-white/45">Dependency details</div>
              <div className="text-sm text-white/80">{selectedDependency.label}</div>
              <div className="text-xs text-white/55">
                Calls: {selectedDependency.calls.length} | Called by: {selectedDependency.called_by.length}
              </div>
              <div className="text-xs text-white/55">
                Depends on: {selectedDependency.depends_on.length} | Used by: {selectedDependency.used_by.length}
              </div>
            </div>
          ) : null}

          {(componentFlows ?? []).length > 0 ? (
            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
              <div className="text-xs uppercase tracking-[0.2em] text-white/45 mb-2">Component flow traces</div>
              {(componentFlows ?? []).slice(0, 6).map((flow) => (
                <button
                  key={`${flow.entry_id}:${flow.start_id}`}
                  onClick={() => setSelectedNodeId(flow.entry_id || flow.start_id || null)}
                  className="block w-full text-left text-[11px] text-white/65 hover:text-white truncate"
                >
                  {flow.entry_id || flow.start_id} • depth {flow.depth}
                </button>
              ))}
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
};

