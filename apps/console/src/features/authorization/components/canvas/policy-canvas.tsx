import "@xyflow/react/dist/style.css";

import { Badge, Button, Skeleton } from "@qeetrix/ui";
import {
  Background,
  BackgroundVariant,
  Controls,
  type Edge,
  Handle,
  type Node,
  type NodeProps,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import {
  KeyRoundIcon,
  NetworkIcon,
  PlusIcon,
  ShieldCheckIcon,
  SlidersHorizontalIcon,
} from "lucide-react";
import { useEffect } from "react";
import { countLeaves } from "@/lib/authz-abac";
import type { PolicyDoc } from "@/lib/authz-codegen";
import { ClientOnly } from "../shared/client-only";

export type BlockKind = "rbac" | "abac" | "rebac" | "decision";

const BLOCK_META: Record<Exclude<BlockKind, "decision">, { title: string; color: string }> = {
  rbac: {
    title: "Role check (RBAC)",
    color: "border-blue-400 bg-blue-50 dark:border-blue-500/60 dark:bg-blue-950/40",
  },
  abac: {
    title: "Condition (ABAC)",
    color: "border-emerald-400 bg-emerald-50 dark:border-emerald-500/60 dark:bg-emerald-950/40",
  },
  rebac: {
    title: "Relationship (ReBAC)",
    color: "border-purple-400 bg-purple-50 dark:border-purple-500/60 dark:bg-purple-950/40",
  },
};

function BlockNode({ data }: NodeProps) {
  const d = data as { kind: Exclude<BlockKind, "decision">; summary: string; selected?: boolean };
  const meta = BLOCK_META[d.kind];
  const Icon =
    d.kind === "rbac" ? ShieldCheckIcon : d.kind === "abac" ? SlidersHorizontalIcon : NetworkIcon;
  return (
    <div
      className={`w-52 rounded-lg border-2 px-3 py-2 shadow-sm ${meta.color} ${d.selected ? "ring-2 ring-primary ring-offset-1 ring-offset-background" : ""}`}
    >
      <div className="flex items-center gap-1.5">
        <Icon className="size-3.5" aria-hidden />
        <p className="text-[11px] font-medium">{meta.title}</p>
      </div>
      <p className="mt-1 truncate font-mono text-[11px] text-muted-foreground">{d.summary}</p>
      <Handle type="source" position={Position.Right} className="!bg-muted-foreground" />
    </div>
  );
}

function DecisionNode({ data }: NodeProps) {
  const d = data as { effect: string; target: string; selected?: boolean };
  const allow = d.effect === "allow";
  return (
    <div
      className={`w-52 rounded-lg border-2 px-3 py-2 shadow-md ${allow ? "border-emerald-500 bg-emerald-50 dark:bg-emerald-950/40" : "border-rose-500 bg-rose-50 dark:bg-rose-950/40"} ${d.selected ? "ring-2 ring-primary ring-offset-1 ring-offset-background" : ""}`}
    >
      <Handle type="target" position={Position.Left} className="!bg-muted-foreground" />
      <div className="flex items-center gap-2">
        <Badge variant={allow ? "success" : "destructive"}>{d.effect.toUpperCase()}</Badge>
        <KeyRoundIcon className="size-3.5 text-muted-foreground" aria-hidden />
      </div>
      <p className="mt-1 truncate font-mono text-[11px]">{d.target}</p>
    </div>
  );
}

const nodeTypes = { block: BlockNode, decision: DecisionNode };

function buildGraph(doc: PolicyDoc, selected: BlockKind | null): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const active: { kind: Exclude<BlockKind, "decision">; y: number; summary: string }[] = [];
  if (doc.requireRole != null)
    active.push({ kind: "rbac", y: 10, summary: doc.requireRole || "(role…)" });
  if (doc.condition != null)
    active.push({ kind: "abac", y: 130, summary: `${countLeaves(doc.condition)} condition(s)` });
  if (doc.relation != null)
    active.push({
      kind: "rebac",
      y: 250,
      summary: `${doc.relation.relation || "rel"} of ${doc.relation.object || "object"}`,
    });

  for (const b of active) {
    nodes.push({
      id: `block:${b.kind}`,
      type: "block",
      position: { x: 20, y: b.y },
      data: { kind: b.kind, summary: b.summary, selected: selected === b.kind },
    });
    edges.push({
      id: `e-${b.kind}`,
      source: `block:${b.kind}`,
      target: "decision",
      type: "smoothstep",
      animated: true,
    });
  }

  nodes.push({
    id: "decision",
    type: "decision",
    position: { x: 380, y: 130 },
    data: {
      effect: doc.effect,
      target: `${doc.resourceType || "*"}:${doc.action || "*"}`,
      selected: selected === "decision",
    },
  });

  return { nodes, edges };
}

function Canvas({
  doc,
  selected,
  onSelect,
  onToggleBlock,
}: {
  doc: PolicyDoc;
  selected: BlockKind | null;
  onSelect: (kind: BlockKind | null) => void;
  onToggleBlock: (kind: Exclude<BlockKind, "decision">) => void;
}) {
  const built = buildGraph(doc, selected);
  const [nodes, setNodes, onNodesChange] = useNodesState(built.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(built.edges);
  useEffect(() => setNodes(built.nodes), [built.nodes, setNodes]);
  useEffect(() => setEdges(built.edges), [built.edges, setEdges]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.25 }}
      nodesConnectable={false}
      minZoom={0.4}
      maxZoom={1.8}
      aria-label="Unified policy builder canvas"
      onNodeClick={(_, node) =>
        onSelect(
          node.id === "decision" ? "decision" : (node.id.slice("block:".length) as BlockKind),
        )
      }
      onPaneClick={() => onSelect(null)}
    >
      <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
      <Controls showInteractive={false} />
      <Panel position="top-left" className="flex flex-wrap gap-1.5">
        {doc.requireRole == null && (
          <Button variant="outline" size="xs" onClick={() => onToggleBlock("rbac")}>
            <PlusIcon /> Role
          </Button>
        )}
        {doc.condition == null && (
          <Button variant="outline" size="xs" onClick={() => onToggleBlock("abac")}>
            <PlusIcon /> Condition
          </Button>
        )}
        {doc.relation == null && (
          <Button variant="outline" size="xs" onClick={() => onToggleBlock("rebac")}>
            <PlusIcon /> Relationship
          </Button>
        )}
      </Panel>
    </ReactFlow>
  );
}

export function PolicyCanvas({
  doc,
  selected,
  onSelect,
  onToggleBlock,
  height = 420,
}: {
  doc: PolicyDoc;
  selected: BlockKind | null;
  onSelect: (kind: BlockKind | null) => void;
  onToggleBlock: (kind: Exclude<BlockKind, "decision">) => void;
  height?: number;
}) {
  return (
    <div className="overflow-hidden rounded-md border bg-muted/20" style={{ height }}>
      <ClientOnly fallback={<Skeleton className="size-full" />}>
        <ReactFlowProvider>
          <Canvas doc={doc} selected={selected} onSelect={onSelect} onToggleBlock={onToggleBlock} />
        </ReactFlowProvider>
      </ClientOnly>
    </div>
  );
}
