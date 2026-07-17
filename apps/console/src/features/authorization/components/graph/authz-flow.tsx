import "@xyflow/react/dist/style.css";

import { Skeleton, usePrefersReducedMotion } from "@qeetrix/ui";
import {
  Background,
  BackgroundVariant,
  Controls,
  type Edge,
  MiniMap,
  type Node,
  type NodeTypes,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import { useEffect } from "react";

import { ClientOnly } from "../shared/client-only";

export interface AuthzFlowProps {
  nodes: Node[];
  edges: Edge[];
  nodeTypes: NodeTypes;
  height?: number;
  ariaLabel?: string;
  fitView?: boolean;
  nodesDraggable?: boolean;
  onNodeClick?: (id: string) => void;
}

function Flow({
  nodes: nodesProp,
  edges: edgesProp,
  nodeTypes,
  ariaLabel,
  fitView = true,
  nodesDraggable = true,
  onNodeClick,
}: AuthzFlowProps) {
  const reduceMotion = usePrefersReducedMotion();
  const [nodes, setNodes, onNodesChange] = useNodesState(nodesProp);
  const [edges, setEdges, onEdgesChange] = useEdgesState(edgesProp);

  // Reseed when the source data changes (a new query result, a new selection).
  useEffect(() => setNodes(nodesProp), [nodesProp, setNodes]);
  useEffect(
    () => setEdges(reduceMotion ? edgesProp.map((e) => ({ ...e, animated: false })) : edgesProp),
    [edgesProp, reduceMotion, setEdges],
  );

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      nodeTypes={nodeTypes}
      fitView={fitView}
      fitViewOptions={{ padding: 0.2 }}
      nodesConnectable={false}
      nodesDraggable={nodesDraggable}
      minZoom={0.2}
      maxZoom={2}
      aria-label={ariaLabel}
      defaultEdgeOptions={{ type: "smoothstep" }}
      onNodeClick={(_, node) => onNodeClick?.(node.id)}
    >
      <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
      <Controls showInteractive={false} />
      <MiniMap pannable zoomable className="!bg-muted" />
    </ReactFlow>
  );
}

/**
 * Reusable React Flow surface for the authorization graphs. Client-only (the
 * console SSRs), reduced-motion aware, with pan/zoom, minimap and controls.
 */
export function AuthzFlow({ height = 440, ...props }: AuthzFlowProps) {
  return (
    <div className="overflow-hidden rounded-md border bg-muted/20" style={{ height }}>
      <ClientOnly fallback={<Skeleton className="size-full" />}>
        <ReactFlowProvider>
          <Flow {...props} />
        </ReactFlowProvider>
      </ClientOnly>
    </div>
  );
}
