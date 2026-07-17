import type { Edge, Node } from "@xyflow/react";
import { useMemo } from "react";

import type { RelationGraph } from "@/lib/relationships";
import { AuthzFlow } from "./authz-flow";
import { layeredLayout } from "./layout";
import { relationshipNodeTypes } from "./nodes";

/** ReBAC identity graph rendered with React Flow (replaces the SVG canvas). */
export function RelationshipGraph({
  graph,
  rootId,
  height,
}: {
  graph: RelationGraph;
  rootId: string;
  height?: number;
}) {
  const { nodes, edges } = useMemo(() => {
    const pos = layeredLayout(
      graph.nodes,
      graph.edges.map((e) => ({ from: e.from, to: e.to })),
      rootId,
    );
    const n: Node[] = graph.nodes.map((node) => ({
      id: node.id,
      type: "entity",
      position: pos.get(node.id) ?? { x: 0, y: 0 },
      data: { type: node.type, label: node.label, root: node.id === rootId },
    }));
    const e: Edge[] = graph.edges.map((edge, i) => ({
      id: `${edge.from}->${edge.to}-${i}`,
      source: edge.from,
      target: edge.to,
      label: edge.relation,
      animated: true,
      type: "smoothstep",
      labelStyle: { fontSize: 10 },
    }));
    return { nodes: n, edges: e };
  }, [graph, rootId]);

  return (
    <AuthzFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={relationshipNodeTypes}
      height={height}
      ariaLabel="ReBAC relationship graph"
    />
  );
}
