// Layered left-to-right BFS layout for the relationship / hierarchy graphs.
// Ported from the original hand-rolled SVG layout in access/relationships.tsx,
// but returns absolute positions that feed React Flow nodes. Root sits in the
// left column; each hop moves one column right, siblings stack vertically.

export const NODE_W = 190;
export const NODE_H = 62;
const LAYER_GAP_X = 260;
const ROW_GAP_Y = 92;

export interface XY {
  x: number;
  y: number;
}

export function layeredLayout(
  nodes: { id: string }[],
  edges: { from: string; to: string }[],
  rootId: string,
): Map<string, XY> {
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from)!.push(e.to);
  }

  const layer = new Map<string, number>();
  const queue: string[] = [];
  if (nodes.some((n) => n.id === rootId)) {
    layer.set(rootId, 0);
    queue.push(rootId);
  }
  while (queue.length) {
    const cur = queue.shift()!;
    const cl = layer.get(cur)!;
    for (const nxt of adj.get(cur) ?? []) {
      if (!layer.has(nxt)) {
        layer.set(nxt, cl + 1);
        queue.push(nxt);
      }
    }
  }
  const maxLayer = layer.size ? Math.max(...layer.values()) : 0;
  for (const n of nodes) if (!layer.has(n.id)) layer.set(n.id, maxLayer + 1);

  const byLayer = new Map<number, string[]>();
  for (const n of nodes) {
    const l = layer.get(n.id) ?? 0;
    if (!byLayer.has(l)) byLayer.set(l, []);
    byLayer.get(l)!.push(n.id);
  }

  const pos = new Map<string, XY>();
  for (const [l, ids] of byLayer) {
    const totalH = ids.length * NODE_H + (ids.length - 1) * (ROW_GAP_Y - NODE_H);
    const startY = -totalH / 2;
    ids.forEach((id, i) => {
      pos.set(id, { x: l * LAYER_GAP_X, y: startY + i * ROW_GAP_Y });
    });
  }
  return pos;
}
