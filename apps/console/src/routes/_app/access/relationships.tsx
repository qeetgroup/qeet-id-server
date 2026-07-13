import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Field,
  FieldDescription,
  FieldLabel,
  Input,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CheckCircle2Icon, Loader2Icon, NetworkIcon, Trash2Icon, XCircleIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import {
  type GraphEdge,
  type GraphNode,
  type RelationGraph,
  useCheckRelation,
  useDeleteTuple,
  useRelationGraph,
  useRelationTuples,
  useWriteTuple,
} from "@/lib/relationships";

export const Route = createFileRoute("/_app/access/relationships")({
  component: RelationshipsPage,
});

function RelationshipsPage() {
  const { t } = useTranslation("rbac");
  const [object, setObject] = useState("");
  const [browseObject, setBrowseObject] = useState("");
  const tuplesQ = useRelationTuples(browseObject);
  const writeM = useWriteTuple();
  const deleteM = useDeleteTuple();

  const [relation, setRelation] = useState("");
  const [subject, setSubject] = useState("");

  const items = tuplesQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description={t("relationships.description")} />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("relationships.write.title")}</CardTitle>
            <CardDescription>
              e.g. object <code>document:readme</code>, relation <code>viewer</code>, subject{" "}
              <code>user:&lt;id&gt;</code> or <code>group:eng#member</code>.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              className="flex flex-col gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                if (object.trim() && relation.trim() && subject.trim()) {
                  writeM.mutate(
                    { object: object.trim(), relation: relation.trim(), subject: subject.trim() },
                    { onSuccess: () => setBrowseObject(object.trim()) },
                  );
                }
              }}
            >
              <Field>
                <FieldLabel htmlFor="object">{t("relationships.write.objectLabel")}</FieldLabel>
                <Input
                  id="object"
                  placeholder="document:readme"
                  value={object}
                  onChange={(e) => setObject(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="relation">{t("relationships.write.relationLabel")}</FieldLabel>
                <Input
                  id="relation"
                  placeholder="viewer"
                  value={relation}
                  onChange={(e) => setRelation(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="subject">{t("relationships.write.subjectLabel")}</FieldLabel>
                <Input
                  id="subject"
                  placeholder="user:… or group:eng#member"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
                <FieldDescription>{t("relationships.write.subjectHelp")}</FieldDescription>
              </Field>
              {writeM.error && (
                <p className="text-destructive text-sm">{(writeM.error as ApiError).message}</p>
              )}
              <Button
                type="submit"
                disabled={writeM.isPending || !object.trim() || !relation.trim() || !subject.trim()}
              >
                {writeM.isPending && <Loader2Icon className="animate-spin" />}
                {t("relationships.write.writeBtn")}
              </Button>
            </form>
          </CardContent>
        </Card>

        <CheckCard />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("relationships.tuples.title")}</CardTitle>
          <CardDescription>{t("relationships.tuples.description")}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Input
            placeholder="document:readme"
            value={browseObject}
            onChange={(e) => setBrowseObject(e.target.value)}
          />
          {browseObject && (
            <DataState
              isLoading={tuplesQ.isLoading}
              isError={tuplesQ.isError}
              error={tuplesQ.error}
              isEmpty={items.length === 0}
              emptyIcon={NetworkIcon}
              emptyTitle={t("relationships.tuples.empty")}
              skeletonRows={2}
            >
              <ul className="divide-y">
                {items.map((tuple) => (
                  <li key={tuple.id} className="flex items-center justify-between gap-4 py-2">
                    <span className="font-mono text-sm">
                      {tuple.object} <span className="text-muted-foreground">#{tuple.relation}</span>{" "}
                      {tuple.subject}
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={deleteM.isPending}
                      onClick={() => deleteM.mutate(tuple.id)}
                    >
                      <Trash2Icon /> {t("relationships.tuples.deleteBtn")}
                    </Button>
                  </li>
                ))}
              </ul>
            </DataState>
          )}
        </CardContent>
      </Card>

      <GraphCard />
    </div>
  );
}

function CheckCard() {
  const { t } = useTranslation("rbac");
  const checkM = useCheckRelation();
  const [object, setObject] = useState("");
  const [relation, setRelation] = useState("");
  const [userId, setUserId] = useState("");
  const result = checkM.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("relationships.check.title")}</CardTitle>
        <CardDescription>{t("relationships.check.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (object.trim() && relation.trim() && userId.trim()) {
              checkM.mutate({
                object: object.trim(),
                relation: relation.trim(),
                user_id: userId.trim(),
              });
            }
          }}
        >
          <Field>
            <FieldLabel htmlFor="c-object">{t("relationships.check.objectLabel")}</FieldLabel>
            <Input
              id="c-object"
              placeholder="document:readme"
              value={object}
              onChange={(e) => setObject(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="c-relation">{t("relationships.check.relationLabel")}</FieldLabel>
            <Input
              id="c-relation"
              placeholder="viewer"
              value={relation}
              onChange={(e) => setRelation(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="c-user">{t("relationships.check.userLabel")}</FieldLabel>
            <Input
              id="c-user"
              placeholder="user uuid"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
            />
          </Field>
          <Button
            type="submit"
            variant="outline"
            disabled={checkM.isPending || !object.trim() || !relation.trim() || !userId.trim()}
          >
            {checkM.isPending && <Loader2Icon className="animate-spin" />}
            {t("relationships.check.checkBtn")}
          </Button>
        </form>
        {result && (
          <div className="mt-3 flex items-center gap-2 text-sm font-medium">
            {result.allowed ? (
              <>
                <CheckCircle2Icon className="size-4 text-emerald-600 dark:text-emerald-400" />
                <Badge variant="success">allowed</Badge>
              </>
            ) : (
              <>
                <XCircleIcon className="text-destructive size-4" />
                <Badge variant="outline">denied</Badge>
              </>
            )}
          </div>
        )}
        {checkM.error && (
          <p className="mt-2 text-destructive text-sm">{(checkM.error as ApiError).message}</p>
        )}
      </CardContent>
    </Card>
  );
}

// ── Identity Graph ──────────────────────────────────────────────────────────

function GraphCard() {
  const { t } = useTranslation("rbac");
  const [object, setObject] = useState("");
  const [relation, setRelation] = useState("");
  const [query, setQuery] = useState<{ object: string; relation: string } | null>(null);
  const graphQ = useRelationGraph(query?.object ?? "", query?.relation ?? "");

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("relationships.graph.title")}</CardTitle>
        <CardDescription>{t("relationships.graph.description")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (object.trim() && relation.trim()) {
              setQuery({ object: object.trim(), relation: relation.trim() });
            }
          }}
        >
          <Input
            className="w-52"
            placeholder="document:readme"
            value={object}
            onChange={(e) => setObject(e.target.value)}
            aria-label={t("relationships.graph.objectAriaLabel")}
          />
          <Input
            className="w-36"
            placeholder="viewer"
            value={relation}
            onChange={(e) => setRelation(e.target.value)}
            aria-label={t("relationships.graph.relationAriaLabel")}
          />
          <Button
            type="submit"
            variant="outline"
            disabled={graphQ.isFetching || !object.trim() || !relation.trim()}
          >
            {graphQ.isFetching && <Loader2Icon className="animate-spin" />}
            {t("relationships.graph.expandBtn")}
          </Button>
        </form>

        {query && (
          <DataState
            isLoading={graphQ.isLoading}
            isError={graphQ.isError}
            error={graphQ.error}
            isEmpty={!graphQ.data || graphQ.data.nodes.length === 0}
            emptyIcon={NetworkIcon}
            emptyTitle={t("relationships.graph.empty")}
            skeletonRows={3}
          >
            {graphQ.data && <GraphCanvas graph={graphQ.data} root={query.object} ariaLabel={t("relationships.graph.svgAriaLabel")} />}
          </DataState>
        )}
      </CardContent>
    </Card>
  );
}

// NODE_W / NODE_H — dimensions of each node rectangle in the SVG.
const NODE_W = 160;
const NODE_H = 36;
const LAYER_GAP_X = 200;
const LAYER_GAP_Y = 52;

interface NodePos {
  x: number;
  y: number;
  node: GraphNode;
}

/** Layered left-to-right BFS layout: root at left, each hop one column right. */
function layoutGraph(graph: RelationGraph, rootId: string): NodePos[] {
  const adjFrom = new Map<string, string[]>();
  for (const e of graph.edges) {
    if (!adjFrom.has(e.from)) adjFrom.set(e.from, []);
    adjFrom.get(e.from)!.push(e.to);
  }

  const layers = new Map<string, number>();
  const queue: string[] = [rootId];
  layers.set(rootId, 0);
  while (queue.length > 0) {
    const cur = queue.shift()!;
    const curLayer = layers.get(cur)!;
    for (const nxt of adjFrom.get(cur) ?? []) {
      if (!layers.has(nxt)) {
        layers.set(nxt, curLayer + 1);
        queue.push(nxt);
      }
    }
  }
  // Nodes not reachable from root get layer = max+1
  const maxLayer = Math.max(0, ...layers.values());
  for (const n of graph.nodes) {
    if (!layers.has(n.id)) layers.set(n.id, maxLayer + 1);
  }

  // Group by layer
  const byLayer = new Map<number, GraphNode[]>();
  for (const n of graph.nodes) {
    const l = layers.get(n.id) ?? 0;
    if (!byLayer.has(l)) byLayer.set(l, []);
    byLayer.get(l)!.push(n);
  }

  const positions: NodePos[] = [];
  for (const [layer, nodes] of byLayer.entries()) {
    const totalH = nodes.length * NODE_H + (nodes.length - 1) * (LAYER_GAP_Y - NODE_H);
    const startY = -totalH / 2;
    nodes.forEach((n, i) => {
      positions.push({
        x: layer * LAYER_GAP_X,
        y: startY + i * LAYER_GAP_Y,
        node: n,
      });
    });
  }
  return positions;
}

const NODE_COLORS: Record<string, string> = {
  user:     "fill-blue-100 dark:fill-blue-900 stroke-blue-400",
  group:    "fill-purple-100 dark:fill-purple-900 stroke-purple-400",
  document: "fill-amber-100 dark:fill-amber-900 stroke-amber-400",
  project:  "fill-green-100 dark:fill-green-900 stroke-green-400",
  agent:    "fill-rose-100 dark:fill-rose-900 stroke-rose-400",
};
function nodeColor(type: string) {
  return NODE_COLORS[type] ?? "fill-muted stroke-muted-foreground";
}

function GraphCanvas({ graph, root, ariaLabel }: { graph: RelationGraph; root: string; ariaLabel: string }) {
  const positions = useMemo(() => layoutGraph(graph, root), [graph, root]);
  const posMap = useMemo(() => new Map(positions.map((p) => [p.node.id, p])), [positions]);

  if (positions.length === 0) return null;

  const xs = positions.map((p) => p.x);
  const ys = positions.map((p) => p.y);
  const minX = Math.min(...xs) - 20;
  const minY = Math.min(...ys) - NODE_H / 2 - 10;
  const maxX = Math.max(...xs) + NODE_W + 20;
  const maxY = Math.max(...ys) + NODE_H / 2 + 10;
  const vw = maxX - minX;
  const vh = maxY - minY;

  return (
    <div className="overflow-x-auto rounded-md border bg-muted/30">
      <svg
        viewBox={`${minX} ${minY} ${vw} ${vh}`}
        width={Math.max(vw, 600)}
        height={Math.max(vh, 200)}
        aria-label={ariaLabel}
        role="img"
      >
        <defs>
          <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" className="fill-muted-foreground" />
          </marker>
        </defs>

        {/* Edges */}
        {graph.edges.map((e: GraphEdge, i) => {
          const from = posMap.get(e.from);
          const to = posMap.get(e.to);
          if (!from || !to) return null;
          const x1 = from.x + NODE_W;
          const y1 = from.y + NODE_H / 2;
          const x2 = to.x;
          const y2 = to.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <g key={i}>
              <path
                d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                fill="none"
                strokeWidth={1.5}
                className="stroke-muted-foreground/60"
                markerEnd="url(#arrowhead)"
              />
              <text
                x={mx}
                y={(y1 + y2) / 2 - 4}
                textAnchor="middle"
                fontSize={9}
                className="fill-muted-foreground select-none"
              >
                {e.relation}
              </text>
            </g>
          );
        })}

        {/* Nodes */}
        {positions.map(({ x, y, node }) => (
          <g key={node.id} transform={`translate(${x},${y})`}>
            <rect
              width={NODE_W}
              height={NODE_H}
              rx={6}
              strokeWidth={1}
              className={nodeColor(node.type)}
            />
            <text
              x={8}
              y={13}
              fontSize={9}
              className="fill-muted-foreground select-none uppercase tracking-wider"
            >
              {node.type}
            </text>
            <text
              x={8}
              y={27}
              fontSize={11}
              fontFamily="monospace"
              className="fill-foreground select-none"
            >
              {node.label.length > 18 ? node.label.slice(0, 16) + "…" : node.label}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}
