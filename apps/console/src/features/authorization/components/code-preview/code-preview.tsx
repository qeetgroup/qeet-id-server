import { Badge, SegmentedControl, SegmentedControlItem } from "@qeetrix/ui";
import { useMemo, useState } from "react";

import {
  type EvalTreeNode,
  type PolicyDoc,
  toDsl,
  toEvalTree,
  toJson,
  toYamlDoc,
} from "@/lib/authz-codegen";
import { MonacoPanel } from "../shared/monaco-panel";

type View = "json" | "yaml" | "dsl" | "tree";

/**
 * Live, read-only preview of the current PolicyDoc in four representations.
 * JSON/YAML/DSL render through Monaco (client-only, lazy); the tree is an
 * interactive evaluation view derived purely on the client.
 */
export function CodePreview({ doc, height = 360 }: { doc: PolicyDoc; height?: number }) {
  const [view, setView] = useState<View>("json");
  const json = useMemo(() => toJson(doc), [doc]);
  const yaml = useMemo(() => toYamlDoc(doc), [doc]);
  const dsl = useMemo(() => toDsl(doc), [doc]);
  const tree = useMemo(() => toEvalTree(doc), [doc]);

  return (
    <div className="flex flex-col gap-3">
      <SegmentedControl
        value={view}
        onValueChange={(v) => setView(v as View)}
        size="sm"
        aria-label="Preview format"
      >
        <SegmentedControlItem value="json">JSON</SegmentedControlItem>
        <SegmentedControlItem value="yaml">YAML</SegmentedControlItem>
        <SegmentedControlItem value="dsl">DSL</SegmentedControlItem>
        <SegmentedControlItem value="tree">Tree</SegmentedControlItem>
      </SegmentedControl>

      {view === "json" && <MonacoPanel value={json} language="json" height={height} />}
      {view === "yaml" && <MonacoPanel value={yaml} language="yaml" height={height} />}
      {view === "dsl" && <MonacoPanel value={dsl} language="plaintext" height={height} />}
      {view === "tree" && (
        <div className="overflow-auto rounded-md border bg-muted/20 p-4" style={{ height }}>
          <EvalTree node={tree} />
        </div>
      )}
    </div>
  );
}

const KIND_STYLES: Record<EvalTreeNode["kind"], string> = {
  decision: "bg-primary/10 text-primary border-primary/30",
  and: "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30",
  or: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30",
  not: "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30",
  leaf: "bg-muted text-foreground border-border",
  block: "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30",
};

function EvalTree({ node, depth = 0 }: { node: EvalTreeNode; depth?: number }) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex flex-wrap items-center gap-2" style={{ paddingLeft: depth * 18 }}>
        {depth > 0 && (
          <span className="text-muted-foreground/50" aria-hidden>
            └
          </span>
        )}
        <span
          className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${KIND_STYLES[node.kind]}`}
        >
          {node.label}
        </span>
        {node.detail && (
          <span className="font-mono text-xs text-muted-foreground">{node.detail}</span>
        )}
        {node.kind === "leaf" && (
          <Badge variant="muted" className="text-[10px]">
            condition
          </Badge>
        )}
      </div>
      {node.children?.map((c) => (
        <EvalTree key={c.id} node={c} depth={depth + 1} />
      ))}
    </div>
  );
}
