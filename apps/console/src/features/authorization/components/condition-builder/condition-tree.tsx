import { Badge, Button, Combobox, Input } from "@qeetrix/ui";
import { FolderPlusIcon, PlusIcon, Trash2Icon } from "lucide-react";

import {
  type CondNode,
  emptyGroup,
  emptyLeaf,
  LIST_OPERATORS,
  NAMESPACES,
  type Namespace,
  NULLARY_OPERATORS,
  OPERATOR_LABELS,
  OPERATORS,
  type Operator,
} from "@/lib/authz-abac";

const NS_ITEMS = NAMESPACES.map((n) => ({ label: n, value: n }));
const OP_ITEMS = OPERATORS.map((o) => ({ label: OPERATOR_LABELS[o], value: o }));

/**
 * Visual, no-code editor for an ABAC condition tree. Nested AND (`all`) / OR
 * (`any`) groups, NOT wrappers, and comparison leaves across 13 operators.
 * Emits the editable CondNode form; callers serialize with toConditionJson.
 */
export function ConditionTree({
  value,
  onChange,
}: {
  value: CondNode;
  onChange: (node: CondNode) => void;
}) {
  return <NodeEditor node={value} onChange={onChange} depth={0} />;
}

function NodeEditor({
  node,
  onChange,
  onRemove,
  depth,
}: {
  node: CondNode;
  onChange: (node: CondNode) => void;
  onRemove?: () => void;
  depth: number;
}) {
  if (node.kind === "leaf")
    return <LeafEditor node={node} onChange={onChange} onRemove={onRemove} />;
  if (node.kind === "not") {
    return (
      <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-3">
        <div className="mb-2 flex items-center justify-between">
          <Badge variant="destructive">NOT</Badge>
          {onRemove && (
            <Button variant="ghost" size="icon-xs" onClick={onRemove} aria-label="Remove NOT">
              <Trash2Icon />
            </Button>
          )}
        </div>
        <NodeEditor
          node={node.child}
          onChange={(child) => onChange({ ...node, child })}
          depth={depth + 1}
        />
      </div>
    );
  }

  // group
  const combinatorColor =
    node.combinator === "all"
      ? "border-blue-500/30 bg-blue-500/5"
      : "border-amber-500/30 bg-amber-500/5";

  // `node` is narrowed to the group variant here; capture it so the closures
  // below (which TypeScript would otherwise widen) keep the narrowed type.
  const group = node;
  const updateChild = (index: number, child: CondNode) => {
    onChange({ ...group, children: group.children.map((c, i) => (i === index ? child : c)) });
  };
  const removeChild = (index: number) => {
    const next = group.children.filter((_, i) => i !== index);
    onChange({ ...group, children: next.length ? next : [emptyLeaf()] });
  };

  return (
    <div className={`rounded-lg border p-3 ${combinatorColor}`}>
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-1 rounded-md border bg-background p-0.5 text-xs font-medium">
          <button
            type="button"
            onClick={() => onChange({ ...node, combinator: "all" })}
            className={`rounded px-2 py-0.5 ${node.combinator === "all" ? "bg-blue-500/20 text-blue-700 dark:text-blue-300" : "text-muted-foreground"}`}
          >
            ALL (AND)
          </button>
          <button
            type="button"
            onClick={() => onChange({ ...node, combinator: "any" })}
            className={`rounded px-2 py-0.5 ${node.combinator === "any" ? "bg-amber-500/20 text-amber-700 dark:text-amber-300" : "text-muted-foreground"}`}
          >
            ANY (OR)
          </button>
        </div>
        {onRemove && (
          <Button variant="ghost" size="icon-xs" onClick={onRemove} aria-label="Remove group">
            <Trash2Icon />
          </Button>
        )}
      </div>

      <div className="flex flex-col gap-2">
        {node.children.map((child, i) => (
          <NodeEditor
            key={child.id}
            node={child}
            onChange={(c) => updateChild(i, c)}
            onRemove={() => removeChild(i)}
            depth={depth + 1}
          />
        ))}
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        <Button
          variant="outline"
          size="xs"
          onClick={() => onChange({ ...node, children: [...node.children, emptyLeaf()] })}
        >
          <PlusIcon /> Condition
        </Button>
        <Button
          variant="outline"
          size="xs"
          onClick={() => onChange({ ...node, children: [...node.children, emptyGroup("all")] })}
        >
          <FolderPlusIcon /> Group
        </Button>
        <Button
          variant="outline"
          size="xs"
          onClick={() =>
            onChange({
              ...node,
              children: [
                ...node.children,
                { id: `not_${Date.now()}`, kind: "not", child: emptyLeaf() },
              ],
            })
          }
        >
          <PlusIcon /> NOT
        </Button>
      </div>
    </div>
  );
}

function LeafEditor({
  node,
  onChange,
  onRemove,
}: {
  node: Extract<CondNode, { kind: "leaf" }>;
  onChange: (node: CondNode) => void;
  onRemove?: () => void;
}) {
  const dot = node.attr.indexOf(".");
  const ns: Namespace = (dot >= 0 ? node.attr.slice(0, dot) : "subject") as Namespace;
  const field = dot >= 0 ? node.attr.slice(dot + 1) : node.attr;
  const isNullary = NULLARY_OPERATORS.includes(node.op);
  const isList = LIST_OPERATORS.includes(node.op);

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border bg-background p-2">
      <div className="w-28 shrink-0">
        <Combobox
          items={NS_ITEMS}
          value={ns}
          onValueChange={(v) => onChange({ ...node, attr: `${v ?? "subject"}.${field}` })}
          aria-label="Namespace"
        />
      </div>
      <Input
        className="w-40 font-mono text-xs"
        placeholder="attribute"
        value={field}
        aria-label="Attribute path"
        onChange={(e) => onChange({ ...node, attr: `${ns}.${e.target.value}` })}
      />
      <div className="w-40 shrink-0">
        <Combobox
          items={OP_ITEMS}
          value={node.op}
          onValueChange={(v) => onChange({ ...node, op: (v ?? "eq") as Operator })}
          aria-label="Operator"
        />
      </div>
      {!isNullary && (
        <Input
          className="w-44 font-mono text-xs"
          placeholder={isList ? "a, b, c" : "value"}
          value={node.value}
          aria-label="Value"
          onChange={(e) => onChange({ ...node, value: e.target.value })}
        />
      )}
      {onRemove && (
        <Button
          variant="ghost"
          size="icon-xs"
          className="ml-auto"
          onClick={onRemove}
          aria-label="Remove condition"
        >
          <Trash2Icon />
        </Button>
      )}
    </div>
  );
}
