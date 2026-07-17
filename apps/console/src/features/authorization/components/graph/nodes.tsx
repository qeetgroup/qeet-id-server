import { Handle, type NodeProps, Position } from "@xyflow/react";
import { KeyRoundIcon, ShieldCheckIcon } from "lucide-react";

import { NODE_W } from "./layout";

// Type → colour mapping mirrors the original ReBAC SVG so the visual language
// carries over. Tailwind classes (not inline colours) keep dark-mode correct.
const TYPE_STYLES: Record<string, string> = {
  user: "border-blue-400 bg-blue-50 dark:border-blue-500/60 dark:bg-blue-950/40",
  group: "border-purple-400 bg-purple-50 dark:border-purple-500/60 dark:bg-purple-950/40",
  document: "border-amber-400 bg-amber-50 dark:border-amber-500/60 dark:bg-amber-950/40",
  project: "border-emerald-400 bg-emerald-50 dark:border-emerald-500/60 dark:bg-emerald-950/40",
  organization: "border-teal-400 bg-teal-50 dark:border-teal-500/60 dark:bg-teal-950/40",
  repository: "border-orange-400 bg-orange-50 dark:border-orange-500/60 dark:bg-orange-950/40",
  agent: "border-rose-400 bg-rose-50 dark:border-rose-500/60 dark:bg-rose-950/40",
};
function typeStyle(type: string): string {
  return TYPE_STYLES[type] ?? "border-border bg-muted";
}

export type EntityNodeData = { type: string; label: string; root?: boolean };

export function EntityNode({ data }: NodeProps) {
  const d = data as EntityNodeData;
  return (
    <div
      className={`rounded-lg border-2 px-3 py-2 shadow-sm transition-shadow ${typeStyle(d.type)} ${
        d.root ? "ring-2 ring-primary ring-offset-1 ring-offset-background" : ""
      }`}
      style={{ width: NODE_W }}
    >
      <Handle type="target" position={Position.Left} className="!bg-muted-foreground" />
      <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
        {d.type}
      </p>
      <p className="truncate font-mono text-xs font-medium">{d.label}</p>
      <Handle type="source" position={Position.Right} className="!bg-muted-foreground" />
    </div>
  );
}

export type RoleNodeData = {
  name: string;
  isSystem: boolean;
  permCount?: number;
  selected?: boolean;
};

export function RoleNode({ data }: NodeProps) {
  const d = data as RoleNodeData;
  return (
    <div
      className={`rounded-lg border-2 px-3 py-2 shadow-sm ${
        d.selected
          ? "border-primary bg-primary/10"
          : "border-blue-400 bg-blue-50 dark:border-blue-500/60 dark:bg-blue-950/40"
      }`}
      style={{ width: NODE_W }}
    >
      <div className="flex items-center gap-1.5">
        <ShieldCheckIcon className="size-3.5 text-blue-600 dark:text-blue-400" aria-hidden />
        <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
          role{d.isSystem ? " · system" : ""}
        </p>
      </div>
      <p className="truncate text-sm font-medium">{d.name}</p>
      {d.permCount != null && (
        <p className="text-[10px] text-muted-foreground">{d.permCount} permissions</p>
      )}
      <Handle type="source" position={Position.Right} className="!bg-muted-foreground" />
    </div>
  );
}

export type PermNodeData = { key: string };

export function PermNode({ data }: NodeProps) {
  const d = data as PermNodeData;
  return (
    <div
      className="rounded-lg border border-border bg-muted px-3 py-2 shadow-sm"
      style={{ width: NODE_W }}
    >
      <Handle type="target" position={Position.Left} className="!bg-muted-foreground" />
      <div className="flex items-center gap-1.5">
        <KeyRoundIcon className="size-3.5 text-muted-foreground" aria-hidden />
        <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
          permission
        </p>
      </div>
      <p className="truncate font-mono text-xs">{d.key}</p>
    </div>
  );
}

export const relationshipNodeTypes = { entity: EntityNode };
export const rbacNodeTypes = { role: RoleNode, permission: PermNode };
