import { Badge } from "@qeetrix/ui";
import { CheckCircle2Icon, XCircleIcon } from "lucide-react";

import type { Engine } from "@/lib/authz-simulate";

export const ENGINE_LABELS: Record<Engine, string> = {
  authzen: "AuthZEN",
  abac: "ABAC",
  rbac: "RBAC",
  rebac: "ReBAC",
};

export const ENGINE_DESCRIPTIONS: Record<Engine, string> = {
  authzen: "Unified policy decision point (RBAC + ReBAC)",
  abac: "Attribute-based conditions",
  rbac: "Role & permission check",
  rebac: "Relationship / tuple traversal",
};

/** ALLOW / DENY pill with icon — the single visual for every decision. */
export function DecisionBadge({ allowed, className }: { allowed: boolean; className?: string }) {
  return (
    <Badge variant={allowed ? "success" : "destructive"} className={className}>
      {allowed ? (
        <CheckCircle2Icon className="size-3.5" aria-hidden />
      ) : (
        <XCircleIcon className="size-3.5" aria-hidden />
      )}
      {allowed ? "ALLOW" : "DENY"}
    </Badge>
  );
}

export function EngineBadge({ engine }: { engine: Engine }) {
  return (
    <Badge variant="outline" className="font-mono text-[10px] uppercase tracking-wide">
      {ENGINE_LABELS[engine]}
    </Badge>
  );
}
