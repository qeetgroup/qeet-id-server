// The console-context contract (Phase 0, frozen). This is what the copilot
// automatically knows about "where the operator is" — route, tenant, the active
// selection a page has published, and current filters. It is grounding/context
// only: the `capabilities` list is a UI/model hint, NEVER an authorization
// decision (the backend endpoints each tool calls remain the real gate).

import type { Capability } from "@/features/access-control/capability-model";

/** A resource the current page has surfaced as "the thing being looked at". */
export interface ContextSelection {
  kind: "user" | "role" | "policy" | "oidc_client" | "agent" | "audit_event" | (string & {});
  id: string;
  label?: string;
}

export interface ConsoleContext {
  route: { pathname: string; title: string; group?: string };
  tenantId: string | null;
  userId: string | null;
  /** Grounding/UI hint only — NOT authorization. */
  capabilities: Capability[];
  selection?: ContextSelection;
  filters?: Record<string, string>;
}
