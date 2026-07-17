// Audit-derived data for the Authorization section. The audit log is the only
// real source of "who changed what, when" for policies/roles/relations, so the
// Audit surface reads it directly and Version History reconstructs a read-only
// change timeline from it. There is no server-side rollback endpoint.
// Backed by GET /v1/tenants/{tenantID}/audit. See domains/operations/audit.

import { useQuery } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface AuditEvent {
  id: string;
  tenant_id: string | null;
  actor_user_id: string | null;
  actor_type: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  ip: string | null;
  user_agent: string | null;
  request_id: string | null;
  created_at: string;
  metadata?: Record<string, unknown> | null;
}

interface AuditResponse {
  items: AuditEvent[];
  next_cursor: string;
}

export interface AuditFilter {
  action?: string;
  resource_type?: string;
  actor_user_id?: string;
  q?: string;
  limit?: number;
  cursor?: string;
}

/** Resource types that belong to the authorization domain. */
export const AUTHZ_RESOURCE_TYPES = [
  "abac_policy",
  "role",
  "rbac_policy",
  "relation_tuple",
  "permission",
  "group_role",
  "security_policy",
] as const;

export function useAuditEvents(filter: AuditFilter = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["authz-audit", tenantId, filter],
    enabled: !!tenantId,
    queryFn: () =>
      api<AuditResponse>(`/v1/tenants/${tenantId}/audit`, {
        query: {
          action: filter.action || undefined,
          resource_type: filter.resource_type || undefined,
          actor_user_id: filter.actor_user_id || undefined,
          q: filter.q || undefined,
          limit: filter.limit ?? 100,
          cursor: filter.cursor || undefined,
        },
      }),
  });
}

/** Whether an event is authorization-related (by resource type or action prefix). */
export function isAuthzEvent(e: AuditEvent): boolean {
  if ((AUTHZ_RESOURCE_TYPES as readonly string[]).includes(e.resource_type)) return true;
  return /^(abac|rbac|role|permission|relation|policy)[._]/i.test(e.action);
}

export interface VersionEntry {
  id: string;
  action: string;
  actor: string;
  at: string;
  metadata?: Record<string, unknown> | null;
}

/**
 * Reconstruct a chronological change timeline for one resource from the audit
 * log. Read-only — there is no rollback endpoint, so the UI surfaces this as
 * history + diff only.
 */
export function toVersionTimeline(events: AuditEvent[], resourceId: string): VersionEntry[] {
  return events
    .filter((e) => e.resource_id === resourceId)
    .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
    .map((e) => ({
      id: e.id,
      action: e.action,
      actor: e.actor_user_id ?? e.actor_type ?? "system",
      at: e.created_at,
      metadata: e.metadata,
    }));
}
