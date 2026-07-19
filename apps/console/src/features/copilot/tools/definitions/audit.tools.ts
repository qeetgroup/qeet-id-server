// Audit & session tools — search_audit_logs, search_sessions.
//
// search_audit_logs: GET /v1/tenants/{tenantId}/audit (tenant-scoped, read-only).
// search_sessions:   GET /v1/auth/sessions — SELF-SCOPED ONLY. No admin cross-user
//                    session search endpoint exists. The tool documents this clearly
//                    so the model never over-promises on its scope.

import { z } from "zod";

import { api } from "@/lib/api";
import type { ToolDefinition } from "../tool-types";

// ── search_audit_logs ─────────────────────────────────────────────────────────

const searchAuditLogsInput = z.object({
  q: z.string().optional(),
  action: z.string().optional(),
  resource_type: z.string().optional(),
  actor_user_id: z.string().optional(),
  limit: z.number().int().min(1).max(100).optional(),
});
type SearchAuditLogsInput = z.infer<typeof searchAuditLogsInput>;

interface AuditEvent {
  id: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  actor_user_id?: string | null;
  ip?: string | null;
  created_at: string;
}

export const searchAuditLogsTool: ToolDefinition<SearchAuditLogsInput> = {
  name: "search_audit_logs",
  category: "audit",
  title: "Search audit logs",
  description:
    "Search the tenant's append-only audit log by free-text, action, resource type, and/or actor. Read-only.",
  input: searchAuditLogsInput,
  requiredCapability: "audit.read",
  destructive: false,
  auditLabel: "copilot.search_audit_logs",
  async run(ctx, input) {
    const data = await api<{ items: AuditEvent[] }>(`/v1/tenants/${ctx.tenantId}/audit`, {
      query: {
        q: input.q,
        action: input.action,
        resource_type: input.resource_type,
        actor_user_id: input.actor_user_id,
        limit: input.limit ?? 25,
      },
      signal: ctx.signal,
    });
    const events = data.items ?? [];
    return {
      ok: true,
      summary: `Found ${events.length} audit event${events.length === 1 ? "" : "s"}.`,
      data: {
        events: events.map((e) => ({
          id: e.id,
          action: e.action,
          resource_type: e.resource_type,
          resource_id: e.resource_id,
          actor_user_id: e.actor_user_id,
          ip: e.ip,
          created_at: e.created_at,
        })),
      },
    };
  },
};

// ── search_sessions ───────────────────────────────────────────────────────────

const searchSessionsInput = z.object({});
type SearchSessionsInput = z.infer<typeof searchSessionsInput>;

interface Session {
  id: string;
  user_id: string;
  user_agent?: string | null;
  ip?: string | null;
  created_at: string;
  last_seen_at?: string | null;
}

export const searchSessionsTool: ToolDefinition<SearchSessionsInput> = {
  name: "search_sessions",
  category: "audit",
  title: "List sessions",
  description:
    "List active sessions for the current principal. Note: this endpoint is self-scoped — there is no admin cross-user session search — so it returns the calling operator's own sessions only.",
  input: searchSessionsInput,
  requiredCapability: "user.read",
  destructive: false,
  auditLabel: "copilot.search_sessions",
  async run(ctx, input) {
    // input is {} — satisfy linter
    void input;
    const data = await api<{ items: Session[] }>("/v1/auth/sessions", {
      signal: ctx.signal,
    });
    const sessions = data.items ?? [];
    return {
      ok: true,
      summary: `Found ${sessions.length} active session${sessions.length === 1 ? "" : "s"} for the current operator. (Note: cross-user session search is not available — this returns only your own sessions.)`,
      data: {
        sessions: sessions.map((s) => ({
          id: s.id,
          user_agent: s.user_agent,
          ip: s.ip,
          created_at: s.created_at,
          last_seen_at: s.last_seen_at,
        })),
      },
    };
  },
};
