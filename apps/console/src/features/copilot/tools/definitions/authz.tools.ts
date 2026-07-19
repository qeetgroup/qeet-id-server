// Authorization tools — simulate_authorization, set_strict_mfa.
//
// simulate_authorization: routes to the real engine endpoints (AuthZEN/ABAC/RBAC/ReBAC)
//   following the same call patterns as lib/authz-simulate.ts (not exported from there,
//   so we call api() directly with the same paths).
//
// set_strict_mfa: GET current auth policy, then PUT with remember_device_enabled toggled.
//   strict_mfa.enabled=true  → remember_device_enabled=false (force MFA every sign-in)
//   strict_mfa.enabled=false → remember_device_enabled=true  (allow adaptive skip)

import { z } from "zod";

import { api } from "@/lib/api";
import type { AuthPolicy } from "@/lib/auth-policy";
import type { ToolDefinition } from "../tool-types";

// ── simulate_authorization ────────────────────────────────────────────────────

const simulateAuthorizationInput = z.object({
  engine: z.enum(["authzen", "abac", "rbac", "rebac"]),
  subject: z.unknown(),
  resource: z.unknown(),
  action: z.string(),
  context: z.record(z.string(), z.unknown()).optional(),
});
type SimulateAuthorizationInput = z.infer<typeof simulateAuthorizationInput>;

type SimulateResult = {
  allowed: boolean;
  reason?: string;
  explain?: unknown;
  durationMs?: number;
};

async function runAuthzenEval(
  tenantId: string,
  input: SimulateAuthorizationInput,
  signal: AbortSignal,
): Promise<SimulateResult> {
  const t0 = Date.now();
  const data = await api<{ decision: boolean; context?: unknown }>(
    `/v1/tenants/${tenantId}/access/v1/evaluation`,
    {
      method: "POST",
      body: {
        subject: input.subject,
        resource: input.resource,
        action: { name: input.action },
        context: { explain: true, ...(input.context ?? {}) },
      },
      signal,
    },
  );
  return {
    allowed: data.decision,
    explain: data.context,
    durationMs: Date.now() - t0,
  };
}

async function runAbacEval(
  tenantId: string,
  input: SimulateAuthorizationInput,
  signal: AbortSignal,
): Promise<SimulateResult> {
  const t0 = Date.now();
  const data = await api<{ allow: boolean; reason?: string; explain?: unknown }>(
    `/v1/tenants/${tenantId}/abac/evaluate`,
    {
      method: "POST",
      body: { subject: input.subject, resource: input.resource, action: input.action },
      query: { explain: "true" },
      signal,
    },
  );
  return {
    allowed: data.allow,
    reason: data.reason,
    explain: data.explain,
    durationMs: Date.now() - t0,
  };
}

async function runRbacCheck(
  tenantId: string,
  input: SimulateAuthorizationInput,
  signal: AbortSignal,
): Promise<SimulateResult> {
  const t0 = Date.now();
  // RBAC check uses subject as a user_id string and action as permission key.
  const userId =
    typeof input.subject === "string"
      ? input.subject
      : (((input.subject as Record<string, unknown>)?.id as string) ?? "");
  const data = await api<{ allowed: boolean; reason?: string; paths?: unknown }>("/v1/check", {
    query: {
      user_id: userId,
      tenant_id: tenantId,
      permission: input.action,
      explain: "true",
    },
    signal,
  });
  return {
    allowed: data.allowed,
    reason: data.reason,
    explain: data.paths,
    durationMs: Date.now() - t0,
  };
}

async function runRebacCheck(
  tenantId: string,
  input: SimulateAuthorizationInput,
  signal: AbortSignal,
): Promise<SimulateResult> {
  const t0 = Date.now();
  const userId =
    typeof input.subject === "string"
      ? input.subject
      : (((input.subject as Record<string, unknown>)?.id as string) ?? "");
  const resourceObj = input.resource as Record<string, unknown> | null;
  const objectStr =
    typeof input.resource === "string"
      ? input.resource
      : `${resourceObj?.type ?? ""}:${resourceObj?.id ?? ""}`;
  const data = await api<{ allowed: boolean; path?: unknown }>(
    `/v1/tenants/${tenantId}/relation-tuples/check`,
    {
      method: "POST",
      body: { object: objectStr, relation: input.action, user_id: userId },
      query: { explain: "true" },
      signal,
    },
  );
  return {
    allowed: data.allowed,
    explain: data.path,
    durationMs: Date.now() - t0,
  };
}

export const simulateAuthorizationTool: ToolDefinition<SimulateAuthorizationInput> = {
  name: "simulate_authorization",
  category: "authz",
  title: "Simulate authorization",
  description:
    "Evaluate whether a subject may perform an action on a resource using a chosen decision engine (AuthZEN/ABAC/RBAC/ReBAC). Returns the decision plus an explain trace. Read-only — nothing is changed.",
  input: simulateAuthorizationInput,
  requiredCapability: "role.read",
  destructive: false,
  auditLabel: "copilot.simulate_authorization",
  async run(ctx, input) {
    let result: SimulateResult;
    switch (input.engine) {
      case "authzen":
        result = await runAuthzenEval(ctx.tenantId, input, ctx.signal);
        break;
      case "abac":
        result = await runAbacEval(ctx.tenantId, input, ctx.signal);
        break;
      case "rbac":
        result = await runRbacCheck(ctx.tenantId, input, ctx.signal);
        break;
      case "rebac":
        result = await runRebacCheck(ctx.tenantId, input, ctx.signal);
        break;
    }
    const verdict = result.allowed ? "ALLOW" : "DENY";
    return {
      ok: true,
      summary: `${input.engine.toUpperCase()} decision: ${verdict}${result.reason ? ` — ${result.reason}` : ""}${result.durationMs !== undefined ? ` (${result.durationMs}ms)` : ""}.`,
      data: {
        engine: input.engine,
        allowed: result.allowed,
        reason: result.reason,
        explain: result.explain,
        duration_ms: result.durationMs,
      },
    };
  },
};

// ── set_strict_mfa ────────────────────────────────────────────────────────────

const setStrictMfaInput = z.object({ enabled: z.boolean() });
type SetStrictMfaInput = z.infer<typeof setStrictMfaInput>;

export const setStrictMfaTool: ToolDefinition<SetStrictMfaInput> = {
  name: "set_strict_mfa",
  category: "authz",
  title: "Set strict MFA",
  description:
    "Toggle strict MFA for the tenant by disabling adaptive device-remembering (remember_device_enabled). When strict, every sign-in must complete MFA with no adaptive skip.",
  input: setStrictMfaInput,
  requiredCapability: "policy.write",
  destructive: false,
  auditLabel: "copilot.set_strict_mfa",
  async run(ctx, input) {
    // Full-replace PUT: GET current policy, flip remember_device_enabled, PUT back.
    // strict enabled=true → remember_device_enabled=false (force MFA every sign-in)
    // strict enabled=false → remember_device_enabled=true (allow adaptive skip)
    const current = await api<AuthPolicy>(`/v1/tenants/${ctx.tenantId}/auth-policy`, {
      signal: ctx.signal,
    });
    const next: AuthPolicy = { ...current, remember_device_enabled: !input.enabled };
    await api<AuthPolicy>(`/v1/tenants/${ctx.tenantId}/auth-policy`, {
      method: "PUT",
      body: next,
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: ["auth-policy"] });
    return {
      ok: true,
      summary: input.enabled
        ? "Strict MFA enabled — every sign-in must complete MFA (device-remembering disabled)."
        : "Strict MFA disabled — adaptive device-remembering is now allowed.",
      data: {
        strict_mfa_enabled: input.enabled,
        remember_device_enabled: !input.enabled,
      },
    };
  },
};
