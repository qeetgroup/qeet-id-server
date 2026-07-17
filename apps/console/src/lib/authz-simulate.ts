// Simulation / policy-decision-point data layer. Every authorization engine
// is exposed as a one-shot mutation that returns a normalised DecisionRecord
// (allow/deny + engine-specific explain payload + measured latency), so the
// Simulator and Decision Explorer can render any engine uniformly.
//
// Real endpoints only:
//   • AuthZEN unified PDP  POST /v1/tenants/{t}/access/v1/evaluation
//   • ABAC engine          POST /v1/tenants/{t}/abac/evaluate?explain=true
//   • RBAC check           GET  /v1/check?...&explain=true
//   • ReBAC check          POST /v1/tenants/{t}/relation-tuples/check?explain=true
// Batch simulation has no server endpoint, so it is a capped client-side
// fan-out over the real single-eval calls above.

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "./api";
import { useTenantId } from "./auth";
import type { AbacDecision } from "./authz-abac";

export type Engine = "authzen" | "abac" | "rbac" | "rebac";

export interface RbacExplainPath {
  permission: string;
  granted_by: string;
  via: string;
  group_id?: string;
  role_id: string;
}
export interface RbacExplain {
  allowed: boolean;
  paths: RbacExplainPath[];
  reason: string;
}

export interface RebacPathStep {
  object: string;
  relation: string;
  subject: string;
  depth: number;
}
export interface RebacExplain {
  allowed: boolean;
  path?: RebacPathStep[];
}

export interface AuthzenResult {
  decision: boolean;
  context?: Record<string, unknown>;
}

/** Uniform record every engine produces — the currency of the Explorer. */
export interface DecisionRecord {
  id: string;
  engine: Engine;
  allowed: boolean;
  at: string;
  durationMs: number;
  reason?: string;
  input: Record<string, unknown>;
  authzen?: AuthzenResult;
  abac?: AbacDecision;
  rbac?: RbacExplain;
  rebac?: RebacExplain;
}

function rid(): string {
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  } catch {
    /* ignore */
  }
  return `d_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

async function timed<T>(fn: () => Promise<T>): Promise<{ data: T; durationMs: number }> {
  const t0 = typeof performance !== "undefined" ? performance.now() : Date.now();
  const data = await fn();
  const t1 = typeof performance !== "undefined" ? performance.now() : Date.now();
  return { data, durationMs: Math.round((t1 - t0) * 10) / 10 };
}

// ── Engine inputs ─────────────────────────────────────────────────────────────

export interface AuthzenInput {
  subject: { type: string; id: string };
  resource: { type: string; id: string };
  action: string;
  context?: Record<string, unknown>;
}

export interface AbacInput {
  subject: Record<string, unknown>;
  resource: { type: string; id: string; attrs?: Record<string, unknown> };
  action: string;
  context?: Record<string, unknown>;
}

export interface RbacInput {
  user_id: string;
  permission: string;
}

export interface RebacInput {
  object: string;
  relation: string;
  user_id: string;
}

// ── Raw calls (also reused by the batch runner) ───────────────────────────────

async function callAuthzen(tenantId: string, input: AuthzenInput): Promise<DecisionRecord> {
  const { data, durationMs } = await timed(() =>
    api<AuthzenResult>(`/v1/tenants/${tenantId}/access/v1/evaluation`, {
      method: "POST",
      body: {
        subject: input.subject,
        resource: input.resource,
        action: { name: input.action },
        context: { explain: true, ...(input.context ?? {}) },
      },
    }),
  );
  return {
    id: rid(),
    engine: "authzen",
    allowed: data.decision,
    at: new Date().toISOString(),
    durationMs,
    input: input as unknown as Record<string, unknown>,
    authzen: data,
  };
}

async function callAbac(tenantId: string, input: AbacInput): Promise<DecisionRecord> {
  const { data, durationMs } = await timed(() =>
    api<AbacDecision>(`/v1/tenants/${tenantId}/abac/evaluate`, {
      method: "POST",
      body: input,
      query: { explain: "true" },
    }),
  );
  return {
    id: rid(),
    engine: "abac",
    allowed: data.allow,
    at: new Date().toISOString(),
    durationMs,
    reason: data.reason,
    input: input as unknown as Record<string, unknown>,
    abac: data,
  };
}

async function callRbac(tenantId: string, input: RbacInput): Promise<DecisionRecord> {
  const { data, durationMs } = await timed(() =>
    api<RbacExplain>("/v1/check", {
      query: {
        user_id: input.user_id,
        tenant_id: tenantId,
        permission: input.permission,
        explain: "true",
      },
    }),
  );
  return {
    id: rid(),
    engine: "rbac",
    allowed: data.allowed,
    at: new Date().toISOString(),
    durationMs,
    reason: data.reason,
    input: input as unknown as Record<string, unknown>,
    rbac: data,
  };
}

async function callRebac(tenantId: string, input: RebacInput): Promise<DecisionRecord> {
  const { data, durationMs } = await timed(() =>
    api<RebacExplain>(`/v1/tenants/${tenantId}/relation-tuples/check`, {
      method: "POST",
      body: input,
      query: { explain: "true" },
    }),
  );
  return {
    id: rid(),
    engine: "rebac",
    allowed: data.allowed,
    at: new Date().toISOString(),
    durationMs,
    input: input as unknown as Record<string, unknown>,
    rebac: data,
  };
}

// ── Hooks ─────────────────────────────────────────────────────────────────────

export function useAuthzenEvaluate() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: (input: AuthzenInput) => callAuthzen(tenantId ?? "", input),
    meta: { silent: true },
  });
}

export function useAbacSimulate() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: (input: AbacInput) => callAbac(tenantId ?? "", input),
    meta: { silent: true },
  });
}

export function useRbacSimulate() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: (input: RbacInput) => callRbac(tenantId ?? "", input),
    meta: { silent: true },
  });
}

export function useRebacSimulate() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: (input: RebacInput) => callRebac(tenantId ?? "", input),
    meta: { silent: true },
  });
}

export const BATCH_CAP = 50;

/**
 * Capped, concurrency-limited fan-out over the real AuthZEN endpoint — the
 * frontend stand-in for a batch-simulation API that does not exist yet.
 */
export function useBatchSimulate() {
  const tenantId = useTenantId();
  const [results, setResults] = useState<DecisionRecord[]>([]);
  const [isRunning, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);

  async function run(
    subjects: { type: string; id: string }[],
    resource: { type: string; id: string },
    action: string,
    context?: Record<string, unknown>,
  ) {
    if (!tenantId) return;
    const capped = subjects.slice(0, BATCH_CAP);
    setRunning(true);
    setResults([]);
    setProgress(0);
    const out: DecisionRecord[] = [];
    // Bounded concurrency of 6 to stay gentle on the PDP.
    const concurrency = 6;
    let cursor = 0;
    async function worker() {
      while (cursor < capped.length) {
        const i = cursor++;
        try {
          out[i] = await callAuthzen(tenantId!, { subject: capped[i], resource, action, context });
        } catch {
          out[i] = {
            id: rid(),
            engine: "authzen",
            allowed: false,
            at: new Date().toISOString(),
            durationMs: 0,
            reason: "request failed",
            input: { subject: capped[i], resource, action },
          };
        }
        setProgress((p) => p + 1);
      }
    }
    await Promise.all(Array.from({ length: Math.min(concurrency, capped.length) }, worker));
    setResults(out.filter(Boolean));
    setRunning(false);
  }

  return { run, results, isRunning, progress };
}
