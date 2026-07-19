// Tool + execution contracts (Phase 0, frozen). Every copilot action is a
// ToolDefinition: a Zod-validated input, an optional required Capability, a
// destructive flag with a confirmation builder, an audit label, and a `run`
// that executes through the EXISTING authenticated hooks/endpoints — so RBAC,
// Postgres RLS tenant isolation, and audit are inherited, never reimplemented.
//
// Note: the execution-engine *types* (ExecutionStatus, ToolExecution) live here
// rather than in execution-engine.ts, so the engine implementation can be owned
// as a single impl file without a types/impl collision.

import type { QueryClient } from "@tanstack/react-query";
import type { z } from "zod";

import type { Capability } from "@/features/access-control/capability-model";
import type { ConsoleContext } from "../context/context-types";

export type ToolCategory = "directory" | "authz" | "credentials" | "audit" | "codegen";

/** A confirmation the user must approve before a destructive tool runs. */
export interface ConfirmRequest {
  title: string;
  body: string;
  /** Concrete resources the action will affect, shown before approval. */
  affected: { label: string; value: string }[];
  confirmText: string;
  tone: "default" | "destructive";
}

export interface ToolResult {
  ok: boolean;
  /** Redacted, model-safe one-liner — fed back to the model AND rendered. */
  summary: string;
  /** Redacted structured payload for rich rendering. Never secret-bearing. */
  data?: Record<string, unknown>;
  /**
   * Secret material (client secret, private key) that must be shown to the
   * operator ONCE but NEVER sent to the model or persisted server-side.
   */
  sensitiveArtifact?: { kind: "secret" | "private_key"; label: string; value: string };
  error?: { code: string; message: string };
}

export interface ToolContext {
  tenantId: string;
  userId: string;
  console: ConsoleContext;
  /** Client-side capability hint for enable/disable + pre-flight UX. */
  can: (c?: Capability) => boolean;
  /** Imperative execution of the existing React Query hooks/`api()` calls. */
  queryClient: QueryClient;
  signal: AbortSignal;
  /** Opens the confirmation dialog; resolves true on approval. */
  confirm: (req: ConfirmRequest) => Promise<boolean>;
}

export interface ToolDefinition<I = unknown> {
  /** snake_case; MUST equal the manifest entry and the backend tool name. */
  name: string;
  category: ToolCategory;
  title: string;
  /** Model-facing description. */
  description: string;
  input: z.ZodType<I>;
  requiredCapability?: Capability;
  destructive: boolean;
  confirm?: (input: I, ctx: ToolContext) => ConfirmRequest;
  auditLabel: string;
  run: (ctx: ToolContext, input: I) => Promise<ToolResult>;
}

export type ExecutionStatus =
  | "queued"
  | "validating"
  | "awaiting_confirmation"
  | "authorizing"
  | "executing"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "timed_out";

export interface ToolExecution {
  /** Equals the originating tool_call id. */
  id: string;
  toolName: string;
  input: unknown;
  status: ExecutionStatus;
  startedAt: number;
  endedAt?: number;
  result?: ToolResult;
  error?: { code: string; message: string };
  attempts: number;
}
