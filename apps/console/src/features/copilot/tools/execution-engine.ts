// Execution engine: runs a ToolDefinition through the full state machine and
// returns a settled ToolExecution.
//
// State machine (per §A frozen contract):
//   queued → validating → [awaiting_confirmation if destructive] →
//   authorizing → executing → succeeded | failed | timed_out
//
//   cancelled  — reachable from any non-terminal state via ctx.signal abort.
//   failed     — retryable (attempts++).
//   timed_out  — retryable (attempts++).
//   capability denial in "authorizing" — terminal, non-retryable.
//
// Usage:
//   const exec = await executeTool(tool, rawInput, ctx, {
//     id: toolCallId,          // model's tool_call id; stable across retries
//     onTransition: (exec) => { ... },   // called on every status change
//     timeoutMs: 30_000,
//     previousAttempts: 0,     // pass previous.attempts for retry
//   });

import type { Capability } from "@/features/access-control/capability-model";
import type {
  ConfirmRequest,
  ToolContext,
  ToolDefinition,
  ToolExecution,
  ToolResult,
} from "./tool-types";

// Re-export types that callers import from here.
export type { ExecutionStatus, ToolExecution } from "./tool-types";
export type { ConfirmRequest };

// ── Options ───────────────────────────────────────────────────────────────────

export interface ExecuteToolOptions {
  /**
   * The tool_call id from the model. Stable across retries — the same id
   * links all attempts for the execution timeline.
   */
  id: string;
  /**
   * Called synchronously after every status transition with an up-to-date
   * ToolExecution snapshot. Used by the timeline UI to render progress live.
   */
  onTransition?: (exec: ToolExecution) => void;
  /**
   * Wall-clock budget for the `executing` phase in ms.
   * Defaults to 30 000 ms (30 s).
   */
  timeoutMs?: number;
  /**
   * Number of prior attempts (0 on first try). Pass `previous.attempts` when
   * retrying a failed or timed_out execution.
   */
  previousAttempts?: number;
}

// ── Engine ────────────────────────────────────────────────────────────────────

function makeError(code: string, message: string): { code: string; message: string } {
  return { code, message };
}

/**
 * Execute a tool through the full state machine.
 *
 * @param tool       - The resolved ToolDefinition from the registry.
 * @param rawInput   - Unvalidated input from the model (validated inside).
 * @param ctx        - ToolContext with tenantId, can(), queryClient, signal, confirm.
 * @param opts       - Execution options (id, onTransition, timeoutMs, previousAttempts).
 * @returns          - A settled ToolExecution (never throws).
 */
export async function executeTool(
  tool: ToolDefinition,
  rawInput: unknown,
  ctx: ToolContext,
  opts: ExecuteToolOptions,
): Promise<ToolExecution> {
  const { id, onTransition, timeoutMs = 30_000, previousAttempts = 0 } = opts;

  // Mutable snapshot; copied on every transition to produce an immutable record.
  let exec: ToolExecution = {
    id,
    toolName: tool.name,
    input: rawInput,
    status: "queued",
    startedAt: Date.now(),
    attempts: previousAttempts + 1,
  };

  function transition(
    status: ToolExecution["status"],
    patch?: Partial<Pick<ToolExecution, "result" | "error" | "endedAt">>,
  ): ToolExecution {
    exec = { ...exec, status, ...patch };
    onTransition?.(exec);
    return exec;
  }

  function terminal(
    status: Extract<ToolExecution["status"], "succeeded" | "failed" | "timed_out" | "cancelled">,
    patch?: Partial<Pick<ToolExecution, "result" | "error">>,
  ): ToolExecution {
    return transition(status, { ...patch, endedAt: Date.now() });
  }

  // ── 1. validating ──────────────────────────────────────────────────────────

  transition("validating");

  if (ctx.signal.aborted) {
    return terminal("cancelled");
  }

  const parsed = tool.input.safeParse(rawInput);
  if (!parsed.success) {
    return terminal("failed", {
      error: makeError(
        "validation_error",
        parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "),
      ),
    });
  }

  // Cast: Zod guarantees the type matches ToolDefinition<I>'s input schema.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const validatedInput: unknown = parsed.data as any;

  // ── 2. awaiting_confirmation (destructive only) ────────────────────────────

  if (tool.destructive && tool.confirm) {
    transition("awaiting_confirmation");

    if (ctx.signal.aborted) {
      return terminal("cancelled");
    }

    // Calls the application's AlertDialog; resolves on user confirm/deny.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const confirmReq: ConfirmRequest = (tool.confirm as (i: any, c: ToolContext) => ConfirmRequest)(
      validatedInput,
      ctx,
    );
    let confirmed = false;
    try {
      confirmed = await ctx.confirm(confirmReq);
    } catch {
      // If the confirm dialog throws (e.g. unmounted), treat as denial.
      confirmed = false;
    }

    if (ctx.signal.aborted) {
      return terminal("cancelled");
    }

    if (!confirmed) {
      return terminal("cancelled");
    }
  }

  // ── 3. authorizing ─────────────────────────────────────────────────────────

  transition("authorizing");

  if (ctx.signal.aborted) {
    return terminal("cancelled");
  }

  if (tool.requiredCapability && !ctx.can(tool.requiredCapability as Capability)) {
    // Terminal — non-retryable (the operator's permissions didn't change).
    return terminal("failed", {
      error: makeError(
        "capability_denied",
        `This action requires the "${tool.requiredCapability}" capability, which is not granted to your account.`,
      ),
    });
  }

  // ── 4. executing ───────────────────────────────────────────────────────────

  transition("executing");

  if (ctx.signal.aborted) {
    return terminal("cancelled");
  }

  // Timeout races the run() call.
  let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
  const timeoutPromise = new Promise<never>((_res, reject) => {
    timeoutHandle = setTimeout(
      () => reject(new DOMException("Tool execution timed out", "TimeoutError")),
      timeoutMs,
    );
  });

  let result: ToolResult;
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    result = await Promise.race([
      (tool.run as (c: ToolContext, i: any) => Promise<ToolResult>)(ctx, validatedInput),
      timeoutPromise,
    ]);
  } catch (err: unknown) {
    if (timeoutHandle !== null) clearTimeout(timeoutHandle);

    if (ctx.signal.aborted) {
      return terminal("cancelled");
    }

    const isTimeout = err instanceof DOMException && err.name === "TimeoutError";

    if (isTimeout) {
      return terminal("timed_out", {
        error: makeError("timeout", `Tool "${tool.name}" exceeded the ${timeoutMs}ms budget.`),
      });
    }

    const message =
      err instanceof Error ? err.message : typeof err === "string" ? err : "Unknown error";
    return terminal("failed", {
      error: makeError("execution_error", message),
    });
  }

  if (timeoutHandle !== null) clearTimeout(timeoutHandle);

  if (ctx.signal.aborted) {
    return terminal("cancelled");
  }

  if (!result.ok) {
    return terminal("failed", {
      result,
      error: result.error ?? makeError("tool_error", result.summary),
    });
  }

  return terminal("succeeded", { result });
}
