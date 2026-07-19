// The AI provider seam (Phase 0, frozen contract). Everything the workspace
// needs from "the model" is a typed async stream, so the conversation UI is
// identical whether tokens come from the server-side SSE endpoint
// (backend-provider) or the graceful-degradation stub (unconfigured-provider).
// Swapping providers never touches the UI.

import type { ConsoleContext } from "../context/context-types";

/**
 * Discriminated stream of everything one turn can emit. `token` carries visible
 * text; `thinking` drives the pre-text indicator; `tool_call`/`tool_result`
 * feed the execution timeline; `error`/`done` are terminal. `done.reason`
 * distinguishes a finished answer (`end_turn`) from a pause for client-side
 * tool execution (`tool_use`).
 */
export type StreamEvent =
  | { type: "thinking"; text?: string }
  | { type: "token"; text: string }
  | { type: "tool_call"; id: string; name: string; input: unknown }
  | {
      type: "tool_result";
      id: string;
      name: string;
      status: "succeeded" | "failed";
      summary: string;
    }
  | { type: "error"; code: string; message: string }
  | { type: "done"; reason: "end_turn" | "tool_use" | "stopped" | "error"; messageId?: string };

/** Result of a client-executed tool, posted back to continue the turn. */
export interface ToolResultInput {
  toolCallId: string;
  name: string;
  output?: unknown;
  error?: { code: string; message: string };
}

/**
 * One `send`: either a new user message, or the results of tools the previous
 * turn requested (to resume orchestration). `context` grounds the model and is
 * treated as untrusted on the server.
 */
export interface SendInput {
  conversationId: string;
  message?: string;
  toolResults?: ToolResultInput[];
  context: ConsoleContext;
}

export interface ProviderStatus {
  configured: boolean;
  provider?: string;
  model?: string;
}

export interface AIProvider {
  /** Stable identifier, e.g. "backend" or "unconfigured". */
  readonly id: string;
  /** Whether real inference is wired up (drives the connect-a-provider CTA). */
  status(signal?: AbortSignal): Promise<ProviderStatus>;
  /** Stream a turn. Implementations must honour `opts.signal` (stop generation). */
  send(input: SendInput, opts: { signal: AbortSignal }): AsyncIterable<StreamEvent>;
}

/** Raised when a turn is aborted via its AbortSignal — callers treat as cancel. */
export class ChatAbortError extends Error {
  constructor() {
    super("Generation stopped");
    this.name = "ChatAbortError";
  }
}
