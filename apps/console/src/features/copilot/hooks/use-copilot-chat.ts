// Turn orchestration for the conversation UI. A turn can span multiple "legs":
// the model streams text, then (if it wants to act) pauses with `done: tool_use`
// and a set of tool_call requests. We execute those tools CLIENT-SIDE through the
// execution engine — under the operator's own token, so RBAC + Postgres RLS +
// audit are inherited and destructive ops are confirmed — then post the redacted
// results back to continue the turn. Loops until `end_turn` (capped). Secret
// artifacts from a tool NEVER flow back to the model; only the redacted summary
// and structured data do. Stop-generation aborts both the stream and any
// in-flight tool.

import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";

import { useCapabilities } from "@/features/access-control/capability-provider";

import type { SendInput, ToolResultInput } from "../ai/ai-provider";
import { useActiveProvider } from "../ai/use-active-provider";
import { useConsoleContext } from "../context/use-console-context";
import { useCopilotRuntime } from "../copilot-provider";
import { conversationActions, conversationStore } from "../store/conversation-store";
import { secretsActions } from "../store/secrets-store";
import { executeTool, getTool } from "../tools";
import type { ToolContext, ToolExecution } from "../tools/tool-types";

/** Hard cap on tool-use round-trips per turn, guarding against runaway loops. */
const MAX_TOOL_LEGS = 8;

type DoneReason = "end_turn" | "tool_use" | "stopped" | "error";
interface PendingToolCall {
  id: string;
  name: string;
  input: unknown;
}

export interface UseCopilotChat {
  isStreaming: boolean;
  /** True between send and the first streamed token. */
  isThinking: boolean;
  send: (text: string) => void;
  regenerate: () => void;
  editAndResend: (messageId: string, text: string) => void;
  stop: () => void;
}

/** Map a settled execution to the tool_result posted back — redacted, model-safe. */
function toToolResult(exec: ToolExecution): ToolResultInput {
  if (exec.status === "succeeded" && exec.result) {
    return {
      toolCallId: exec.id,
      name: exec.toolName,
      // summary + structured data only; sensitiveArtifact is never sent onward.
      output: { summary: exec.result.summary, ...(exec.result.data ?? {}) },
    };
  }
  return {
    toolCallId: exec.id,
    name: exec.toolName,
    error: exec.error ?? { code: "tool_failed", message: "The tool did not complete." },
  };
}

/**
 * Persist an execution to the conversation store — but FIRST divert any secret
 * artifact (OAuth secret, signing private key) to the in-memory secrets store and
 * strip it from the persisted copy. Secrets must never reach localStorage.
 */
function recordExecution(conversationId: string, messageId: string, exec: ToolExecution) {
  let safe = exec;
  if (exec.result?.sensitiveArtifact) {
    secretsActions.set(exec.id, exec.result.sensitiveArtifact);
    safe = { ...exec, result: { ...exec.result, sensitiveArtifact: undefined } };
  }
  conversationActions.upsertMessageExecution(conversationId, messageId, safe);
}

export function useCopilotChat(): UseCopilotChat {
  const provider = useActiveProvider();
  const context = useConsoleContext();
  const access = useCapabilities();
  const queryClient = useQueryClient();
  const { confirm } = useCopilotRuntime();
  const [isStreaming, setStreaming] = useState(false);
  const [isThinking, setThinking] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // Abort any in-flight turn if the component using this hook unmounts.
  useEffect(() => () => abortRef.current?.abort(), []);

  const stop = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  const runTurn = useCallback(
    (conversationId: string, userText: string) => {
      const { messageId: assistantId } = conversationActions.appendMessage({
        role: "assistant",
        content: "",
        status: "streaming",
        contextPath: context.route.pathname,
      });

      const controller = new AbortController();
      abortRef.current = controller;
      setStreaming(true);
      setThinking(true);

      const toolCtx: ToolContext = {
        tenantId: context.tenantId ?? "",
        userId: context.userId ?? "",
        console: context,
        can: access.can,
        queryClient,
        signal: controller.signal,
        confirm,
      };

      // Consume one streamed leg; collect any tool_call requests + the stop reason.
      const streamLeg = async (
        input: SendInput,
      ): Promise<{ calls: PendingToolCall[]; reason: DoneReason }> => {
        const calls: PendingToolCall[] = [];
        let reason: DoneReason = "end_turn";
        for await (const event of provider.send(input, { signal: controller.signal })) {
          switch (event.type) {
            case "thinking":
              setThinking(true);
              break;
            case "token":
              setThinking(false);
              conversationActions.appendChunk(conversationId, assistantId, event.text);
              break;
            case "tool_call":
              setThinking(false);
              calls.push({ id: event.id, name: event.name, input: event.input });
              break;
            case "error":
              conversationActions.updateMessage(conversationId, assistantId, {
                status: "error",
                error: event.message,
              });
              reason = "error";
              break;
            case "done":
              reason = event.reason;
              break;
            default:
              break;
          }
        }
        return { calls, reason };
      };

      void (async () => {
        try {
          let input: SendInput = { conversationId, message: userText, context };

          for (let leg = 0; leg < MAX_TOOL_LEGS; leg++) {
            const { calls, reason } = await streamLeg(input);

            if (reason === "stopped") {
              conversationActions.updateMessage(conversationId, assistantId, {
                status: "cancelled",
              });
              return;
            }
            if (reason === "error") return; // message already marked errored
            if (reason !== "tool_use" || calls.length === 0) {
              conversationActions.updateMessage(conversationId, assistantId, {
                status: "complete",
              });
              return;
            }

            // Execute the requested tools client-side, streaming status into the timeline.
            const results: ToolResultInput[] = [];
            for (const call of calls) {
              if (controller.signal.aborted) break;
              const tool = getTool(call.name);
              let exec: ToolExecution;
              if (!tool) {
                exec = {
                  id: call.id,
                  toolName: call.name,
                  input: call.input,
                  status: "failed",
                  startedAt: Date.now(),
                  endedAt: Date.now(),
                  attempts: 1,
                  error: { code: "unknown_tool", message: `Unknown tool: ${call.name}` },
                };
                recordExecution(conversationId, assistantId, exec);
              } else {
                exec = await executeTool(tool, call.input, toolCtx, {
                  id: call.id,
                  onTransition: (e) => recordExecution(conversationId, assistantId, e),
                });
              }
              results.push(toToolResult(exec));
            }

            if (controller.signal.aborted) {
              conversationActions.updateMessage(conversationId, assistantId, {
                status: "cancelled",
              });
              return;
            }
            input = { conversationId, toolResults: results, context };
          }

          // Reached the tool-leg cap — settle gracefully rather than loop forever.
          conversationActions.updateMessage(conversationId, assistantId, { status: "complete" });
        } catch {
          conversationActions.updateMessage(conversationId, assistantId, {
            status: "error",
            error: "The assistant could not complete this turn.",
          });
        } finally {
          if (abortRef.current === controller) abortRef.current = null;
          setStreaming(false);
          setThinking(false);
        }
      })();
    },
    [provider, context, access.can, queryClient, confirm],
  );

  const send = useCallback(
    (raw: string) => {
      const text = raw.trim();
      if (!text || abortRef.current) return;
      const { conversationId } = conversationActions.appendMessage({
        role: "user",
        content: text,
        contextPath: context.route.pathname,
      });
      runTurn(conversationId, text);
    },
    [context.route.pathname, runTurn],
  );

  const regenerate = useCallback(() => {
    if (abortRef.current) return;
    const { activeId, conversations } = conversationStore.state;
    const conv = conversations.find((c) => c.id === activeId);
    if (!conv) return;
    const lastUser = [...conv.messages].reverse().find((m) => m.role === "user");
    if (!lastUser) return;
    conversationActions.truncateAfter(conv.id, lastUser.id);
    runTurn(conv.id, lastUser.content);
  }, [runTurn]);

  const editAndResend = useCallback(
    (messageId: string, raw: string) => {
      const text = raw.trim();
      if (!text || abortRef.current) return;
      const convId = conversationStore.state.activeId;
      if (!convId) return;
      conversationActions.editUserMessage(convId, messageId, text);
      runTurn(convId, text);
    },
    [runTurn],
  );

  return { isStreaming, isThinking, send, regenerate, editAndResend, stop };
}
