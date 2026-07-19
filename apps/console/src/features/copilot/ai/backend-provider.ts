// AIProvider backed by the live Go copilot service. A turn streams over SSE from
// `POST /v1/copilot/conversations/{id}/messages`. Because the workspace's
// conversations are local-first, the server-side conversation is created lazily
// on the first streamed turn and its UUID is remembered on the local record.

import { api } from "@/lib/api";
import { createCopilotConversation } from "@/lib/copilot";

import { conversationActions, conversationStore } from "../store/conversation-store";
import type { AIProvider, ProviderStatus, SendInput, StreamEvent } from "./ai-provider";
import { buildTurnBody } from "./prompt-builder";
import { streamCopilotTurn } from "./streaming-client";

/** Resolve (creating if needed) the server conversation id for a local one. */
async function ensureServerConversation(localId: string): Promise<string | null> {
  const existing = conversationStore.state.conversations.find((c) => c.id === localId);
  if (existing?.serverId) return existing.serverId;
  try {
    const created = await createCopilotConversation(existing?.title);
    conversationActions.setServerConversationId(localId, created.id);
    return created.id;
  } catch {
    return null;
  }
}

export const backendProvider: AIProvider = {
  id: "backend",

  status(signal) {
    return api<ProviderStatus>("/v1/copilot/status", { signal });
  },

  async *send(input: SendInput, opts: { signal: AbortSignal }): AsyncIterable<StreamEvent> {
    const serverId = await ensureServerConversation(input.conversationId);
    if (!serverId) {
      yield {
        type: "error",
        code: "conversation_unavailable",
        message: "Could not open a conversation on the server.",
      };
      yield { type: "done", reason: "error" };
      return;
    }
    yield* streamCopilotTurn(
      `/v1/copilot/conversations/${serverId}/messages`,
      buildTurnBody(input),
      opts.signal,
    );
  },
};
