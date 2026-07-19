// Copilot REST data layer over the Go backend (`/v1/copilot/*`). Conversation
// streaming lives in features/copilot/ai/streaming-client.ts; this module owns
// the plain request/reply endpoints: the provider-status probe (used to pick the
// live vs. graceful provider) and server-side conversation creation (used lazily
// the first time a local conversation streams a turn).

import { useQuery } from "@tanstack/react-query";

import { api } from "./api";

export interface CopilotStatus {
  configured: boolean;
  provider?: string;
  model?: string;
}

/** Server conversation shape (the subset the client consumes). */
export interface ServerConversation {
  id: string;
  title: string;
  pinned: boolean;
  created_at: string;
  updated_at: string;
}

export const COPILOT_STATUS_KEY = ["copilot", "status"] as const;

/**
 * Whether a model provider is configured on the server. Cached for a few minutes
 * and non-retrying — an unconfigured deployment is a normal steady state, not an
 * error, so it must not spam the network or toast.
 */
export function useCopilotStatus() {
  return useQuery({
    queryKey: COPILOT_STATUS_KEY,
    queryFn: ({ signal }) => api<CopilotStatus>("/v1/copilot/status", { signal }),
    staleTime: 5 * 60_000,
    retry: false,
    meta: { silent: true },
  });
}

/** Create a server-side conversation and return it (id used for streaming). */
export function createCopilotConversation(title?: string): Promise<ServerConversation> {
  return api<ServerConversation>("/v1/copilot/conversations", {
    method: "POST",
    body: title ? { title } : {},
  });
}
