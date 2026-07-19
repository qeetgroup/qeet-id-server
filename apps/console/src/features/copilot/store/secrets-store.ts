// In-memory ONLY (never persisted) store for secret material a tool surfaces for
// a one-time reveal — OAuth client secrets, OIDC signing private keys. Keyed by
// tool-execution id. This exists BECAUSE the conversation store persists to
// localStorage: secrets must never be written there (a leaked signing key = token
// forgery for the whole tenant), so they live here, in memory, and are gone on
// reload — genuinely "shown once". Security review HIGH finding.

import { Store, useStore } from "@tanstack/react-store";

import type { ToolResult } from "../tools/tool-types";

export type SensitiveArtifact = NonNullable<ToolResult["sensitiveArtifact"]>;

const secretsStore = new Store<Record<string, SensitiveArtifact>>({});

export const secretsActions = {
  /** Record a secret artifact for one-time reveal (in memory only). */
  set(executionId: string, artifact: SensitiveArtifact) {
    secretsStore.setState((s) => ({ ...s, [executionId]: artifact }));
  },
  /** Drop a secret (e.g. after the user has copied/dismissed it). */
  clear(executionId: string) {
    secretsStore.setState((s) => {
      if (!(executionId in s)) return s;
      const next = { ...s };
      delete next[executionId];
      return next;
    });
  },
};

/** Reactively read the (in-memory) secret artifact for an execution, if any. */
export function useSensitiveArtifact(executionId: string): SensitiveArtifact | undefined {
  return useStore(secretsStore, (s) => s[executionId]);
}
