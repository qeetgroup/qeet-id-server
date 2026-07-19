// Selects the AIProvider the workspace talks to: the live backend SSE provider
// whenever `/v1/copilot/status` reports `configured: true`, otherwise the
// graceful-degradation stub. Isolated here so the switch touches one file, never
// the conversation UI.

import { useMemo } from "react";

import { useCopilotStatus } from "@/lib/copilot";

import type { AIProvider } from "./ai-provider";
import { backendProvider } from "./backend-provider";
import { unconfiguredProvider } from "./unconfigured-provider";

export function useActiveProvider(): AIProvider {
  const status = useCopilotStatus();
  return useMemo(
    () => (status.data?.configured ? backendProvider : unconfiguredProvider),
    [status.data?.configured],
  );
}
