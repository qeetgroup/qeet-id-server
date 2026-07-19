// Translates a SendInput into the wire body the backend `…/messages` endpoint
// expects. The server owns the system prompt; the client only forwards the raw
// user message (or tool results) plus the grounding context, converting the
// frontend's camelCase tool-result shape to the backend's snake_case.

import type { SendInput } from "./ai-provider";

export interface CopilotTurnBody {
  message?: string;
  tool_results?: {
    tool_call_id: string;
    name: string;
    output?: unknown;
    error?: { code: string; message: string };
  }[];
  context: unknown;
}

export function buildTurnBody(input: SendInput): CopilotTurnBody {
  return {
    message: input.message,
    tool_results: input.toolResults?.map((result) => ({
      tool_call_id: result.toolCallId,
      name: result.name,
      output: result.output,
      error: result.error,
    })),
    context: input.context,
  };
}
