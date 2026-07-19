// SSE reader for a copilot turn. POSTs to the streaming endpoint and turns the
// backend's `event: <type>\ndata: <json>` frames into the typed StreamEvent
// stream the conversation UI consumes. Keep-alive comments (": ping") are
// skipped, and an aborted turn resolves to a clean `done: stopped`.

import { API_BASE_URL, tokenStore } from "@/lib/api";

import type { StreamEvent } from "./ai-provider";

function mapEvent(name: string, data: Record<string, unknown>): StreamEvent | null {
  switch (name) {
    case "thinking":
      return { type: "thinking", text: typeof data.text === "string" ? data.text : undefined };
    case "token":
      return { type: "token", text: typeof data.text === "string" ? data.text : "" };
    case "tool_call":
      return {
        type: "tool_call",
        id: String(data.id ?? ""),
        name: String(data.name ?? ""),
        input: data.input,
      };
    case "tool_result":
      return {
        type: "tool_result",
        id: String(data.id ?? ""),
        name: String(data.name ?? ""),
        status: data.status === "succeeded" ? "succeeded" : "failed",
        summary: typeof data.summary === "string" ? data.summary : "",
      };
    case "error":
      return {
        type: "error",
        code: String(data.code ?? "error"),
        message: String(data.message ?? "The assistant hit an error."),
      };
    case "done": {
      const reason = data.reason;
      return {
        type: "done",
        reason:
          reason === "tool_use" || reason === "stopped" || reason === "error" ? reason : "end_turn",
        messageId: typeof data.message_id === "string" ? data.message_id : undefined,
      };
    }
    default:
      return null;
  }
}

function parseFrame(frame: string): StreamEvent | null {
  let event = "message";
  const dataLines: string[] = [];
  for (const line of frame.split("\n")) {
    if (line.startsWith(":")) continue; // comment / keep-alive
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
  }
  if (dataLines.length === 0) return null;
  try {
    return mapEvent(event, JSON.parse(dataLines.join("\n")) as Record<string, unknown>);
  } catch {
    return null;
  }
}

export async function* streamCopilotTurn(
  path: string,
  body: unknown,
  signal: AbortSignal,
): AsyncIterable<StreamEvent> {
  const url = new URL(path.startsWith("/") ? path.slice(1) : path, `${API_BASE_URL}/`);
  const token = tokenStore.get();

  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "text/event-stream",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
      signal,
    });
  } catch {
    if (signal.aborted) {
      yield { type: "done", reason: "stopped" };
      return;
    }
    yield { type: "error", code: "network_error", message: "Could not reach the copilot service." };
    yield { type: "done", reason: "error" };
    return;
  }

  if (!res.ok || !res.body) {
    let code = `http_${res.status}`;
    let message = res.statusText || "Request failed";
    try {
      const parsed = (await res.json()) as { error?: { code?: string; message?: string } };
      if (parsed?.error) {
        code = parsed.error.code ?? code;
        message = parsed.error.message ?? message;
      }
    } catch {
      /* non-JSON error body — keep the status-derived message */
    }
    yield { type: "error", code, message };
    yield { type: "done", reason: "error" };
    return;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let sep = buffer.indexOf("\n\n");
      while (sep !== -1) {
        const frame = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        const event = parseFrame(frame);
        if (event) yield event;
        sep = buffer.indexOf("\n\n");
      }
    }
  } catch {
    if (signal.aborted) {
      yield { type: "done", reason: "stopped" };
      return;
    }
    yield { type: "error", code: "stream_error", message: "The response stream was interrupted." };
    yield { type: "done", reason: "error" };
    return;
  } finally {
    try {
      await reader.cancel();
    } catch {
      /* reader already released */
    }
  }
}
