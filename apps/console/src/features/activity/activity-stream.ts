// SSE activity stream client. Mirrors the proven pattern from
// features/copilot/ai/streaming-client.ts but for GET-based SSE,
// with reconnect + exponential backoff and Last-Event-ID replay.
// Do NOT import from features/copilot — this is a standalone client.

import { API_BASE_URL, tokenStore } from "@/lib/api";

import type { ActivityEvent } from "./types";

// ---------------------------------------------------------------------------
// Frame parsing
// ---------------------------------------------------------------------------

/**
 * Parse a single SSE frame (the text between two double-newlines) into an
 * ActivityEvent. Returns null for keep-alive comments (": …"), unknown
 * event types, or malformed JSON.
 */
export function parseActivityFrame(frame: string): ActivityEvent | null {
  let eventType = "activity";
  const dataLines: string[] = [];

  for (const line of frame.split("\n")) {
    if (line.startsWith(":")) continue; // keep-alive / comment
    if (line.startsWith("event:")) {
      eventType = line.slice(6).trim();
      continue;
    }
    if (line.startsWith("data:")) {
      dataLines.push(line.slice(5).trim());
    }
  }

  if (eventType !== "activity") return null;
  if (dataLines.length === 0) return null;

  try {
    const data = JSON.parse(dataLines.join("\n")) as Partial<ActivityEvent>;
    if (typeof data.id !== "string" || !data.id) return null;
    if (typeof data.type !== "string") return null;
    // Minimal validation — backend enforces the full schema
    return data as ActivityEvent;
  } catch {
    return null;
  }
}

/** Extract the SSE `id:` field from a frame string. */
function extractFrameId(frame: string): string | null {
  for (const line of frame.split("\n")) {
    if (line.startsWith("id:")) return line.slice(3).trim();
  }
  return null;
}

// ---------------------------------------------------------------------------
// Stream client
// ---------------------------------------------------------------------------

const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 30_000;
const BACKOFF_MULTIPLIER = 2;
const BURST_FLUSH_MS = 50;
/** After this many consecutive failed reconnect attempts the stream gives up and
 *  calls onStatusChange("disconnected"). Call start() again to retry. */
const MAX_RECONNECT_ATTEMPTS = 5;

export type ActivityStreamCallbacks = {
  onEvents: (events: ActivityEvent[]) => void;
  onStatusChange: (status: "connected" | "reconnecting" | "disconnected") => void;
  onLastEventId: (id: string) => void;
};

/**
 * Creates an SSE activity stream client. Returns an object with `start()` and
 * `stop()` methods. The callbacks are called from within the async loop.
 * Safe to call `stop()` from any context — it aborts any in-flight fetch.
 */
export function createActivityStream(callbacks: ActivityStreamCallbacks) {
  let stopped = false;
  let abortController: AbortController | null = null;
  let backoffMs = INITIAL_BACKOFF_MS;
  let backoffTimer: ReturnType<typeof setTimeout> | null = null;
  let flushTimer: ReturnType<typeof setTimeout> | null = null;
  let burstBuffer: ActivityEvent[] = [];
  let lastEventId: string | null = null;
  /** Consecutive failed reconnect attempts. Reset on successful connection or explicit start(). */
  let reconnectAttempts = 0;

  function flushBurst() {
    flushTimer = null;
    if (burstBuffer.length === 0) return;
    const toFlush = burstBuffer;
    burstBuffer = [];
    callbacks.onEvents(toFlush);
  }

  function scheduleFlush(event: ActivityEvent) {
    burstBuffer.push(event);
    if (!flushTimer) {
      flushTimer = setTimeout(flushBurst, BURST_FLUSH_MS);
    }
  }

  function scheduleReconnect() {
    if (stopped) return;
    reconnectAttempts++;
    if (reconnectAttempts > MAX_RECONNECT_ATTEMPTS) {
      // Give up after MAX_RECONNECT_ATTEMPTS consecutive failures.
      // The caller can restart by calling start() again.
      stopped = true;
      callbacks.onStatusChange("disconnected");
      return;
    }
    callbacks.onStatusChange("reconnecting");
    const delay = backoffMs;
    backoffMs = Math.min(backoffMs * BACKOFF_MULTIPLIER, MAX_BACKOFF_MS);
    backoffTimer = setTimeout(() => {
      void connect();
    }, delay);
  }

  async function connect() {
    if (stopped) return;

    abortController = new AbortController();
    const { signal } = abortController;

    callbacks.onStatusChange("reconnecting");

    const url = new URL("v1/activity/stream", `${API_BASE_URL}/`);
    const token = tokenStore.get();
    const headers: Record<string, string> = {
      Accept: "text/event-stream",
      "Cache-Control": "no-cache",
    };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (lastEventId) headers["Last-Event-ID"] = lastEventId;

    let res: Response;
    try {
      res = await fetch(url, { method: "GET", headers, signal });
    } catch {
      if (stopped || signal.aborted) return;
      scheduleReconnect();
      return;
    }

    if (!res.ok || !res.body) {
      if (stopped) return;
      // 404 / 503 = backend not yet deployed; back off and retry silently
      scheduleReconnect();
      return;
    }

    // Successful connection — reset backoff and consecutive-failure counter
    backoffMs = INITIAL_BACKOFF_MS;
    reconnectAttempts = 0;
    callbacks.onStatusChange("connected");

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      while (!stopped) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        let sep = buffer.indexOf("\n\n");

        while (sep !== -1) {
          const frame = buffer.slice(0, sep);
          buffer = buffer.slice(sep + 2);

          // Track the SSE event id for Last-Event-ID replay
          const frameId = extractFrameId(frame);
          if (frameId) {
            lastEventId = frameId;
            callbacks.onLastEventId(frameId);
          }

          const event = parseActivityFrame(frame);
          if (event) scheduleFlush(event);

          sep = buffer.indexOf("\n\n");
        }
      }
    } catch {
      if (stopped || signal.aborted) return;
    } finally {
      try {
        await reader.cancel();
      } catch {
        /* reader already released */
      }
    }

    if (!stopped) scheduleReconnect();
  }

  return {
    start() {
      stopped = false;
      backoffMs = INITIAL_BACKOFF_MS;
      reconnectAttempts = 0;
      void connect();
    },
    stop() {
      stopped = true;
      if (backoffTimer !== null) {
        clearTimeout(backoffTimer);
        backoffTimer = null;
      }
      if (flushTimer !== null) {
        clearTimeout(flushTimer);
        // Flush any buffered events synchronously so nothing is dropped
        flushBurst();
      }
      abortController?.abort();
      abortController = null;
      callbacks.onStatusChange("disconnected");
    },
  };
}
