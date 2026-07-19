// Ref-counted SSE subscription singleton.
// The first acquirer starts the stream; subsequent acquirers share it.
// When the last acquirer releases, the stream is stopped.
// This ensures the dashboard widget and the full activity page share
// exactly one SSE connection, regardless of mount order.

import { activityActions } from "./activity-store";
import { createActivityStream } from "./activity-stream";
import type { ActivityEvent, ConnectionStatus } from "./types";

let refCount = 0;
let client: ReturnType<typeof createActivityStream> | null = null;

function onEvents(events: ActivityEvent[]) {
  activityActions.addLiveEvents(events);
}

function onStatusChange(status: "connected" | "reconnecting" | "disconnected") {
  activityActions.setStatus(status as ConnectionStatus);
}

function onLastEventId(id: string) {
  activityActions.setLastEventId(id);
}

/**
 * Acquire a reference to the shared SSE subscription.
 * Returns a cleanup function — call it on unmount to release.
 *
 * Usage (in a React useEffect):
 * ```ts
 * useEffect(() => acquireSubscription(), []);
 * ```
 */
export function acquireSubscription(): () => void {
  refCount++;

  if (refCount === 1) {
    // First subscriber — create and start the stream
    client = createActivityStream({ onEvents, onStatusChange, onLastEventId });
    client.start();
  }

  let released = false;
  return () => {
    if (released) return;
    released = true;
    refCount = Math.max(0, refCount - 1);
    if (refCount === 0 && client) {
      client.stop();
      client = null;
    }
  };
}

/**
 * Restart the shared SSE stream after it has given up (MAX_RECONNECT_ATTEMPTS exceeded).
 * Safe to call even if the stream is already running — start() resets the backoff.
 */
export function restartStream(): void {
  if (client) {
    client.start();
  }
}

/** Visible for tests — resets the singleton state between test runs. */
export function _resetSubscriptionForTest() {
  if (client) {
    client.stop();
    client = null;
  }
  refCount = 0;
}
