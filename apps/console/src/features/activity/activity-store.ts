// TanStack Store for live activity events streamed via SSE.
// Holds ONLY live events (newest-first, rolling buffer).
// Historical pages are managed separately by TanStack Query.

import { Store } from "@tanstack/react-store";

import type { ActivityEvent, ConnectionStatus } from "./types";

const MAX_LIVE = 200;
const PREFS_KEY = "qeetid.activity.prefs";

export interface ActivityStoreState {
  /** Newest-first live events from the SSE stream. Capped at MAX_LIVE. */
  liveEvents: ActivityEvent[];
  /** Events queued while paused; flushed on resume. */
  pendingBuffer: ActivityEvent[];
  /** Count of live events added since the last markAllRead(). */
  unreadCount: number;
  /** When true, incoming live events go to pendingBuffer instead of liveEvents. */
  paused: boolean;
  /** SSE connection state. */
  status: ConnectionStatus;
  /** Last received SSE event id — sent as Last-Event-ID on reconnect. */
  lastEventId: string | null;
}

/** Module-level deduplication cache. Cleared by clearAll(). */
const seenIds = new Set<string>();

export const activityStore = new Store<ActivityStoreState>({
  liveEvents: [],
  pendingBuffer: [],
  unreadCount: 0,
  paused: false,
  status: "disconnected",
  lastEventId: null,
});

/** Load lightweight prefs from localStorage. Call once from the provider's mount effect. */
export function initActivityPrefs() {
  if (typeof window === "undefined") return;
  try {
    const raw = window.localStorage.getItem(PREFS_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw) as { paused?: boolean };
    if (parsed.paused) {
      activityStore.setState((s) => ({ ...s, paused: true, status: "paused" as ConnectionStatus }));
    }
  } catch {
    /* corrupt payload — start with defaults */
  }
}

function savePrefs(paused: boolean) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(PREFS_KEY, JSON.stringify({ paused }));
  } catch {
    /* best-effort */
  }
}

/** Returns events not already seen, preserving order. */
function dedupeNew(incoming: ActivityEvent[]): ActivityEvent[] {
  const fresh: ActivityEvent[] = [];
  for (const e of incoming) {
    if (!seenIds.has(e.id)) {
      seenIds.add(e.id);
      fresh.push(e);
    }
  }
  return fresh;
}

export const activityActions = {
  /**
   * Add live events from the SSE stream.
   * When paused, events are queued in pendingBuffer.
   * When active, events are prepended to liveEvents.
   */
  addLiveEvents(incoming: ActivityEvent[]) {
    activityStore.setState((s) => {
      if (s.paused) {
        // Check seenIds without adding — IDs are committed to seenIds on flush,
        // so that dedupeNew in setPaused(false) can still mark them properly.
        const trulyNew = incoming.filter((e) => !seenIds.has(e.id));
        if (trulyNew.length === 0) return s;
        return { ...s, pendingBuffer: [...trulyNew, ...s.pendingBuffer] };
      }
      const fresh = dedupeNew(incoming);
      if (fresh.length === 0) return s;
      const liveEvents = [...fresh, ...s.liveEvents].slice(0, MAX_LIVE);
      const latestId = fresh[0]?.id ?? s.lastEventId;
      return {
        ...s,
        liveEvents,
        unreadCount: s.unreadCount + fresh.length,
        lastEventId: latestId ?? null,
      };
    });
  },

  setPaused(paused: boolean) {
    activityStore.setState((s) => {
      if (paused === s.paused) return s;
      if (paused) {
        savePrefs(true);
        return { ...s, paused: true, status: "paused" as ConnectionStatus };
      }
      // Resume: flush pending buffer
      const fresh = dedupeNew(s.pendingBuffer);
      const liveEvents = [...fresh, ...s.liveEvents].slice(0, MAX_LIVE);
      const latestId = fresh[0]?.id ?? s.lastEventId;
      savePrefs(false);
      return {
        ...s,
        paused: false,
        status: "connected" as ConnectionStatus,
        pendingBuffer: [],
        liveEvents,
        unreadCount: s.unreadCount + fresh.length,
        lastEventId: latestId ?? null,
      };
    });
  },

  setStatus(status: ConnectionStatus) {
    activityStore.setState((s) => {
      // Don't overwrite the "paused" status with stream connection changes
      if (s.paused && status !== "paused") return s;
      return { ...s, status };
    });
  },

  setLastEventId(id: string) {
    activityStore.setState((s) => ({ ...s, lastEventId: id }));
  },

  markAllRead() {
    activityStore.setState((s) => ({ ...s, unreadCount: 0 }));
  },

  clearAll() {
    seenIds.clear();
    activityStore.setState((_s) => ({
      liveEvents: [],
      pendingBuffer: [],
      unreadCount: 0,
      paused: false,
      status: "disconnected" as ConnectionStatus,
      lastEventId: null,
    }));
  },
};

/** Exported for unit tests only. */
export { seenIds as _seenIds };
