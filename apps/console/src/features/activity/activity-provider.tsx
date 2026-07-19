// ActivityProvider — React context for the full Live Activity Center.
// Mounts the shared SSE subscription, loads history, and provides a merged,
// filtered view of live + historical events with controls (pause, mark-read).
//
// The dashboard widget bypasses this context and reads directly from
// activityStore + acquireSubscription — see use-dashboard-activity.ts.

import { useStore } from "@tanstack/react-store";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { useCapabilities } from "@/features/access-control/capability-provider";
import { useActivityHistory } from "./activity-service";
import { activityActions, activityStore, initActivityPrefs } from "./activity-store";
import { applyFilters, groupByDate } from "./filter-manager";
import { acquireSubscription, restartStream } from "./subscription-manager";
import {
  type ActivityEvent,
  type ActivityFilters,
  type ConnectionStatus,
  type DateGroup,
  DEFAULT_FILTERS,
} from "./types";

// ---------------------------------------------------------------------------
// Context contract
// ---------------------------------------------------------------------------

type ActivityContextValue = {
  /** Merged live + historical events (newest-first, filtered). */
  filteredEvents: ActivityEvent[];
  /** Events grouped by date bucket: Today / Yesterday / This Week / Older. */
  groups: DateGroup[];
  /** Count of live events added since the last markAllRead(). */
  unreadCount: number;
  /** Whether the live stream is paused (live events queue but don't render). */
  paused: boolean;
  /** SSE connection state. */
  status: ConnectionStatus;
  /** Active filter values. */
  filters: ActivityFilters;
  setFilters: (patch: Partial<ActivityFilters>) => void;
  resetFilters: () => void;
  markAllRead: () => void;
  pause: () => void;
  resume: () => void;
  /** Whether the first history page is loading. */
  isLoadingHistory: boolean;
  /** Whether a subsequent history page is loading. */
  isFetchingNextPage: boolean;
  /** Whether there are more history pages to load. */
  hasNextPage: boolean;
  /** Trigger loading the next history page (infinite scroll). */
  fetchNextPage: () => void;
  /** Set of IDs of events that arrived since this provider mounted (for "new" highlights). */
  newEventIds: ReadonlySet<string>;
  /** True when the history fetch failed with a non-graceful error. */
  isHistoryError: boolean;
  /** Re-fetch the history page from the server. */
  retryHistory: () => void;
  /** Restart the SSE stream after it has given up (MAX_RECONNECT_ATTEMPTS exceeded). */
  retryStream: () => void;
};

const ActivityContext = createContext<ActivityContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function ActivityProvider({ children }: { children: ReactNode }) {
  const access = useCapabilities();
  const canRead = access.can("audit.read");

  // Store slices (subscribe only to what we need)
  const liveEvents = useStore(activityStore, (s) => s.liveEvents);
  const unreadCount = useStore(activityStore, (s) => s.unreadCount);
  const paused = useStore(activityStore, (s) => s.paused);
  const status = useStore(activityStore, (s) => s.status);

  // Filters — local state (not persisted; too ephemeral)
  const [filters, setFiltersState] = useState<ActivityFilters>(DEFAULT_FILTERS);

  // Track IDs that were already in the store when this provider mounted
  // so we can highlight events that arrived after navigation.
  const seedIdsRef = useRef<ReadonlySet<string> | null>(null);
  if (seedIdsRef.current === null) {
    seedIdsRef.current = new Set(liveEvents.map((e) => e.id));
  }

  // Load prefs (paused state) once on mount
  useEffect(() => {
    initActivityPrefs();
  }, []);

  // Acquire the shared SSE subscription
  useEffect(() => {
    if (!canRead) return;
    return acquireSubscription();
  }, [canRead]);

  // History query (re-fetches when filters change)
  const history = useActivityHistory(filters, canRead);

  // Merge live + history, deduped by id
  const allEvents = useMemo(() => {
    const historyEvents = (history.data?.pages ?? []).flatMap((p) => p.events);
    // liveEvents are newest-first; history is oldest-first within pages.
    // Dedup history against live events by building a Set from live event ids.
    const liveIds = new Set(liveEvents.map((e) => e.id));
    const uniqueHistory = historyEvents.filter((e) => !liveIds.has(e.id));
    return [...liveEvents, ...uniqueHistory];
  }, [liveEvents, history.data]);

  const filteredEvents = useMemo(() => applyFilters(allEvents, filters), [allEvents, filters]);
  const groups = useMemo(() => groupByDate(filteredEvents), [filteredEvents]);

  // Track which events are "new" (arrived after this provider mounted)
  const newEventIds = useMemo<ReadonlySet<string>>(() => {
    const seed = seedIdsRef.current;
    if (!seed) return new Set<string>();
    const newIds = new Set<string>();
    for (const e of liveEvents) {
      if (!seed.has(e.id)) newIds.add(e.id);
    }
    return newIds;
  }, [liveEvents]);

  const setFilters = useCallback(
    (patch: Partial<ActivityFilters>) => setFiltersState((prev) => ({ ...prev, ...patch })),
    [],
  );
  const resetFilters = useCallback(() => setFiltersState(DEFAULT_FILTERS), []);
  const fetchNextPage = useCallback(() => {
    void history.fetchNextPage();
  }, [history.fetchNextPage]);

  const retryHistory = useCallback(() => {
    void history.refetch();
  }, [history.refetch]);

  const value = useMemo<ActivityContextValue>(
    () => ({
      filteredEvents,
      groups,
      unreadCount,
      paused,
      status,
      filters,
      setFilters,
      resetFilters,
      markAllRead: activityActions.markAllRead,
      pause: () => activityActions.setPaused(true),
      resume: () => activityActions.setPaused(false),
      isLoadingHistory: history.isLoading,
      isFetchingNextPage: history.isFetchingNextPage,
      hasNextPage: history.hasNextPage,
      fetchNextPage,
      newEventIds,
      isHistoryError: history.isError,
      retryHistory,
      retryStream: restartStream,
    }),
    [
      filteredEvents,
      groups,
      unreadCount,
      paused,
      status,
      filters,
      setFilters,
      resetFilters,
      history.isLoading,
      history.isFetchingNextPage,
      history.hasNextPage,
      history.isError,
      fetchNextPage,
      newEventIds,
      retryHistory,
    ],
  );

  return <ActivityContext.Provider value={value}>{children}</ActivityContext.Provider>;
}

export function useActivity(): ActivityContextValue {
  const ctx = useContext(ActivityContext);
  if (!ctx) throw new Error("useActivity must be used inside ActivityProvider");
  return ctx;
}
