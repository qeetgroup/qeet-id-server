// TimelineProvider — context for the per-user identity timeline.
// Wraps the TanStack Query infinite hook, client-side filtering, and
// date-grouping into a single context consumed by the timeline components.

import { useStore } from "@tanstack/react-store";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
} from "react";

import { useCapabilities } from "@/features/access-control/capability-provider";
import { applyFilters } from "@/features/activity/filter-manager";
import type { ActivityEvent, DateGroup } from "@/features/activity/types";
import { groupTimelineByDate } from "./grouping";
import { type TimelineFilters, timelineActions, timelineStore } from "./timeline-store";
import { useIdentityTimeline } from "./use-identity-timeline";

// ---------------------------------------------------------------------------
// Context contract
// ---------------------------------------------------------------------------

export type TimelineContextValue = {
  /** Filtered events (newest-first). */
  events: ActivityEvent[];
  /** Events grouped by date bucket for the vertical timeline display. */
  groups: DateGroup[];
  /** Currently active filter values. */
  filters: TimelineFilters;
  /** ID of the selected event (drives the details drawer). */
  selectedEventId: string | null;
  setFilters: (patch: Partial<TimelineFilters>) => void;
  resetFilters: () => void;
  setSelectedEventId: (id: string | null) => void;
  /** Whether the first page is loading. */
  isLoading: boolean;
  /** Whether a subsequent page is loading. */
  isFetchingNextPage: boolean;
  /** Whether more pages are available. */
  hasNextPage: boolean;
  /** Trigger loading the next page (for IntersectionObserver sentinel). */
  fetchNextPage: () => void;
  /** True when the history fetch failed with a non-graceful error. */
  isError: boolean;
  /** Re-fetch the current pages. */
  retry: () => void;
};

const TimelineContext = createContext<TimelineContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function TimelineProvider({ userId, children }: { userId: string; children: ReactNode }) {
  const access = useCapabilities();
  // Both audit.read AND user.read are required to view the timeline.
  const canRead = access.can("audit.read") && access.can("user.read");

  const filters = useStore(timelineStore, (s) => s.filters);
  const selectedEventId = useStore(timelineStore, (s) => s.selectedEventId);

  // Clear the drawer selection when the target user changes mid-session.
  // prevUserIdRef lets us skip the initial mount (selection is null already).
  const prevUserIdRef = useRef(userId);
  useEffect(() => {
    if (prevUserIdRef.current === userId) return;
    prevUserIdRef.current = userId;
    timelineActions.clearSelection();
  }, [userId]);

  const query = useIdentityTimeline(userId, filters, canRead);

  // Flatten all loaded pages into a single event array.
  const allEvents = useMemo(() => query.data?.pages.flatMap((p) => p.events) ?? [], [query.data]);

  // Convert TimelineFilters to ActivityFilters shape so we can reuse applyFilters.
  // The unused ActivityFilters fields (actor, source, status, types) are zeroed out.
  const activityFilters = useMemo(
    () => ({
      types: [] as string[],
      severity: filters.severity,
      category: filters.category,
      actor: "",
      q: filters.q,
      from: filters.from,
      to: filters.to,
      source: "",
      status: "",
    }),
    [filters],
  );

  // Client-side filter pass for instant feedback on chip toggles.
  const filteredEvents = useMemo(
    () => applyFilters(allEvents, activityFilters),
    [allEvents, activityFilters],
  );

  const groups = useMemo(() => groupTimelineByDate(filteredEvents), [filteredEvents]);

  const fetchNextPage = useCallback(() => {
    void query.fetchNextPage();
  }, [query.fetchNextPage]);

  const retry = useCallback(() => {
    void query.refetch();
  }, [query.refetch]);

  const value = useMemo<TimelineContextValue>(
    () => ({
      events: filteredEvents,
      groups,
      filters,
      selectedEventId,
      setFilters: timelineActions.setFilters,
      resetFilters: timelineActions.resetFilters,
      setSelectedEventId: timelineActions.setSelectedEventId,
      isLoading: query.isLoading,
      isFetchingNextPage: query.isFetchingNextPage,
      hasNextPage: query.hasNextPage,
      fetchNextPage,
      isError: query.isError,
      retry,
    }),
    [
      filteredEvents,
      groups,
      filters,
      selectedEventId,
      query.isLoading,
      query.isFetchingNextPage,
      query.hasNextPage,
      query.isError,
      fetchNextPage,
      retry,
    ],
  );

  return <TimelineContext.Provider value={value}>{children}</TimelineContext.Provider>;
}

export function useTimeline(): TimelineContextValue {
  const ctx = useContext(TimelineContext);
  if (!ctx) throw new Error("useTimeline must be used inside TimelineProvider");
  return ctx;
}
