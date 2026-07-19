// TanStack Store for timeline filter state and event selection.
// Historical events themselves are managed by TanStack Query (use-identity-timeline.ts).
// Filters are not persisted — they reset when the page is unmounted.

import { Store } from "@tanstack/react-store";

import type { Severity } from "@/features/activity/types";

export interface TimelineFilters {
  /** Category chips filter — empty means "everything". */
  category: string[];
  /** Severity badges filter — empty means "all severities". */
  severity: Severity[];
  /** Full-text search query (debounced before sending to the API). */
  q: string;
  /** ISO 8601 date lower bound (from). */
  from: string;
  /** ISO 8601 date upper bound (to). */
  to: string;
}

export const DEFAULT_TIMELINE_FILTERS: TimelineFilters = {
  category: [],
  severity: [],
  q: "",
  from: "",
  to: "",
};

export interface TimelineStoreState {
  filters: TimelineFilters;
  /** ID of the currently selected event; drives the details drawer. */
  selectedEventId: string | null;
}

export const timelineStore = new Store<TimelineStoreState>({
  filters: DEFAULT_TIMELINE_FILTERS,
  selectedEventId: null,
});

export const timelineActions = {
  setFilters(patch: Partial<TimelineFilters>) {
    timelineStore.setState((s) => ({
      ...s,
      filters: { ...s.filters, ...patch },
    }));
  },

  resetFilters() {
    timelineStore.setState((s) => ({
      ...s,
      filters: DEFAULT_TIMELINE_FILTERS,
    }));
  },

  setSelectedEventId(id: string | null) {
    timelineStore.setState((s) => ({ ...s, selectedEventId: id }));
  },

  /** Called when navigating to a new user's timeline to clear stale selection. */
  clearSelection() {
    timelineStore.setState((s) => ({ ...s, selectedEventId: null }));
  },
};
