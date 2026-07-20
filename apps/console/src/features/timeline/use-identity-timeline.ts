// TanStack Query infinite hook for the per-user identity timeline.
// Debounces the `q` filter (full-text search) to avoid excessive API calls
// while the user types; all other filters (category, severity, date range)
// are applied immediately.

import { useInfiniteQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { fetchTimelinePage } from "./timeline-service";
import type { TimelineFilters } from "./timeline-store";

const DEBOUNCE_MS = 400;

/**
 * Loads paginated timeline events for a specific user via cursor pagination.
 * Uses `placeholderData: (prev) => prev` to prevent flicker when filters change.
 *
 * @param userId - The user whose timeline to load.
 * @param filters - Active filter state from timelineStore.
 * @param enabled - Set false when the caller lacks `audit.read` capability.
 */
export function useIdentityTimeline(userId: string, filters: TimelineFilters, enabled = true) {
  // Debounce only the search query to limit API calls on every keystroke.
  // Category/severity/date filters fire immediately (low-volume, single-shot).
  const [debouncedQ, setDebouncedQ] = useState(filters.q);

  useEffect(() => {
    if (filters.q === debouncedQ) return;
    const id = setTimeout(() => setDebouncedQ(filters.q), DEBOUNCE_MS);
    return () => clearTimeout(id);
  }, [filters.q, debouncedQ]);

  // Compose the effective filters with the debounced search query.
  const effectiveFilters: TimelineFilters = { ...filters, q: debouncedQ };

  return useInfiniteQuery({
    queryKey: ["identity-timeline", userId, effectiveFilters] as const,
    queryFn: ({ pageParam }: { pageParam: string }) =>
      fetchTimelinePage(userId, effectiveFilters, pageParam),
    initialPageParam: "",
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    enabled: enabled && !!userId,
    staleTime: 30_000,
    // Retain previous page data while new pages load to avoid blank flash.
    placeholderData: (prev) => prev,
    meta: { silent: true },
  });
}
