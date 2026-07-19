// TanStack Query hook for fetching the historical activity event log
// via GET /v1/activity with cursor-based pagination.
// 404 and network errors are treated as empty pages to prevent console crashes
// when the backend endpoint is not yet deployed.

import { useInfiniteQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";

import type { ActivityEvent, ActivityFilters } from "./types";

export type ActivityHistoryPage = {
  events: ActivityEvent[];
  next_cursor?: string;
};

const HISTORY_LIMIT = 50;

function buildQuery(
  filters: ActivityFilters,
  cursor: string,
): Record<string, string | number | undefined> {
  return {
    limit: HISTORY_LIMIT,
    cursor: cursor || undefined,
    types: filters.types.join(",") || undefined,
    severity: filters.severity.join(",") || undefined,
    category: filters.category.join(",") || undefined,
    actor: filters.actor || undefined,
    q: filters.q || undefined,
    from: filters.from || undefined,
    to: filters.to || undefined,
    source: filters.source || undefined,
    status: filters.status || undefined,
  };
}

/**
 * Loads paginated historical activity events from GET /v1/activity.
 * Returns empty pages on 404/network errors (graceful degradation while
 * the backend is being deployed in parallel).
 */
export function useActivityHistory(filters: ActivityFilters, enabled = true) {
  return useInfiniteQuery({
    queryKey: ["activity-history", filters] as const,
    queryFn: async ({ pageParam }: { pageParam: string }) => {
      const query = buildQuery(filters, pageParam);
      try {
        return await api<ActivityHistoryPage>("/v1/activity", { query });
      } catch (err) {
        // Treat 404 (not deployed) and network errors as empty pages
        const status = (err as { status?: number }).status;
        if (!status || status === 404 || status === 503) {
          return { events: [], next_cursor: undefined };
        }
        throw err;
      }
    },
    initialPageParam: "",
    getNextPageParam: (page: ActivityHistoryPage) => page.next_cursor ?? undefined,
    enabled,
    staleTime: 30_000,
    meta: { silent: true },
  });
}
