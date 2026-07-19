// Base fetch logic for the identity timeline.
// Builds the query string, calls the API, and normalises 404/503 as empty pages
// (graceful degradation while the backend `subject` filter is being deployed).

import type { ActivityEvent } from "@/features/activity/types";
import { api } from "@/lib/api";
import type { TimelineFilters } from "./timeline-store";

export type TimelinePage = {
  events: ActivityEvent[];
  next_cursor?: string;
};

export const TIMELINE_LIMIT = 50;

/**
 * Builds the query params for GET /v1/activity?subject={userId}.
 * Arrays are joined as comma-separated strings; empty strings are omitted.
 */
export function buildTimelineQuery(
  userId: string,
  filters: TimelineFilters,
  cursor: string,
): Record<string, string | number | undefined> {
  return {
    subject: userId,
    limit: TIMELINE_LIMIT,
    cursor: cursor || undefined,
    category: filters.category.join(",") || undefined,
    severity: filters.severity.join(",") || undefined,
    q: filters.q || undefined,
    from: filters.from || undefined,
    to: filters.to || undefined,
  };
}

/**
 * Fetches one page of timeline events from GET /v1/activity?subject={userId}.
 * Returns an empty page on 404 (endpoint not yet deployed), 503, or network
 * failure — the timeline degrades gracefully in those cases.
 */
export async function fetchTimelinePage(
  userId: string,
  filters: TimelineFilters,
  cursor: string,
): Promise<TimelinePage> {
  const query = buildTimelineQuery(userId, filters, cursor);
  try {
    return await api<TimelinePage>("/v1/activity", { query });
  } catch (err) {
    const status = (err as { status?: number }).status;
    // Treat "not deployed yet" and service-unavailable as empty (never crash).
    if (!status || status === 404 || status === 503) {
      return { events: [], next_cursor: undefined };
    }
    throw err;
  }
}
