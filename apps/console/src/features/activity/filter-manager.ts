// Pure filter and grouping functions for the activity feed.
// No side effects, no imports from React or the store — easy to unit-test.

import type { ActivityEvent, ActivityFilters, DateGroup, Severity } from "./types";

/** Returns true if the event matches all active filters. */
export function matchesFilters(event: ActivityEvent, filters: ActivityFilters): boolean {
  if (filters.types.length > 0 && !filters.types.includes(event.type)) return false;
  if (filters.severity.length > 0 && !filters.severity.includes(event.severity)) return false;
  if (filters.category.length > 0 && !filters.category.includes(event.category)) return false;
  if (filters.status && event.status !== filters.status) return false;
  if (filters.source && event.source !== filters.source) return false;
  if (filters.actor) {
    const q = filters.actor.toLowerCase();
    const actorMatch =
      (event.actor?.name?.toLowerCase().includes(q) ?? false) ||
      (event.actor?.id?.toLowerCase().includes(q) ?? false);
    if (!actorMatch) return false;
  }
  if (filters.from && event.at < filters.from) return false;
  if (filters.to && event.at > filters.to) return false;
  if (filters.q) {
    const q = filters.q.toLowerCase();
    const inTitle = event.title.toLowerCase().includes(q);
    const inDesc = event.description?.toLowerCase().includes(q) ?? false;
    const inActor = event.actor?.name?.toLowerCase().includes(q) ?? false;
    const inTarget = event.target?.label?.toLowerCase().includes(q) ?? false;
    if (!inTitle && !inDesc && !inActor && !inTarget) return false;
  }
  return true;
}

/** Returns true when no filters are active (fast-path for no filtering). */
function hasActiveFilters(filters: ActivityFilters): boolean {
  return (
    filters.types.length > 0 ||
    filters.severity.length > 0 ||
    filters.category.length > 0 ||
    !!filters.actor ||
    !!filters.q ||
    !!filters.from ||
    !!filters.to ||
    !!filters.source ||
    !!filters.status
  );
}

/** Apply filters to an array of events. Returns the same array reference when no filters are active. */
export function applyFilters(events: ActivityEvent[], filters: ActivityFilters): ActivityEvent[] {
  if (!hasActiveFilters(filters)) return events;
  return events.filter((e) => matchesFilters(e, filters));
}

const MS_PER_DAY = 86_400_000;

function startOfDayMs(now: Date): number {
  return new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
}

/**
 * Groups events by relative date bucket: Today / Yesterday / This Week / Older.
 * Expects events in newest-first order; output groups preserve that order.
 * Accepts an optional `now` for deterministic testing.
 */
export function groupByDate(events: ActivityEvent[], now = new Date()): DateGroup[] {
  if (events.length === 0) return [];

  const todayStart = startOfDayMs(now);
  const yesterdayStart = todayStart - MS_PER_DAY;
  const weekStart = todayStart - 6 * MS_PER_DAY;

  const today: ActivityEvent[] = [];
  const yesterday: ActivityEvent[] = [];
  const thisWeek: ActivityEvent[] = [];
  const older: ActivityEvent[] = [];

  for (const event of events) {
    const ts = new Date(event.at).getTime();
    if (ts >= todayStart) today.push(event);
    else if (ts >= yesterdayStart) yesterday.push(event);
    else if (ts >= weekStart) thisWeek.push(event);
    else older.push(event);
  }

  const result: DateGroup[] = [];
  if (today.length > 0) result.push({ label: "Today", events: today });
  if (yesterday.length > 0) result.push({ label: "Yesterday", events: yesterday });
  if (thisWeek.length > 0) result.push({ label: "This Week", events: thisWeek });
  if (older.length > 0) result.push({ label: "Older", events: older });
  return result;
}

/** Extract unique filter option values from the current event set. */
export function extractFilterOptions(events: ActivityEvent[]): {
  types: string[];
  categories: string[];
  severities: Severity[];
  sources: string[];
  statuses: string[];
} {
  const types = new Set<string>();
  const categories = new Set<string>();
  const severities = new Set<Severity>();
  const sources = new Set<string>();
  const statuses = new Set<string>();

  for (const e of events) {
    types.add(e.type);
    categories.add(e.category);
    severities.add(e.severity);
    if (e.source) sources.add(e.source);
    if (e.status) statuses.add(e.status);
  }

  return {
    types: Array.from(types).sort(),
    categories: Array.from(categories).sort(),
    severities: Array.from(severities),
    sources: Array.from(sources).sort(),
    statuses: Array.from(statuses).sort(),
  };
}
