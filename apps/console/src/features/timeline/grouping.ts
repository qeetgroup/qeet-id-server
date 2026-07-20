// Timeline date-grouping helper — extends activity's filter-manager approach.
// Adds "Last Week" and "Last Month" buckets so user lifecycle timelines
// spanning months remain legible. Accepts an optional `now` for deterministic testing.

import type { ActivityEvent, DateGroup } from "@/features/activity/types";

const MS_PER_DAY = 86_400_000;

function startOfDayMs(now: Date): number {
  return new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
}

/**
 * Groups timeline events by relative date bucket:
 *   Today / Yesterday / Last Week / Last Month / Older
 *
 * Expects events in newest-first order; output groups preserve that order.
 * Compared to activity's `groupByDate`, this adds a "Last Month" bucket so
 * user lifecycle timelines that span months (account creation, first login,
 * password resets…) are legible without everything collapsing into "Older".
 */
export function groupTimelineByDate(events: ActivityEvent[], now = new Date()): DateGroup[] {
  if (events.length === 0) return [];

  const todayStart = startOfDayMs(now);
  const yesterdayStart = todayStart - MS_PER_DAY;
  const lastWeekStart = todayStart - 7 * MS_PER_DAY;
  const lastMonthStart = todayStart - 30 * MS_PER_DAY;

  const today: ActivityEvent[] = [];
  const yesterday: ActivityEvent[] = [];
  const lastWeek: ActivityEvent[] = [];
  const lastMonth: ActivityEvent[] = [];
  const older: ActivityEvent[] = [];

  for (const event of events) {
    const ts = new Date(event.at).getTime();
    if (ts >= todayStart) today.push(event);
    else if (ts >= yesterdayStart) yesterday.push(event);
    else if (ts >= lastWeekStart) lastWeek.push(event);
    else if (ts >= lastMonthStart) lastMonth.push(event);
    else older.push(event);
  }

  const result: DateGroup[] = [];
  if (today.length > 0) result.push({ label: "Today", events: today });
  if (yesterday.length > 0) result.push({ label: "Yesterday", events: yesterday });
  if (lastWeek.length > 0) result.push({ label: "Last Week", events: lastWeek });
  if (lastMonth.length > 0) result.push({ label: "Last Month", events: lastMonth });
  if (older.length > 0) result.push({ label: "Older", events: older });
  return result;
}
