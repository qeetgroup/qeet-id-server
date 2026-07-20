import { describe, expect, it } from "vitest";
import type { ActivityEvent } from "@/features/activity/types";
import { groupTimelineByDate } from "./grouping";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let counter = 0;

function makeEvent(daysAgo: number, overrides: Partial<ActivityEvent> = {}): ActivityEvent {
  counter++;
  const at = new Date(
    // Base date is fixed to a known Monday to avoid DST edge cases in CI
    new Date("2025-06-16T12:00:00.000Z").getTime() - daysAgo * 86_400_000,
  ).toISOString();
  return {
    id: `evt-${counter}`,
    type: "user.login",
    category: "authentication",
    severity: "info",
    title: `Event ${counter}`,
    at,
    ...overrides,
  };
}

/** Fixed "now" for all tests: 2025-06-16 at noon UTC */
const NOW = new Date("2025-06-16T12:00:00.000Z");

// ---------------------------------------------------------------------------
// groupTimelineByDate
// ---------------------------------------------------------------------------

describe("groupTimelineByDate", () => {
  it("returns an empty array for no events", () => {
    expect(groupTimelineByDate([], NOW)).toEqual([]);
  });

  it("places an event from today in the Today bucket", () => {
    const event = makeEvent(0); // 0 days ago = today
    const groups = groupTimelineByDate([event], NOW);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.label).toBe("Today");
    expect(groups[0]?.events).toContain(event);
  });

  it("places an event from yesterday in the Yesterday bucket", () => {
    const event = makeEvent(1); // 1 day ago
    const groups = groupTimelineByDate([event], NOW);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.label).toBe("Yesterday");
  });

  it("places events from 2-7 days ago in Last Week", () => {
    const event3 = makeEvent(3);
    const event7 = makeEvent(7);
    const groups = groupTimelineByDate([event3, event7], NOW);
    const labels = groups.map((g) => g.label);
    expect(labels).toContain("Last Week");
    const lastWeek = groups.find((g) => g.label === "Last Week");
    expect(lastWeek?.events).toContain(event3);
    expect(lastWeek?.events).toContain(event7);
  });

  it("places events from 8-30 days ago in Last Month", () => {
    const event15 = makeEvent(15);
    const event30 = makeEvent(30);
    const groups = groupTimelineByDate([event15, event30], NOW);
    const lastMonth = groups.find((g) => g.label === "Last Month");
    expect(lastMonth).toBeDefined();
    expect(lastMonth?.events).toContain(event15);
    expect(lastMonth?.events).toContain(event30);
  });

  it("places events older than 30 days in Older", () => {
    const event = makeEvent(31);
    const groups = groupTimelineByDate([event], NOW);
    expect(groups[0]?.label).toBe("Older");
  });

  it("produces groups in Today → Older order when events span all buckets", () => {
    const events = [makeEvent(0), makeEvent(1), makeEvent(5), makeEvent(20), makeEvent(40)];
    const groups = groupTimelineByDate(events, NOW);
    const labels = groups.map((g) => g.label);
    expect(labels).toEqual(["Today", "Yesterday", "Last Week", "Last Month", "Older"]);
  });

  it("omits buckets with no events", () => {
    const events = [makeEvent(0), makeEvent(40)]; // Today + Older only
    const groups = groupTimelineByDate(events, NOW);
    const labels = groups.map((g) => g.label);
    expect(labels).toEqual(["Today", "Older"]);
    expect(labels).not.toContain("Yesterday");
    expect(labels).not.toContain("Last Week");
    expect(labels).not.toContain("Last Month");
  });

  it("preserves newest-first order within each group", () => {
    // Events at different offsets within "Last Week" (3 days ago, 4 days ago)
    const newer = makeEvent(3);
    const older = makeEvent(4);
    // Pass newest-first (as the timeline would)
    const groups = groupTimelineByDate([newer, older], NOW);
    const lastWeek = groups.find((g) => g.label === "Last Week");
    expect(lastWeek?.events[0]).toBe(newer);
    expect(lastWeek?.events[1]).toBe(older);
  });

  it("handles a single event correctly", () => {
    const event = makeEvent(0);
    const groups = groupTimelineByDate([event], NOW);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.events).toHaveLength(1);
  });
});
