import { describe, expect, it } from "vitest";

import { applyFilters, groupByDate, matchesFilters } from "./filter-manager";
import type { ActivityEvent, ActivityFilters } from "./types";
import { DEFAULT_FILTERS } from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let counter = 0;

function makeEvent(overrides: Partial<ActivityEvent> = {}): ActivityEvent {
  counter++;
  return {
    id: `evt-${counter}`,
    type: "user.login",
    category: "authentication",
    severity: "info",
    title: `Event ${counter}`,
    at: new Date().toISOString(),
    ...overrides,
  };
}

function filters(patch: Partial<ActivityFilters> = {}): ActivityFilters {
  return { ...DEFAULT_FILTERS, ...patch };
}

// ---------------------------------------------------------------------------
// matchesFilters
// ---------------------------------------------------------------------------

describe("matchesFilters", () => {
  it("returns true when no filters are active", () => {
    expect(matchesFilters(makeEvent(), DEFAULT_FILTERS)).toBe(true);
  });

  it("filters by severity", () => {
    const evt = makeEvent({ severity: "critical" });
    expect(matchesFilters(evt, filters({ severity: ["critical"] }))).toBe(true);
    expect(matchesFilters(evt, filters({ severity: ["info"] }))).toBe(false);
  });

  it("filters by category", () => {
    const evt = makeEvent({ category: "authorization" });
    expect(matchesFilters(evt, filters({ category: ["authorization"] }))).toBe(true);
    expect(matchesFilters(evt, filters({ category: ["authentication"] }))).toBe(false);
  });

  it("filters by type (array)", () => {
    const evt = makeEvent({ type: "api_key.revoked" });
    expect(matchesFilters(evt, filters({ types: ["api_key.revoked"] }))).toBe(true);
    expect(matchesFilters(evt, filters({ types: ["user.login"] }))).toBe(false);
  });

  it("filters by full-text search (q) across title, description, actor, target", () => {
    const evt = makeEvent({
      title: "Login attempt",
      description: "Failed from unusual IP",
      actor: { name: "alice@example.com" },
      target: { label: "admin-panel" },
    });
    expect(matchesFilters(evt, filters({ q: "alice" }))).toBe(true);
    expect(matchesFilters(evt, filters({ q: "admin-panel" }))).toBe(true);
    expect(matchesFilters(evt, filters({ q: "unusual" }))).toBe(true);
    expect(matchesFilters(evt, filters({ q: "login" }))).toBe(true);
    expect(matchesFilters(evt, filters({ q: "ALICE" }))).toBe(true); // case-insensitive
    expect(matchesFilters(evt, filters({ q: "xyz-never-matches" }))).toBe(false);
  });

  it("filters by actor name (case-insensitive)", () => {
    const evt = makeEvent({ actor: { name: "Bob Smith", id: "u-123", type: "user" } });
    expect(matchesFilters(evt, filters({ actor: "bob" }))).toBe(true);
    expect(matchesFilters(evt, filters({ actor: "u-123" }))).toBe(true);
    expect(matchesFilters(evt, filters({ actor: "charlie" }))).toBe(false);
  });

  it("filters by source", () => {
    const evt = makeEvent({ source: "api-gateway" });
    expect(matchesFilters(evt, filters({ source: "api-gateway" }))).toBe(true);
    expect(matchesFilters(evt, filters({ source: "console" }))).toBe(false);
  });

  it("filters by status", () => {
    const evt = makeEvent({ status: "failed" });
    expect(matchesFilters(evt, filters({ status: "failed" }))).toBe(true);
    expect(matchesFilters(evt, filters({ status: "succeeded" }))).toBe(false);
  });

  it("filters by date range (ISO strings)", () => {
    const ts = "2024-06-15T12:00:00Z";
    const evt = makeEvent({ at: ts });
    // within range
    expect(
      matchesFilters(evt, filters({ from: "2024-06-01T00:00:00Z", to: "2024-06-30T23:59:59Z" })),
    ).toBe(true);
    // before range
    expect(matchesFilters(evt, filters({ from: "2024-07-01T00:00:00Z" }))).toBe(false);
    // after range
    expect(matchesFilters(evt, filters({ to: "2024-06-01T00:00:00Z" }))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// applyFilters
// ---------------------------------------------------------------------------

describe("applyFilters", () => {
  it("returns the same array reference when no filters are active", () => {
    const events = [makeEvent(), makeEvent()];
    const result = applyFilters(events, DEFAULT_FILTERS);
    expect(result).toBe(events); // same reference = fast-path
  });

  it("filters the array when filters are active", () => {
    const events = [
      makeEvent({ severity: "info" }),
      makeEvent({ severity: "critical" }),
      makeEvent({ severity: "warning" }),
    ];
    const result = applyFilters(events, filters({ severity: ["critical"] }));
    expect(result).toHaveLength(1);
    expect(result[0]?.severity).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// groupByDate
// ---------------------------------------------------------------------------

describe("groupByDate", () => {
  it("produces no groups for an empty array", () => {
    expect(groupByDate([], new Date())).toEqual([]);
  });

  it("puts today's events in 'Today'", () => {
    const now = new Date("2024-06-15T12:00:00Z");
    const evt = makeEvent({ at: "2024-06-15T08:00:00Z" });
    const groups = groupByDate([evt], now);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.label).toBe("Today");
    expect(groups[0]?.events).toHaveLength(1);
  });

  it("puts yesterday's events in 'Yesterday'", () => {
    const now = new Date("2024-06-15T12:00:00Z");
    const evt = makeEvent({ at: "2024-06-14T10:00:00Z" });
    const groups = groupByDate([evt], now);
    expect(groups[0]?.label).toBe("Yesterday");
  });

  it("puts 2-6 days ago in 'This Week'", () => {
    const now = new Date("2024-06-15T12:00:00Z");
    const evt = makeEvent({ at: "2024-06-12T10:00:00Z" }); // 3 days ago
    const groups = groupByDate([evt], now);
    expect(groups[0]?.label).toBe("This Week");
  });

  it("puts events older than 7 days in 'Older'", () => {
    const now = new Date("2024-06-15T12:00:00Z");
    const evt = makeEvent({ at: "2024-06-01T10:00:00Z" }); // 14 days ago
    const groups = groupByDate([evt], now);
    expect(groups[0]?.label).toBe("Older");
  });

  it("emits only non-empty groups and preserves order: Today→Yesterday→This Week→Older", () => {
    const now = new Date("2024-06-15T12:00:00Z");
    const events = [
      makeEvent({ at: "2024-06-15T09:00:00Z" }), // Today
      makeEvent({ at: "2024-06-14T09:00:00Z" }), // Yesterday
      makeEvent({ at: "2024-06-10T09:00:00Z" }), // This Week
      makeEvent({ at: "2024-05-01T09:00:00Z" }), // Older
    ];
    const groups = groupByDate(events, now);
    expect(groups.map((g) => g.label)).toEqual(["Today", "Yesterday", "This Week", "Older"]);
  });
});
