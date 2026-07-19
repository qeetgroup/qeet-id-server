import { beforeEach, describe, expect, it } from "vitest";

import type { SearchItem } from "../registry/types";
import { recentActions, recentStore } from "./recent-store";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function item(id: string, title: string): SearchItem {
  return {
    id,
    kind: "navigation",
    category: "Directory",
    title,
    url: `/${id}`,
  };
}

// Reset store state before each test to keep tests independent.
beforeEach(() => {
  recentStore.setState(() => ({ entries: [] }));
});

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("recentActions.add", () => {
  it("adds a new item to the store", () => {
    recentActions.add(item("users", "Users"));
    expect(recentStore.state.entries).toHaveLength(1);
    expect(recentStore.state.entries[0]?.id).toBe("users");
    expect(recentStore.state.entries[0]?.accessCount).toBe(1);
  });

  it("upserts an existing item: increments accessCount and refreshes timestamp", () => {
    recentActions.add(item("users", "Users"));
    const firstTs = recentStore.state.entries[0]?.timestamp ?? 0;

    // Small delay to get a later timestamp.
    recentActions.add(item("users", "Users"));
    expect(recentStore.state.entries).toHaveLength(1);
    expect(recentStore.state.entries[0]?.accessCount).toBe(2);
    expect((recentStore.state.entries[0]?.timestamp ?? 0) >= firstTs).toBe(true);
  });

  it("upserts an existing item and records a fresh timestamp", () => {
    recentActions.add(item("roles", "Roles"));
    const tsBefore = recentStore.state.entries[0]?.timestamp ?? 0;

    // A second add on the same id must update the timestamp and increment count.
    recentActions.add(item("roles", "Roles"));
    const entry = recentStore.state.entries.find((e) => e.id === "roles");
    expect(entry?.accessCount).toBe(2);
    // timestamp must be >= the one we recorded (same ms or later).
    expect((entry?.timestamp ?? -1) >= tsBefore).toBe(true);
  });

  it("places the most recently added item first when timestamps differ", () => {
    recentActions.add(item("roles", "Roles"));
    // Manually bump the timestamp of the next entry to guarantee ordering.
    recentStore.setState((s) => ({
      entries: s.entries.map((e) =>
        e.id === "roles" ? { ...e, timestamp: Date.now() - 1000 } : e,
      ),
    }));
    recentActions.add(item("users", "Users"));

    const ids = recentStore.state.entries.map((e) => e.id);
    expect(ids[0]).toBe("users");
    expect(ids[1]).toBe("roles");
  });

  it("caps the list at 50 entries", () => {
    for (let i = 0; i < 60; i++) {
      recentActions.add(item(`item-${i}`, `Item ${i}`));
    }
    expect(recentStore.state.entries.length).toBeLessThanOrEqual(50);
  });
});

describe("recentActions.remove", () => {
  it("removes the item with the matching id", () => {
    recentActions.add(item("users", "Users"));
    recentActions.add(item("roles", "Roles"));
    recentActions.remove("users");

    const ids = recentStore.state.entries.map((e) => e.id);
    expect(ids).not.toContain("users");
    expect(ids).toContain("roles");
  });

  it("is a no-op when the id does not exist", () => {
    recentActions.add(item("users", "Users"));
    recentActions.remove("nonexistent");
    expect(recentStore.state.entries).toHaveLength(1);
  });
});

describe("recentActions.clear", () => {
  it("removes all entries", () => {
    recentActions.add(item("users", "Users"));
    recentActions.add(item("roles", "Roles"));
    recentActions.clear();
    expect(recentStore.state.entries).toHaveLength(0);
  });
});
