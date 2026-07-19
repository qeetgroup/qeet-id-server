import { beforeEach, describe, expect, it } from "vitest";

import type { SearchItem } from "../registry/types";
import { favoritesActions, favoritesStore } from "./favorites-store";

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

beforeEach(() => {
  favoritesStore.setState(() => ({ entries: [] }));
});

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("favoritesActions.toggle", () => {
  it("adds an item when it is not yet a favorite", () => {
    favoritesActions.toggle(item("users", "Users"));
    expect(favoritesStore.state.entries).toHaveLength(1);
    expect(favoritesStore.state.entries[0]?.id).toBe("users");
  });

  it("removes an item when it is already a favorite", () => {
    favoritesActions.toggle(item("users", "Users"));
    favoritesActions.toggle(item("users", "Users"));
    expect(favoritesStore.state.entries).toHaveLength(0);
  });

  it("preserves other favorites when removing one", () => {
    favoritesActions.toggle(item("users", "Users"));
    favoritesActions.toggle(item("roles", "Roles"));
    favoritesActions.toggle(item("users", "Users")); // remove users

    const ids = favoritesStore.state.entries.map((e) => e.id);
    expect(ids).not.toContain("users");
    expect(ids).toContain("roles");
  });

  it("stores pinnedAt as a unix ms timestamp", () => {
    const before = Date.now();
    favoritesActions.toggle(item("users", "Users"));
    const after = Date.now();
    const pinnedAt = favoritesStore.state.entries[0]?.pinnedAt ?? 0;
    expect(pinnedAt).toBeGreaterThanOrEqual(before);
    expect(pinnedAt).toBeLessThanOrEqual(after);
  });
});

describe("favoritesActions.isFavorite", () => {
  it("returns false when the item is not a favorite", () => {
    expect(favoritesActions.isFavorite("users")).toBe(false);
  });

  it("returns true after the item has been added", () => {
    favoritesActions.toggle(item("users", "Users"));
    expect(favoritesActions.isFavorite("users")).toBe(true);
  });

  it("returns false after the item has been removed", () => {
    favoritesActions.toggle(item("users", "Users"));
    favoritesActions.toggle(item("users", "Users"));
    expect(favoritesActions.isFavorite("users")).toBe(false);
  });
});

describe("favoritesActions.clear", () => {
  it("removes all entries", () => {
    favoritesActions.toggle(item("users", "Users"));
    favoritesActions.toggle(item("roles", "Roles"));
    favoritesActions.clear();
    expect(favoritesStore.state.entries).toHaveLength(0);
  });
});
