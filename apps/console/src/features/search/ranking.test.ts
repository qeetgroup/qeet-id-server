import { describe, expect, it } from "vitest";

import {
  editDistance,
  type RankCandidate,
  type RankContext,
  rankItems,
  score,
  scoreText,
} from "./ranking";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const emptyCtx: RankContext = {
  recentIds: new Set(),
  recentAccessCounts: new Map(),
  favoriteIds: new Set(),
  currentPathname: "/",
};

function candidate(
  overrides: Partial<RankCandidate> & { id: string; title: string },
): RankCandidate {
  return { keywords: [], ...overrides };
}

// ─── scoreText ────────────────────────────────────────────────────────────────

describe("scoreText", () => {
  it("returns 100 for an exact match", () => {
    expect(scoreText("users", "users")).toBe(100);
  });

  it("returns 90 for a prefix match", () => {
    expect(scoreText("us", "users")).toBe(90);
  });

  it("returns a word-boundary score for a first-word match that is also a prefix", () => {
    // "audit logs" starts with "audit", so prefix (90) wins over word-boundary.
    // The important property: score is >= 70 (word found) and > substring (60).
    const s = scoreText("audit", "audit logs");
    expect(s).toBeGreaterThanOrEqual(70);
  });

  it("returns 70 for a later-word boundary match", () => {
    // "logs" does NOT start the full string, so prefix (90) is skipped.
    // Word boundary at index 1 → 70.
    expect(scoreText("logs", "audit logs")).toBe(70);
  });

  it("returns 60 for a substring match", () => {
    expect(scoreText("it lo", "audit logs")).toBe(60);
  });

  it("returns > 0 for a subsequence match", () => {
    const s = scoreText("ul", "audit logs");
    expect(s).toBeGreaterThan(0);
    expect(s).toBeLessThan(60);
  });

  it("returns > 0 for a typo-tolerant match (1 substitution)", () => {
    // "usars" vs "users" — edit distance 1
    expect(scoreText("usars", "users")).toBeGreaterThan(0);
  });

  it("returns 0 for a completely unrelated query", () => {
    expect(scoreText("zxqwerty", "users")).toBe(0);
  });

  it("returns 0 for empty query", () => {
    expect(scoreText("", "users")).toBe(0);
  });

  it("returns 0 for empty text", () => {
    expect(scoreText("users", "")).toBe(0);
  });

  it("is case-insensitive", () => {
    expect(scoreText("USERS", "Users")).toBe(100);
  });
});

// ─── editDistance ─────────────────────────────────────────────────────────────

describe("editDistance", () => {
  it("returns 0 for identical strings", () => {
    expect(editDistance("abc", "abc")).toBe(0);
  });

  it("returns 1 for a single substitution", () => {
    expect(editDistance("abc", "axc")).toBe(1);
  });

  it("returns 1 for a single insertion", () => {
    expect(editDistance("abc", "abdc")).toBe(1);
  });

  it("returns 1 for a single deletion", () => {
    expect(editDistance("abcd", "abc")).toBe(1);
  });

  it("handles empty strings", () => {
    expect(editDistance("", "abc")).toBe(3);
    expect(editDistance("abc", "")).toBe(3);
    expect(editDistance("", "")).toBe(0);
  });
});

// ─── score (multi-field) ──────────────────────────────────────────────────────

describe("score", () => {
  it("returns 0 for an empty query", () => {
    expect(score("", candidate({ id: "a", title: "Users" }))).toBe(0);
  });

  it("returns full score for an exact title match", () => {
    expect(score("users", candidate({ id: "a", title: "Users" }))).toBe(100);
  });

  it("weights title above keywords (90 % factor)", () => {
    const c = candidate({ id: "a", title: "Settings", keywords: ["users"] });
    const titleScore = score("settings", c);
    const keywordScore = score("users", c);
    // Title match = 100, keyword match = 90 % of some value
    expect(titleScore).toBeGreaterThan(keywordScore);
  });

  it("finds a match via keywords when title does not match", () => {
    const c = candidate({
      id: "a",
      title: "API Keys",
      keywords: ["machine identity", "service account"],
    });
    expect(score("service", c)).toBeGreaterThan(0);
  });

  it("returns 0 when nothing matches", () => {
    const c = candidate({ id: "a", title: "Users", keywords: ["members"] });
    expect(score("zqxjkl", c)).toBe(0);
  });
});

// ─── rankItems ────────────────────────────────────────────────────────────────

describe("rankItems", () => {
  const items: RankCandidate[] = [
    candidate({ id: "nav.users", title: "Users", category: "Directory" }),
    candidate({ id: "nav.roles", title: "Roles", category: "Authorization" }),
    candidate({ id: "cmd.create-user", title: "Create User", keywords: ["add user"] }),
  ];

  it("returns an empty array when no items match the query", () => {
    const result = rankItems(items, "zxqwerty", emptyCtx);
    expect(result).toHaveLength(0);
  });

  it("returns matched items sorted descending by score", () => {
    const result = rankItems(items, "user", emptyCtx);
    expect(result.length).toBeGreaterThan(0);
    for (let i = 1; i < result.length; i++) {
      const prev = result[i - 1];
      const curr = result[i];
      if (prev && curr) {
        expect(prev.score).toBeGreaterThanOrEqual(curr.score);
      }
    }
  });

  it("applies a favorites boost to favourited items", () => {
    const ctx: RankContext = {
      ...emptyCtx,
      favoriteIds: new Set(["nav.roles"]),
    };
    const result = rankItems(items, "r", ctx);
    const rolesResult = result.find((r) => r.item.id === "nav.roles");
    const otherResult = result.find((r) => r.item.id !== "nav.roles");
    if (rolesResult && otherResult) {
      expect(rolesResult.score).toBeGreaterThan(otherResult.score);
    }
  });

  it("applies a frequency boost proportional to accessCount", () => {
    const ctx: RankContext = {
      ...emptyCtx,
      recentIds: new Set(["nav.users"]),
      recentAccessCounts: new Map([["nav.users", 10]]),
    };
    const withFreq = rankItems(items, "u", ctx);
    const withoutFreq = rankItems(items, "u", emptyCtx);
    const usersWithFreq = withFreq.find((r) => r.item.id === "nav.users");
    const usersWithout = withoutFreq.find((r) => r.item.id === "nav.users");
    if (usersWithFreq && usersWithout) {
      expect(usersWithFreq.score).toBeGreaterThan(usersWithout.score);
    }
  });

  it("returns only recents/favorites when query is empty", () => {
    const ctx: RankContext = {
      ...emptyCtx,
      recentIds: new Set(["nav.roles"]),
      recentAccessCounts: new Map([["nav.roles", 1]]),
    };
    const result = rankItems(items, "", ctx);
    expect(result).toHaveLength(1);
    expect(result[0]?.item.id).toBe("nav.roles");
  });

  it("returns an empty array with no query and no recents/favorites", () => {
    const result = rankItems(items, "", emptyCtx);
    expect(result).toHaveLength(0);
  });

  it("boosts items sharing path segments with currentPathname", () => {
    const ctx: RankContext = {
      ...emptyCtx,
      currentPathname: "/users",
    };
    const navItems: RankCandidate[] = [
      candidate({ id: "/users", title: "Users", url: "/users" }),
      candidate({ id: "/roles", title: "Roles", url: "/roles" }),
    ];
    const result = rankItems(navItems, "u", ctx);
    const usersResult = result.find((r) => r.item.id === "/users");
    const rolesResult = result.find((r) => r.item.id === "/roles");
    if (usersResult && rolesResult) {
      // /users shares the "users" segment with currentPathname
      expect(usersResult.score).toBeGreaterThan(rolesResult.score);
    }
  });
});
