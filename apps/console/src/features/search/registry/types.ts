// Core type contracts for the universal search feature.
// Every module in features/search/ compiles against these.

import type { ReactNode } from "react";

import type { Capability } from "@/features/access-control/capability-model";

export type SearchItemKind = "navigation" | "command" | "resource" | "recent" | "favorite";

export interface QuickAction {
  id: string;
  label: string;
  icon?: ReactNode;
  run(ctx: SearchContext): void;
}

export interface SearchItem {
  /** Stable unique key across all sources. */
  id: string;
  kind: SearchItemKind;
  category: string;
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  keywords?: string[];
  url?: string;
  capability?: Capability;
  /** Well-known status string (passed to StatusPill). */
  status?: string;
  /** ISO 8601 timestamp for display in the preview pane. */
  updatedAt?: string;
  metadata?: Record<string, string>;
  /**
   * Execute the item. When absent the launcher navigates to `url`.
   * Commands that do more than navigate (API calls, create flows) supply this.
   */
  run?(ctx: SearchContext): void;
  quickActions?: QuickAction[];
}

export interface SearchContext {
  pathname: string;
  tenantId: string | null;
  /** Read-only view of the current capability set (permission strings). */
  capabilities: ReadonlySet<string>;
  navigate(url: string): void;
}

export interface SearchSource {
  id: string;
  getItems(query: string, ctx: SearchContext): SearchItem[];
}

export type SearchResultGroup = {
  category: string;
  items: SearchItem[];
};

// ─── Resource search API types ───────────────────────────────────────────────

/** A single hit from GET /v1/search */
export type SearchHit = {
  type: string;
  id: string;
  title: string;
  subtitle?: string;
  url: string;
  status?: string;
  updated_at?: string;
  score: number;
  metadata?: Record<string, string>;
};

export type SearchResponse = {
  results: SearchHit[];
  next_cursor?: string;
};
