// Recent-search store: persists the last N items the operator opened via
// universal search (pages, commands, resources). Uses TanStack Store as the
// reactive layer; localStorage for cross-session persistence. Guards all
// localStorage access with typeof window checks so the module is safe in
// server/test environments.

import { Store } from "@tanstack/react-store";

import type { SearchItem, SearchItemKind } from "../registry/types";

const STORE_KEY = "qeetid.search.recent";
const MAX_ENTRIES = 50;

export interface RecentEntry {
  /** Matches the SearchItem.id that was opened. */
  id: string;
  kind: SearchItemKind;
  category: string;
  title: string;
  subtitle?: string;
  url?: string;
  /** Unix ms — used for recency ordering. */
  timestamp: number;
  /** How many times this id has been opened — used for frequency boost. */
  accessCount: number;
}

export interface RecentState {
  entries: RecentEntry[];
}

export const recentStore = new Store<RecentState>({ entries: [] });

function persist(state: RecentState): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORE_KEY, JSON.stringify(state));
  } catch {
    /* storage quota or private mode — best-effort */
  }
}

export const recentActions = {
  /** Add or upsert an item into the recent list. */
  add(item: SearchItem): void {
    recentStore.setState((s) => {
      const now = Date.now();
      const existing = s.entries.find((e) => e.id === item.id);
      let entries: RecentEntry[];
      if (existing) {
        entries = s.entries.map((e) =>
          e.id === item.id ? { ...e, timestamp: now, accessCount: e.accessCount + 1 } : e,
        );
      } else {
        const entry: RecentEntry = {
          id: item.id,
          kind: item.kind,
          category: item.category,
          title: item.title,
          subtitle: item.subtitle,
          url: item.url,
          timestamp: now,
          accessCount: 1,
        };
        entries = [entry, ...s.entries].slice(0, MAX_ENTRIES);
      }
      // Keep sorted newest-first after upsert.
      const sorted = [...entries].sort((a, b) => b.timestamp - a.timestamp);
      const next: RecentState = { entries: sorted };
      persist(next);
      return next;
    });
  },

  remove(id: string): void {
    recentStore.setState((s) => {
      const entries = s.entries.filter((e) => e.id !== id);
      const next: RecentState = { entries };
      persist(next);
      return next;
    });
  },

  clear(): void {
    const next: RecentState = { entries: [] };
    recentStore.setState(() => next);
    persist(next);
  },
};

/**
 * Rehydrate from localStorage. Call once from a client-side mount effect,
 * never during render (keeps SSR output deterministic).
 */
export function hydrateRecent(): void {
  if (typeof window === "undefined") return;
  try {
    const raw = window.localStorage.getItem(STORE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw) as Partial<RecentState>;
    if (!parsed || !Array.isArray(parsed.entries)) return;
    recentStore.setState(() => ({ entries: parsed.entries as RecentEntry[] }));
  } catch {
    /* corrupt payload — start clean */
  }
}
