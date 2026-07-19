// Favorites store: lets operators pin search items (navigation pages, commands,
// resources) for quick access without a query. Same pattern as recent-store:
// TanStack Store for reactivity, localStorage for persistence, SSR-safe guards.

import { Store } from "@tanstack/react-store";

import type { SearchItem, SearchItemKind } from "../registry/types";

const STORE_KEY = "qeetid.search.favorites";

export interface FavoriteEntry {
  id: string;
  kind: SearchItemKind;
  category: string;
  title: string;
  subtitle?: string;
  url?: string;
  /** Unix ms of when the item was pinned. */
  pinnedAt: number;
}

export interface FavoritesState {
  entries: FavoriteEntry[];
}

export const favoritesStore = new Store<FavoritesState>({ entries: [] });

function persist(state: FavoritesState): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORE_KEY, JSON.stringify(state));
  } catch {
    /* best-effort */
  }
}

export const favoritesActions = {
  /** Add if not favorited; remove if already favorited. */
  toggle(item: SearchItem): void {
    favoritesStore.setState((s) => {
      const exists = s.entries.some((e) => e.id === item.id);
      let entries: FavoriteEntry[];
      if (exists) {
        entries = s.entries.filter((e) => e.id !== item.id);
      } else {
        const entry: FavoriteEntry = {
          id: item.id,
          kind: item.kind,
          category: item.category,
          title: item.title,
          subtitle: item.subtitle,
          url: item.url,
          pinnedAt: Date.now(),
        };
        entries = [entry, ...s.entries];
      }
      const next: FavoritesState = { entries };
      persist(next);
      return next;
    });
  },

  /** Synchronous read — safe to call outside React (e.g. in action handlers). */
  isFavorite(id: string): boolean {
    return favoritesStore.state.entries.some((e) => e.id === id);
  },

  clear(): void {
    const next: FavoritesState = { entries: [] };
    favoritesStore.setState(() => next);
    persist(next);
  },
};

export function hydrateFavorites(): void {
  if (typeof window === "undefined") return;
  try {
    const raw = window.localStorage.getItem(STORE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw) as Partial<FavoritesState>;
    if (!parsed || !Array.isArray(parsed.entries)) return;
    favoritesStore.setState(() => ({ entries: parsed.entries as FavoriteEntry[] }));
  } catch {
    /* corrupt payload */
  }
}
