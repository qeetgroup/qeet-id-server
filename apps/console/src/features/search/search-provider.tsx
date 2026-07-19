// SearchProvider: assembles navigation and command sources, builds the
// SearchContext from router + capabilities, hydrates persistent stores on
// mount, and exposes useUniversalSearch() to any child.

import { useNavigate, useRouterState } from "@tanstack/react-router";
import { useStore } from "@tanstack/react-store";
import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo } from "react";

import { useCapabilities } from "@/features/access-control/capability-provider";

import type { RankContext } from "./ranking";
import { createCommandSource } from "./registry/command-source";
import { createNavigationSource } from "./registry/navigation-source";
import type { SearchContext, SearchItem } from "./registry/types";
import type { FavoriteEntry } from "./store/favorites-store";
import { favoritesActions, favoritesStore, hydrateFavorites } from "./store/favorites-store";
import type { RecentEntry } from "./store/recent-store";
import { hydrateRecent, recentActions, recentStore } from "./store/recent-store";

export interface UniversalSearchContextValue {
  /** The current search context (pathname, tenantId, capabilities, navigate). */
  searchCtx: SearchContext;
  /** All navigation items from the sidebar, capability-filtered. */
  navigationItems: SearchItem[];
  /** All executable command items, capability-filtered. */
  commandItems: SearchItem[];
  recentEntries: RecentEntry[];
  favoriteEntries: FavoriteEntry[];
  addRecent(item: SearchItem): void;
  removeRecent(id: string): void;
  clearRecent(): void;
  toggleFavorite(item: SearchItem): void;
  isFavorite(id: string): boolean;
  /** Snapshot of rank context — call inside useMemo for stable references. */
  getRankContext(): RankContext;
}

const UniversalSearchContext = createContext<UniversalSearchContextValue | null>(null);

// Module-level source singletons: built once, never rebuilt. The items they
// return are capability-filtered at call time via ctx.capabilities.
const navSource = createNavigationSource();
const cmdSource = createCommandSource();

export function SearchProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const access = useCapabilities();

  // Hydrate persistent stores on the client (never during render).
  useEffect(() => {
    hydrateRecent();
    hydrateFavorites();
  }, []);

  // Reactive store subscriptions.
  const recentEntries = useStore(recentStore, (s) => s.entries);
  const favoriteEntries = useStore(favoritesStore, (s) => s.entries);

  const searchCtx = useMemo<SearchContext>(
    () => ({
      pathname,
      tenantId: access.tenantId,
      capabilities: access.permissions,
      navigate: (url: string) => navigate({ to: url }),
    }),
    // navigate is stable across renders (TanStack Router guarantee).
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [pathname, access.tenantId, access.permissions],
  );

  // Build items only when access is ready (avoids empty results on first mount).
  const navigationItems = useMemo(
    () => (access.state === "ready" ? navSource.getItems("", searchCtx) : []),
    [access.state, searchCtx],
  );
  const commandItems = useMemo(
    () => (access.state === "ready" ? cmdSource.getItems("", searchCtx) : []),
    [access.state, searchCtx],
  );

  const getRankContext = useCallback(
    (): RankContext => ({
      recentIds: new Set(recentEntries.map((e) => e.id)),
      recentAccessCounts: new Map(recentEntries.map((e) => [e.id, e.accessCount])),
      favoriteIds: new Set(favoriteEntries.map((e) => e.id)),
      currentPathname: pathname,
    }),
    [recentEntries, favoriteEntries, pathname],
  );

  const addRecent = useCallback((item: SearchItem) => recentActions.add(item), []);
  const removeRecent = useCallback((id: string) => recentActions.remove(id), []);
  const clearRecent = useCallback(() => recentActions.clear(), []);
  const toggleFavorite = useCallback((item: SearchItem) => favoritesActions.toggle(item), []);
  const isFavorite = useCallback((id: string) => favoritesActions.isFavorite(id), []);

  const value = useMemo<UniversalSearchContextValue>(
    () => ({
      searchCtx,
      navigationItems,
      commandItems,
      recentEntries,
      favoriteEntries,
      addRecent,
      removeRecent,
      clearRecent,
      toggleFavorite,
      isFavorite,
      getRankContext,
    }),
    [
      searchCtx,
      navigationItems,
      commandItems,
      recentEntries,
      favoriteEntries,
      addRecent,
      removeRecent,
      clearRecent,
      toggleFavorite,
      isFavorite,
      getRankContext,
    ],
  );

  return (
    <UniversalSearchContext.Provider value={value}>{children}</UniversalSearchContext.Provider>
  );
}

export function useUniversalSearch(): UniversalSearchContextValue {
  const value = useContext(UniversalSearchContext);
  if (!value) throw new Error("useUniversalSearch must be used inside SearchProvider");
  return value;
}
