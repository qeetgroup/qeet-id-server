// UniversalSearch: the Raycast/Linear-class command palette for the Qeet ID
// admin console. Evolves the existing CommandPalette with:
//   • Navigation (sidebar tree, capability-filtered)
//   • Commands (executable admin actions, capability-gated)
//   • Resources (async GET /v1/search, gracefully degraded)
//   • Recents + Favorites (from TanStack Store, localStorage-persisted)
//   • In-house fuzzy ranking with recency/frequency/favorites boosts
//   • Preview pane with quick actions on the highlighted item
//   • Full keyboard (↑↓ Enter Esc Tab) + WCAG 2.2 AA combobox/listbox ARIA

import { cn, EmptyState, Kbd, ScrollArea, Separator, Skeleton, Spinner } from "@qeetrix/ui";
import { useQuery } from "@tanstack/react-query";
import { HistoryIcon, SearchIcon, XIcon } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { ApiError, api } from "@/lib/api";

import { moveHighlight } from "../keyboard";
import { rankItems } from "../ranking";
import { resourceHitsToSearchItems } from "../registry/resource-source";
import type { SearchItem, SearchResponse, SearchResultGroup } from "../registry/types";
import { useUniversalSearch } from "../search-provider";
import { PreviewPane } from "./preview-pane";
import { ResultGroups } from "./result-groups";

// ─── Constants ────────────────────────────────────────────────────────────────
const LISTBOX_ID = "us-listbox";
const MAX_NAV_RESULTS = 20;
const MAX_CMD_RESULTS = 10;
const MAX_RESOURCE_RESULTS = 10;
const MAX_RECENT_SHOWN = 8;
const DEBOUNCE_MS = 200;

// ─── Props ────────────────────────────────────────────────────────────────────
interface UniversalSearchProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

// ─── Component ────────────────────────────────────────────────────────────────
export function UniversalSearch({ open, onOpenChange }: UniversalSearchProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [highlightIndex, setHighlightIndex] = useState(0);

  const {
    searchCtx,
    navigationItems,
    commandItems,
    recentEntries,
    favoriteEntries,
    addRecent,
    clearRecent,
    toggleFavorite,
    isFavorite,
    getRankContext,
  } = useUniversalSearch();

  // ── Debounce ──────────────────────────────────────────────────────────────
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(query), DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [query]);

  // ── Reset on open ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (open) {
      setQuery("");
      setDebouncedQuery("");
      setHighlightIndex(0);
    }
  }, [open]);

  // ── Drive native <dialog> ─────────────────────────────────────────────────
  useEffect(() => {
    const d = dialogRef.current;
    if (!d) return;
    if (open && !d.open) {
      d.showModal();
      requestAnimationFrame(() => inputRef.current?.focus());
    } else if (!open && d.open) {
      d.close();
    }
  }, [open]);

  // ── Resource search ───────────────────────────────────────────────────────
  const resourceQuery = useQuery({
    queryKey: ["universal-search", debouncedQuery],
    queryFn: async ({ signal }) => {
      try {
        return await api<SearchResponse>("/v1/search", {
          query: { q: debouncedQuery, limit: MAX_RESOURCE_RESULTS },
          signal,
        });
      } catch (err) {
        // Re-throw so TanStack Query cancels correctly on abort.
        if (err instanceof Error && err.name === "AbortError") throw err;
        // Graceful degradation: /v1/search may not be deployed yet.
        // Treat any error (404, 501, network) as empty results.
        if (err instanceof ApiError || err instanceof Error) {
          return { results: [], next_cursor: undefined } satisfies SearchResponse;
        }
        throw err;
      }
    },
    enabled: open && debouncedQuery.length >= 2,
    // Keep previous data visible while the new query loads (avoids list flicker).
    placeholderData: (prev) => prev,
    staleTime: 10_000,
    retry: false,
    meta: { silent: true },
  });

  // ── Rank + group results ──────────────────────────────────────────────────
  const rankCtx = useMemo(() => getRankContext(), [getRankContext]);

  const { groups, allItems } = useMemo<{
    groups: SearchResultGroup[];
    allItems: SearchItem[];
  }>(() => {
    const grouped: SearchResultGroup[] = [];
    const all: SearchItem[] = [];

    if (!query) {
      // No query: surface pinned favorites then recent history.
      if (favoriteEntries.length > 0) {
        const items: SearchItem[] = favoriteEntries.map(
          (e): SearchItem => ({
            id: e.id,
            kind: "favorite",
            category: "Favorites",
            title: e.title,
            subtitle: e.subtitle,
            url: e.url,
          }),
        );
        grouped.push({ category: "Favorites", items });
        all.push(...items);
      }

      const recentSlice = recentEntries.slice(0, MAX_RECENT_SHOWN);
      if (recentSlice.length > 0) {
        const items: SearchItem[] = recentSlice.map(
          (e): SearchItem => ({
            id: e.id,
            kind: "recent",
            category: "Recent",
            title: e.title,
            subtitle: e.subtitle,
            url: e.url,
          }),
        );
        grouped.push({ category: "Recent", items });
        all.push(...items);
      }

      return { groups: grouped, allItems: all };
    }

    // With query: rank each source and group the winners.
    const navRanked = rankItems(navigationItems, query, rankCtx).slice(0, MAX_NAV_RESULTS);
    if (navRanked.length > 0) {
      const items = navRanked.map((r) => r.item);
      grouped.push({ category: "Navigation", items });
      all.push(...items);
    }

    const cmdRanked = rankItems(commandItems, query, rankCtx).slice(0, MAX_CMD_RESULTS);
    if (cmdRanked.length > 0) {
      const items = cmdRanked.map((r) => r.item);
      grouped.push({ category: "Commands", items });
      all.push(...items);
    }

    // Resource results: group by type returned from the API.
    const hits = resourceQuery.data?.results ?? [];
    const resourceItems = resourceHitsToSearchItems(hits);
    const byCategory = new Map<string, SearchItem[]>();
    for (const ri of resourceItems) {
      const bucket = byCategory.get(ri.category) ?? [];
      bucket.push(ri);
      byCategory.set(ri.category, bucket);
    }
    for (const [cat, items] of byCategory) {
      grouped.push({ category: cat, items });
      all.push(...items);
    }

    return { groups: grouped, allItems: all };
  }, [
    query,
    navigationItems,
    commandItems,
    rankCtx,
    resourceQuery.data,
    recentEntries,
    favoriteEntries,
  ]);

  // ── Keyboard ──────────────────────────────────────────────────────────────
  const clampedHighlight = Math.min(highlightIndex, Math.max(0, allItems.length - 1));
  const selectedItem: SearchItem | null = allItems[clampedHighlight] ?? null;

  function commit(item: SearchItem): void {
    if (item.run) {
      item.run(searchCtx);
    } else if (item.url) {
      searchCtx.navigate(item.url);
    }
    addRecent(item);
    onOpenChange(false);
  }

  function handleKeyDown(e: React.KeyboardEvent): void {
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setHighlightIndex((h) => moveHighlight(h, "down", allItems.length));
        break;
      case "ArrowUp":
        e.preventDefault();
        setHighlightIndex((h) => moveHighlight(h, "up", allItems.length));
        break;
      case "Enter":
        e.preventDefault();
        if (selectedItem) commit(selectedItem);
        break;
      // Esc: the native <dialog> fires onClose automatically.
    }
  }

  // ── Display state ─────────────────────────────────────────────────────────
  const isLoadingResources = resourceQuery.isFetching && debouncedQuery.length >= 2;
  const hasResults = allItems.length > 0;
  const showEmpty = query.length >= 2 && !isLoadingResources && !hasResults;
  const showPreview = selectedItem !== null && query.length > 0;

  const getItemId = (idx: number) => `us-item-${idx}`;
  const highlightedItemId = hasResults ? getItemId(clampedHighlight) : undefined;

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <dialog
      ref={dialogRef}
      onKeyDown={handleKeyDown}
      onClose={() => onOpenChange(false)}
      onClick={(e) => {
        // Clicking the native backdrop (the dialog element itself, outside its
        // content box) closes the palette — same as CommandPalette.
        if (e.target === dialogRef.current) onOpenChange(false);
      }}
      aria-label="Universal search"
      className={cn(
        "fixed left-1/2 top-[8vh] -translate-x-1/2",
        // Wider than the legacy CommandPalette (32 rem → 52 rem) to accommodate
        // the preview pane while remaining within a 1024 px viewport.
        "w-[min(52rem,calc(100%-2rem))]",
        "rounded-xl border bg-popover p-0 text-popover-foreground shadow-modal",
        "backdrop:bg-foreground/30 backdrop:backdrop-blur-sm",
        "open:animate-in open:fade-in-0 open:zoom-in-95",
      )}
    >
      <div className="flex flex-col" style={{ maxHeight: "80vh" }}>
        {/* ── Search input ─────────────────────────────────────────────── */}
        <div className="flex items-center gap-2 border-b px-3">
          <SearchIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-controls={LISTBOX_ID}
            aria-expanded={hasResults}
            aria-autocomplete="list"
            aria-activedescendant={highlightedItemId}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setHighlightIndex(0);
            }}
            placeholder="Search the control plane…"
            aria-label="Search"
            className="h-12 w-full border-0 bg-transparent text-base outline-none placeholder:text-muted-foreground"
          />
          {isLoadingResources && (
            <Spinner size="sm" label="Searching resources" className="shrink-0" />
          )}
          {query.length > 0 && (
            <button
              type="button"
              aria-label="Clear search"
              className="shrink-0 rounded p-0.5 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onClick={() => {
                setQuery("");
                setDebouncedQuery("");
                setHighlightIndex(0);
                inputRef.current?.focus();
              }}
            >
              <XIcon className="size-4" aria-hidden="true" />
            </button>
          )}
        </div>

        {/* ── Content area ─────────────────────────────────────────────── */}
        <div className="flex min-h-0 flex-1 overflow-hidden">
          {/* Results list */}
          <ScrollArea className="min-w-0 flex-1">
            <div
              id={LISTBOX_ID}
              role="listbox"
              aria-label="Search results"
              aria-multiselectable="false"
              className="p-1"
            >
              {showEmpty ? (
                <EmptyState
                  title="No results"
                  description={`Nothing matched "${query}". Try a different term.`}
                  className="py-8"
                />
              ) : isLoadingResources && !hasResults ? (
                <SearchSkeleton />
              ) : (
                <ResultGroups
                  groups={groups}
                  query={query}
                  highlightIndex={clampedHighlight}
                  allItems={allItems}
                  onHighlight={setHighlightIndex}
                  onSelect={commit}
                  getItemId={getItemId}
                />
              )}

              {/* Recents management link */}
              {!query && recentEntries.length > 0 && (
                <div className="border-t px-2 py-2">
                  <button
                    type="button"
                    className="flex items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground"
                    onClick={() => clearRecent()}
                  >
                    <HistoryIcon className="size-3" aria-hidden="true" />
                    Clear recent history
                  </button>
                </div>
              )}
            </div>
          </ScrollArea>

          {/* Preview pane — hidden on small viewports to avoid squashing the results list */}
          {showPreview && selectedItem !== null && (
            <>
              <Separator orientation="vertical" className="hidden sm:block" />
              <div className="hidden sm:block sm:w-52 sm:shrink-0 sm:overflow-y-auto">
                <PreviewPane
                  item={selectedItem}
                  ctx={searchCtx}
                  isFavorite={isFavorite(selectedItem.id)}
                  onToggleFavorite={() => toggleFavorite(selectedItem)}
                />
              </div>
            </>
          )}
        </div>

        {/* ── Footer ───────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between border-t px-3 py-2 text-xs text-muted-foreground">
          <span className="flex items-center gap-3">
            <span>
              <Kbd>↑↓</Kbd> <span className="opacity-80">navigate</span>
            </span>
            <span>
              <Kbd>↵</Kbd> <span className="opacity-80">select</span>
            </span>
            <span>
              <Kbd>esc</Kbd> <span className="opacity-80">close</span>
            </span>
          </span>
          {hasResults && (
            <span>
              {allItems.length} result{allItems.length === 1 ? "" : "s"}
            </span>
          )}
        </div>
      </div>
    </dialog>
  );
}

// ─── Loading skeleton ─────────────────────────────────────────────────────────
function SearchSkeleton() {
  return (
    <div
      role="status"
      className="flex flex-col gap-1 p-1"
      aria-label="Loading results"
      aria-busy="true"
    >
      <SkRow />
      <SkRow />
      <SkRow wide />
      <SkRow />
      <SkRow wide />
    </div>
  );
}

function SkRow({ wide = false }: { wide?: boolean }) {
  return (
    <div className="flex items-center gap-2.5 rounded-md px-2.5 py-2">
      <Skeleton className="size-5 shrink-0 rounded-md" />
      <div className="flex flex-1 flex-col gap-1">
        <Skeleton className={cn("h-3.5 rounded", wide ? "w-40" : "w-28")} />
        <Skeleton className={cn("h-2.5 rounded", wide ? "w-56" : "w-44")} />
      </div>
    </div>
  );
}
