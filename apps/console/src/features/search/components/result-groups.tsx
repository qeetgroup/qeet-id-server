// ResultGroups: renders the grouped list of search results inside the listbox.
// Categories appear as sticky headers; items are rendered via ResultRow.

import type { SearchItem, SearchResultGroup } from "../registry/types";
import { ResultRow } from "./result-row";

interface ResultGroupsProps {
  groups: SearchResultGroup[];
  query: string;
  /** Flat-list index of the currently highlighted item. */
  highlightIndex: number;
  /** Flat list (same order as groups flattened). */
  allItems: SearchItem[];
  onHighlight(idx: number): void;
  onSelect(item: SearchItem): void;
  getItemId(idx: number): string;
}

export function ResultGroups({
  groups,
  query,
  highlightIndex,
  allItems,
  onHighlight,
  onSelect,
  getItemId,
}: ResultGroupsProps) {
  if (groups.length === 0) return null;

  return (
    <>
      {groups.map(({ category, items }) => {
        const headerId = `us-group-${category.toLowerCase().replace(/\s+/g, "-")}`;
        return (
          // role="group" + aria-labelledby is the correct ARIA pattern for grouping options
          // inside a role="listbox" (ARIA APG §3.14 Listbox). <fieldset> is the semantic
          // equivalent for form fields but is not valid inside a listbox subtree.
          // biome-ignore lint/a11y/useSemanticElements: role="group" is correct for listbox option groups per ARIA APG
          <div key={category} role="group" aria-labelledby={headerId}>
            <div
              id={headerId}
              className="sticky top-0 bg-popover px-2 pb-1 pt-2 text-xs font-medium text-muted-foreground"
            >
              {category}
            </div>
            {items.map((item) => {
              const globalIdx = allItems.indexOf(item);
              return (
                <ResultRow
                  key={item.id}
                  id={getItemId(globalIdx)}
                  item={item}
                  query={query}
                  isHighlighted={globalIdx === highlightIndex}
                  onMouseEnter={() => onHighlight(globalIdx)}
                  onClick={() => onSelect(item)}
                />
              );
            })}
          </div>
        );
      })}
    </>
  );
}
