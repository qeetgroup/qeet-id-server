// ResultRow: a single search result rendered inside the listbox.
// Uses @qeetrix/ui Highlight for match emphasis and StatusPill for status display.

import { Badge, cn, Highlight, StatusPill } from "@qeetrix/ui";

import type { SearchItem } from "../registry/types";

interface ResultRowProps {
  item: SearchItem;
  query: string;
  isHighlighted: boolean;
  onMouseEnter(): void;
  onClick(): void;
  id: string;
}

export function ResultRow({
  item,
  query,
  isHighlighted,
  onMouseEnter,
  onClick,
  id,
}: ResultRowProps) {
  return (
    <button
      type="button"
      role="option"
      id={id}
      aria-selected={isHighlighted}
      className={cn(
        "flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-start text-sm",
        "transition-colors",
        isHighlighted ? "bg-accent text-accent-foreground" : "text-foreground hover:bg-muted/50",
      )}
      onMouseEnter={onMouseEnter}
      onClick={onClick}
    >
      {item.icon != null && (
        <span
          className="grid size-5 shrink-0 place-items-center text-muted-foreground"
          aria-hidden="true"
        >
          {item.icon}
        </span>
      )}

      <span className="flex min-w-0 flex-1 flex-col">
        <span className="truncate font-medium">
          <Highlight query={query}>{item.title}</Highlight>
        </span>
        {item.subtitle != null && (
          <span className="truncate text-xs text-muted-foreground">
            <Highlight query={query}>{item.subtitle}</Highlight>
          </span>
        )}
      </span>

      {/* Right-side badges */}
      <span className="flex shrink-0 items-center gap-1.5">
        {item.kind === "command" && (
          <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
            cmd
          </Badge>
        )}
        {item.kind === "favorite" && (
          <Badge variant="muted" className="px-1.5 py-0 text-[10px]">
            ★
          </Badge>
        )}
        {item.status != null && <StatusPill status={item.status} className="text-[10px]" />}
      </span>
    </button>
  );
}
