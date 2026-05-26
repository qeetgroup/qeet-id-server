import * as React from "react"

import { cn } from "@/lib/utils"

export interface CommandPaletteItem {
  /** Stable id used as React key. */
  id: string
  /** Visible label. */
  title: string
  /** Optional group heading (items are clustered by group in display order). */
  group?: string
  /** Optional leading icon. */
  icon?: React.ReactNode
  /** Extra search terms — matched in addition to title/group. */
  keywords?: string[]
  /** Optional payload the caller can attach (e.g. a route, a callback). */
  payload?: unknown
}

interface CommandPaletteProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  items: CommandPaletteItem[]
  onSelect: (item: CommandPaletteItem) => void
  placeholder?: string
  emptyMessage?: string
  /** Show the footer hint with ↑↓ / ↵ / esc. Default true. */
  showHint?: boolean
  className?: string
}

function matches(item: CommandPaletteItem, q: string): boolean {
  if (!q) return true
  const ql = q.toLowerCase()
  if (item.title.toLowerCase().includes(ql)) return true
  if (item.group?.toLowerCase().includes(ql)) return true
  if (item.keywords?.some((k) => k.toLowerCase().includes(ql))) return true
  return false
}

/**
 * CommandPalette is a Cmd-K modal: a centered search box with a filtered,
 * grouped list of navigable items. Built on the browser's native
 * `<dialog>` (top-layer rendering, focus trap, ESC handling, ARIA modal
 * semantics for free).
 *
 * Caller owns open state, items, and onSelect. Items render in the order
 * provided, clustered by `group` headings as they appear in the
 * filtered list.
 *
 * Keyboard: ↑↓ moves highlight, ↵ selects, ESC closes. Clicking the
 * backdrop also closes.
 */
function CommandPalette({
  open,
  onOpenChange,
  items,
  onSelect,
  placeholder = "Search…",
  emptyMessage = "No matches",
  showHint = true,
  className,
}: CommandPaletteProps) {
  const dialogRef = React.useRef<HTMLDialogElement>(null)
  const inputRef = React.useRef<HTMLInputElement>(null)
  const [query, setQuery] = React.useState("")
  const [highlight, setHighlight] = React.useState(0)

  const filtered = React.useMemo(() => items.filter((i) => matches(i, query)), [items, query])

  // Cluster filtered items by group, preserving original order.
  const grouped = React.useMemo(() => {
    const order: string[] = []
    const map = new Map<string, CommandPaletteItem[]>()
    for (const item of filtered) {
      const g = item.group ?? ""
      if (!map.has(g)) {
        map.set(g, [])
        order.push(g)
      }
      map.get(g)!.push(item)
    }
    return order.map((g) => ({ group: g, items: map.get(g)! }))
  }, [filtered])

  // Drive the native dialog open/closed from React state.
  React.useEffect(() => {
    const d = dialogRef.current
    if (!d) return
    if (open && !d.open) {
      d.showModal()
      // Defer focus to after the dialog finishes opening.
      requestAnimationFrame(() => inputRef.current?.focus())
    } else if (!open && d.open) {
      d.close()
    }
  }, [open])

  // Reset query + highlight every time the palette opens.
  React.useEffect(() => {
    if (open) {
      setQuery("")
      setHighlight(0)
    }
  }, [open])

  // Clamp highlight when the filtered list shrinks.
  React.useEffect(() => {
    setHighlight(0)
  }, [query])

  function commit(item: CommandPaletteItem | undefined) {
    if (!item) return
    onSelect(item)
    onOpenChange(false)
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault()
      setHighlight((h) => Math.min(filtered.length - 1, h + 1))
    } else if (e.key === "ArrowUp") {
      e.preventDefault()
      setHighlight((h) => Math.max(0, h - 1))
    } else if (e.key === "Enter") {
      e.preventDefault()
      commit(filtered[highlight])
    }
    // Native <dialog> handles Esc → close → onClose handler below.
  }

  return (
    <dialog
      ref={dialogRef}
      onClose={() => onOpenChange(false)}
      onClick={(e) => {
        // Clicking the backdrop (the dialog element itself, outside its
        // child content box) closes the palette.
        if (e.target === dialogRef.current) onOpenChange(false)
      }}
      aria-label="Command palette"
      className={cn(
        "mt-[10vh] w-full max-w-lg rounded-xl border bg-popover p-0 text-popover-foreground shadow-2xl",
        "backdrop:bg-foreground/30 backdrop:backdrop-blur-sm",
        "open:animate-in open:fade-in-0 open:zoom-in-95",
        className,
      )}
    >
      <div onKeyDown={handleKeyDown} className="flex flex-col">
        <div className="border-b">
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            aria-label={placeholder}
            className="h-12 w-full border-0 bg-transparent px-4 text-base outline-none placeholder:text-muted-foreground"
          />
        </div>
        <div className="max-h-96 overflow-y-auto p-1">
          {filtered.length === 0 ? (
            <div className="p-6 text-center text-sm text-muted-foreground">{emptyMessage}</div>
          ) : (
            grouped.map(({ group, items: groupItems }) => (
              <div key={group || "_"}>
                {group && (
                  <div className="px-2 pt-2 pb-1 text-xs font-medium text-muted-foreground">
                    {group}
                  </div>
                )}
                {groupItems.map((item) => {
                  const idx = filtered.indexOf(item)
                  const isHighlighted = idx === highlight
                  return (
                    <button
                      key={item.id}
                      type="button"
                      role="option"
                      aria-selected={isHighlighted}
                      data-highlighted={isHighlighted || undefined}
                      className={cn(
                        "flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-sm",
                        "transition-colors",
                        isHighlighted
                          ? "bg-accent text-accent-foreground"
                          : "text-foreground hover:bg-muted/50",
                      )}
                      onMouseEnter={() => setHighlight(idx)}
                      onClick={() => commit(item)}
                    >
                      {item.icon && (
                        <span className="grid size-4 place-items-center text-muted-foreground">
                          {item.icon}
                        </span>
                      )}
                      <span className="truncate">{item.title}</span>
                    </button>
                  )
                })}
              </div>
            ))
          )}
        </div>
        {showHint && (
          <div className="flex items-center justify-between border-t px-3 py-2 text-xs text-muted-foreground">
            <span>
              <kbd className="rounded border px-1 font-sans">↑↓</kbd>{" "}
              <span className="opacity-80">navigate</span>
              {" · "}
              <kbd className="rounded border px-1 font-sans">↵</kbd>{" "}
              <span className="opacity-80">select</span>
              {" · "}
              <kbd className="rounded border px-1 font-sans">esc</kbd>{" "}
              <span className="opacity-80">close</span>
            </span>
            <span>{filtered.length} result{filtered.length === 1 ? "" : "s"}</span>
          </div>
        )}
      </div>
    </dialog>
  )
}

export { CommandPalette }
export type { CommandPaletteProps }
