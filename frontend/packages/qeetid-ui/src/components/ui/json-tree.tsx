import * as React from "react"
import { ChevronRightIcon } from "lucide-react"

import { cn } from "@/lib/utils"

interface JSONTreeProps {
  /** Any JSON-serialisable value: object, array, string, number, boolean, null. */
  value: unknown
  /** Tree depth at which nested nodes start collapsed. Default 1 (top-level
   *  is open, anything nested starts collapsed). 0 collapses everything. */
  initialOpenDepth?: number
  /** Default root label (e.g. "payload"). Not shown when null. */
  rootLabel?: string | null
  className?: string
}

const TOKEN = {
  punct: "text-muted-foreground",
  key: "text-sky-700 dark:text-sky-400",
  string: "text-emerald-700 dark:text-emerald-400",
  number: "text-amber-700 dark:text-amber-400",
  literal: "text-violet-700 dark:text-violet-400",
} as const

function summary(value: unknown): string {
  if (Array.isArray(value)) {
    const n = value.length
    return `[ ${n} item${n === 1 ? "" : "s"} ]`
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value as object)
    return `{ ${keys.length} key${keys.length === 1 ? "" : "s"} }`
  }
  return ""
}

interface NodeProps {
  name?: string | number
  value: unknown
  depth: number
  initialOpenDepth: number
  isLast: boolean
}

function Node({ name, value, depth, initialOpenDepth, isLast }: NodeProps) {
  const isContainer =
    value !== null && typeof value === "object" && (Array.isArray(value) || true)
  const [open, setOpen] = React.useState(depth < initialOpenDepth)
  const indent = { paddingInlineStart: depth * 14 + "px" } as const

  const renderKey = name !== undefined && (
    <>
      {typeof name === "number" ? (
        <span className={TOKEN.punct}>{name}</span>
      ) : (
        <span className={TOKEN.key}>"{name}"</span>
      )}
      <span className={TOKEN.punct}>: </span>
    </>
  )

  if (value === null) {
    return (
      <div style={indent}>
        {renderKey}
        <span className={TOKEN.literal}>null</span>
        {!isLast && <span className={TOKEN.punct}>,</span>}
      </div>
    )
  }
  if (typeof value === "boolean") {
    return (
      <div style={indent}>
        {renderKey}
        <span className={TOKEN.literal}>{String(value)}</span>
        {!isLast && <span className={TOKEN.punct}>,</span>}
      </div>
    )
  }
  if (typeof value === "number") {
    return (
      <div style={indent}>
        {renderKey}
        <span className={TOKEN.number}>{value}</span>
        {!isLast && <span className={TOKEN.punct}>,</span>}
      </div>
    )
  }
  if (typeof value === "string") {
    return (
      <div style={indent}>
        {renderKey}
        <span className={TOKEN.string}>"{value}"</span>
        {!isLast && <span className={TOKEN.punct}>,</span>}
      </div>
    )
  }

  // Container: array or object
  if (Array.isArray(value)) {
    return (
      <div>
        <div
          style={indent}
          className="flex items-center gap-1 hover:bg-muted/40 rounded-sm"
        >
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            aria-label={open ? "Collapse" : "Expand"}
            className="grid size-3 place-items-center"
          >
            <ChevronRightIcon
              className={cn(
                "size-3 text-muted-foreground transition-transform",
                open && "rotate-90",
              )}
            />
          </button>
          {renderKey}
          {open ? (
            <span className={TOKEN.punct}>[</span>
          ) : (
            <>
              <span className={TOKEN.punct}>[</span>
              <span className="text-muted-foreground/70 text-xs">
                {summary(value)}
              </span>
              <span className={TOKEN.punct}>]</span>
              {!isLast && <span className={TOKEN.punct}>,</span>}
            </>
          )}
        </div>
        {open && (
          <>
            {value.map((item, i) => (
              <Node
                key={i}
                name={i}
                value={item}
                depth={depth + 1}
                initialOpenDepth={initialOpenDepth}
                isLast={i === value.length - 1}
              />
            ))}
            <div style={indent}>
              <span className={TOKEN.punct}>]</span>
              {!isLast && <span className={TOKEN.punct}>,</span>}
            </div>
          </>
        )}
      </div>
    )
  }

  if (isContainer && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
    return (
      <div>
        <div
          style={indent}
          className="flex items-center gap-1 hover:bg-muted/40 rounded-sm"
        >
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            aria-label={open ? "Collapse" : "Expand"}
            className="grid size-3 place-items-center"
          >
            <ChevronRightIcon
              className={cn(
                "size-3 text-muted-foreground transition-transform",
                open && "rotate-90",
              )}
            />
          </button>
          {renderKey}
          {open ? (
            <span className={TOKEN.punct}>{"{"}</span>
          ) : (
            <>
              <span className={TOKEN.punct}>{"{"}</span>
              <span className="text-muted-foreground/70 text-xs">
                {summary(value)}
              </span>
              <span className={TOKEN.punct}>{"}"}</span>
              {!isLast && <span className={TOKEN.punct}>,</span>}
            </>
          )}
        </div>
        {open && (
          <>
            {entries.map(([k, v], i) => (
              <Node
                key={k}
                name={k}
                value={v}
                depth={depth + 1}
                initialOpenDepth={initialOpenDepth}
                isLast={i === entries.length - 1}
              />
            ))}
            <div style={indent}>
              <span className={TOKEN.punct}>{"}"}</span>
              {!isLast && <span className={TOKEN.punct}>,</span>}
            </div>
          </>
        )}
      </div>
    )
  }

  // Fallback for unexpected types (functions, undefined, etc.)
  return (
    <div style={indent}>
      {renderKey}
      <span className={TOKEN.punct}>{String(value)}</span>
    </div>
  )
}

/**
 * JSONTree renders any JSON-serialisable value as a collapsible
 * indented tree. Each object/array node gets a disclosure triangle and
 * a summary line ("{ 3 keys }" / "[ 12 items ]") so deep payloads stay
 * compact until the reader drills in.
 *
 * Used for inspecting webhook delivery payloads, audit event metadata,
 * OIDC discovery documents — anywhere the data is large enough that
 * `<CodeBlock>` would scroll forever.
 */
function JSONTree({ value, initialOpenDepth = 1, rootLabel = null, className }: JSONTreeProps) {
  return (
    <div
      data-slot="json-tree"
      className={cn(
        "overflow-auto rounded-md border bg-muted/30 p-2 font-mono text-xs leading-relaxed",
        className,
      )}
    >
      <Node
        name={rootLabel ?? undefined}
        value={value}
        depth={0}
        initialOpenDepth={initialOpenDepth}
        isLast
      />
    </div>
  )
}

export { JSONTree }
export type { JSONTreeProps }
