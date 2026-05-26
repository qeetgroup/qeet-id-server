import * as React from "react"
import { CheckIcon, CopyIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export type CodeLanguage = "json" | "text" | "shell" | "http"

interface CodeBlockProps {
  /** The code to display. */
  value: string
  /** Light-touch syntax highlighting for "json"; other values render
   *  as plain monospace. Defaults to "text". */
  language?: CodeLanguage
  /** Show line numbers in the gutter. Defaults to false. */
  lineNumbers?: boolean
  /** Show the copy button. Defaults to true. */
  copy?: boolean
  /** CSS max-height utility before vertical scrolling kicks in. */
  maxHeight?: string
  className?: string
  /** Optional caption shown above the block (e.g. filename, content-type). */
  caption?: React.ReactNode
}

// ---------------------------------------------------------------------------
// JSON tokenizer
//
// Walks a JSON string with a single regex, emitting span-wrapped tokens for
// strings, keys, numbers, and literals. Anything else (commas, brackets,
// whitespace) passes through unchanged. Not a full grammar parser — just
// good enough to colour normal JSON payloads from the API. Pathological
// input (HTML embedded in a key, etc.) is harmless because we escape every
// emitted text node.
// ---------------------------------------------------------------------------

const JSON_TOKEN_RE =
  /("(?:\\.|[^"\\])*")(\s*:)?|(\b(?:true|false|null)\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g

const C = {
  key: "text-sky-700 dark:text-sky-400",
  string: "text-emerald-700 dark:text-emerald-400",
  number: "text-amber-700 dark:text-amber-400",
  literal: "text-violet-700 dark:text-violet-400",
}

function highlightJSON(input: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  let last = 0
  let i = 0
  for (const m of input.matchAll(JSON_TOKEN_RE)) {
    if (m.index! > last) {
      out.push(input.slice(last, m.index))
    }
    const [, strOrKey, colon, literal, num] = m
    if (strOrKey) {
      if (colon) {
        out.push(
          <span key={`k${i++}`} className={C.key}>
            {strOrKey}
          </span>,
        )
        out.push(colon)
      } else {
        out.push(
          <span key={`s${i++}`} className={C.string}>
            {strOrKey}
          </span>,
        )
      }
    } else if (literal) {
      out.push(
        <span key={`l${i++}`} className={C.literal}>
          {literal}
        </span>,
      )
    } else if (num) {
      out.push(
        <span key={`n${i++}`} className={C.number}>
          {num}
        </span>,
      )
    }
    last = m.index! + m[0].length
  }
  if (last < input.length) out.push(input.slice(last))
  return out
}

/**
 * CodeBlock renders a copyable, optionally syntax-highlighted code
 * block. JSON gets a small in-house highlighter; other languages render
 * as plain monospace. There's no external syntax-highlighter dependency
 * — for richer highlighting, pass already-rendered children via the
 * children-as-data pattern at a future point.
 */
function CodeBlock({
  value,
  language = "text",
  lineNumbers,
  copy = true,
  maxHeight = "max-h-96",
  className,
  caption,
}: CodeBlockProps) {
  const [copied, setCopied] = React.useState(false)
  const timerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null)

  React.useEffect(() => () => {
    if (timerRef.current) clearTimeout(timerRef.current)
  }, [])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value)
    } catch {
      return
    }
    setCopied(true)
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setCopied(false), 1500)
  }

  const lines = React.useMemo(() => value.split("\n"), [value])
  const rendered = React.useMemo<React.ReactNode>(() => {
    if (language === "json") {
      return highlightJSON(value)
    }
    return value
  }, [value, language])

  return (
    <div
      data-slot="code-block"
      className={cn(
        "group relative overflow-hidden rounded-md border bg-muted/30 font-mono text-xs",
        className,
      )}
    >
      {caption && (
        <div className="flex items-center justify-between border-b px-3 py-1.5 text-[11px] text-muted-foreground">
          {caption}
        </div>
      )}
      {copy && (
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={handleCopy}
          aria-label={copied ? "Copied" : "Copy code"}
          className="absolute end-2 top-2 z-10 opacity-0 transition-opacity group-hover:opacity-100 focus:opacity-100"
        >
          {copied ? (
            <CheckIcon className="text-emerald-600 dark:text-emerald-400" />
          ) : (
            <CopyIcon />
          )}
        </Button>
      )}
      <pre className={cn("m-0 overflow-auto p-3 leading-relaxed", maxHeight)}>
        {lineNumbers ? (
          <div className="flex">
            <div
              aria-hidden="true"
              className="me-3 select-none text-right text-muted-foreground/60"
            >
              {lines.map((_, i) => (
                <div key={i}>{i + 1}</div>
              ))}
            </div>
            <code className="flex-1 whitespace-pre">{rendered}</code>
          </div>
        ) : (
          <code className="whitespace-pre">{rendered}</code>
        )}
      </pre>
    </div>
  )
}

export { CodeBlock }
export type { CodeBlockProps }
