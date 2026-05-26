import * as React from "react"
import { CheckIcon, CopyIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

interface CopyableSecretProps {
  /** The string the user wants to copy. */
  value: string
  /**
   * Optional inline label appended before the value inside the code box —
   * e.g. `label="client_secret="` produces `client_secret=<value>`.
   * Only the bare `value` (without the label prefix) is copied.
   */
  label?: string
  /** Render as a single non-wrapping line instead of letting the value wrap. */
  oneLine?: boolean
  /** Tighter padding for inline use inside dialogs / lists. */
  size?: "sm" | "md"
  /** Disable the copy button (read-only fallback while still visually rendered). */
  disabled?: boolean
  className?: string
  /** Override the default "Copy" / "Copied" labels for i18n later. */
  copyLabel?: string
  copiedLabel?: string
  /** Optional hook that fires after a successful copy. */
  onCopy?: (value: string) => void
  /** Override the post-copy "Copied" indicator duration in milliseconds. */
  copiedDurationMs?: number
}

/**
 * CopyableSecret renders a read-only code box next to a Copy button.
 * After a successful copy, the button briefly flips to a checkmark +
 * "Copied" label for `copiedDurationMs` (default 1500 ms) before
 * reverting.
 *
 * The value is always fully visible — this primitive is intended for
 * one-time secret-reveal panels (API keys, OAuth client secrets,
 * webhook signing secrets), where masking the value would defeat the
 * purpose. For inspect/masked use cases, build on top of this with a
 * separate reveal toggle.
 */
function CopyableSecret({
  value,
  label,
  oneLine,
  size = "md",
  disabled,
  className,
  copyLabel = "Copy",
  copiedLabel = "Copied",
  onCopy,
  copiedDurationMs = 1500,
}: CopyableSecretProps) {
  const [copied, setCopied] = React.useState(false)
  const timerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null)

  React.useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value)
    } catch {
      // Browsers without async clipboard API (Safari incognito etc.):
      // fall back to a transient textarea + execCommand("copy").
      const ta = document.createElement("textarea")
      ta.value = value
      ta.setAttribute("readonly", "")
      ta.style.position = "fixed"
      ta.style.opacity = "0"
      document.body.appendChild(ta)
      ta.select()
      try {
        document.execCommand("copy")
      } catch {
        document.body.removeChild(ta)
        return
      }
      document.body.removeChild(ta)
    }
    onCopy?.(value)
    setCopied(true)
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setCopied(false), copiedDurationMs)
  }

  const codeClasses = cn(
    "flex-1 rounded-md border bg-muted font-mono",
    size === "sm" ? "px-2 py-1 text-xs" : "px-3 py-2 text-sm",
    oneLine ? "overflow-x-auto whitespace-nowrap" : "break-all",
  )

  return (
    <div data-slot="copyable-secret" className={cn("flex items-center gap-2", className)}>
      <code className={codeClasses} aria-label={label ? `${label}${value}` : value}>
        {label}
        {value}
      </code>
      <Button
        type="button"
        variant="outline"
        size={size === "sm" ? "sm" : "default"}
        onClick={handleCopy}
        disabled={disabled}
        aria-label={copied ? copiedLabel : `${copyLabel} ${label?.trim() ?? "secret"}`.trim()}
      >
        {copied ? (
          <>
            <CheckIcon className="text-emerald-600 dark:text-emerald-400" />
            <span className="hidden sm:inline">{copiedLabel}</span>
          </>
        ) : (
          <>
            <CopyIcon />
            <span className="hidden sm:inline">{copyLabel}</span>
          </>
        )}
      </Button>
    </div>
  )
}

export { CopyableSecret }
export type { CopyableSecretProps }
