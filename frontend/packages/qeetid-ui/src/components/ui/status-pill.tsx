import { Badge, type BadgeProps } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

/**
 * The visual kind drives both the leading dot colour and the Badge
 * variant. These map 1:1 onto the existing Badge variants so a pill
 * never looks out-of-place next to a hand-rolled Badge.
 */
export type StatusKind = "success" | "warning" | "danger" | "info" | "muted" | "neutral"

const KIND_TO_BADGE: Record<StatusKind, BadgeProps["variant"]> = {
  success: "success",
  warning: "warning",
  danger: "destructive",
  info: "default",
  muted: "muted",
  neutral: "outline",
}

const KIND_TO_DOT: Record<StatusKind, string> = {
  success: "bg-emerald-500",
  warning: "bg-amber-500",
  danger: "bg-rose-500",
  info: "bg-sky-500",
  muted: "bg-muted-foreground/60",
  neutral: "bg-muted-foreground/60",
}

/**
 * Well-known status strings the API surfaces. New strings can be added
 * here without touching call sites. Keys are lowercased before lookup,
 * so the API can send "Active" / "active" / "ACTIVE" interchangeably.
 */
const KNOWN_STATUSES: Record<string, { kind: StatusKind; label: string }> = {
  active: { kind: "success", label: "Active" },
  enabled: { kind: "success", label: "Enabled" },
  verified: { kind: "success", label: "Verified" },
  ok: { kind: "success", label: "OK" },
  up: { kind: "success", label: "Up" },
  delivered: { kind: "success", label: "Delivered" },
  succeeded: { kind: "success", label: "Succeeded" },
  live: { kind: "success", label: "Live" },

  pending: { kind: "warning", label: "Pending" },
  expiring: { kind: "warning", label: "Expiring" },
  degraded: { kind: "warning", label: "Degraded" },
  warn: { kind: "warning", label: "Warning" },
  unverified: { kind: "warning", label: "Unverified" },

  expired: { kind: "danger", label: "Expired" },
  revoked: { kind: "danger", label: "Revoked" },
  disabled: { kind: "danger", label: "Disabled" },
  suspended: { kind: "danger", label: "Suspended" },
  deleted: { kind: "danger", label: "Deleted" },
  failed: { kind: "danger", label: "Failed" },
  down: { kind: "danger", label: "Down" },

  draft: { kind: "muted", label: "Draft" },
  archived: { kind: "muted", label: "Archived" },
  inactive: { kind: "muted", label: "Inactive" },
}

interface StatusPillProps {
  /** Well-known status string (matched case-insensitively). */
  status?: string
  /** Explicit kind override; takes precedence over `status`. */
  kind?: StatusKind
  /** Show the leading dot. Defaults to true. */
  dot?: boolean
  /** Custom label. Defaults to the known label, or a Title-cased status. */
  children?: React.ReactNode
  className?: string
}

function titleCase(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase()
}

/**
 * StatusPill is a thin wrapper over Badge that centralises the
 * status-to-colour mapping (active = green, expired = red, etc.).
 *
 * Pass `status="active"` (or any known key) for automatic colour +
 * label, or pass an explicit `kind` and `children` for one-off shapes
 * the API doesn't speak. Unknown strings fall back to neutral styling
 * with the status title-cased as the label.
 */
function StatusPill({ status, kind, dot = true, children, className }: StatusPillProps) {
  const known = status ? KNOWN_STATUSES[status.toLowerCase()] : undefined
  const resolved: StatusKind = kind ?? known?.kind ?? "neutral"
  const label = children ?? known?.label ?? (status ? titleCase(status) : "")

  return (
    <Badge variant={KIND_TO_BADGE[resolved]} className={cn("gap-1.5", className)}>
      {dot && (
        <span
          data-slot="status-pill-dot"
          aria-hidden="true"
          className={cn("size-1.5 rounded-full", KIND_TO_DOT[resolved])}
        />
      )}
      {label}
    </Badge>
  )
}

export { StatusPill }
export type { StatusPillProps }
