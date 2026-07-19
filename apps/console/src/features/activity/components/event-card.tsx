import {
  Avatar,
  AvatarFallback,
  Badge,
  cn,
  TimeSince,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@qeetrix/ui";
import {
  ActivityIcon,
  AlertTriangleIcon,
  CheckCircleIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  FingerprintIcon,
  GlobeIcon,
  InfoIcon,
  KeyRoundIcon,
  LogInIcon,
  MonitorIcon,
  ServerIcon,
  ShieldAlertIcon,
  UserIcon,
  WebhookIcon,
  XCircleIcon,
} from "lucide-react";
import { useState } from "react";

import type { ActivityEvent, Severity } from "../types";
import { SeverityBadge } from "./severity-badge";

// ---------------------------------------------------------------------------
// Category → icon mapping
// ---------------------------------------------------------------------------

const CATEGORY_ICONS: Record<string, typeof ActivityIcon> = {
  authentication: LogInIcon,
  authorization: ShieldAlertIcon,
  mfa: FingerprintIcon,
  "api-key": KeyRoundIcon,
  apikey: KeyRoundIcon,
  webhook: WebhookIcon,
  user: UserIcon,
  session: MonitorIcon,
  system: ServerIcon,
  federation: GlobeIcon,
};

const SEVERITY_ICON: Record<Severity, typeof ActivityIcon> = {
  critical: XCircleIcon,
  error: XCircleIcon,
  warning: AlertTriangleIcon,
  success: CheckCircleIcon,
  info: InfoIcon,
};

const SEVERITY_ICON_CLASS: Record<Severity, string> = {
  critical: "text-destructive",
  error: "text-destructive",
  warning: "text-warning",
  success: "text-success",
  info: "text-info",
};

function getCategoryIcon(category: string): typeof ActivityIcon {
  const key = category.toLowerCase().replace(/[^a-z-]/g, "");
  return CATEGORY_ICONS[key] ?? ActivityIcon;
}

// ---------------------------------------------------------------------------
// EventCard
// ---------------------------------------------------------------------------

type EventCardProps = {
  event: ActivityEvent;
  isNew?: boolean;
  isSelected?: boolean;
  compact?: boolean;
  onClick?: () => void;
};

/**
 * A single activity event row. Supports a compact mode (dashboard widget)
 * and a full mode (activity page timeline). Keyboard-accessible.
 */
export function EventCard({
  event,
  isNew = false,
  isSelected = false,
  compact = false,
  onClick,
}: EventCardProps) {
  const [expanded, setExpanded] = useState(false);
  const CategoryIcon = getCategoryIcon(event.category);
  const SeverityIcon = SEVERITY_ICON[event.severity];
  const isCritical = event.severity === "critical" || event.severity === "error";

  const actorInitials =
    event.actor?.name
      ?.split(" ")
      .map((n) => n[0])
      .join("")
      .slice(0, 2)
      .toUpperCase() ?? "?";

  if (compact) {
    return (
      <button
        type="button"
        className={cn(
          "group flex w-full min-w-0 items-center gap-3 px-4 py-3 text-left transition-colors duration-150 hover:bg-muted/35 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring sm:px-4.5",
          isCritical && "bg-destructive/5 hover:bg-destructive/10",
          isNew && "bg-success/10",
          isSelected && "bg-muted/55",
        )}
        onClick={onClick}
        aria-label={`${event.title}${event.actor?.name ? `, by ${event.actor.name}` : ""}`}
      >
        <span
          className={cn(
            "grid size-9 shrink-0 place-items-center rounded-lg bg-muted ring-1 ring-foreground/6 [&_svg]:size-3.5",
            isCritical && "bg-destructive/10 text-destructive ring-destructive/20",
          )}
          aria-hidden="true"
        >
          <CategoryIcon />
        </span>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{event.title}</p>
          <div className="mt-0.5 flex min-w-0 items-center gap-1.5">
            {event.actor?.type && (
              <Badge variant="muted" className="max-w-24 truncate text-[10px]">
                {event.actor.type}
              </Badge>
            )}
            <span className="truncate text-[11px] text-muted-foreground">{event.category}</span>
          </div>
        </div>
        <TimeSince
          value={event.at}
          className="shrink-0 text-[11px] text-muted-foreground tabular-nums"
        />
      </button>
    );
  }

  // Full event card (activity page timeline)
  return (
    <article
      className={cn(
        "group/card relative flex min-w-0 flex-col gap-3 rounded-lg border border-border/60 bg-card p-4 shadow-rest transition-all duration-150",
        "hover:border-border hover:shadow-hover",
        "focus-within:ring-2 focus-within:ring-ring/50",
        isCritical && "border-destructive/30 bg-destructive/3",
        isNew && "border-success/30 bg-success/10",
        isSelected && "ring-2 ring-ring",
      )}
      aria-label={event.title}
    >
      {/* Header row */}
      <div className="flex min-w-0 items-start gap-3">
        {/* Category icon */}
        <span
          className={cn(
            "mt-0.5 grid size-8 shrink-0 place-items-center rounded-md bg-muted text-muted-foreground ring-1 ring-foreground/6 [&_svg]:size-4",
            isCritical && "bg-destructive/10 text-destructive ring-destructive/15",
          )}
          aria-hidden="true"
        >
          <CategoryIcon />
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="min-w-0 flex-1 truncate text-sm font-semibold">{event.title}</span>
            <SeverityBadge severity={event.severity} />
            {isNew && (
              <Badge variant="success" className="text-[10px]">
                New
              </Badge>
            )}
          </div>
          {event.description && (
            <p className="mt-1 text-xs leading-5 text-muted-foreground">{event.description}</p>
          )}
        </div>

        {/* Timestamp + expand toggle */}
        <div className="flex shrink-0 flex-col items-end gap-1.5">
          <TimeSince value={event.at} className="text-[11px] text-muted-foreground tabular-nums" />
          {onClick && (
            <button
              type="button"
              className="inline-flex items-center gap-1 text-[10px] text-muted-foreground underline-offset-2 hover:text-foreground hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              onClick={onClick}
              aria-label="Open event details"
            >
              Details <ChevronRightIcon className="size-3" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      {/* Meta row: actor, target, source */}
      <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
        {event.actor && (
          <div className="flex items-center gap-1.5">
            <Tooltip>
              <TooltipTrigger
                render={
                  <span className="flex items-center gap-1">
                    <Avatar className="size-4">
                      <AvatarFallback className="text-[8px]">{actorInitials}</AvatarFallback>
                    </Avatar>
                    <span className="max-w-32 truncate">
                      {event.actor.name ?? event.actor.id ?? event.actor.type ?? "Unknown"}
                    </span>
                  </span>
                }
              />
              <TooltipContent>
                {event.actor.type && <p className="text-xs">Type: {event.actor.type}</p>}
                {event.actor.id && <p className="font-mono text-xs">ID: {event.actor.id}</p>}
              </TooltipContent>
            </Tooltip>
          </div>
        )}

        {event.target && (
          <>
            <span aria-hidden="true">→</span>
            <span className="max-w-40 truncate">
              {event.target.label ?? event.target.id ?? event.target.type}
            </span>
          </>
        )}

        {event.source && (
          <>
            <span className="size-1 rounded-full bg-muted-foreground/40" aria-hidden="true" />
            <span>{event.source}</span>
          </>
        )}

        {event.ip && (
          <>
            <span className="size-1 rounded-full bg-muted-foreground/40" aria-hidden="true" />
            <span className="font-mono">{event.ip}</span>
          </>
        )}

        {event.severity === "info" || event.severity === "success" ? (
          <span className="ml-auto">
            <SeverityIcon
              className={cn("size-3.5", SEVERITY_ICON_CLASS[event.severity])}
              aria-hidden="true"
            />
          </span>
        ) : null}
      </div>

      {/* Expandable metadata */}
      {event.metadata && Object.keys(event.metadata).length > 0 && (
        <div>
          <button
            type="button"
            className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            aria-controls={`event-meta-${event.id}`}
          >
            {expanded ? (
              <ChevronDownIcon className="size-3" aria-hidden="true" />
            ) : (
              <ChevronRightIcon className="size-3" aria-hidden="true" />
            )}
            Metadata
          </button>
          {expanded && (
            <pre
              id={`event-meta-${event.id}`}
              className="mt-2 overflow-auto rounded-md bg-muted p-2 text-[10px] leading-5 text-muted-foreground"
            >
              {JSON.stringify(event.metadata, null, 2)}
            </pre>
          )}
        </div>
      )}
    </article>
  );
}
