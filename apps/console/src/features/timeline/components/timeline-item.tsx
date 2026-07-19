// TimelineItem — one row of the identity timeline.
// Composes the @qeetrix/ui Timeline primitives (TimelineItem, TimelineIndicator,
// TimelineContent) with the reused compact EventCard from the activity feature.

import {
  cn,
  TimelineContent,
  TimelineIndicator,
  TimeSince,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TimelineItem as UITimelineItem,
} from "@qeetrix/ui";
import { ChevronRightIcon } from "lucide-react";

import { EventCard } from "@/features/activity/components/event-card";
import type { ActivityEvent, Severity } from "@/features/activity/types";

// ---------------------------------------------------------------------------
// Severity → dot color
// ---------------------------------------------------------------------------

const SEVERITY_DOT_CLASS: Record<Severity, string> = {
  critical: "bg-destructive ring-destructive/40",
  error: "bg-destructive ring-destructive/30",
  warning: "bg-warning ring-warning/30",
  success: "bg-success ring-success/30",
  info: "bg-muted-foreground/50 ring-border",
};

// ---------------------------------------------------------------------------
// TimelineItem
// ---------------------------------------------------------------------------

type TimelineItemProps = {
  event: ActivityEvent;
  isSelected?: boolean;
  isCurrent?: boolean;
  onClick: (event: ActivityEvent) => void;
  /** Aria position in the list for APG Feed pattern. */
  posInSet?: number;
  setSize?: number;
};

/**
 * One row in the identity timeline: a severity-colored dot on the connector
 * rail + the compact EventCard + a relative timestamp tooltip.
 *
 * Keyboard-accessible: the item focuses the inner EventCard button.
 * aria-current="true" is set on the selected item.
 */
export function TimelineItem({
  event,
  isSelected = false,
  isCurrent = false,
  onClick,
  posInSet,
  setSize,
}: TimelineItemProps) {
  const dotClass = SEVERITY_DOT_CLASS[event.severity];

  return (
    <UITimelineItem
      className={cn(
        "group/item relative pb-3",
        isSelected && "rounded-md bg-muted/40 ring-1 ring-ring/40",
      )}
      aria-current={isCurrent ? "true" : undefined}
      aria-posinset={posInSet}
      aria-setsize={setSize}
    >
      {/* Severity dot — replaces the default bg-primary dot */}
      <TimelineIndicator>
        <Tooltip>
          <TooltipTrigger
            render={
              <span
                role="img"
                className={cn(
                  "z-10 mt-0.5 size-2.5 rounded-full ring-4 ring-background",
                  dotClass,
                  "transition-all duration-150 group-hover/item:scale-125",
                )}
                aria-label={`Severity: ${event.severity}`}
              />
            }
          />
          <TooltipContent className="capitalize">{event.severity}</TooltipContent>
        </Tooltip>
      </TimelineIndicator>

      <TimelineContent className="min-w-0 flex-1">
        {/* Compact event card — reused from activity feature */}
        <EventCard event={event} compact isSelected={isSelected} onClick={() => onClick(event)} />

        {/* Exact timestamp below card (relative shown inside EventCard) */}
        <div className="mt-0.5 flex items-center justify-end gap-1.5 px-4 pb-0.5">
          <Tooltip>
            <TooltipTrigger
              render={
                <time
                  dateTime={event.at}
                  className="text-[10px] text-muted-foreground tabular-nums"
                >
                  <TimeSince value={event.at} />
                </time>
              }
            />
            <TooltipContent>
              {new Date(event.at).toLocaleString(undefined, {
                dateStyle: "medium",
                timeStyle: "long",
              })}
            </TooltipContent>
          </Tooltip>

          {/* Quick-open affordance */}
          <button
            type="button"
            className="inline-flex items-center gap-0.5 text-[10px] text-muted-foreground opacity-0 underline-offset-2 transition-opacity hover:text-foreground hover:underline focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring group-hover/item:opacity-100"
            onClick={() => onClick(event)}
            aria-label={`Open details for ${event.title}`}
            tabIndex={-1}
          >
            Details
            <ChevronRightIcon className="size-3" aria-hidden="true" />
          </button>
        </div>
      </TimelineContent>
    </UITimelineItem>
  );
}
