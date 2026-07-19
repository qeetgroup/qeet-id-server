// Identity Timeline — git-history-style vertical timeline of a user's lifecycle.
// Groups events by date bucket (Today → Older), virtualises with
// IntersectionObserver + bounded DOM (cap via cursor pagination), supports
// infinite scroll, keyboard nav, and motion-safe animations.
//
// ARIA: The outer list is a semantic <ol> (historical data, not a live region).
//       Individual items use aria-posinset / aria-setsize per APG guidelines.

import {
  Button,
  cn,
  EmptyState,
  ScrollArea,
  Separator,
  Skeleton,
  Timeline,
  usePrefersReducedMotion,
} from "@qeetrix/ui";
import { ActivityIcon, RefreshCwIcon } from "lucide-react";
import { useEffect, useRef } from "react";

import type { ActivityEvent, DateGroup } from "@/features/activity/types";
import { TimelineItem } from "./timeline-item";

// ---------------------------------------------------------------------------
// Date-group header
// ---------------------------------------------------------------------------

function GroupHeader({ label }: { label: string }) {
  return (
    <div className="sticky top-0 z-10 flex items-center gap-3 bg-background/90 py-2 backdrop-blur-sm">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <Separator className="flex-1" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skeleton placeholders
// ---------------------------------------------------------------------------

const SKELETON_IDS = ["a", "b", "c", "d"] as const;

function TimelineSkeletons() {
  return (
    /* role="status" supports aria-label; aria-busy signals loading in progress */
    <div role="status" aria-label="Loading timeline events" className="flex flex-col gap-3 pl-5">
      {SKELETON_IDS.map((id) => (
        <div key={id} className="flex gap-3">
          <Skeleton className="size-7 shrink-0 rounded-md" />
          <div className="flex-1 space-y-2 pt-0.5">
            <Skeleton className="h-3.5 w-48 max-w-full" />
            <Skeleton className="h-2.5 w-32 max-w-full" />
          </div>
          <Skeleton className="h-2.5 w-14 shrink-0" />
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// IdentityTimeline
// ---------------------------------------------------------------------------

type IdentityTimelineProps = {
  groups: DateGroup[];
  isLoadingHistory: boolean;
  isFetchingNextPage: boolean;
  hasNextPage: boolean;
  onLoadMore: () => void;
  onSelectEvent: (event: ActivityEvent) => void;
  selectedEventId?: string | null;
  isError?: boolean;
  onRetry?: () => void;
};

/**
 * The main identity timeline component.
 *
 * Virtualization approach: cursor-based pagination (50 events/page) keeps the
 * DOM bounded without adding a new virtualizer dependency.
 * IntersectionObserver at the bottom sentinel triggers the next page load
 * (mirroring the activity feed's approach).
 */
export function IdentityTimeline({
  groups,
  isLoadingHistory,
  isFetchingNextPage,
  hasNextPage,
  onLoadMore,
  onSelectEvent,
  selectedEventId,
  isError = false,
  onRetry,
}: IdentityTimelineProps) {
  const reducedMotion = usePrefersReducedMotion();
  const sentinelRef = useRef<HTMLLIElement>(null);

  // IntersectionObserver: load next page when the sentinel enters the viewport.
  useEffect(() => {
    const sentinel = sentinelRef.current;
    if (!sentinel || !hasNextPage) return;

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) onLoadMore();
        }
      },
      { rootMargin: "200px" },
    );
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [hasNextPage, onLoadMore]);

  // ── Early-return states ─────────────────────────────────────────────────

  if (isLoadingHistory && groups.length === 0) {
    return (
      <div className="px-1 py-4">
        <TimelineSkeletons />
      </div>
    );
  }

  if (isError && groups.length === 0) {
    return (
      <div className="flex min-h-72 items-center justify-center">
        <EmptyState
          icon={RefreshCwIcon}
          title="Couldn't load timeline"
          description="There was a problem fetching this user's event history."
          action={
            onRetry && (
              <Button variant="outline" size="sm" onClick={onRetry}>
                <RefreshCwIcon className="size-3.5" aria-hidden="true" />
                Retry
              </Button>
            )
          }
        />
      </div>
    );
  }

  if (groups.length === 0) {
    return (
      <div className="flex min-h-72 items-center justify-center">
        <EmptyState
          icon={ActivityIcon}
          title="No events found"
          description="No activity events match your current filters for this user."
        />
      </div>
    );
  }

  // Flatten all events for aria-posinset / aria-setsize totals
  const totalEvents = groups.reduce((acc, g) => acc + g.events.length, 0);
  let globalIndex = 0;

  return (
    <ScrollArea className="flex-1">
      {/*
        Semantic <ol> — this is historical data, not a live region.
        aria-live must NOT be on historical content (APG spec).
      */}
      <ol aria-label="Identity timeline events" className="flex flex-col gap-0 px-1 pb-6">
        {groups.map((group) => (
          <li key={group.label}>
            <section aria-label={`${group.label} events`}>
              <GroupHeader label={group.label} />

              {/* @qeetrix/ui Timeline provides the vertical connector rail */}
              <Timeline>
                {group.events.map((event, index) => {
                  const itemIndex = ++globalIndex;
                  const isSelected = event.id === selectedEventId;

                  return (
                    <div
                      key={event.id}
                      className={cn(
                        !reducedMotion && index === 0
                          ? "motion-safe:animate-in motion-safe:fade-in-0 motion-safe:duration-200"
                          : "",
                      )}
                    >
                      <TimelineItem
                        event={event}
                        isSelected={isSelected}
                        isCurrent={isSelected}
                        onClick={onSelectEvent}
                        posInSet={itemIndex}
                        setSize={totalEvents}
                      />
                    </div>
                  );
                })}
              </Timeline>
            </section>
          </li>
        ))}

        {/* Infinite scroll sentinel */}
        {hasNextPage && (
          <li ref={sentinelRef} className="py-2" aria-hidden="true">
            {isFetchingNextPage && (
              <div className="px-1">
                <TimelineSkeletons />
              </div>
            )}
          </li>
        )}

        {!hasNextPage && groups.length > 0 && (
          <li>
            <p
              className="py-4 text-center text-[11px] text-muted-foreground"
              aria-live="polite"
              aria-atomic="true"
            >
              All events loaded · {totalEvents} total
            </p>
          </li>
        )}
      </ol>
    </ScrollArea>
  );
}
