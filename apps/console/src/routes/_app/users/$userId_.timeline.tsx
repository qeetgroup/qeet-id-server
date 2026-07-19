// Identity Timeline route — /users/$userId/timeline
// A per-user, git-history-style chronological view of a user's entire lifecycle.
// Capability-gated on audit.read + user.read (server enforces tenant isolation).

import { EmptyState } from "@qeetrix/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeftIcon, ClockIcon, ShieldIcon } from "lucide-react";
import { useCallback, useMemo, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { useCapabilities } from "@/features/access-control/capability-provider";
import type { ActivityEvent } from "@/features/activity/types";
import { IdentityTimeline } from "@/features/timeline/components/identity-timeline";
import { TimelineDetailsDrawer } from "@/features/timeline/components/timeline-details-drawer";
import { TimelineFilters } from "@/features/timeline/components/timeline-filters";
import { TimelineProvider, useTimeline } from "@/features/timeline/timeline-provider";

export const Route = createFileRoute("/_app/users/$userId_/timeline")({
  component: TimelinePageWrapper,
});

// ---------------------------------------------------------------------------
// Inner page (requires TimelineProvider)
// ---------------------------------------------------------------------------

function TimelinePage() {
  const { userId } = Route.useParams();
  const access = useCapabilities();
  const canRead = access.can("audit.read") && access.can("user.read");

  const {
    events,
    groups,
    isLoading,
    isFetchingNextPage,
    hasNextPage,
    fetchNextPage,
    isError,
    retry,
    setSelectedEventId,
    selectedEventId,
  } = useTimeline();

  const [selectedEvent, setSelectedEvent] = useState<ActivityEvent | null>(null);

  const handleSelectEvent = useCallback(
    (event: ActivityEvent) => {
      setSelectedEvent(event);
      setSelectedEventId(event.id);
    },
    [setSelectedEventId],
  );

  const handleCloseDrawer = useCallback(() => {
    setSelectedEvent(null);
    setSelectedEventId(null);
  }, [setSelectedEventId]);

  // Derive prev/next for drawer navigation
  const selectedIndex = useMemo(
    () => events.findIndex((e) => e.id === selectedEvent?.id),
    [events, selectedEvent],
  );
  const prevEvent = selectedIndex > 0 ? events[selectedIndex - 1] : null;
  const nextEvent =
    selectedIndex >= 0 && selectedIndex < events.length - 1 ? events[selectedIndex + 1] : null;

  if (!canRead) {
    return (
      <div className="flex min-w-0 flex-col gap-4">
        <PageHeader
          title="Identity Timeline"
          description="A chronological view of this user's lifecycle events."
        />
        <div className="enterprise-panel flex min-h-64 items-center justify-center">
          <EmptyState
            icon={ShieldIcon}
            title="Access restricted"
            description={
              <>
                You need the <code className="font-mono">audit.read</code> and{" "}
                <code className="font-mono">user.read</code> capabilities to view the timeline.
              </>
            }
          />
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {/* Back link + page header */}
      <Link
        to="/users/$userId"
        params={{ userId }}
        className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
      >
        <ArrowLeftIcon className="size-3" aria-hidden="true" />
        Back to user
      </Link>

      <PageHeader
        title="Identity Timeline"
        description="Chronological view of this user's lifecycle — authentication, access changes, security events, and more."
        actions={
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <ClockIcon className="size-3.5" aria-hidden="true" />
            <span>
              {isLoading
                ? "Loading…"
                : `${events.length} event${events.length === 1 ? "" : "s"}${hasNextPage ? "+" : ""}`}
            </span>
          </div>
        }
      />

      {/* Filter panel */}
      <div className="enterprise-panel p-4">
        <TimelineFilters />
      </div>

      {/* Timeline */}
      <div className="enterprise-panel min-h-96 overflow-hidden">
        <IdentityTimeline
          groups={groups}
          isLoadingHistory={isLoading}
          isFetchingNextPage={isFetchingNextPage}
          hasNextPage={hasNextPage}
          onLoadMore={fetchNextPage}
          onSelectEvent={handleSelectEvent}
          selectedEventId={selectedEventId}
          isError={isError}
          onRetry={retry}
        />
      </div>

      {/* Details drawer — always in DOM for transition animation */}
      <TimelineDetailsDrawer
        event={selectedEvent}
        userId={userId}
        prevEvent={prevEvent}
        nextEvent={nextEvent}
        onClose={handleCloseDrawer}
        onSelectPrev={prevEvent ? () => handleSelectEvent(prevEvent) : undefined}
        onSelectNext={nextEvent ? () => handleSelectEvent(nextEvent) : undefined}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Wrapper: mounts the TimelineProvider for the route
// ---------------------------------------------------------------------------

function TimelinePageWrapper() {
  const { userId } = Route.useParams();

  return (
    <TimelineProvider userId={userId}>
      <TimelinePage />
    </TimelineProvider>
  );
}
