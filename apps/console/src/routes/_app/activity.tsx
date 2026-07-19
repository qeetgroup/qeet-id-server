// Enterprise Live Activity Center — evolved from the original /activity route.
// Keeps the same route path and "Workspace → Activity" nav entry (navigation.tsx untouched).
// Now features: real-time SSE stream, filter bar, search, date-grouped timeline,
// event details drawer, pause/resume, and unread counter.

import {
  type ActiveFilter,
  Button,
  EmptyState,
  FilterBar,
  type FilterField,
  Input,
  Separator,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { ActivityIcon, PauseIcon, PlayIcon, SearchIcon } from "lucide-react";
import { useCallback, useMemo, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { useCapabilities } from "@/features/access-control/capability-provider";
import { ActivityProvider, useActivity } from "@/features/activity/activity-provider";
import { ActivityTimeline } from "@/features/activity/components/activity-timeline";
import { EventDetailsDrawer } from "@/features/activity/components/event-details-drawer";
import { LiveIndicator } from "@/features/activity/components/live-indicator";
import type { ActivityEvent, ActivityFilters, Severity } from "@/features/activity/types";

export const Route = createFileRoute("/_app/activity")({
  component: ActivityPageWrapper,
});

// ---------------------------------------------------------------------------
// FilterBar field definitions (static; options driven by current event set)
// ---------------------------------------------------------------------------

const SEVERITY_OPTIONS: { label: string; value: string }[] = [
  { label: "Info", value: "info" },
  { label: "Success", value: "success" },
  { label: "Warning", value: "warning" },
  { label: "Error", value: "error" },
  { label: "Critical", value: "critical" },
];

const FILTER_FIELDS: FilterField[] = [
  {
    key: "severity",
    label: "Severity",
    options: SEVERITY_OPTIONS,
  },
  { key: "category", label: "Category" },
  { key: "type", label: "Event type" },
  { key: "actor", label: "Actor" },
  { key: "source", label: "Source" },
  { key: "status", label: "Status" },
  { key: "from", label: "From date" },
  { key: "to", label: "To date" },
];

// ---------------------------------------------------------------------------
// Inner page (requires ActivityProvider)
// ---------------------------------------------------------------------------

function ActivityPage() {
  const access = useCapabilities();
  const canRead = access.can("audit.read");

  const {
    filteredEvents,
    groups,
    unreadCount,
    paused,
    status,
    filters,
    setFilters,
    resetFilters,
    markAllRead,
    pause,
    resume,
    isLoadingHistory,
    isFetchingNextPage,
    hasNextPage,
    fetchNextPage,
    newEventIds,
    isHistoryError,
    retryHistory,
    retryStream,
  } = useActivity();

  const [selectedEvent, setSelectedEvent] = useState<ActivityEvent | null>(null);
  const [activeFilters, setActiveFilters] = useState<ActiveFilter[]>([]);

  // Derive prev/next for drawer navigation
  const selectedIndex = useMemo(
    () => filteredEvents.findIndex((e) => e.id === selectedEvent?.id),
    [filteredEvents, selectedEvent],
  );
  const prevEvent = selectedIndex > 0 ? filteredEvents[selectedIndex - 1] : null;
  const nextEvent =
    selectedIndex >= 0 && selectedIndex < filteredEvents.length - 1
      ? filteredEvents[selectedIndex + 1]
      : null;

  // Sync FilterBar's controlled state → activity filters
  const handleActiveFiltersChange = useCallback(
    (next: ActiveFilter[]) => {
      setActiveFilters(next);
      const patch: Partial<ActivityFilters> = {
        severity: [],
        category: [],
        types: [],
        actor: "",
        source: "",
        status: "",
        from: "",
        to: "",
      };
      for (const f of next) {
        switch (f.field) {
          case "severity":
            patch.severity = [...(patch.severity ?? []), f.value as Severity];
            break;
          case "category":
            patch.category = [...(patch.category ?? []), f.value];
            break;
          case "type":
            patch.types = [...(patch.types ?? []), f.value];
            break;
          case "actor":
            patch.actor = f.value;
            break;
          case "source":
            patch.source = f.value;
            break;
          case "status":
            patch.status = f.value;
            break;
          case "from":
            patch.from = f.value;
            break;
          case "to":
            patch.to = f.value;
            break;
        }
      }
      setFilters(patch);
    },
    [setFilters],
  );

  const handleSearchChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setFilters({ q: e.target.value });
    },
    [setFilters],
  );

  const handleResetFilters = useCallback(() => {
    setActiveFilters([]);
    resetFilters();
  }, [resetFilters]);

  const handleSelectEvent = useCallback(
    (event: ActivityEvent) => {
      setSelectedEvent(event);
      markAllRead();
    },
    [markAllRead],
  );

  if (!canRead) {
    return (
      <div className="flex min-w-0 flex-col gap-4">
        <PageHeader />
        <div className="enterprise-panel flex min-h-64 items-center justify-center">
          <EmptyState
            icon={ActivityIcon}
            title="Activity not available"
            description={
              <>
                You don't have permission to view the activity feed. Contact your workspace admin to
                request the <code className="font-mono">audit.read</code> capability.
              </>
            }
          />
        </div>
      </div>
    );
  }

  const hasCritical = filteredEvents.some(
    (e) => newEventIds.has(e.id) && (e.severity === "critical" || e.severity === "error"),
  );

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {/* Page header with live indicator */}
      <PageHeader
        actions={<LiveIndicator status={status} unreadCount={unreadCount} className="flex-wrap" />}
      />

      {/* Critical event announcement for screen readers */}
      <div
        role="alert"
        aria-live="assertive"
        aria-atomic="true"
        className="sr-only"
        aria-label={
          hasCritical ? `${unreadCount} critical or error events require attention` : undefined
        }
      >
        {hasCritical ? `${unreadCount} critical or error events require attention` : ""}
      </div>

      {/* Controls bar */}
      <div className="enterprise-panel flex flex-col gap-3 p-3">
        {/* Search + pause toggle */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-48 flex-1">
            <SearchIcon
              className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              placeholder="Search events…"
              value={filters.q}
              onChange={handleSearchChange}
              className="pl-8"
              aria-label="Search activity events"
            />
          </div>

          <Button
            variant={paused ? "default" : "outline"}
            size="sm"
            onClick={paused ? resume : pause}
            aria-label={paused ? "Resume live stream" : "Pause live stream"}
            aria-pressed={paused}
          >
            {paused ? (
              <>
                <PlayIcon className="size-3.5" aria-hidden="true" />
                Resume
              </>
            ) : (
              <>
                <PauseIcon className="size-3.5" aria-hidden="true" />
                Pause
              </>
            )}
          </Button>

          {unreadCount > 0 && (
            <Button variant="ghost" size="sm" onClick={markAllRead}>
              Mark all read
            </Button>
          )}

          {(activeFilters.length > 0 || filters.q) && (
            <Button variant="ghost" size="sm" onClick={handleResetFilters}>
              Clear all
            </Button>
          )}
        </div>

        <Separator />

        {/* Faceted filter bar */}
        <FilterBar
          fields={FILTER_FIELDS}
          value={activeFilters}
          onValueChange={handleActiveFiltersChange}
          addLabel="Add filter"
        />
      </div>

      {/* Timeline */}
      <div className="enterprise-panel min-h-96 overflow-hidden">
        <ActivityTimeline
          groups={groups}
          newEventIds={newEventIds}
          status={status}
          isLoadingHistory={isLoadingHistory}
          isFetchingNextPage={isFetchingNextPage}
          hasNextPage={hasNextPage}
          onLoadMore={fetchNextPage}
          onSelectEvent={handleSelectEvent}
          selectedEventId={selectedEvent?.id}
          isError={isHistoryError}
          onRetryHistory={retryHistory}
          onRetryStream={retryStream}
        />
      </div>

      {/* Details drawer (always in DOM for animation) */}
      <EventDetailsDrawer
        event={selectedEvent}
        prevEvent={prevEvent}
        nextEvent={nextEvent}
        onClose={() => setSelectedEvent(null)}
        onSelectPrev={prevEvent ? () => setSelectedEvent(prevEvent) : undefined}
        onSelectNext={nextEvent ? () => setSelectedEvent(nextEvent) : undefined}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Wrapper: mounts the ActivityProvider for the full page
// ---------------------------------------------------------------------------

function ActivityPageWrapper() {
  return (
    <ActivityProvider>
      <ActivityPage />
    </ActivityProvider>
  );
}
