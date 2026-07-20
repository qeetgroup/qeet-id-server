// Timeline filter bar — category chips + severity chips + search input + date range.
// Capability-aware: requires audit.read + user.read to be interactive.

import { Badge, Chip, ChipGroup, cn, Input, Separator } from "@qeetrix/ui";
import { SearchIcon, XIcon } from "lucide-react";
import { useCallback } from "react";

import { useCapabilities } from "@/features/access-control/capability-provider";
import type { Severity } from "@/features/activity/types";
import { useTimeline } from "../timeline-provider";
import type { TimelineFilters as TimelineFiltersState } from "../timeline-store";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CATEGORY_OPTIONS = [
  { value: "authentication", label: "Authentication" },
  { value: "authorization", label: "Authorization" },
  { value: "security", label: "Security" },
  { value: "provisioning", label: "Provisioning" },
  { value: "organizations", label: "Organizations" },
  { value: "groups", label: "Groups" },
  { value: "policies", label: "Policies" },
  { value: "applications", label: "Applications" },
  { value: "devices", label: "Devices" },
  { value: "sessions", label: "Sessions" },
  { value: "api", label: "API" },
  { value: "administration", label: "Administration" },
] as const;

const SEVERITY_OPTIONS: { value: Severity; label: string }[] = [
  { value: "info", label: "Info" },
  { value: "success", label: "Success" },
  { value: "warning", label: "Warning" },
  { value: "error", label: "Error" },
  { value: "critical", label: "Critical" },
];

const SEVERITY_CLASS: Record<Severity, string> = {
  info: "data-[selected]:bg-info data-[selected]:text-info-foreground",
  success: "data-[selected]:bg-success data-[selected]:text-success-foreground",
  warning: "data-[selected]:bg-warning data-[selected]:text-warning-foreground",
  error: "data-[selected]:bg-destructive data-[selected]:text-destructive-foreground",
  critical:
    "data-[selected]:bg-destructive data-[selected]:text-destructive-foreground data-[selected]:ring-2 data-[selected]:ring-destructive/30",
};

// ---------------------------------------------------------------------------
// TimelineFilters
// ---------------------------------------------------------------------------

export function TimelineFilters() {
  const access = useCapabilities();
  const disabled = !access.can("audit.read") || !access.can("user.read");

  const { filters, setFilters, resetFilters } = useTimeline();

  const hasActiveFilters =
    filters.category.length > 0 ||
    filters.severity.length > 0 ||
    !!filters.q ||
    !!filters.from ||
    !!filters.to;

  const handleCategoryChange = useCallback(
    (value: string | string[]) => {
      const next = Array.isArray(value) ? value : [value];
      setFilters({ category: next });
    },
    [setFilters],
  );

  const handleSeverityChange = useCallback(
    (value: string | string[]) => {
      const next = (Array.isArray(value) ? value : [value]) as Severity[];
      setFilters({ severity: next });
    },
    [setFilters],
  );

  const handleSearchChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setFilters({ q: e.target.value });
    },
    [setFilters],
  );

  const handleDateChange = useCallback(
    (field: "from" | "to") => (e: React.ChangeEvent<HTMLInputElement>) => {
      setFilters({ [field]: e.target.value } as Partial<TimelineFiltersState>);
    },
    [setFilters],
  );

  return (
    <fieldset className="m-0 flex flex-col gap-3 border-0 p-0" aria-label="Timeline filters">
      {/* Search + date range row */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-44 flex-1">
          <SearchIcon
            className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            type="search"
            placeholder="Search events…"
            value={filters.q}
            onChange={handleSearchChange}
            disabled={disabled}
            className="pl-8"
            aria-label="Search identity timeline events"
          />
        </div>

        <div className="flex items-center gap-1.5">
          <label htmlFor="timeline-from" className="sr-only">
            From date
          </label>
          <Input
            id="timeline-from"
            type="date"
            value={filters.from}
            onChange={handleDateChange("from")}
            disabled={disabled}
            className="h-9 w-36 text-xs"
            aria-label="Filter events from date"
          />
          <span className="text-xs text-muted-foreground" aria-hidden="true">
            —
          </span>
          <label htmlFor="timeline-to" className="sr-only">
            To date
          </label>
          <Input
            id="timeline-to"
            type="date"
            value={filters.to}
            onChange={handleDateChange("to")}
            disabled={disabled}
            className="h-9 w-36 text-xs"
            aria-label="Filter events to date"
          />
        </div>

        {hasActiveFilters && (
          <button
            type="button"
            onClick={resetFilters}
            className="inline-flex items-center gap-1 text-xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label="Clear all timeline filters"
          >
            <XIcon className="size-3" aria-hidden="true" />
            Clear all
          </button>
        )}
      </div>

      <Separator />

      {/* Category chips */}
      <div className="flex flex-col gap-1.5">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Category
        </span>
        <ChipGroup
          value={filters.category}
          onValueChange={handleCategoryChange}
          multiple
          disabled={disabled}
          size="sm"
          aria-label="Filter by category"
        >
          {CATEGORY_OPTIONS.map((opt) => (
            <Chip key={opt.value} value={opt.value}>
              {opt.label}
            </Chip>
          ))}
        </ChipGroup>
      </div>

      {/* Severity chips */}
      <div className="flex flex-col gap-1.5">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Severity
        </span>
        <ChipGroup
          value={filters.severity}
          onValueChange={handleSeverityChange}
          multiple
          disabled={disabled}
          size="sm"
          aria-label="Filter by severity"
        >
          {SEVERITY_OPTIONS.map((opt) => (
            <Chip key={opt.value} value={opt.value} className={cn(SEVERITY_CLASS[opt.value])}>
              {opt.label}
            </Chip>
          ))}
        </ChipGroup>
      </div>

      {/* Active filter count badge */}
      {hasActiveFilters && (
        <div className="flex items-center gap-1.5" aria-live="polite" aria-atomic="true">
          <Badge variant="muted" className="text-[10px]">
            {[
              filters.category.length > 0 &&
                `${filters.category.length} categor${filters.category.length === 1 ? "y" : "ies"}`,
              filters.severity.length > 0 &&
                `${filters.severity.length} severit${filters.severity.length === 1 ? "y" : "ies"}`,
              filters.q && "search",
              (filters.from || filters.to) && "date range",
            ]
              .filter(Boolean)
              .join(" · ")}
          </Badge>
        </div>
      )}
    </fieldset>
  );
}
