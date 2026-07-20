// Public surface for the timeline feature module.
// Import from here; don't reach into sub-modules directly.

// Components
export { IdentityTimeline } from "./components/identity-timeline";
export { TimelineDetailsDrawer } from "./components/timeline-details-drawer";
export { TimelineFilters as TimelineFilterBar } from "./components/timeline-filters";
export { TimelineItem } from "./components/timeline-item";
export { groupTimelineByDate } from "./grouping";
export { TimelineProvider, useTimeline } from "./timeline-provider";
export type { TimelinePage } from "./timeline-service";
export { buildTimelineQuery, fetchTimelinePage, TIMELINE_LIMIT } from "./timeline-service";
export {
  DEFAULT_TIMELINE_FILTERS,
  type TimelineFilters,
  type TimelineStoreState,
  timelineActions,
  timelineStore,
} from "./timeline-store";
export { useIdentityTimeline } from "./use-identity-timeline";
