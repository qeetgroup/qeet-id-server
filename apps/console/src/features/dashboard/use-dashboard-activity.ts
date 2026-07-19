// Evolved from the original polling-based hook to the shared live activity store.
// The dashboard widget acquires a ref-counted SSE subscription (sharing the stream
// with the full activity page when both are mounted) and reads the latest live events
// directly from the module-level activityStore.

import { useStore } from "@tanstack/react-store";
import { useEffect } from "react";

import { useCapabilities } from "@/features/access-control/capability-provider";
import { activityStore } from "@/features/activity/activity-store";
import { acquireSubscription } from "@/features/activity/subscription-manager";
import type { ActivityEvent, ConnectionStatus } from "@/features/activity/types";

const DASHBOARD_LIMIT = 10;

export type { ActivityEvent as DashboardAuditEvent };

export type DashboardActivityResult = {
  events: ActivityEvent[];
  status: ConnectionStatus;
  /** True while connecting for the first time and no events have arrived yet. */
  connecting: boolean;
};

/**
 * Hook for the dashboard activity widget.
 * Acquires the shared SSE subscription and returns the latest live events.
 * When the backend stream is not yet deployed (disconnected/reconnecting),
 * `connecting` is true and `events` is empty — show a loading skeleton.
 */
export function useDashboardActivity(_tenantId?: string, enabled = true): DashboardActivityResult {
  const access = useCapabilities();
  const canRead = access.can("audit.read");

  const liveEvents = useStore(activityStore, (s) => s.liveEvents);
  const status = useStore(activityStore, (s) => s.status);

  useEffect(() => {
    if (!enabled || !canRead) return;
    return acquireSubscription();
  }, [enabled, canRead]);

  return {
    events: liveEvents.slice(0, DASHBOARD_LIMIT),
    status,
    connecting: (status === "reconnecting" || status === "disconnected") && liveEvents.length === 0,
  };
}
