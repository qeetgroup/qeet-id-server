import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";

export type DashboardAuditEvent = {
  id: string;
  actor_type: string;
  action: string;
  resource_type: string;
  created_at: string;
};

/** Fresh, low-volume audit stream used only by the command-center overview. */
export function useDashboardActivity(tenantId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["activity-recent-dashboard", tenantId],
    queryFn: () => api<{ items: DashboardAuditEvent[] }>(`/v1/tenants/${tenantId}/audit?limit=5`),
    staleTime: 60_000,
    refetchInterval: 15_000,
    refetchIntervalInBackground: false,
    enabled: !!tenantId && enabled,
    meta: { silent: true },
  });
}
