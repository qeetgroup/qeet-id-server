// Data-retention policy. Currently governs how long soft-deleted users are
// kept before being permanently purged. Opt-in per tenant; a background sweeper
// applies it, and preview/run let an admin see and trigger it on demand.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface RetentionPolicy {
  deleted_users_enabled: boolean;
  deleted_users_days: number;
}

export function useRetentionPolicy() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["retention", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<RetentionPolicy>(`/v1/tenants/${tenantId}/retention`),
  });
}

export function useUpdateRetentionPolicy() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RetentionPolicy) =>
      api<RetentionPolicy>(`/v1/tenants/${tenantId}/retention`, {
        method: "PUT",
        body,
      }),
    onSuccess: (data) => qc.setQueryData(["retention", tenantId], data),
    meta: { successMessage: "Retention policy saved" },
  });
}

export function useRetentionPreview() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: () =>
      api<{ ripe_deleted_users: number; deleted_users_days: number }>(
        `/v1/tenants/${tenantId}/retention/preview`,
        { method: "POST" },
      ),
  });
}

export function useRunRetention() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api<{ purged: number }>(`/v1/tenants/${tenantId}/retention/run`, {
        method: "POST",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users", "deleted"] }),
    meta: { successMessage: "Retention purge complete" },
  });
}
