// Audit-intelligence data layer: behavioral-baseline anomaly detection over
// the hash-chained audit log (distinct from Threats → Anomalies, which is
// auth-time signals like credential stuffing — see lib/anomalies.ts).
// Backed by GET /v1/tenants/{tenantID}/audit/anomalies (+ /summary),
// POST .../anomalies/{id}/resolve, and the anomaly-settings pair.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export type AnomalyReason = "new_action_type" | "unusual_hour" | "new_ip";

export interface AuditAnomaly {
  id: string;
  tenant_id: string;
  event_id: string;
  actor_user_id?: string | null;
  actor_email?: string | null;
  score: number;
  reasons: AnomalyReason[];
  status: "open" | "resolved";
  resolved_at?: string | null;
  resolved_by?: string | null;
  created_at: string;
  action: string;
  resource_type: string;
  ip?: string | null;
  event_at: string;
}

export interface AuditAnomalySummary {
  open: number;
  resolved_7d: number;
  high_score_open: number;
}

export interface AuditAnomalySettings {
  tenant_id: string;
  enabled: boolean;
  score_threshold: number;
  min_baseline_events: number;
}

const KEY = ["audit-anomalies"];

export function useAuditAnomalies(status?: "open" | "resolved") {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, tenantId, status ?? "all"],
    queryFn: () =>
      api<{ items: AuditAnomaly[] }>(`/v1/tenants/${tenantId}/audit/anomalies`, {
        query: status ? { status } : undefined,
      }),
    enabled: !!tenantId,
    staleTime: 30_000,
  });
}

export function useAuditAnomalySummary() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, "summary", tenantId],
    queryFn: () => api<AuditAnomalySummary>(`/v1/tenants/${tenantId}/audit/anomalies/summary`),
    enabled: !!tenantId,
    staleTime: 30_000,
  });
}

export function useResolveAuditAnomaly() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/audit/anomalies/${id}/resolve`, {
        method: "POST",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useAuditAnomalySettings() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, "settings", tenantId],
    queryFn: () => api<AuditAnomalySettings>(`/v1/tenants/${tenantId}/audit/anomaly-settings`),
    enabled: !!tenantId,
  });
}

export function useUpdateAuditAnomalySettings() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Omit<AuditAnomalySettings, "tenant_id">) =>
      api<AuditAnomalySettings>(`/v1/tenants/${tenantId}/audit/anomaly-settings`, {
        method: "PUT",
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...KEY, "settings"] }),
    meta: { successMessage: "Anomaly-detection settings updated" },
  });
}

export function useVerifyAuditChain() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: () =>
      api<{
        ok: boolean;
        rows_checked: number;
        last_verified_id?: string;
        broken_at_id?: string;
        broken_reason?: string;
      }>(`/v1/tenants/${tenantId}/audit/verify`),
  });
}
