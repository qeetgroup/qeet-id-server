// Security-anomaly data layer for the Threats → Anomalies screen. Backed by
// GET /v1/tenants/{tenantID}/security/anomalies (+ /summary) and
// POST .../anomalies/{id}/resolve. Detections are written server-side (e.g.
// brute-force / credential-stuffing on account lockout).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, api } from "./api";
import { useTenantId } from "./auth";

export interface Anomaly {
  id: string;
  type: string;
  severity: string;
  detail: string;
  status: string;
  user_id?: string | null;
  user_email?: string | null;
  ip?: string | null;
  created_at: string;
  resolved_at?: string | null;
}

export interface AnomalySummary {
  open: number;
  resolved_24h: number;
  affected_accounts: number;
  high_severity_24h: number;
}

const KEY = ["anomalies"];

export function useAnomalies() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, tenantId],
    queryFn: async (): Promise<{ items: Anomaly[] }> => {
      try {
        return await api<{ items: Anomaly[] }>(`/v1/tenants/${tenantId}/security/anomalies`);
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) return { items: [] };
        throw err;
      }
    },
    enabled: !!tenantId,
    staleTime: 30_000,
  });
}

export function useAnomalySummary() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, "summary", tenantId],
    queryFn: () => api<AnomalySummary>(`/v1/tenants/${tenantId}/security/anomalies/summary`),
    enabled: !!tenantId,
    staleTime: 30_000,
  });
}

export function useResolveAnomaly() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/security/anomalies/${id}/resolve`, {
        method: "POST",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
