// SIEM / log-streaming sink data layer (Security → Log Streaming). A tenant
// forwards its audit events to Splunk HEC, Datadog, or a generic HTTP endpoint.
// Backed by /v1/tenants/{tenantID}/log-sinks. The token is write-only (sent on
// create, never returned).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export type SinkType = "splunk_hec" | "datadog" | "http";

export interface LogSink {
  id: string;
  type: SinkType;
  endpoint: string;
  enabled: boolean;
  last_forwarded_at?: string | null;
  last_error?: string;
  created_at: string;
}

const KEY = ["log-sinks"];

export function useLogSinks() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, tenantId],
    queryFn: () => api<{ items: LogSink[] }>(`/v1/tenants/${tenantId}/log-sinks`),
    enabled: !!tenantId,
  });
}

export function useCreateLogSink() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { type: SinkType; endpoint: string; token: string }) =>
      api<LogSink>(`/v1/tenants/${tenantId}/log-sinks`, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
    meta: { successMessage: "Log sink added" },
  });
}

export function useToggleLogSink() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api<void>(`/v1/tenants/${tenantId}/log-sinks/${id}`, { method: "PATCH", body: { enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useDeleteLogSink() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/log-sinks/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
