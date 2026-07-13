// Secrets vault data layer. The API returns only metadata (never the value)
// except via an explicit, audited reveal.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface Secret {
  id: string;
  name: string;
  scope: string;
  last4: string;
  created_at: string;
  updated_at: string;
}

export function useSecrets() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["secrets", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: Secret[] }>(`/v1/tenants/${tenantId}/secrets`),
  });
}

export function useCreateSecret() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; scope: string; value: string }) =>
      api<Secret>(`/v1/tenants/${tenantId}/secrets`, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["secrets"] }),
    meta: { successMessage: "Secret created" },
  });
}

export function useRotateSecret() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) =>
      api<Secret>(`/v1/tenants/${tenantId}/secrets/${id}`, {
        method: "PATCH",
        body: { value },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["secrets"] }),
    meta: { successMessage: "Secret rotated" },
  });
}

export function useRevealSecret() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: (id: string) =>
      api<{ value: string }>(`/v1/tenants/${tenantId}/secrets/${id}/reveal`, {
        method: "POST",
      }),
  });
}

export function useDeleteSecret() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/secrets/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["secrets"] }),
    meta: { successMessage: "Secret deleted" },
  });
}
