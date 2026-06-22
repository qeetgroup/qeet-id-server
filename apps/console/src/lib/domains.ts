// Domain-verification data layer (Organizations → Domains). A tenant claims an
// email domain, publishes the returned DNS TXT record, then verifies it.
// Backed by /v1/tenants/{tenantID}/domains[/{id}/verify].

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface TenantDomain {
  id: string;
  domain: string;
  verification_token: string;
  dns_record_name: string;
  dns_record_type: string;
  dns_record_value: string;
  verified_at?: string | null;
  created_at: string;
}

const KEY = ["domains"];

export function useDomains() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, tenantId],
    queryFn: () => api<{ items: TenantDomain[] }>(`/v1/tenants/${tenantId}/domains`),
    enabled: !!tenantId,
  });
}

export function useAddDomain() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (domain: string) =>
      api<TenantDomain>(`/v1/tenants/${tenantId}/domains`, { method: "POST", body: { domain } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useVerifyDomain() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<TenantDomain>(`/v1/tenants/${tenantId}/domains/${id}/verify`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
    meta: { successMessage: "Domain verified" },
  });
}

export function useRemoveDomain() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/domains/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
