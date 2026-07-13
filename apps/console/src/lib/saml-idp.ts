// SAML IdP data layer — the *inverse* of src/lib/saml.ts. Here Qeet ID acts as
// the Identity Provider and the rows are the Service Providers (SPs) that trust
// us: the apps that consume our assertions. SPs import a single shared IdP
// metadata document (idpMetadataUrl()) served at the API origin's /saml/idp
// route, so that URL is derived from API_BASE_URL rather than per-row.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { API_BASE_URL, api } from "./api";
import { useTenantId } from "./auth";

export interface SamlProvider {
  id: string;
  tenant_id: string;
  name: string;
  entity_id: string;
  acs_url: string;
  name_id_format: string;
  name_id_attribute: string;
  certificate: string;
  status: string;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
}

export interface CreateSamlProviderInput {
  name: string;
  entity_id: string;
  acs_url: string;
  name_id_format?: string;
  name_id_attribute?: string;
  certificate?: string;
}

/** The single IdP metadata document an SP imports to trust this deployment. */
export const idpMetadataUrl = () => `${API_BASE_URL.replace(/\/$/, "")}/saml/idp/metadata`;

export function useSamlProviders() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["saml-providers", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: SamlProvider[] }>(`/v1/tenants/${tenantId}/saml-providers`),
  });
}

export function useCreateSamlProvider() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateSamlProviderInput) =>
      api<SamlProvider>(`/v1/tenants/${tenantId}/saml-providers`, {
        method: "POST",
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saml-providers"] }),
    meta: { successMessage: "Service provider added" },
  });
}

export function useUpdateSamlProvider() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: Partial<CreateSamlProviderInput> & { id: string }) =>
      api<SamlProvider>(`/v1/tenants/${tenantId}/saml-providers/${id}`, {
        method: "PATCH",
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saml-providers"] }),
    meta: { successMessage: "Service provider updated" },
  });
}

export function useDeleteSamlProvider() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/saml-providers/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saml-providers"] }),
    meta: { successMessage: "Service provider removed" },
  });
}
