// SAML 2.0 connection data layer. Connections are managed under the tenant;
// the SP metadata + login URLs an IdP needs live at the API origin's /saml/*
// routes, so they're derived from API_BASE_URL.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { API_BASE_URL, api } from "./api";
import { useTenantId } from "./auth";

export type SamlStatus = "draft" | "active" | "disabled";

export interface SamlConnection {
  id: string;
  tenant_id: string;
  name: string;
  idp_entity_id: string;
  idp_sso_url: string;
  idp_certificate: string;
  email_attribute: string;
  name_attribute: string;
  status: SamlStatus;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
}

export interface CreateSamlInput {
  name: string;
  idp_entity_id: string;
  idp_sso_url: string;
  idp_certificate: string;
  email_attribute?: string;
  name_attribute?: string;
  status?: SamlStatus;
}

const apiOrigin = API_BASE_URL.replace(/\/$/, "");
export const samlMetadataUrl = (id: string) => `${apiOrigin}/saml/metadata/${id}`;
export const samlLoginUrl = (id: string) => `${apiOrigin}/saml/login/${id}`;

export function useSamlConnections() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["saml", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: SamlConnection[] }>(`/v1/tenants/${tenantId}/saml`),
  });
}

export function useCreateSamlConnection() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateSamlInput) =>
      api<SamlConnection>(`/v1/tenants/${tenantId}/saml`, {
        method: "POST",
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saml"] }),
    meta: { successMessage: "SAML connection created" },
  });
}

export function useUpdateSamlConnection() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: Partial<CreateSamlInput> & { id: string }) =>
      api<SamlConnection>(`/v1/tenants/${tenantId}/saml/${id}`, {
        method: "PATCH",
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saml"] }),
    meta: { successMessage: "SAML connection updated" },
  });
}

export function useDeleteSamlConnection() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/saml/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saml"] }),
    meta: { successMessage: "SAML connection deleted" },
  });
}

export interface SamlTestCheck {
  name: string;
  ok: boolean;
  detail?: string;
}
export interface SamlTestResult {
  ok: boolean;
  checks: SamlTestCheck[];
}

/** Preflight a connection's config (offline checks) before enabling it. */
export function useTestSamlConnection() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: (id: string) =>
      api<SamlTestResult>(`/v1/tenants/${tenantId}/saml/${id}/test`, {
        method: "POST",
      }),
  });
}
