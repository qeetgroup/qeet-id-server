// OIDC / OAuth 2.0 client (application) administration. Clients are registered
// per tenant; the list/read/update/rotate endpoints are tenant-scoped while
// create/delete operate on the global /v1/oidc/clients collection (the body /
// the row already carries the tenant). Client secrets are returned exactly
// once (on create + on rotate) and are bcrypt-hashed server-side after that —
// surface them via CopyableSecret immediately; they can't be re-read.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface OidcClient {
  id: string;
  tenant_id: string;
  client_id: string;
  name: string;
  type: "public" | "confidential";
  redirect_uris: string[];
  post_logout_uris?: string[] | null;
  grant_types: string[];
  scopes: string[];
  created_at: string;
}

export interface CreateOidcInput {
  name: string;
  type: "public" | "confidential";
  redirect_uris?: string[];
  post_logout_uris?: string[];
  grant_types?: string[];
  scopes?: string[];
}

export interface CreateOidcResponse {
  client: OidcClient;
  client_secret: string;
  warning: string;
}

export interface UpdateOidcInput {
  name?: string;
  redirect_uris?: string[];
  post_logout_uris?: string[];
  grant_types?: string[];
  scopes?: string[];
}

export interface RotateSecretResponse {
  client_secret: string;
  warning: string;
}

export function useOidcClients() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["oidc-clients", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: OidcClient[] }>(`/v1/tenants/${tenantId}/oidc/clients`),
  });
}

export function useOidcClient(id: string) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["oidc-client", tenantId, id],
    enabled: !!tenantId && !!id,
    queryFn: () => api<OidcClient>(`/v1/tenants/${tenantId}/oidc/clients/${id}`),
  });
}

export function useCreateOidcClient() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateOidcInput) =>
      api<CreateOidcResponse>("/v1/oidc/clients", {
        method: "POST",
        body: { tenant_id: tenantId, ...input },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["oidc-clients"] }),
    meta: { successMessage: "Application registered" },
  });
}

export function useUpdateOidcClient(id: string) {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateOidcInput) =>
      api<OidcClient>(`/v1/tenants/${tenantId}/oidc/clients/${id}`, { method: "PATCH", body }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["oidc-clients"] });
      qc.invalidateQueries({ queryKey: ["oidc-client"] });
    },
    meta: { successMessage: "Application updated" },
  });
}

export function useDeleteOidcClient() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/v1/oidc/clients/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["oidc-clients"] }),
    meta: { successMessage: "Application deleted" },
  });
}

export function useRotateClientSecret(id: string) {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api<RotateSecretResponse>(`/v1/tenants/${tenantId}/oidc/clients/${id}/rotate-secret`, {
        method: "POST",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["oidc-clients"] }),
    meta: { successMessage: "Client secret rotated" },
  });
}
