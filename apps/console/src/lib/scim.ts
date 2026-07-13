// SCIM 2.0 provisioning data layer. The admin surface manages the per-tenant
// bearer token an IdP (Okta / Entra ID / Google) presents to the SCIM
// endpoints. The SCIM base URL is derived from the API origin — the same
// host that serves /scim/v2 — so the value shown here is always correct for
// the deployment the console is talking to.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { API_BASE_URL, api } from "./api";
import { useTenantId } from "./auth";

export interface ScimConfig {
  token_set: boolean;
  token_prefix?: string;
  created_at: string | null;
  last_used_at: string | null;
  provisioned_count: number;
}

export interface ScimProvisionedUser {
  id: string;
  email: string;
  display_name: string | null;
  status: string;
  external_id: string | null;
  created_at: string;
}

/** The /scim/v2 base an IdP should be pointed at for this deployment. */
export const SCIM_BASE_URL = `${API_BASE_URL.replace(/\/$/, "")}/scim/v2`;

export function useScimConfig() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["scim", "config", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<ScimConfig>(`/v1/tenants/${tenantId}/scim`),
  });
}

export function useScimProvisionedUsers() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["scim", "users", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: ScimProvisionedUser[] }>(`/v1/tenants/${tenantId}/scim/users`),
  });
}

/** Rotate (or first-time generate) the bearer token. The plaintext token is
 *  in the response exactly once — surface it immediately, it can't be reread. */
export function useRotateScimToken() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api<{ token: string; config: ScimConfig }>(`/v1/tenants/${tenantId}/scim/token`, {
        method: "POST",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scim"] }),
    meta: { successMessage: "SCIM bearer token generated" },
  });
}

export function useRevokeScimToken() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<void>(`/v1/tenants/${tenantId}/scim/token`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scim"] }),
    meta: { successMessage: "SCIM provisioning disabled" },
  });
}
