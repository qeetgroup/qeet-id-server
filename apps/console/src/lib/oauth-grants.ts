// OAuth grant administration. Access tokens themselves are stateless JWTs;
// what's listable/revocable is the stored OIDC refresh-token grant per
// (client, user). Revoking a grant invalidates the whole rotation chain.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface OAuthGrant {
  id: string;
  client_id: string;
  user_id: string;
  user_email: string;
  scopes: string[];
  issued_at: string;
  expires_at: string;
}

export function useOAuthGrants() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["oauth-grants", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: OAuthGrant[] }>(`/v1/tenants/${tenantId}/oauth/grants`),
  });
}

export function useRevokeOAuthGrant() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/oauth/grants/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["oauth-grants"] }),
    meta: { successMessage: "Grant revoked" },
  });
}
