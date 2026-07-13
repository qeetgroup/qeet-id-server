// Self-serve Admin Portal data layer. A link is a capability-scoped
// ("saml"/"scim"), time-limited token an external IT admin — no Qeet ID
// account — follows to configure this tenant's SSO themselves. The raw
// token/url is returned exactly once, on generate.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export type AdminPortalCapability = "saml" | "scim";

export interface AdminPortalLink {
  id: string;
  tenant_id: string;
  capabilities: AdminPortalCapability[];
  created_by: string | null;
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface GenerateAdminPortalLinkInput {
  capabilities: AdminPortalCapability[];
  ttl_seconds?: number;
}

export interface GenerateAdminPortalLinkResponse {
  link: AdminPortalLink;
  token: string;
  url: string;
}

const KEY = ["admin-portal-links"];

export function useAdminPortalLinks() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: AdminPortalLink[] }>(`/v1/tenants/${tenantId}/admin-portal/links`),
  });
}

export function useGenerateAdminPortalLink() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: GenerateAdminPortalLinkInput) =>
      api<GenerateAdminPortalLinkResponse>(`/v1/tenants/${tenantId}/admin-portal/links`, {
        method: "POST",
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useRevokeAdminPortalLink() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/admin-portal/links/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
    meta: { successMessage: "Admin portal link revoked" },
  });
}

export function isAdminPortalLinkActive(l: AdminPortalLink): boolean {
  return !l.revoked_at && new Date(l.expires_at).getTime() > Date.now();
}
