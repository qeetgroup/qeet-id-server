// OAuth 2.0 Device Authorization Grant (RFC 8628) administration. Each row is a
// pending/approved device flow keyed by its user_code — what a user types at
// the verification URL on a second screen. Admins can list active flows and
// revoke a suspicious one before it's redeemed.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface DeviceAuth {
  id: string;
  client_id: string;
  user_code: string;
  status: string;
  user_id: string;
  user_email: string;
  scopes: string[];
  created_at: string;
  expires_at: string;
  last_polled_at: string | null;
}

export function useDeviceAuthorizations() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["device-auth", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: DeviceAuth[] }>(`/v1/tenants/${tenantId}/oauth/devices`),
  });
}

export function useRevokeDeviceAuth() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/oauth/devices/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["device-auth"] }),
    meta: { successMessage: "Device authorization revoked" },
  });
}
