// Tenant authentication-policy data layer: password complexity rules and which
// login methods are permitted. The whole policy is read and written as one
// object (PUT is a full replace), so each page loads it, edits its slice, and
// saves the merged result.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface AuthPolicy {
  password_enabled: boolean;
  password_min_length: number;
  password_require_uppercase: boolean;
  password_require_number: boolean;
  password_require_symbol: boolean;
  magic_link_enabled: boolean;
  magic_link_ttl_minutes: number;
  passkey_enabled: boolean;
  otp_email_enabled: boolean;
  otp_sms_enabled: boolean;
  // Hosted end-user self-registration (B2C signup). Full-replace PUT preserves
  // it even on pages that don't edit it.
  self_registration_enabled: boolean;
  // Adaptive MFA: allow skipping the second factor on a trusted device.
  remember_device_enabled: boolean;
}

export function useAuthPolicy() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["auth-policy", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<AuthPolicy>(`/v1/tenants/${tenantId}/auth-policy`),
  });
}

export function useUpdateAuthPolicy() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AuthPolicy) =>
      api<AuthPolicy>(`/v1/tenants/${tenantId}/auth-policy`, {
        method: "PUT",
        body,
      }),
    onSuccess: (data) => {
      qc.setQueryData(["auth-policy", tenantId], data);
      qc.invalidateQueries({ queryKey: ["auth-policy"] });
    },
    meta: { successMessage: "Authentication policy saved" },
  });
}
