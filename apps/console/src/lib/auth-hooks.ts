// Auth Actions/Hooks data layer (Developer → Auth Hooks). A synchronous
// post-credential policy gate: Qeet POSTs a signed event to the hook URL and
// honours its allow/deny. Backed by /v1/tenants/{tenantID}/auth-hooks. The
// secret is write-only (sent on create, never returned).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface AuthHook {
  id: string;
  trigger: string;
  url: string;
  enabled: boolean;
  fail_open: boolean;
  created_at: string;
}

const KEY = ["auth-hooks"];

export function useAuthHooks() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, tenantId],
    queryFn: () => api<{ items: AuthHook[] }>(`/v1/tenants/${tenantId}/auth-hooks`),
    enabled: !!tenantId,
  });
}

export function useCreateAuthHook() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { url: string; secret: string; fail_open: boolean }) =>
      api<AuthHook>(`/v1/tenants/${tenantId}/auth-hooks`, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
    meta: { successMessage: "Hook added" },
  });
}

export function useUpdateAuthHook() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      enabled,
      fail_open,
    }: {
      id: string;
      enabled: boolean;
      fail_open: boolean;
    }) =>
      api<void>(`/v1/tenants/${tenantId}/auth-hooks/${id}`, {
        method: "PATCH",
        body: { enabled, fail_open },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useDeleteAuthHook() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/auth-hooks/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
