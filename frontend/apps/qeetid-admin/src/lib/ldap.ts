// LDAP / Active Directory connection data layer. bind_password is write-only:
// it's accepted on create/update but never returned by the API.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export type LdapStatus = "draft" | "active" | "disabled";

export interface LdapConnection {
  id: string;
  tenant_id: string;
  name: string;
  server_url: string;
  start_tls: boolean;
  skip_tls_verify: boolean;
  bind_dn: string;
  base_dn: string;
  user_filter: string;
  email_attribute: string;
  name_attribute: string;
  status: LdapStatus;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
}

export interface CreateLdapInput {
  name: string;
  server_url: string;
  start_tls?: boolean;
  skip_tls_verify?: boolean;
  bind_dn: string;
  bind_password: string;
  base_dn: string;
  user_filter?: string;
  email_attribute?: string;
  name_attribute?: string;
  status?: LdapStatus;
}

export function useLdapConnections() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["ldap", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: LdapConnection[] }>(`/v1/tenants/${tenantId}/ldap`),
  });
}

export function useCreateLdapConnection() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateLdapInput) =>
      api<LdapConnection>(`/v1/tenants/${tenantId}/ldap`, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ldap"] }),
    meta: { successMessage: "LDAP connection created" },
  });
}

export function useUpdateLdapConnection() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: Partial<CreateLdapInput> & { id: string }) =>
      api<LdapConnection>(`/v1/tenants/${tenantId}/ldap/${id}`, { method: "PATCH", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ldap"] }),
    meta: { successMessage: "LDAP connection updated" },
  });
}

export function useDeleteLdapConnection() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/v1/tenants/${tenantId}/ldap/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ldap"] }),
    meta: { successMessage: "LDAP connection deleted" },
  });
}

/** Service-account bind test — proves the connection settings reach the directory. */
export function useTestLdapConnection() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: (id: string) =>
      api<{ ok: boolean }>(`/v1/tenants/${tenantId}/ldap/${id}/test`, { method: "POST" }),
    meta: { successMessage: "Directory bind succeeded" },
  });
}
