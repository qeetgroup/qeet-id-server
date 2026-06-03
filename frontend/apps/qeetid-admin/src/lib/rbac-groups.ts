// RBAC: group → role grants. A group can be granted any number of roles; every
// member of the group then inherits that role's permissions. Roles themselves
// are tenant-scoped (some are system roles that can't be deleted). Grants are
// keyed by (group, role) and toggled via PUT/DELETE-style POST/DELETE on the
// nested /roles/{roleId} path.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface GroupRole {
  role_id: string;
  name: string;
  granted_at: string;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  is_system: boolean;
  created_at: string;
}

export function useRoles() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["roles", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: Role[] }>(`/v1/tenants/${tenantId}/roles`),
  });
}

export function useGroupRoles(groupId: string) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["group-roles", tenantId, groupId],
    enabled: !!tenantId && !!groupId,
    queryFn: () =>
      api<{ items: GroupRole[] }>(`/v1/tenants/${tenantId}/groups/${groupId}/roles`),
  });
}

export function useGrantGroupRole(groupId: string) {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (roleId: string) =>
      api<void>(`/v1/tenants/${tenantId}/groups/${groupId}/roles/${roleId}`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["group-roles", tenantId, groupId] }),
    meta: { successMessage: "Role granted to group" },
  });
}

export function useRevokeGroupRole(groupId: string) {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (roleId: string) =>
      api<void>(`/v1/tenants/${tenantId}/groups/${groupId}/roles/${roleId}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["group-roles", tenantId, groupId] }),
    meta: { successMessage: "Role revoked from group" },
  });
}
