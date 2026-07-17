// RBAC data layer for the Authorization section. Wraps the role / permission
// endpoints so the Roles, Permissions and RBAC-graph surfaces share one typed
// source. Backed by /v1/permissions, /v1/tenants/{t}/roles and
// /v1/roles/{id}/permissions. See domains/access/authorization/rbac/http.go.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface Permission {
  id: string;
  key: string;
  description: string;
}

export interface Role {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  is_system: boolean;
  created_at: string;
}

export function usePermissions() {
  return useQuery({
    queryKey: ["permissions"],
    queryFn: () => api<{ items: Permission[] }>("/v1/permissions"),
  });
}

export function useRoles() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["roles", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: Role[] }>(`/v1/tenants/${tenantId}/roles`),
  });
}

export function useCreateRole() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; description: string }) =>
      api<Role>(`/v1/tenants/${tenantId}/roles`, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["roles"] }),
    meta: { successMessage: "Role created" },
  });
}

/** Permissions currently granted to a role. */
export function useRolePermissions(roleId: string | null) {
  return useQuery({
    queryKey: ["role-permissions", roleId],
    enabled: !!roleId,
    queryFn: () => api<{ items: Permission[] }>(`/v1/roles/${roleId}/permissions`),
  });
}

export function useGrantPermission(roleId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (permId: string) =>
      api<void>(`/v1/roles/${roleId}/permissions/${permId}`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["role-permissions", roleId] }),
    meta: { successMessage: "Permission granted" },
  });
}

export function useRevokePermission(roleId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (permId: string) =>
      api<void>(`/v1/roles/${roleId}/permissions/${permId}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["role-permissions", roleId] }),
    meta: { successMessage: "Permission revoked" },
  });
}

/** Effective permission keys resolved for a user (direct ∪ role ∪ group). */
export function useEffectivePermissions(userId: string | null) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["effective-permissions", tenantId, userId],
    enabled: !!tenantId && !!userId,
    queryFn: () =>
      api<{ permissions: string[] }>(`/v1/users/${userId}/tenants/${tenantId}/permissions`),
  });
}

// ── Derived catalogue helpers (shared by Permissions + Dashboard) ─────────────

/** Group permissions by their `resource` prefix (the part before the dot). */
export function groupPermissionsByResource(perms: Permission[]): Map<string, Permission[]> {
  const groups = new Map<string, Permission[]>();
  for (const p of perms) {
    const resource = p.key.includes(".") ? p.key.slice(0, p.key.indexOf(".")) : p.key;
    const bucket = groups.get(resource) ?? [];
    bucket.push(p);
    groups.set(resource, bucket);
  }
  return groups;
}

/** Permission keys containing a wildcard — flagged as a security risk. */
export function wildcardPermissions(perms: Permission[]): Permission[] {
  return perms.filter((p) => p.key.includes("*"));
}
