// User CRUD data layer — thin React Query hooks over the existing
// /v1/users/* endpoints. Extracted from routes/_app/users/index.tsx and
// routes/_app/users/$userId.tsx so that both the route pages (UI path) and
// the copilot tools (tool-call path) share one authenticated hook.
//
// Tool run() functions call api() directly; these hooks are the UI layer.
// Follow the house pattern: useMutation + api() + onSuccess invalidate + meta.

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

// ── Shared types ──────────────────────────────────────────────────────────────

export type UserStatus = "active" | "invited" | "suspended" | "deleted";

export interface User {
  id: string;
  tenant_id: string;
  email: string;
  display_name?: string | null;
  phone?: string | null;
  status: UserStatus;
  email_verified_at?: string | null;
  phone_verified_at?: string | null;
  roles?: string[] | null;
  created_at: string;
  updated_at?: string;
}

export interface CreateUserInput {
  email: string;
  tenant_id: string;
  password?: string;
  display_name?: string;
  phone?: string;
  /** Optional role to assign immediately after creation. */
  role_id?: string;
}

export interface UpdateUserBody {
  display_name?: string | null;
  phone?: string | null;
  status?: "active" | "suspended";
}

// Stable React Query key roots for cache invalidation.
export const USER_KEYS = {
  all: ["users"] as const,
  detail: (id: string) => ["user", id] as const,
  activity: (id: string, tenantId: string | null) => ["user-activity", id, tenantId] as const,
};

// ── Mutations ─────────────────────────────────────────────────────────────────

/**
 * Create a new user (POST /v1/users). Optionally assigns an initial role via
 * POST /v1/users/{id}/tenants/{tenantId}/roles/{roleId}.
 */
export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: CreateUserInput) => {
      const { role_id, ...body } = input;
      const user = await api<User>("/v1/users", { method: "POST", body });
      if (role_id) {
        await api<void>(`/v1/users/${user.id}/tenants/${body.tenant_id}/roles/${role_id}`, {
          method: "POST",
        });
      }
      return user;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: USER_KEYS.all }),
    meta: { successMessage: "User created" },
  });
}

/**
 * Update a user's mutable profile fields (PATCH /v1/users/{id}).
 * Accepts display_name, phone, and/or status in one call.
 */
export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, body }: { userId: string; body: UpdateUserBody }) =>
      api<User>(`/v1/users/${userId}`, { method: "PATCH", body }),
    onSuccess: (_, { userId }) => {
      qc.invalidateQueries({ queryKey: USER_KEYS.all });
      qc.invalidateQueries({ queryKey: USER_KEYS.detail(userId) });
    },
    meta: { successMessage: "User updated" },
  });
}

/**
 * Set a user's status to "active" or "suspended" (PATCH /v1/users/{id}).
 * Used by the copilot's disable_user / enable_user tools.
 */
export function useSetUserStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, status }: { userId: string; status: "active" | "suspended" }) =>
      api<User>(`/v1/users/${userId}`, { method: "PATCH", body: { status } }),
    onSuccess: (_, { userId }) => {
      qc.invalidateQueries({ queryKey: USER_KEYS.all });
      qc.invalidateQueries({ queryKey: USER_KEYS.detail(userId) });
    },
    meta: { successMessage: "User status updated" },
  });
}

/**
 * Soft-delete a user (DELETE /v1/users/{id}).
 */
export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) => api<void>(`/v1/users/${userId}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: USER_KEYS.all }),
    meta: { successMessage: "User deleted" },
  });
}

/**
 * Admin MFA reset: clears all enrolled factors for a user, forcing
 * re-enrollment at next sign-in (DELETE /v1/users/{id}/mfa).
 * Gated server-side on user.write; audited as mfa.admin_reset.
 */
export function useResetUserMfa() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) =>
      api<{ message: string }>(`/v1/users/${userId}/mfa`, { method: "DELETE" }),
    onSuccess: (_, userId) => {
      qc.invalidateQueries({ queryKey: USER_KEYS.detail(userId) });
    },
    meta: { successMessage: "Multi-factor authentication reset for this user" },
  });
}

/**
 * Assign a role to a user within the current tenant
 * (POST /v1/users/{userID}/tenants/{tenantID}/roles/{roleID}).
 */
export function useAssignRole() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, roleId }: { userId: string; roleId: string }) => {
      if (!tenantId) throw new Error("No tenant selected");
      return api<void>(`/v1/users/${userId}/tenants/${tenantId}/roles/${roleId}`, {
        method: "POST",
      });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: USER_KEYS.all }),
    meta: { successMessage: "Role assigned" },
  });
}
