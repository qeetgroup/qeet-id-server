// User directory tools — search_users, create_user, update_user, disable_user,
// enable_user, delete_user, reset_user_mfa.
//
// Every run() calls the EXISTING authenticated endpoint via api() using
// ctx.tenantId, so RBAC + Postgres RLS + audit are inherited unchanged.
// Secret material: none (user operations don't produce secrets).

import { z } from "zod";

import { api } from "@/lib/api";
import { USER_KEYS, type User } from "@/lib/users";
import type { ToolDefinition } from "../tool-types";

// ── search_users ──────────────────────────────────────────────────────────────

const searchUsersInput = z.object({
  q: z.string().optional(),
  status: z.enum(["active", "suspended", "invited", "deleted"]).optional(),
  limit: z.number().int().min(1).max(100).optional(),
});
type SearchUsersInput = z.infer<typeof searchUsersInput>;

export const searchUsersTool: ToolDefinition<SearchUsersInput> = {
  name: "search_users",
  category: "directory",
  title: "Search users",
  description:
    "Search users in the current tenant by free-text query and/or status. Returns a redacted list of users (id, email, name, status). Read-only.",
  input: searchUsersInput,
  requiredCapability: "user.read",
  destructive: false,
  auditLabel: "copilot.search_users",
  async run(ctx, input) {
    const data = await api<{ items: User[] }>("/v1/users", {
      query: {
        q: input.q,
        status: input.status,
        limit: input.limit ?? 20,
      },
      signal: ctx.signal,
    });
    const users = data.items ?? [];
    return {
      ok: true,
      summary: `Found ${users.length} user${users.length === 1 ? "" : "s"}.`,
      data: {
        users: users.map((u) => ({
          id: u.id,
          email: u.email,
          display_name: u.display_name,
          status: u.status,
        })),
      },
    };
  },
};

// ── create_user ───────────────────────────────────────────────────────────────

const createUserInput = z.object({
  email: z.string().email(),
  name: z.string().optional(),
  password: z.string().min(8).optional(),
  tenant_id: z.string(),
  role_id: z.string().optional(),
});
type CreateUserInput = z.infer<typeof createUserInput>;

export const createUserTool: ToolDefinition<CreateUserInput> = {
  name: "create_user",
  category: "directory",
  title: "Create user",
  description:
    "Create a new user in a tenant. Optionally assign an initial role. If no password is given, the user is created for invitation/passwordless onboarding.",
  input: createUserInput,
  requiredCapability: "user.write",
  destructive: false,
  auditLabel: "copilot.create_user",
  async run(ctx, input) {
    const { role_id, name, ...rest } = input;
    const user = await api<User>("/v1/users", {
      method: "POST",
      body: { ...rest, display_name: name },
      signal: ctx.signal,
    });
    if (role_id) {
      await api<void>(`/v1/users/${user.id}/tenants/${input.tenant_id}/roles/${role_id}`, {
        method: "POST",
        signal: ctx.signal,
      });
    }
    ctx.queryClient.invalidateQueries({ queryKey: USER_KEYS.all });
    return {
      ok: true,
      summary: `Created user ${user.email} (id: ${user.id})${role_id ? " and assigned the requested role" : ""}.`,
      data: { id: user.id, email: user.email, status: user.status },
    };
  },
};

// ── update_user ───────────────────────────────────────────────────────────────

const updateUserInput = z.object({
  user_id: z.string(),
  name: z.string().optional(),
});
type UpdateUserInput = z.infer<typeof updateUserInput>;

export const updateUserTool: ToolDefinition<UpdateUserInput> = {
  name: "update_user",
  category: "directory",
  title: "Update user",
  description: "Update a user's mutable profile fields (currently display name).",
  input: updateUserInput,
  requiredCapability: "user.write",
  destructive: false,
  auditLabel: "copilot.update_user",
  async run(ctx, input) {
    await api<User>(`/v1/users/${input.user_id}`, {
      method: "PATCH",
      body: { display_name: input.name ?? null },
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: USER_KEYS.all });
    ctx.queryClient.invalidateQueries({ queryKey: USER_KEYS.detail(input.user_id) });
    return {
      ok: true,
      summary: `Updated display name for user ${input.user_id}.`,
      data: { user_id: input.user_id, name: input.name },
    };
  },
};

// ── disable_user ──────────────────────────────────────────────────────────────

const disableUserInput = z.object({ user_id: z.string() });
type DisableUserInput = z.infer<typeof disableUserInput>;

export const disableUserTool: ToolDefinition<DisableUserInput> = {
  name: "disable_user",
  category: "directory",
  title: "Disable user",
  description:
    "Suspend a user, immediately blocking their sign-in. Reversible with enable_user. Destructive: requires confirmation.",
  input: disableUserInput,
  requiredCapability: "user.write",
  destructive: true,
  confirm: (input) => ({
    title: "Disable user",
    body: "This will immediately block the user from signing in. They can be re-enabled with enable_user.",
    affected: [{ label: "User ID", value: input.user_id }],
    confirmText: "Disable",
    tone: "destructive",
  }),
  auditLabel: "copilot.disable_user",
  async run(ctx, input) {
    await api<User>(`/v1/users/${input.user_id}`, {
      method: "PATCH",
      body: { status: "suspended" },
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: USER_KEYS.all });
    ctx.queryClient.invalidateQueries({ queryKey: USER_KEYS.detail(input.user_id) });
    return {
      ok: true,
      summary: `User ${input.user_id} has been suspended and can no longer sign in.`,
      data: { user_id: input.user_id, status: "suspended" },
    };
  },
};

// ── enable_user ───────────────────────────────────────────────────────────────

const enableUserInput = z.object({ user_id: z.string() });
type EnableUserInput = z.infer<typeof enableUserInput>;

export const enableUserTool: ToolDefinition<EnableUserInput> = {
  name: "enable_user",
  category: "directory",
  title: "Enable user",
  description: "Re-activate a suspended user, restoring their ability to sign in.",
  input: enableUserInput,
  requiredCapability: "user.write",
  destructive: false,
  auditLabel: "copilot.enable_user",
  async run(ctx, input) {
    await api<User>(`/v1/users/${input.user_id}`, {
      method: "PATCH",
      body: { status: "active" },
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: USER_KEYS.all });
    ctx.queryClient.invalidateQueries({ queryKey: USER_KEYS.detail(input.user_id) });
    return {
      ok: true,
      summary: `User ${input.user_id} has been re-activated and can sign in again.`,
      data: { user_id: input.user_id, status: "active" },
    };
  },
};

// ── delete_user ───────────────────────────────────────────────────────────────

const deleteUserInput = z.object({ user_id: z.string() });
type DeleteUserInput = z.infer<typeof deleteUserInput>;

export const deleteUserTool: ToolDefinition<DeleteUserInput> = {
  name: "delete_user",
  category: "directory",
  title: "Delete user",
  description:
    "Soft-delete a user. Destructive: requires confirmation and shows the affected user before proceeding.",
  input: deleteUserInput,
  requiredCapability: "user.write",
  destructive: true,
  confirm: (input) => ({
    title: "Delete user",
    body: "This will permanently soft-delete the user. This action cannot be easily reversed.",
    affected: [{ label: "User ID", value: input.user_id }],
    confirmText: "Delete",
    tone: "destructive",
  }),
  auditLabel: "copilot.delete_user",
  async run(ctx, input) {
    await api<void>(`/v1/users/${input.user_id}`, {
      method: "DELETE",
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: USER_KEYS.all });
    return {
      ok: true,
      summary: `User ${input.user_id} has been deleted.`,
      data: { user_id: input.user_id },
    };
  },
};

// ── reset_user_mfa ────────────────────────────────────────────────────────────

const resetUserMfaInput = z.object({ user_id: z.string() });
type ResetUserMfaInput = z.infer<typeof resetUserMfaInput>;

export const resetUserMfaTool: ToolDefinition<ResetUserMfaInput> = {
  name: "reset_user_mfa",
  category: "directory",
  title: "Reset user MFA",
  description:
    "Remove a user's enrolled MFA factors, forcing re-enrollment at next sign-in. Use when a user has lost their device. Destructive: requires confirmation. (There is no admin endpoint to ENABLE a specific factor for another user — MFA enrollment is a self-scoped ceremony.)",
  input: resetUserMfaInput,
  requiredCapability: "user.write",
  destructive: true,
  confirm: (input) => ({
    title: "Reset MFA",
    body: "This will clear all enrolled MFA factors. The user must re-enroll at their next sign-in.",
    affected: [{ label: "User ID", value: input.user_id }],
    confirmText: "Reset MFA",
    tone: "destructive",
  }),
  auditLabel: "copilot.reset_user_mfa",
  async run(ctx, input) {
    await api<{ message: string }>(`/v1/users/${input.user_id}/mfa`, {
      method: "DELETE",
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: USER_KEYS.detail(input.user_id) });
    return {
      ok: true,
      summary: `MFA has been reset for user ${input.user_id}. They will be prompted to re-enroll.`,
      data: { user_id: input.user_id },
    };
  },
};
