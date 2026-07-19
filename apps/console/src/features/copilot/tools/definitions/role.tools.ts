// RBAC role tools — create_role, assign_role, grant_permission.
//
// Reuse patterns from lib/authz-rbac.ts; run() calls api() directly with
// ctx.tenantId so RBAC + RLS + audit are inherited.

import { z } from "zod";

import { api } from "@/lib/api";
import type { ToolDefinition } from "../tool-types";

// ── create_role ───────────────────────────────────────────────────────────────

const createRoleInput = z.object({
  name: z.string(),
  description: z.string().optional(),
});
type CreateRoleInput = z.infer<typeof createRoleInput>;

export const createRoleTool: ToolDefinition<CreateRoleInput> = {
  name: "create_role",
  category: "directory",
  title: "Create role",
  description:
    "Create a role in the current tenant. Permissions are granted separately with grant_permission.",
  input: createRoleInput,
  requiredCapability: "role.write",
  destructive: false,
  auditLabel: "copilot.create_role",
  async run(ctx, input) {
    const role = await api<{ id: string; name: string; description: string }>(
      `/v1/tenants/${ctx.tenantId}/roles`,
      {
        method: "POST",
        body: { name: input.name, description: input.description ?? "" },
        signal: ctx.signal,
      },
    );
    ctx.queryClient.invalidateQueries({ queryKey: ["roles"] });
    return {
      ok: true,
      summary: `Role "${role.name}" created (id: ${role.id}).`,
      data: { id: role.id, name: role.name, description: role.description },
    };
  },
};

// ── assign_role ───────────────────────────────────────────────────────────────

const assignRoleInput = z.object({
  user_id: z.string(),
  role_id: z.string(),
});
type AssignRoleInput = z.infer<typeof assignRoleInput>;

export const assignRoleTool: ToolDefinition<AssignRoleInput> = {
  name: "assign_role",
  category: "directory",
  title: "Assign role to user",
  description: "Assign an existing role to a user within the current tenant.",
  input: assignRoleInput,
  requiredCapability: "role.write",
  destructive: false,
  auditLabel: "copilot.assign_role",
  async run(ctx, input) {
    await api<void>(`/v1/users/${input.user_id}/tenants/${ctx.tenantId}/roles/${input.role_id}`, {
      method: "POST",
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: ["users"] });
    ctx.queryClient.invalidateQueries({ queryKey: ["user", input.user_id] });
    return {
      ok: true,
      summary: `Role ${input.role_id} assigned to user ${input.user_id} in tenant ${ctx.tenantId}.`,
      data: { user_id: input.user_id, role_id: input.role_id, tenant_id: ctx.tenantId },
    };
  },
};

// ── grant_permission ──────────────────────────────────────────────────────────

const grantPermissionInput = z.object({
  role_id: z.string(),
  permission_id: z.string(),
});
type GrantPermissionInput = z.infer<typeof grantPermissionInput>;

export const grantPermissionTool: ToolDefinition<GrantPermissionInput> = {
  name: "grant_permission",
  category: "directory",
  title: "Grant permission to role",
  description: "Grant a permission to a role. Broadens what every user holding the role can do.",
  input: grantPermissionInput,
  requiredCapability: "role.write",
  destructive: false,
  auditLabel: "copilot.grant_permission",
  async run(ctx, input) {
    await api<void>(`/v1/roles/${input.role_id}/permissions/${input.permission_id}`, {
      method: "POST",
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: ["role-permissions", input.role_id] });
    return {
      ok: true,
      summary: `Permission ${input.permission_id} granted to role ${input.role_id}.`,
      data: { role_id: input.role_id, permission_id: input.permission_id },
    };
  },
};
