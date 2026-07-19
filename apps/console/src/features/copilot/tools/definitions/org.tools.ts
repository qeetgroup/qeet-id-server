// Organization (tenant) tools — create_organization.
//
// run() calls POST /v1/tenants via api() so RBAC + RLS + audit are inherited.

import { z } from "zod";

import { api } from "@/lib/api";
import type { ToolDefinition } from "../tool-types";

interface Tenant {
  id: string;
  name: string;
  slug: string;
  created_at: string;
}

// ── create_organization ───────────────────────────────────────────────────────

const createOrgInput = z.object({
  name: z.string(),
  slug: z.string().optional(),
});
type CreateOrgInput = z.infer<typeof createOrgInput>;

export const createOrganizationTool: ToolDefinition<CreateOrgInput> = {
  name: "create_organization",
  category: "directory",
  title: "Create organization",
  description: "Create a new organization (tenant).",
  input: createOrgInput,
  requiredCapability: "tenant.write",
  destructive: false,
  auditLabel: "copilot.create_organization",
  async run(ctx, input) {
    const tenant = await api<Tenant>("/v1/tenants", {
      method: "POST",
      body: input,
      signal: ctx.signal,
    });
    ctx.queryClient.invalidateQueries({ queryKey: ["tenants"] });
    return {
      ok: true,
      summary: `Organization "${tenant.name}" created (id: ${tenant.id}, slug: ${tenant.slug}).`,
      data: { id: tenant.id, name: tenant.name, slug: tenant.slug },
    };
  },
};
