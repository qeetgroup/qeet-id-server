import type { Page } from "@playwright/test";

/**
 * Seed credentials — verified live against `cmd/seed/main.go` (QID-11: this
 * file previously listed `@demo.id.qeet.in` addresses that were never
 * actually created by the seed script and returned 401 on login).
 *
 * All three accounts belong to the "Qeet Group" tenant (`saibabu@qeet.in` is
 * the founder/owner). For cross-tenant isolation tests, the seed also
 * provisions 7 separate customer workspaces (northwind/meridian/lumen/aster/
 * vertex/cobalt/fjord) with generated owner emails — query
 * `select u.email from "user".users u join tenant.tenants t on t.id = u.tenant_id
 * where t.slug = 'northwind' order by u.created_at limit 1;` rather than
 * hardcoding them here, since they're generated from a name pool and would
 * silently go stale the same way this file just did.
 */
export const DEMO_USERS = {
  superAdmin: { email: "saibabu@qeet.in", password: "Password123!" }, // founder/owner, Qeet Group
  orgAdmin: { email: "aarav@qeet.in", password: "Password123!" }, // admin role, Qeet Group
  member: { email: "sneha@qeet.in", password: "Password123!" }, // member role, Qeet Group
} as const;

export async function loginAs(page: Page, email: string, password: string): Promise<void> {
  await page.goto("http://localhost:3004");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/dashboard|\/$/);
}

export async function loginAsAdmin(page: Page): Promise<void> {
  await loginAs(page, DEMO_USERS.superAdmin.email, DEMO_USERS.superAdmin.password);
  await page.waitForURL("http://localhost:3002/**");
}
