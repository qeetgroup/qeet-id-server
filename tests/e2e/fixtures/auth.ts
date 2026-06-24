import type { Page } from "@playwright/test";

/** Demo seed credentials (matches cmd/seed/main.go) */
export const DEMO_USERS = {
  superAdmin: { email: "admin@demo.id.qeet.in", password: "Password123!" },
  orgAdmin: { email: "org-admin@demo.id.qeet.in", password: "Password123!" },
  member: { email: "member@demo.id.qeet.in", password: "Password123!" },
} as const;

export async function loginAs(
  page: Page,
  email: string,
  password: string,
): Promise<void> {
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
