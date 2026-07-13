import { expect, test } from "@playwright/test";
import { DEMO_USERS, loginAs } from "../fixtures/auth";

test.describe("Email + password login", () => {
  test("successful login redirects to dashboard", async ({ page }) => {
    await loginAs(page, DEMO_USERS.member.email, DEMO_USERS.member.password);
    await expect(page).not.toHaveURL(/login/);
  });

  test("wrong password shows error", async ({ page }) => {
    await page.goto("http://localhost:3004");
    await page.getByLabel("Email").fill(DEMO_USERS.member.email);
    await page.getByLabel("Password").fill("wrong-password");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("alert")).toContainText(/invalid|incorrect/i);
  });

  test("unknown email shows error", async ({ page }) => {
    await page.goto("http://localhost:3004");
    await page.getByLabel("Email").fill("nobody@example.com");
    await page.getByLabel("Password").fill("Password123!");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("alert")).toBeVisible();
  });

  test("sign out returns to login page", async ({ page }) => {
    await loginAs(page, DEMO_USERS.member.email, DEMO_USERS.member.password);
    await page.getByRole("button", { name: /sign out|logout/i }).click();
    await expect(page).toHaveURL(/login|\/$/);
  });
});
