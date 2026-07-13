import { expect, test } from "@playwright/test";
import { loginAsAdmin } from "../fixtures/auth";

test.describe("Admin — user management", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("http://localhost:3002/users");
  });

  test("users list loads", async ({ page }) => {
    await expect(page.getByRole("table")).toBeVisible();
  });

  test("invite user dialog opens", async ({ page }) => {
    await page.getByRole("button", { name: /invite/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByLabel("Email")).toBeVisible();
  });

  test("search filters users", async ({ page }) => {
    await page.getByPlaceholder(/search/i).fill("admin");
    await expect(page.getByRole("row").nth(1)).toContainText("admin");
  });
});
