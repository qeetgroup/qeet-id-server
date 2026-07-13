import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./",
  testMatch: "**/*.spec.ts",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: [["html", { outputFolder: "playwright-report" }]],

  use: {
    baseURL: "http://localhost:3004",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
  ],

  // Commands run from the repo root (two levels up from tests/e2e). These match
  // the real Makefile / package.json targets — the previous `make dev-backend`
  // / `make dev-login` / `make dev-console` targets never existed (QID-08), so the
  // harness could not start a stack on its own. `reuseExistingServer` means a
  // stack already up via `make dev` + `bun run dev:login` + `bun run dev:console` is
  // reused locally; CI starts them fresh.
  webServer: [
    {
      command: "make dev",
      cwd: "../..",
      url: "http://localhost:4001/healthz",
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      command: "bun run dev:login",
      cwd: "../..",
      url: "http://localhost:3004",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
    {
      command: "bun run dev:console",
      cwd: "../..",
      url: "http://localhost:3002",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
  ],
});
