# tests/e2e/

End-to-end tests that drive the full stack through a browser. These tests verify complete user journeys across the frontend apps and backend API.

## Tech stack

- **Playwright** (TypeScript) — browser automation
- **@playwright/test** — test runner
- **Three apps under test**: Login (`localhost:3004`), Admin (`localhost:3002`), Website (`localhost:3001`)

## Prerequisites

```bash
nvm use v22.20.0
cd qeet-id
make db-up migrate-up
make seed              # seed demo data
make dev               # starts all 3 apps + backend in parallel
```

In a second terminal:

```bash
pnpm --filter @qeetid/e2e exec playwright install --with-deps
```

## Run

```bash
# All E2E tests
pnpm --filter @qeetid/e2e exec playwright test

# Headed (watch mode)
pnpm --filter @qeetid/e2e exec playwright test --headed

# Single file
pnpm --filter @qeetid/e2e exec playwright test login/email-password.spec.ts

# Debug
pnpm --filter @qeetid/e2e exec playwright test --debug
```

## Test files

| File | Covers |
|---|---|
| `login/email-password.spec.ts` | Login with email+password, MFA, lockout |
| `login/passkeys.spec.ts` | Passkey registration and authentication |
| `login/magic-link.spec.ts` | Magic-link and OTP flows |
| `login/social.spec.ts` | Social OAuth (Google stub) |
| `admin/dashboard.spec.ts` | Admin app login + dashboard landing |
| `admin/users.spec.ts` | User CRUD, invite, suspend |
| `admin/organizations.spec.ts` | Org create, branding, domain verification |
| `admin/roles.spec.ts` | Role assignment, RBAC gates |
| `admin/api-keys.spec.ts` | API key create / rotate / delete |
| `admin/audit.spec.ts` | Audit log view, export |

## Fixtures

Shared page objects, auth helpers, and test data are in `fixtures/`:
- `fixtures/auth.ts` — `loginAs(page, email, password)`, `loginAsAdmin(page)`
- `fixtures/pages.ts` — Page Object Model wrappers
- `fixtures/data.ts` — seed user/org constants (matches `cmd/seed/main.go`)

## Seed credentials (matches demo seed)

| Role | Email | Password |
|---|---|---|
| Super-admin | `admin@demo.id.qeet.in` | `Password123!` |
| Org admin | `org-admin@demo.id.qeet.in` | `Password123!` |
| Member | `member@demo.id.qeet.in` | `Password123!` |
