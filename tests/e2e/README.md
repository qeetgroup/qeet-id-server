# tests/e2e/

End-to-end tests that drive the full stack through a browser. These tests verify complete user journeys across the frontend apps and backend API.

## Tech stack

- **Playwright** (TypeScript) — browser automation
- **@playwright/test** — test runner
- **Three apps under test**: Login (`localhost:3004`), Admin (`localhost:3002`), Website (`localhost:3001`)

## Prerequisites

```bash
cd qeet-id
nvm use   # reads .nvmrc (Node 24)
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
| `login/passkeys.spec.ts` | Passkey registration and authentication — ⚠️ not yet written. The security-critical WebAuthn ceremony (full register + login + forged-assertion rejection) is covered at the more robust, CI-wired Go layer in `tests/integration/passkey_ceremony_test.go` (virtual authenticator); this browser-level spec (exercising the login app's `navigator.credentials` JS) is a P2 follow-up. |
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

## Seed credentials (verified live against `cmd/seed/main.go`, 2026-07-11 — QID-11)

All three belong to the "Qeet Group" tenant (`saibabu@qeet.in` is the founder/owner).

| Role | Email | Password |
|---|---|---|
| Super-admin (owner) | `saibabu@qeet.in` | `Password123!` |
| Org admin | `aarav@qeet.in` | `Password123!` |
| Member | `sneha@qeet.in` | `Password123!` |

The seed also provisions 7 separate customer workspaces (northwind/meridian/lumen/aster/vertex/cobalt/fjord) for cross-tenant isolation testing, each with a generated owner email — query the DB rather than hardcoding them, since they're derived from a name pool:
```sql
select u.email from "user".users u join tenant.tenants t on t.id = u.tenant_id
where t.slug = 'northwind' order by u.created_at limit 1;
```
