# Sprint 16 — OpenAPI Completion (#27) + Client SDKs (#22) + CLI (#28) ⏳XL

| | |
|---|---|
| **Window** | 2027-01-25 → 2027-02-12 (3 weeks, ⏳XL) |
| **Theme** | Make Qeet ID as easy to adopt as Clerk — ship the SDKs the docs already promise |
| **Depends on** | All prior backend sprints (the API surface to wrap) |
| **Closes** | Gap **#27** (OpenAPI), **#22** (SDKs), **#28** (CLI) |
| **Status** | ⬜ Not started |

**Why:** The docs site already documents `@qeetid/sdk`, `@qeetid/react`, `@qeetid/nextjs`, Go and Python SDKs — **but none exist in the repo**. That's a credibility gap and the #1 adoption blocker. We complete the OpenAPI spec (currently ~3% coverage) and **generate** SDKs from it so they never drift from the API.

---

## Part A — 🧪 Test the newly-built feature (E2E)

### 🧪 SCENARIO 16.1 — OpenAPI spec is complete + accurate (#27)
- **Steps:** lint the spec (`spectral`/`vacuum`); diff documented endpoints against the live router; run contract tests.
- **Pass:** [ ] 100% of routes documented [ ] schemas match real responses [ ] examples validate [ ] CI fails if a route is added without a spec entry.

### 🧪 SCENARIO 16.2 — TS/JS SDK round-trip (#22)
- **Steps:** `npm i @qeetid/sdk`; in a Node + an Edge runtime, sign up → login → list users → verify a session → verify a webhook signature.
- **Pass:** [ ] works in Node + Edge/Bun/Deno + browser [ ] types match API [ ] refresh handled [ ] tree-shakeable.

### 🧪 SCENARIO 16.3 — Go + Python SDK round-trip
- **Pass:** [ ] Go server SDK: token verify (JWKS), `check`/`explain`, admin ops [ ] Python sync + async clients work [ ] versioned to match API (SDK 1.x ↔ API 1.x).

### 🧪 SCENARIO 16.4 — CLI (#28)
- **Steps:** `qeetid login`; `qeetid tenants list`; `qeetid users import users.csv`; `qeetid dev tunnel` (local webhook tunnel, ties to Sprint 6/D dev tooling).
- **Pass:** [ ] auth + core ops from terminal [ ] CSV import works [ ] dev tunnel forwards webhooks locally.

**Part A exit:** SDK conformance suite runs against a live local API in CI for each language.

---

## Part B — Build: spec-first SDKs + CLI

### Design / changes
**Backend / spec**
- Complete `backend/api/openapi.yaml` to 100% (all ~130+ routes, schemas, errors, examples). Add a CI gate: new route without spec entry → build fails. Regenerate the Postman collection from the spec.

**SDKs (new packages — spec-generated core + hand-written ergonomics)**
- `packages/qeetid-sdk` (TS) — universal client (Node/Edge/Deno/Bun/browser): auth, sessions, users, tenants, RBAC `check`/`explain`, webhook verification, edge token verify (reuse Sprint-4 edge kit).
- `packages/qeetid-nextjs` — App Router middleware, server actions, route handlers.
- `backend/sdk/go` (or separate module) — server SDK: JWKS verify, `check`/`explain`, admin ops.
- `sdks/python` — sync + async.
- All cores generated from OpenAPI (e.g. `openapi-generator`/`oazapfts` + a thin ergonomic layer); versioned in lockstep with the API.

**CLI**
- `qeetid` (Go or TS): login, tenant/user/app management, `users import` (wraps Sprint-9 importer), `dev tunnel` (local webhook forwarding + Dev Inbox tail), `keys rotate`.

**Docs**
- Update `content/docs/sdks/*` to match the **real** shipped packages; mark anything still pending as "coming soon"; add `content/docs/cli.mdx` real usage. Generate API reference pages from the spec.

### Acceptance criteria
- [ ] OpenAPI covers 100% of routes; CI gate enforces it; Postman regenerated from spec.
- [ ] TS SDK works across Node/Edge/Deno/Bun/browser with correct types; Next.js middleware protects routes.
- [ ] Go + Python SDKs cover verify + admin ops; versioned to the API.
- [ ] CLI does login + core management + CSV import + dev tunnel.
- [ ] Docs SDK pages reflect reality (no documented-but-unbuilt packages).

---

## Definition of Done
- [ ] Part A: spec + SDK conformance + CLI scenarios pass in CI (all languages).
- [ ] Part B: OpenAPI 100%, TS/Next/Go/Python SDKs, CLI published + versioned.
- [ ] `sdks/*` + `cli.mdx` docs corrected to match shipped artifacts.
- [ ] Roadmap: #27, #22, #28 checked; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
