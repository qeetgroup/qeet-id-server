# Qeet ID — Launch Readiness Summary

**As of 2026-07-12** · Target GA **July 21, 2026** (flexible into August if needed) · Full detail in [`TESTING-FINDINGS.md`](./TESTING-FINDINGS.md)

This is the go/no-go capstone for the QA cycle. It consolidates what was tested, what was fixed, what's verified, and what still needs a human (you) or an external dependency.

---

## TL;DR

- **20 findings** logged; **15 fixed & verified live**, 2 more fixed (QID-06 react-app / QID-11 test creds), 1 partially fixed (QID-08 harness), 1 deferred-with-rationale (QID-12), 1 open doc-gap (QID-09). External/ops items unchanged.
- **1 was launch-blocking (S1):** a **systemic cross-tenant data leak** (QID-18) — found, fixed in depth, regression-tested, verified live. This alone justified the QA cycle.
- **Whole batch is green:** full fresh regression sweep (unit `-race`, integration/testcontainers, security, OpenAPI-coverage, route-audit, console typecheck/lint/build, smoke) all pass.
- **Biggest remaining risk is process, not code:** ~46 changed paths (incl. an S1 security fix) are **uncommitted and unreviewed**. Recommend a review+commit checkpoint before further work.

---

## Phase status

| Phase | Scope | Status |
|---|---|---|
| 0 — Setup & infra triage | stack up, findings tracker, route-audit tool, SDK unblock, quick-fix known bugs | ✅ Done |
| 1 — Core auth | password/passwordless/magic-link/OTP/MFA/passkeys/sessions | ✅ Done (multi-browser session test incl.) |
| 2 — Authorization | RBAC/ABAC/ReBAC explainability + **cross-tenant isolation** | ✅ Done (found+fixed the S1) |
| 3 — Federation | OIDC provider surface + console federation screens | ✅ Self-testable parts done · ⏳ external-IdP interop needs trial accounts |
| 4 — Machine/agent identity | agent tokens/MCP introspection, API keys, secrets, JWT-VC, webhooks | ✅ Done |
| 5 — Security/compliance/ops | tamper-evident audit `/verify`, GDPR round-trip, all screens | ✅ Done |
| 6 — SDK + example E2E | run examples against SDKs | 🟡 Partial — react-app builds (QID-06/13); full browser OAuth round-trip deferred |
| 7 — Competitor UX + polish | Auth0/Okta/Clerk comparison + UX consistency | ⏳ Needs competitor accounts · UX audit found console already consistent |
| 8 — Full regression | whole suite fresh | ✅ Done — all green (caught QID-20) |
| 9 — Launch-day smoke | prod smoke + external checklist | ⏳ Needs production + external/ops items |

---

## Findings by severity

**S1 — launch-blocking (fixed & verified):**
- **QID-18 — cross-tenant data leak.** A tenant admin could read (and in cases modify/delete) ~12 other-tenant resources + a users IDOR. Fixed with a central `EnforceTenantScope` middleware + per-handler guards; all cross-tenant reads now 403/404, own-tenant unaffected; regression-tested.
- **QID-06 — SDK/examples broken** (a prior commit deleted in-repo SDKs mid-migration). react-app relinked & building; nextjs-app cleanly excluded (no replacement package exists); documented.
- **QID-10 — launch smoke test called a nonexistent endpoint** (would fail every deploy). Fixed.

**S2 — high (all fixed & verified):**
- QID-01 role permissions 404 · QID-02 onboarding checklist wrong URL · QID-03 social providers that look configurable but can't work · QID-13 SDK example API drift · QID-14 passkey signup dup-email · QID-17 MFA step-up dead-end · QID-19 four unreachable detail pages (roles/groups/webhooks/OIDC).

**S3 — medium (fixed):** QID-04/05 fully-mock pages → honest placeholders · QID-15/16 test bugs · QID-20 vacuously-passing security test · QID-11 stale test credentials · QID-08 broken e2e harness config.

**Coverage gap closed:** QID-07 — passkey WebAuthn ceremony had zero automated coverage; added a virtual-authenticator integration test (register+login+forged-assertion rejection), CI-wired.

**Deferred with rationale (not defects):** QID-12 (4 gracefully-degrading roadmap endpoints), QID-09 (SDK docs naming drift — doc fix).

---

## What's verified working (highlights)

- **Auth:** password/passwordless/magic-link config, **full passkey ceremony** (browser + Go layers), TOTP enroll, **session revocation across two browsers**.
- **Authorization:** RBAC + **ReBAC recursive `/check` with grant-path explainability** (the differentiators), cross-tenant isolation (post-fix).
- **Agent identity (crown jewel):** create → short-lived scoped token → introspection shows `actor_type=agent`/`agent_id` → suspend blocks issuance.
- **OIDC provider:** discovery, JWKS (ES256), PRM (RFC 9728), M2M client_credentials, RFC 7662 introspection.
- **Compliance:** **tamper-evident audit `/verify` stays `ok` through GDPR erasure**; GDPR export→erasure round-trip.
- **W3C JWT-VC** issue→verify round-trip.

---

## Needs YOU (cannot be closed solo)

1. **Review + commit the ~46-path batch** — incl. the S1 fix. Highest-leverage next step. (Commit plan below.)
2. **External trial accounts** for real interop: Okta / Microsoft Entra / Google Workspace / GitHub OAuth app / Apple (Apple has the longest lead time). → unblocks Phase 3 & 6 interop + social login.
3. **Auth0 / Okta / Clerk accounts** → Phase 7 competitor UX comparison.
4. **PRD §12.2 external/ops GA items** (none closeable by QA): AWS KMS BYOK, OpenID conformance submission, SAML/SCIM interop cert, email deliverability domain (SPF/DKIM/DMARC), RDS PITR, external pentest, billing env keys (Stripe/Razorpay), i18n/a11y retrofit of legacy screens.
5. **Decision:** the Python / Next.js / browser-client SDKs have no code anywhere (deleted, not replaced) — resurrect or scrub the "6 SDKs" claims from README/PRD/docs before GA.

---

## Recommended commit plan (turn the batch into reviewable commits)

Suggested logical groupings (branch off `develop` first):
1. `fix(security): enforce tenant scope on all tenant-scoped routes (QID-18)` — `router.go`, `httpx/auth.go`(+test), `rbac/http.go`, `rbac/rbac.go`, `users/http.go`, `users/repository.go`, `permissions.go`, `authz_test.go`
2. `fix(rbac): add GET /roles/{id}/permissions (QID-01)` — `rbac.go`, `http.go`, `permissions.go`, `api/openapi/auth.yaml`, `authz_test.go`
3. `fix(mfa): step-up dialog for regenerate/disable + record verification on enroll (QID-17)` — `mfa.go`, `lib/mfa.ts`, `step-up-dialog.tsx`, `recovery-codes.tsx`, `totp.tsx`, `coverage_test.go`
4. `fix(console): repair 4 unreachable detail routes via folder pattern (QID-19)` — the 8 renamed route files + routeTree.gen.ts
5. `fix(console): honest placeholders for mock bots/infra pages (QID-04/05)`; `fix(console): onboarding + social provider truthfulness (QID-02/03)`
6. `test: passkey ceremony + fix stale security/e2e tests (QID-07/11/20); tools: route-audit`; `fix(examples): relink SDKs (QID-06/13)`; `fix(scripts): smoke-test endpoint (QID-10)`
7. `docs(qa): findings tracker, launch-readiness, UX audit` — the `qa/` folder

---

## Go / No-Go

- **For a P0 self-hosted GA:** core auth, authorization + isolation, agent identity, OIDC provider, audit/GDPR are **verified**. The one launch-blocker (QID-18) is fixed. **Green to proceed on code**, gated on: (a) committing/reviewing this batch, (b) the external/ops items in §Needs-You #4.
- **July 21 vs August:** the *code* is in good shape for July 21. What realistically pushes toward August is the **external/ops track** (pentest, conformance, deliverability, interop cert, billing keys) — none of which QA can close and several of which have real lead time. Recommend: commit + review now, run the external track in parallel, and set the final date on that track's progress rather than the code's.
