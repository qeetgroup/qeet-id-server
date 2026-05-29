# Sprint 13 — SCIM 2.0 (#10) + Org-level SSO Connections (#11) ⏳XL

| | |
|---|---|
| **Window** | 2026-11-23 → 2026-12-11 (3 weeks, ⏳XL) |
| **Theme** | Automated directory provisioning + per-tenant SSO so enterprises self-onboard |
| **Depends on** | Sprint 12 (SAML), Sprint 2 (groups/RBAC), Sprint 11 (identity graph) |
| **Closes** | Gap **#10** (SCIM 2.0), **#11** (org-level SSO connections) |
| **Status** | ⬜ Not started |

**Why:** SAML logs people in; **SCIM keeps the user list in sync** (auto-provision on hire, auto-deprovision on termination) — the other half of the enterprise requirement. Pair it with per-organization SSO connections so each customer tenant points at its own IdP.

---

## Part A — 🧪 Test the newly-built feature (E2E)

> Use a sandbox directory (Okta/Azure AD SCIM, or a SCIM test client) pointed at our SCIM base URL + bearer token.

### 🧪 SCENARIO 13.1 — SCIM provisioning (create/update)
- **Steps:** from the directory, assign a user → SCIM `POST /scim/v2/Users`; update attributes → `PATCH`/`PUT`.
- **Expect:** user created/updated in the right tenant; mapped to Qeet ID schema; idempotent on retries.
- **Pass:** [ ] create provisions user [ ] PATCH updates (active=false → suspend) [ ] duplicate create is idempotent [ ] schema/Service Provider Config endpoints respond.

### 🧪 SCENARIO 13.2 — Deprovisioning (the critical one)
- **Steps:** unassign/disable user in directory → SCIM `PATCH active:false` or `DELETE`.
- **Expect:** user suspended/soft-deleted; **all sessions + tokens revoked immediately** (reuse Sprint-8 revocation fan-out).
- **Pass:** [ ] deprovision suspends access within seconds [ ] sessions/tokens killed [ ] audited.

### 🧪 SCENARIO 13.3 — Group sync
- **Steps:** directory group membership changes → SCIM `Groups` ops.
- **Pass:** [ ] groups created/updated [ ] membership maps to Qeet ID groups → roles (Sprint 2 group RBAC) [ ] filtering (`filter=userName eq …`) works.

### 🧪 SCENARIO 13.4 — Org-level SSO connection (#11)
- **Steps:** for tenant Acme, configure its own SAML/OIDC IdP + claimed email domain; a user at `@acme.com` is routed to Acme's IdP automatically (home-realm discovery).
- **Pass:** [ ] per-tenant IdP config isolated [ ] domain-based routing sends user to the right IdP [ ] one tenant's connection never affects another.

**Part A exit:** SCIM CRUD + deprovision + group sync verified against a real directory; added to conformance checklist.

---

## Part B — Build: SCIM 2.0 + Org SSO

### Design / changes
**Backend**
- New module `internal/scim/`: RFC 7643/7644 — `/scim/v2/Users`, `/Groups`, `/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`; filtering, pagination, PATCH ops; bearer auth per connection; mapping lambda (configurable attribute → profile).
- **Deprovision = revoke**: hook SCIM `active:false`/DELETE into the Sprint-8 revocation fan-out + token revocation epoch (Sprint 4) so edge verifiers honor it instantly.
- **Org SSO (#11):** `internal/orgsso/` (or extend `social`/`saml`): per-tenant connection registry + **home-realm discovery** (email-domain → connection); claimed-domain verification (DNS TXT).
- Migration `0038_scim.up.sql` (`scim.connections`, `scim.provisioning_log`) + `0039_org_sso.up.sql` (`sso.connections`, `sso.claimed_domains`).

**Frontend (admin)**
- **Connections → SCIM**: real provisioning config (base URL, token issue/rotate, mapping, provisioning log). 
- **Connections → SSO**: per-tenant SAML/OIDC connection + domain claim/verify. (Goes self-serve in Sprint 14.)

**Docs**
- `content/docs/authentication/scim.mdx` (+ Okta/Azure AD setup), `content/docs/authentication/sso.mdx` updated for org connections + home-realm discovery.

### Acceptance criteria
- [ ] SCIM passes CRUD + filter + PATCH against Okta + Azure AD provisioning.
- [ ] Deprovision revokes access within one revocation-digest cycle and is audited.
- [ ] Group membership syncs to roles via group RBAC.
- [ ] Claimed-domain verification (DNS) gates org SSO; home-realm discovery routes correctly.
- [ ] Tenant isolation holds across connections.

---

## Definition of Done
- [ ] Part A: SCIM + org-SSO scenarios pass against ≥1 real directory + isolation tests.
- [ ] Part B: `scim` + `orgsso` modules, deprovision→revoke wiring, migrations, tests green.
- [ ] Admin SCIM + SSO connection screens live (no stubs).
- [ ] `scim.mdx` + updated `sso.mdx` published.
- [ ] Roadmap: #10, #11 checked; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
