# Sprint 14 — Self-serve Enterprise Admin Portal (#12) + LDAP/AD (#13)

| | |
|---|---|
| **Window** | 2026-12-14 → 2027-01-08 (3 weeks, incl. holidays) |
| **Theme** | Let *customers'* IT admins configure their own SSO/SCIM — the WorkOS killer feature — and add legacy directory support |
| **Depends on** | Sprints 12 (SAML), 13 (SCIM + org SSO) |
| **Closes** | Gap **#12** (admin portal), **#13** (LDAP/AD) |
| **Status** | ⬜ Not started |

**Why:** WorkOS/Stytch/Frontegg's standout feature is an **embeddable, white-labeled portal** where the customer's IT team self-configures SSO + SCIM **without a support ticket**. It's the difference between "enterprise onboarding takes a week of back-and-forth" and "takes 20 minutes." We make it **free** (no SSO tax). LDAP/AD rounds out legacy on-prem directories.

---

## Part A — 🧪 Test the newly-built feature (E2E)

### 🧪 SCENARIO 14.1 — Generate + open a portal link
- **Steps:** `POST /v1/portal/link` for tenant Acme (scopes: `sso`,`scim`) → returns a signed, expiring portal URL; open it.
- **Pass:** [ ] link is tenant-scoped + time-limited [ ] opens a branded portal [ ] expired/tampered link rejected [ ] no Qeet ID admin privileges leak (portal user can only touch their tenant's connections).

### 🧪 SCENARIO 14.2 — Customer self-configures SAML SSO via portal
- **Steps:** as the customer IT admin, in the portal: paste IdP metadata, map attributes, run "Test connection," activate.
- **Pass:** [ ] config saved to the org SSO connection (Sprint 13) [ ] test-connection validates a real assertion [ ] activation enables login for that tenant only.

### 🧪 SCENARIO 14.3 — Customer self-configures SCIM via portal
- **Pass:** [ ] portal issues/rotates the SCIM bearer token [ ] provisioning log visible to the customer [ ] customer cannot see other tenants.

### 🧪 SCENARIO 14.4 — LDAP/AD bind (#13)
- **Steps:** configure an LDAP connection (host, bind DN, base DN, TLS); a user authenticates via LDAP bind; attributes/groups sync.
- **Pass:** [ ] LDAP bind authenticates [ ] StartTLS/LDAPS enforced [ ] group/attribute sync maps to Qeet ID [ ] connection failures degrade gracefully.

**Part A exit:** a non-Qeet ID "customer admin" persona completes SSO + SCIM setup end-to-end with zero engineering help.

---

## Part B — Build: Admin Portal + LDAP

### Design / changes
**Backend**
- New module `internal/portal/`: signed, scoped, expiring **portal sessions** (a constrained principal that can only manage its tenant's SSO/SCIM/branding); `POST /v1/portal/link` (admin generates), portal-scoped API surface (reuses Sprint 12/13 connection APIs behind a tenant-locked guard).
- `internal/ldap/`: LDAP/AD connector — bind auth, search, group/attribute mapping, TLS; JIT provisioning + linking (Sprint 11).
- Migration `0040_portal_ldap.up.sql`: `portal.sessions`, `ldap.connections`.

**Frontend**
- New **embeddable Admin Portal** (can be its own small app or a hardened route): white-labeled (tenant branding from existing branding module), guided SSO/SCIM setup wizards, test-connection, provisioning logs. Embeddable via the portal link (iframe-safe + redirect modes).
- **Admin (internal)**: "Invite customer to configure" → generates portal link; view what customers configured.

**Docs**
- `content/docs/enterprise/admin-portal.mdx` (how to embed + share links), `content/docs/authentication/ldap.mdx`.

### Acceptance criteria
- [ ] A portal link lets a customer admin configure SAML SSO + SCIM for their tenant only, end-to-end, no support.
- [ ] Portal sessions are scoped/expiring; cannot escalate or cross tenants (explicit isolation tests).
- [ ] Portal is white-labeled with tenant branding.
- [ ] LDAP/AD bind authentication works over TLS with group sync.
- [ ] "No SSO tax": SSO/SCIM/portal are available on all plans (document this explicitly as positioning).

---

## Definition of Done
- [ ] Part A: customer-persona self-serve SSO+SCIM + LDAP scenarios pass + isolation tests.
- [ ] Part B: `portal` + `ldap` modules, embeddable portal app, migrations, tests green.
- [ ] Internal admin "invite to configure" + portal live; SAML/SCIM/LDAP stubs replaced.
- [ ] `enterprise/admin-portal.mdx` + `authentication/ldap.mdx` published.
- [ ] Roadmap: #12, #13 checked; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
