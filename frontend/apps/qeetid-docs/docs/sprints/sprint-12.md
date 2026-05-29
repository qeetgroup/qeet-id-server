# Sprint 12 — SAML 2.0 SP + IdP (#9) ⏳XL

| | |
|---|---|
| **Window** | 2026-11-02 → 2026-11-20 (3 weeks, ⏳XL — may split into 12a SP / 12b IdP) |
| **Theme** | The single biggest enterprise gate: SAML 2.0 |
| **Depends on** | Sprint 4 (signing keys/JWKS), Sprint 11 (identity linking) |
| **Closes** | Gap **#9** (SAML 2.0) |
| **Status** | ⬜ Not started |

**Why:** SAML 2.0 is the hard requirement that gates B2B/enterprise deals. Every serious competitor (Auth0, WorkOS, Okta, Keycloak, FusionAuth, Zitadel) ships it; we have **nothing** today. This is XL — budget for a conformance pass.

> **Effort note (⏳XL):** the roadmap rates SAML XL. Recommended split: **12a — SAML SP** (Qeet ID consumes enterprise IdPs: Okta/Azure AD/Google), **12b — SAML IdP** (Qeet ID acts as IdP to downstream apps). 12a unblocks the common "log in with our corp Okta" case first.

---

## Part A — 🧪 Test the newly-built feature (E2E)

> SAML doesn't exist yet, so Part A is a conformance/interop test plan for what 12 builds. Use a sandbox IdP (e.g. a free Okta/Azure AD dev tenant or `samltest.id`).

### 🧪 SCENARIO 12.1 — SP-initiated SSO (12a)
- **Steps:** configure a SAML connection (upload IdP metadata / paste URL); start login → redirect to IdP → POST assertion to our **ACS** URL.
- **Expect:** signature validated against IdP cert; assertion conditions (audience, notBefore/notOnOrAfter, recipient) enforced; user provisioned/linked (via Sprint 11 graph); session issued.
- **Pass:** [ ] our SP metadata + ACS/EntityID published [ ] valid assertion → session [ ] tampered/expired/wrong-audience assertion → rejected [ ] replay (same assertion ID) → rejected.

### 🧪 SCENARIO 12.2 — IdP-initiated SSO (12a)
- **Steps:** from the IdP dashboard, launch the app (unsolicited assertion to ACS).
- **Pass:** [ ] IdP-initiated flow accepted per config [ ] RelayState honored.

### 🧪 SCENARIO 12.3 — Qeet ID as IdP (12b)
- **Steps:** register a downstream SP (metadata); SP-initiated AuthnRequest → our SSO endpoint → signed assertion back.
- **Pass:** [ ] we issue valid signed assertions [ ] NameID format configurable [ ] attribute mapping works [ ] SLO (single logout) round-trips.

### 🧪 SCENARIO 12.4 — Attribute & group mapping
- **Pass:** [ ] IdP attributes map to user profile fields [ ] group claims map to Qeet ID groups/roles (ties to Sprint 2 group RBAC).

**Part A exit:** interop verified against ≥2 IdPs (Okta + Azure AD or samltest.id); added to a SAML conformance checklist.

---

## Part B — Build: SAML 2.0

### Design / changes
**Backend**
- New module `internal/saml/`:
  - **SP role (12a):** metadata endpoint, ACS (assertion consume), AuthnRequest builder, XML signature validation (xmldsig), assertion condition/replay checks, encrypted-assertion support, RelayState.
  - **IdP role (12b):** SSO endpoint (parse AuthnRequest), signed assertion issuance, SP registry, NameID + attribute mapping, **SLO** (single logout, front/back-channel).
  - Per-connection config (cert, entityID, endpoints, signing/encryption prefs, attribute map).
- Reuse Sprint-4 signing keys; XML canonicalization + signing library (vetted Go xmldsig).
- Migration `0037_saml.up.sql`: `saml.connections` (SP-side IdP configs), `saml.service_providers` (IdP-side SP registry), `saml.replay_ids`.
- Provisioning hooks: JIT user creation + linking via the identity graph (Sprint 11); group/role mapping.

**Frontend (admin)**
- **Connections → SAML**: replace the stub with a real connection editor (metadata upload/URL, cert, attribute mapping, test-connection button) for both SP and IdP roles. (This becomes self-serve in Sprint 14's Admin Portal.)

**Docs**
- `content/docs/authentication/saml.mdx` (SP + IdP setup, per-IdP guides for Okta/Azure AD/Google), security notes (signature/replay/audience).

### Acceptance criteria
- [ ] SP role: validated assertions from Okta + Azure AD produce sessions; all signature/condition/replay checks enforced (negative tests pass).
- [ ] IdP role: a downstream SP can SSO against Qeet ID with signed assertions + SLO.
- [ ] Encrypted assertions supported; RelayState preserved.
- [ ] Attribute → profile and group → role mapping works.
- [ ] No XML-signature-wrapping / comment-injection vulnerabilities (explicit security tests).

---

## Definition of Done
- [ ] Part A: conformance scenarios pass against ≥2 real IdPs + negative/security tests.
- [ ] Part B: `saml` module (SP + IdP), migrations, signature/replay security tests green.
- [ ] Admin SAML connection editor live (no stub).
- [ ] `authentication/saml.mdx` + per-IdP guides published.
- [ ] Roadmap: #9 checked; status ✅; changelog filled. (Record 12a/12b split dates if used.)

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
