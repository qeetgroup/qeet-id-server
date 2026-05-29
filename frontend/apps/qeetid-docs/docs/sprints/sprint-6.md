# Sprint 6 — Webhooks & GDPR E2E + 🚀 Consent & Preference Ledger + Portability (D6)

| | |
|---|---|
| **Window** | 2026-08-10 → 2026-08-21 (2 weeks) |
| **Theme** | Verify webhooks & GDPR erasure, then ship cryptographically-provable consent and clean data portability |
| **Depends on** | Sprints 1, 5 (consent receipts anchor into verifiable audit) |
| **Closes** | New differentiator **D6** |
| **Status** | ⬜ Not started |

**Why:** Privacy regimes (GDPR/CCPA/HIPAA-adjacent) demand **proof of consent** and **data portability**, but every CIAM bolts consent on as a checkbox with no audit-grade receipt, and "export my data" is usually a support task. We make consent a first-class, versioned, provable ledger and portability a one-call signed bundle.

---

## Part A — 🧪 Test existing features (E2E)

### 🧪 SCENARIO 6.1 — Webhook subscription + delivery
- **Steps:** `POST /v1/webhooks` subscribing to `user.created`; trigger by creating a user; use a local receiver (e.g. `webhook.site` or a tiny local server / Dev Inbox proxy).
- **Expect:** event delivered with `X-Webhook-Signature` (HMAC-SHA256) you can verify with the secret.
- **Pass:** [ ] delivery received [ ] HMAC verifies [ ] payload matches event.

### 🧪 SCENARIO 6.2 — Retry + DLQ
- **Steps:** point a webhook at an endpoint that returns 500; create events; watch retries; then inspect `GET /v1/admin/outbox/dlq`.
- **Expect:** exponential-backoff retries, then dead-letter after max attempts.
- **Pass:** [ ] retries with backoff [ ] lands in DLQ after exhaustion [ ] `GET /v1/webhooks/{id}/events` shows attempts.

### 🧪 SCENARIO 6.3 — GDPR erasure request + grace + purge
- **Steps:** `POST /v1/users/{u}/purge/request`; `GET /v1/tenants/{t}/purge/requests`; advance Test Clock past grace; let the purge worker run.
- **Expect:** during grace, request is cancellable (`/purge/cancel`); after grace, PII → `[REDACTED]` but audit references survive.
- **Pass:** [ ] grace period honored [ ] cancel works pre-grace [ ] PII redacted post-grace [ ] audit chain still verifies.

**Part A exit:** green + in Newman (`FOLDER=Webhooks`, `FOLDER=GDPR`).

---

## Part B — 🚀 D6: Consent & Preference Ledger + Portability Bundle

### The problem nobody solves well
- **Consent**: most platforms store a boolean "accepted ToS." Regulators increasingly want **consent receipts** (Kantara-style): *what* was consented to, *which version* of the policy, *when*, *how*, and proof it wasn't backdated. Auth0/Clerk/etc. don't ship this.
- **Preferences**: marketing/communication preferences are scattered across apps; there's no central, queryable, versioned preference store tied to identity.
- **Portability**: GDPR Art. 20 (data portability) is real, but "export my data" is a manual support job almost everywhere.

### Our solution
1. **Consent Ledger**: append-only, versioned consent records anchored into the **verifiable audit (D5)** so a consent receipt is tamper-evident and independently provable.
   - `POST /v1/users/{u}/consents` — record consent to a named, versioned **purpose** (e.g. `marketing-email v3`), capturing method/locale/IP/policy-hash.
   - `DELETE /v1/users/{u}/consents/{purpose}` — withdraw (also recorded).
   - `GET /v1/users/{u}/consents` — current state + full history; `GET …/{purpose}/receipt` — a signed consent receipt (verifiable via JWKS).
   - **Purpose registry** per tenant: define purposes, versions, and required-vs-optional.
2. **Preference Center**: `GET/PUT /v1/users/{u}/preferences` — structured, namespaced preferences (channels, frequency, topics), versioned, queryable; webhook on change so downstream apps stay in sync.
3. **Portability Bundle**: `POST /v1/users/{u}/export` → builds a **signed** archive (profile, identities, roles/groups, consents+receipts, preferences, audit slice) in a portable JSON schema; downloadable + verifiable. This also strengthens GDPR SAR (subject access request) handling.

### Design / changes
**Backend**
- New module `internal/consent/`: purpose registry, consent ledger, receipts (signed via #3 key), preference store.
- `internal/gdpr/`: add `export` (portability bundle) alongside existing erasure; bundle is signed + optionally anchored (D5).
- Migration `0031_consent.up.sql`: `consent.purposes`, `consent.records`, `consent.preferences`.
- Emit webhook events: `consent.granted`, `consent.withdrawn`, `preferences.updated`.

**Frontend**
- **Admin**: Purpose registry editor; per-user consent/preference viewer; "Generate portability bundle."
- **End-user/account**: a real **Preference Center** + "Download my data" (replaces stub data page).

**Docs**
- `content/docs/privacy/consent.mdx`, `content/docs/privacy/data-portability.mdx`.

### Acceptance criteria
- [ ] Recording consent produces a signed receipt verifiable via JWKS and anchored in the audit log.
- [ ] Withdrawing consent is recorded and reflected immediately in current-state queries.
- [ ] Policy version + hash are captured so you can prove *which* terms were consented to.
- [ ] Preference changes emit webhooks and are versioned.
- [ ] Portability bundle validates against the published JSON schema and its signature verifies.

### 🧪 How you test D6
1. Define purpose `marketing-email v1`; record consent for a user; fetch the receipt; verify its signature with the JWKS key.
2. Publish `v2` of the purpose; confirm the user's consent shows as "stale/needs re-consent."
3. Withdraw consent; confirm `consent.withdrawn` webhook fired (Dev Inbox/receiver) and current state flipped.
4. Generate the portability bundle; validate schema + signature; confirm it contains consents, preferences, roles, and an audit slice.

---

## Definition of Done
- [ ] Part A: scenarios pass + in Newman.
- [ ] Part B: consent module, preference store, signed receipts, portability bundle, webhooks, migrations, tests green.
- [ ] Admin purpose registry + per-user consent/preference UI + end-user Preference Center & data download live.
- [ ] `privacy/consent.mdx` + `privacy/data-portability.mdx` published.
- [ ] Roadmap: D6 noted; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
