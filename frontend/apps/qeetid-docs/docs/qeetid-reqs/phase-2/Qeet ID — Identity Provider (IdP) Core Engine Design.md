# Qeet ID — Identity Provider (IdP) Core Engine Design

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Identity Provider (IdP) Core Engine Design |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Backend Lead + Security Architect |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the design of the Qeet ID Identity Provider (IdP) Core Engine — the cryptographic, credential, and token-lifecycle heart of the platform. It addresses the build-vs-buy-vs-adopt decision (Keycloak / Ory / build), the token lifecycle, signing key management and rotation, session management, credential storage (passwords, passkeys, TOTP), refresh-token rotation and reuse detection, authorization-code single-use enforcement, account lockout, and cross-service authentication.

The IdP Core Engine is implemented across three services from [Microservices Decomposition](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md): **Auth Service** (ceremony orchestration), **Token Service** (cryptographic boundary, OAuth/OIDC endpoints, JWKS), and **MFA Service** (TOTP/SMS/WebAuthn). The Session Service supports lifecycle; the User Service supports credentials at rest.

The audience is the Backend Lead, Security Architect, every engineer on Team Auth, the CISO, and the Solution Architect. The document is referenced by [Authentication Flow Designs](Qeet ID%20%E2%80%94%20Authentication%20Flow%20Designs.md) for step-by-step flows.

---

### 3. Build vs Buy vs Adopt — IdP Base Layer

### 3.1 The Decision in Front of Us

Phase 1 left this as the most consequential open decision (Stakeholder findings; Compliance CG-06): does Qeet ID build the OAuth 2.0 / OIDC / SAML 2.0 implementation from scratch, adopt an open-source identity foundation (Keycloak, Ory) as the base layer, or buy a commercial component? The stakes are 3–4 months of MVP timeline, the long-term customisation ceiling, the license posture, and the maintenance burden over the platform's life.

This document **does not force a choice** — Phase 1 explicitly carries this forward. It presents the comparative analysis, the recommendation, and the fallback plan, leaving the formal close to the ADR-011 review (Phase 2 Week 4, gated on the Legal license audit).

### 3.2 Options Considered

#### Option A — Keycloak as Base Layer

Open-source IdP from Red Hat. Implements OAuth 2.0, OIDC, SAML 2.0, SCIM (via SCIM-for-Keycloak extension), WebAuthn, and a customisable admin UI. Apache 2.0 licensed.

#### Option B — Ory Stack as Base Layer

A composable set of services: Ory Hydra (OAuth 2.0 / OIDC), Ory Kratos (identity & credential management), Ory Keto (authorization — Zanzibar-style), Ory Oathkeeper (zero-trust proxy). Apache 2.0 licensed.

#### Option C — Build From Scratch

Implement OAuth 2.0, OIDC, SAML 2.0, SCIM, WebAuthn natively in Qeet ID code, leveraging well-maintained protocol libraries (jose, panva/node-oidc-provider as a reference, go-jose, fosite, samlify, simplesamlphp etc.) but composing them ourselves.

### 3.3 Comparative Analysis

| Criterion | Keycloak | Ory Stack | Build From Scratch |
| --- | --- | --- | --- |
| License | Apache 2.0 | Apache 2.0 | n/a |
| OAuth 2.0 / OIDC conformance | OpenID Foundation certified | Hydra: OpenID Foundation certified | Must pursue certification independently |
| SAML 2.0 | Built-in, mature | Not part of Ory stack — would need separate component | Must implement |
| SCIM 2.0 | Via extension (third-party) | Kratos has provisioning primitives but not full SCIM | Must implement |
| WebAuthn / FIDO2 | Built-in (Level 2) | Kratos supports | Must implement using a vetted library |
| Multi-tenancy model | Realms (one realm per tenant) — works up to several thousand realms; degrades beyond | No native multi-tenancy — would model tenants ourselves | We design from scratch — optimal for our scale targets |
| MVP timeline impact | Save ~3–4 months on auth core; spend time on multi-tenancy retrofit | Save ~2–3 months on OAuth/OIDC; build SAML, SCIM, multi-tenancy ourselves | Full build — longest path |
| Customisation ceiling | High but path-dependent — opinionated; deep customisation requires Java SPI work | Higher — small, composable services; replace components freely | Highest — every choice is ours |
| Operational complexity | Java/JVM; well-known ops profile | Polyglot small services; modern ops profile | Whatever we choose |
| Long-term maintenance burden | Track Keycloak upgrades (twice yearly); fork risk if customisations diverge | Track each Ory service independently | Track upstream protocol libraries; full responsibility for protocol correctness |
| Security posture | Mature; large user base; known CVEs disclosed and patched promptly | Mature on Hydra/Kratos; smaller user base than Keycloak | We are responsible for finding vulnerabilities first |
| Migration path away | Hard once realms model is entrenched | Easier — service-by-service replacement | n/a (we own it) |
| Multi-tenancy at 100,000 tenants | Realms degrade well past mid-tens-of-thousands; would need significant sharding work | Build-our-own tenancy → built for our scale | Built for our scale |
| Federation depth (Entra, Okta, etc.) | Native, well-tested | Native via Hydra | We must build & test |
| Admin UI | Built-in; could be hidden behind Qeet ID admin dash | None — Qeet ID builds | Qeet ID builds |

### 3.4 Recommendation

**Recommended option: Option B — Ory Stack as Base Layer** with the following posture:

- **Adopt Ory Hydra** for OAuth 2.0 / OIDC authorisation server (token issuance, introspection, revocation, JWKS).
- **Build the SAML, SCIM, and multi-tenancy layers natively** — these are areas where neither Keycloak nor Ory match our requirements at MVP scale.
- **Build the User / Credential layer natively** — we own the data model, residency, and credential storage scheme. Ory Kratos is not adopted; its model would constrain our schema.
- **Build Qeet ID Access (RBAC) natively** at MVP; consider **Ory Keto** for FGA in v2.0.

**Rationale:**

1. Hydra is a focused OAuth/OIDC server with strict conformance and small surface; we save protocol work without inheriting an opinionated user model.
2. We retain full control of multi-tenancy, residency, and credential storage — the areas where stakeholder requirements diverge most from either open-source default.
3. The Apache 2.0 license is permissive — Legal confirmation pending (CG-06).
4. The migration cost away from Hydra is bounded: it speaks OAuth/OIDC, our customers do not depend on its internals.

**Fallback plan (in priority order):**

1. If Ory Hydra falls out of license/legal review → adopt Keycloak with multi-tenancy retrofit budget acknowledged in the timeline.
2. If Keycloak also fails → build-from-scratch with a 3-month timeline slip flagged to the CEO.

This recommendation is formalised as **ADR-011 (Status: Proposed)** in [Architecture Decision Records](Qeet ID%20%E2%80%94%20Architecture%20Decision%20Records%20%28ADRs%29.md) and tracked in [Open-Decisions-Register.md](Open-Decisions-Register.md). Decision deadline: Phase 2 Week 4. Owners: Solution Architect + CTO + Legal Counsel.

### 3.5 What "Adopting Hydra" Means in Practice

If ADR-011 lands on Ory Hydra:

- Hydra runs as a stateless deployment in the Qeet ID VPC, configured by Qeet ID Token Service.
- Hydra's persistence is **redirected to Qeet ID's PostgreSQL** (Hydra supports it); the operational DB is in our control.
- Qeet ID's Token Service is **the public OAuth API surface** — the customer never talks to Hydra directly. Token Service authenticates, decides tenant-policy gates, then delegates the cryptographic protocol mechanics to Hydra.
- Hydra's signing-key store is replaced by Qeet ID's KMS-managed JWKS so that key custody stays with Qeet ID.
- Hydra version pinning + upgrade rehearsal per release; CVE patch SLA inherited from Compliance IN-10.

If ADR-011 lands on **build-from-scratch**:

- Token Service implements OAuth 2.0 + OIDC directly against well-maintained protocol libraries (`fosite` in Go or `node-oidc-provider` in Node — owner team's language choice from OQ-MS-04).
- The rest of §4–§11 of this document is unchanged — the lifecycle, key management, session, credential, and rotation designs are platform-level, not library-level.

The remainder of this document is written **library-agnostic**: every constraint and policy applies regardless of which base layer is adopted.

---

### 4. Token Lifecycle Management

The Token Service is the cryptographic boundary of Qeet ID. The token lifecycle is the most security-sensitive flow on the platform.

### 4.1 Token Types

Defined in [Protocol Requirements §4.5](../phase-1/Qeet%20ID%20%E2%80%94%20Protocol%20Requirements%20Document.md). The IdP Core implementation honours those choices verbatim:

| Token | Format | Lifetime | Signing | Storage |
| --- | --- | --- | --- | --- |
| Access token | JWT (RS256 / ES256) | 15 min default; 5 min–1 h configurable | KMS-backed asymmetric | Not stored after issuance |
| ID token | JWT (RS256 / ES256) | 1 h | Same as access | Not stored |
| Refresh token | Opaque 256-bit random, prefixed `qf_rt_*` | 30 d default; 1 d–90 d configurable | HMAC-SHA256 reference stored | HMAC hash + metadata in Postgres |
| Authorization code | Opaque 256-bit random, prefixed `qf_ac_*` | 60 s | Single-use marker in Postgres | HMAC hash + metadata; deleted on use |
| Client credentials access token | JWT (RS256 / ES256) | 1 h default; 5 min–24 h configurable | Same as user access | Not stored |
| Magic-link / email-OTP JWT | JWT (RS256) | 15 min | RS256 | Not stored; single-use enforced via nonce table |

### 4.2 Token Issuance State Machine

```
   ┌─────────────────┐    valid auth         ┌─────────────────┐
   │  Auth Service   ├──────────────────────▶│ Token Service    │
   │                 │  signed assertion     │                  │
   └─────────────────┘                       │                  │
                                             │  1. validate     │
                                             │     assertion    │
                                             │  2. claim build  │
                                             │  3. sign access  │
                                             │  4. issue refresh│
                                             │  5. record       │
                                             │     refresh      │
                                             │     hash         │
                                             │  6. emit audit   │
                                             └──────────┬───────┘
                                                        ▼
                                          ┌──────────────────────┐
                                          │  RP / Customer App   │
                                          └──────────────────────┘
```

The internal "authentication assertion" is a short-lived (30 s) signed token produced by Auth Service after successful credential verification (password + MFA, passkey, social IdP, SAML, magic link). Token Service verifies the assertion signature using an internal key pair separate from the public JWT signing keys, then proceeds. Auth Service never has access to user-facing signing keys; only Token Service does.

### 4.3 Claim Composition

The Token Service composes the JWT payload from:

- `iss`, `aud`, `exp`, `iat`, `sub`, `nonce`, `auth_time`, `acr`, `amr`, `azp`, `at_hash`, `c_hash` — per OIDC standard (Protocol §5.4)
- `qeetify/org_id`, `qeetify/roles`, `qeetify/permissions`, `qeetify/plan`, `qeetify/mfa_enrolled`, `qeetify/passkey_enrolled`, `qeetify/user_id` — Qeet ID custom (Protocol §5.6)
- `scope` — granted scopes from the authorization request, intersected with the user's permissions
- `sid` — session identifier for back-channel logout (OIDC BC Logout 1.0, post-launch)

Claims that come from other services (roles, permissions) are fetched at token-issue time from cached views (Redis), with a synchronous fallback to RBAC Service if the cache is stale. RBAC misses or timeouts produce a degraded token (empty roles/permissions) with an audit flag — not a token-issuance failure — because authentication must not be blocked by authorization-system unavailability (per HLSA P-06 / NFR TO-01 nuance; we degrade authorization, never authentication).

### 4.4 Token Validation (at Resource Servers and Internal Consumers)

Resource servers — including Qeet ID-internal services validating customer-issued tokens — follow [Protocol §9.3](../phase-1/Qeet%20ID%20%E2%80%94%20Protocol%20Requirements%20Document.md):

1. Fetch JWKS at `jwks_uri` (cache 1 h, NFR CA-01).
2. Verify signature with key matching `kid`.
3. Confirm `alg` is `RS256` or `ES256` — reject anything else.
4. Validate `iss`, `aud`, `exp`, `nbf`, scope, subject.
5. For high-sensitivity operations, query the introspection endpoint for revocation state.

### 4.5 Token Revocation

Three revocation sources:

- **Customer-initiated:** `/oauth/revoke` endpoint (RFC 7009).
- **Session-driven:** user logout or SCIM `active=false` → Session Service emits `auth.session.revoked` on Kafka; Token Service revokes all bound refresh tokens within 60 s (NFR DI-03).
- **Security-driven:** refresh-token reuse detection → revoke entire authorization chain (NFR OS-07).

Revoked tokens are recorded in PostgreSQL `revocation_list`. Revocation propagation to access tokens is bounded by their natural 15-minute lifetime; high-sensitivity resource servers should call introspection rather than relying on JWT expiry.

A **Redis bloom filter** caches revoked refresh-token hashes (NFR CA-07) for fast negative lookups. Bloom filter false positives fall through to the source-of-truth Postgres check.

---

### 5. Signing Key Management & Rotation

### 5.1 Key Hierarchy

```
                   ┌────────────────────────────────┐
                   │            KMS (AWS)           │
                   │  - Root KEK (Customer Master   │
                   │    Key, HSM-backed)            │
                   └──────────────┬─────────────────┘
                                  │ wrap / unwrap
                                  ▼
   ┌──────────────────────────────────────────────────────────┐
   │            Qeet ID Key Store (Postgres + KMS refs)       │
   │                                                          │
   │   - JWT signing keys (RSA-2048 / ECDSA P-256)            │
   │     - kid, alg, status (active|previous|retired)         │
   │     - private key wrapped by KEK                         │
   │   - Internal service token signing keys                  │
   │   - Magic-link signing keys                              │
   │   - Per-tenant field-encryption data keys (envelope)     │
   └──────────────────────────────────────────────────────────┘
```

The platform never holds an unwrapped private signing key on disk. At service start, the Token Service fetches the wrapped key blob, asks KMS to unwrap it, and holds the unwrapped material in memory only.

### 5.2 Key Algorithms

- **JWT signing — public-facing tokens:** RS256 (RSA-2048) and ES256 (ECDSA P-256). Both algorithms published in JWKS; clients may verify against either. ES256 is preferred for new tenants for performance; RS256 retained for compatibility with older client libraries (Protocol JT-11, JW-02).
- **Internal service tokens:** ES256 (separate keys from public-facing).
- **Magic-link signing:** RS256 (separate key from public-facing tokens).
- **HMAC for refresh-token / API-key hashing:** HMAC-SHA256 — keyed hash with a per-tenant or global pepper (the pepper is itself in KMS; we never store unsalted hashes).

### 5.3 Key Rotation

| Key Class | Rotation Cadence | Retired-Key Retention |
| --- | --- | --- |
| Public JWT signing (RS256 / ES256) | 90 days (Protocol JW-05) | 24 h after rotation (Protocol JW-07) |
| Internal service token signing | 30 days | 1 h after rotation |
| Magic-link signing | 90 days | 15 min after rotation (link TTL) |
| Field-encryption data keys (envelope) | 365 days | All historical keys retained for read; new writes use current key |
| HMAC pepper (refresh tokens, API keys) | Manual on incident; default infinite | n/a — rotation requires re-hash of all tokens (expensive) |

### 5.4 Rotation Flow (Public JWT Keys)

1. Background worker schedules rotation 7 days before expiry of current key.
2. New key generated inside KMS; key blob wrapped, stored in Postgres with status `pending`.
3. JWKS published list updated to include both current + pending keys.
4. After 1 h propagation window, status flips to `pending` → `current`; old key → `previous`.
5. After 24 h, `previous` → `retired`; JWKS removes it.
6. Audit event `audit.security.key_rotated` emitted at every transition.

The 24-hour retired-key retention is the critical correctness property: tokens issued in the moments before rotation must validate for their full 15-minute lifetime even after rotation. The 24-hour window absorbs token lifetime + clock skew + JWKS cache TTL.

### 5.5 Compromise Response

If a signing key is suspected compromised:

1. Operator triggers emergency rotation (CLI runbook).
2. New key promoted; old key immediately retired (skip 24-hour window).
3. All access tokens issued before the rotation are no longer valid; relying parties forced to re-fetch JWKS.
4. Refresh tokens remain valid (they are opaque, not signed by this key) — but session-binding identifies impacted users for forced re-authentication.
5. Customer security advisory issued per Protocol PV-04.

---

### 6. Session Management Design

### 6.1 Session Model

A *session* is the logical artefact of an authenticated user-agent. It is created when authentication succeeds and lives until logout, expiry, or revocation.

A session is **not** a token. Tokens are short-lived credentials issued *within* a session.

```
   ┌──────────────────────────────────────────────────────────┐
   │                       Session                            │
   │                                                          │
   │   session_id (UUID v7)                                   │
   │   tenant_id                                              │
   │   user_id                                                │
   │   client_id (the OAuth client that initiated)            │
   │   acr (authentication strength)                          │
   │   amr (methods used)                                     │
   │   created_at, last_activity_at, absolute_expires_at      │
   │   idle_timeout_seconds, absolute_timeout_seconds         │
   │   ip_address, user_agent, device_fingerprint             │
   │   geo (country, region, city)                            │
   │   revoked (bool), revoked_reason, revoked_at             │
   └──────────────────────────────────────────────────────────┘
                  ▲                          │
                  │ 1                        │ many
                  │                          ▼
   ┌──────────────────────┐         ┌─────────────────────────┐
   │  Refresh tokens      │         │  Access tokens          │
   │  (bound to session)  │         │  (transient; not stored)│
   └──────────────────────┘         └─────────────────────────┘
```

### 6.2 Session Storage

Sessions are written to PostgreSQL (system of record) and cached in Redis (hot reads). Read path resolves from Redis first, falls back to Postgres, repopulates Redis on miss. Writes go to Postgres then update Redis synchronously.

This split satisfies NFR DU-04 (sessions 99.99% durable; acceptable to lose on cache failure with database fallback).

### 6.3 Session Timeouts

Defaults aligned to Compliance AS-07:

- **Absolute timeout:** 24 hours.
- **Idle timeout:** 30 minutes (configurable per tenant).

Idle timeout is enforced at the Session Service: every token introspection or refresh-token use updates `last_activity_at`. If the gap exceeds `idle_timeout_seconds`, the session is revoked and the token request fails with `invalid_grant`.

### 6.4 Concurrent Session Control

A tenant can configure a maximum number of concurrent sessions per user. Default at MVP: unlimited (Compliance AS-08 allows configurable). Enforcement is at session creation: if creating a new session would exceed the configured limit, the oldest session is revoked (LRU).

Users can view their active sessions and revoke individual sessions from the account portal — the API is `GET /v1/sessions` and `DELETE /v1/sessions/{id}`.

### 6.5 Session Binding

Each session is bound to:

- The OAuth `client_id` that initiated authentication.
- The IP address at authentication time (recorded; not strictly enforced on every request).
- The user-agent fingerprint (recorded).
- The device identifier (passkey AAGUID or browser cookie fingerprint).

Binding violations (e.g., refresh token presented from a wildly different geo and device) are flagged to the Anomaly Service for step-up triggering. They do not auto-revoke at MVP — false positives would frustrate legitimate users on mobile networks; step-up is the trade-off. Auto-revocation moves to v1.5 once we have production data to tune thresholds.

---

### 7. Credential Storage Design

The MFA Service and User Service together own credential storage. The cryptographic boundary is strict: no other service ever sees a credential plaintext.

### 7.1 Password Storage

**Algorithm:** Argon2id (Compliance EN-02; NFR SE-07).

**Parameters at MVP:**

| Parameter | Value | Notes |
| --- | --- | --- |
| Memory cost (m) | 64 MiB | NFR SE-07 minimum |
| Iterations (t) | 3 | NFR SE-07 minimum |
| Parallelism (p) | 4 | NFR SE-07 minimum |
| Salt | 16 bytes random per password | Generated by CSPRNG |
| Output length | 32 bytes |  |

Encoded result stored in the `users.password_hash` column as the standard Argon2id PHC string. We re-tune parameters annually against current hardware (target verification cost ~150 ms on production CPU class).

**Pepper:** A platform-wide pepper held in KMS is HMAC-applied to the password before Argon2id. Pepper rotation requires re-hashing on next successful login.

**Password policy:**

- Minimum 8 characters (Compliance AS-05); upper limit ≥ 64.
- Compromised-password check via HIBP k-anonymity at registration, change, and login (NIST SP 800-63B aligned; Compliance AS-04).
- No composition rules forced — NIST guidance prefers length over complexity.
- Tenant can configure stricter (length, banned words, periodic change) but cannot weaken below the platform minimum.

**Migration:** if a future Argon2id parameter increase is adopted, the next successful login re-hashes the password with the new parameters.

### 7.2 Passkey Credential Storage

WebAuthn credentials are stored per [Protocol §8.3](../phase-1/Qeet%20ID%20%E2%80%94%20Protocol%20Requirements%20Document.md):

```
   passkey_credentials
   ─────────────────────────────────────────────
   id (UUID, internal)
   user_id
   tenant_id
   credential_id (bytes, indexed)
   public_key_cose (bytes — COSE format)
   aaguid (bytes)
   sign_count (int)
   transports (array — usb, nfc, ble, internal, hybrid)
   backup_eligible (bool)
   backup_state (bool)
   attestation_format (text)
   attestation_statement (bytes, optional, retained for trust evaluation)
   nickname (text — user-set)
   created_at, last_used_at, revoked_at
```

Public keys are stored unencrypted — they are public. The credential ID is indexed for fast lookup. Sign-count enforcement follows Protocol WA-07 / WA-08 (synced passkeys may have sign_count 0).

### 7.3 TOTP Seed Storage

TOTP seeds are 160-bit random secrets (Protocol TP-05). They are sensitive — anyone with the seed can produce valid OTP codes — so they are encrypted at rest with field-level encryption:

- Per-tenant data encryption key (DEK), wrapped by the platform KEK in KMS.
- Encryption: AES-256-GCM.
- Stored ciphertext alongside an `enc_version` marker for future algorithm migration.
- Decryption only inside MFA Service at challenge time, in memory.

Backup codes are stored as bcrypt hashes (Protocol TP-09) so they verify in constant time and resist offline brute force.

### 7.4 Sensitive Field-Level Encryption Scheme

The same envelope-encryption scheme is used for:

- TOTP seeds
- User email (encrypted but indexed via a deterministic search hash; see [Database Design](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md))
- User phone number (E.164 + deterministic search hash)
- Billing name and address fields
- Audit log PII redacted fields
- Refresh-token "device fingerprint" payloads

```
   plaintext
       │
       ▼
   AES-256-GCM(plaintext, DEK_tenant) → ciphertext + nonce + tag
       │
       ▼
   stored {ciphertext, nonce, tag, dek_id, enc_version}
       │
   DEK_tenant is wrapped:
       KMS.Encrypt(DEK_tenant, KEK_root) → wrapped_dek
       │ stored in tenant_dek table
```

A DEK is unwrapped via KMS once and then cached in-process for a bounded window (15 min). A DEK rotation re-encrypts the affected DEK row but not the data rows — data rows continue to reference the previous DEK by `dek_id` for read; new writes use the new DEK.

---

### 8. Account Lockout & Anti-Brute-Force Design

### 8.1 Lockout Policy

- 5 failed login attempts → 15-minute account lock (Compliance AS-03).
- Exponential backoff after lock release: each subsequent failure doubles the lock duration up to 24 hours.
- CAPTCHA challenge inserted from the 3rd failed attempt of a session (hCaptcha or reCAPTCHA — Feature scope).
- Lockout state per `(tenant_id, user_id)` *and* per `(ip_address)` separately — both counters tick; either threshold trips.

### 8.2 Anti-Enumeration

Login failure responses do not distinguish "user not found" from "wrong password" — both return the generic `invalid_credentials` error and the same timing characteristic. The Auth Service uses a constant-time path: if the user does not exist, it still computes a dummy Argon2id verification against a dummy hash so that timing does not leak.

### 8.3 Credential Stuffing Mitigation

- HIBP password check at every login (Compliance AS-04) — blocks known-compromised passwords at the source.
- Rate limiting per IP across the platform (Guard Service; NFR RL-02).
- Bot detection at Cloudflare edge; bot-scored requests routed to CAPTCHA.
- Future (v1.1): adaptive risk scoring via Anomaly Service.

### 8.4 Brute-Force Detection at Refresh-Token Layer

Refresh-token reuse is the principal brute-force surface beyond passwords. Reuse detection (§4 above; §9 below) revokes the entire authorization chain — not just the token in question — so a compromised refresh token cannot be brute-forced through retry.

---

### 9. Multi-Factor Enrolment & Verification Flows

### 9.1 Enrolment

| Factor | Enrolment | Required at MVP |
| --- | --- | --- |
| TOTP | QR code provisioning (`otpauth://...` URI); user-supplied verification OTP confirms enrolment; backup codes generated and shown once | Yes |
| SMS OTP | Phone number verification (challenge + OTP); phone number registered for future challenges | Yes |
| Email OTP | Pre-verified email (account email by default); explicit opt-in for second-factor use | Yes |
| WebAuthn / passkey | Standard WebAuthn registration ceremony; multi-passkey per user up to 10 (Protocol PK-06) | Yes — primary factor |

Enrolment writes happen in the MFA Service. The User Service maintains an aggregate "MFA enrolled?" flag that becomes the `qeetify/mfa_enrolled` claim.

### 9.2 Verification

Verification is initiated by Auth Service mid-flow. Auth Service computes the *required factor strength* by:

1. Looking up the authentication-policy of the tenant (Tenant Service).
2. Looking up the user's enrolled factors (MFA Service).
3. Considering the requested ACR (`acr_values` in the OAuth authorization request).
4. Applying step-up rules from the resource server.

Auth Service then asks MFA Service to issue a challenge for the chosen factor; the user responds; MFA Service verifies; Auth Service composes the authentication assertion with the satisfied factors recorded in `amr`.

### 9.3 Step-Up Authentication

Step-up is requested by a resource server through the `acr_values` parameter on the authorization request (Protocol §5.7). The user's current session ACR is compared:

- If the session ACR satisfies the required ACR, no step-up is performed.
- Otherwise the user is re-prompted for additional factors to reach the required ACR.

The session ACR is updated on successful step-up and carried forward.

---

### 10. Refresh Token Rotation & Reuse Detection

### 10.1 Rotation

Every successful refresh-token use issues a new refresh token and invalidates the presented token *atomically* in PostgreSQL (Protocol OS-06). The new token is returned alongside a new access token.

```
   POST /oauth/token grant_type=refresh_token refresh_token=qf_rt_abc...
                          │
                          ▼
                  Token Service
                          │
                  BEGIN TRANSACTION
                  - Look up refresh_token by HMAC hash
                  - Check NOT revoked, NOT used_at set, exp valid, session active
                  - Mark presented token used_at = now() (NOT delete — needed for reuse detect)
                  - Generate new refresh token
                  - Insert new refresh token with parent_id = presented token id
                  COMMIT
                          │
                          ▼
                  Issue new access token + new refresh token
```

The presented token is **marked**, not deleted. This is what enables reuse detection.

### 10.2 Reuse Detection

If a refresh token is presented and its `used_at` is already set:

1. **All refresh tokens in the same authorization chain are revoked** (the original token and every descendant). Chain is traced by walking `parent_id` to root and then forward through the children graph.
2. The session is revoked (`auth.session.revoked` emitted).
3. A security audit event `audit.security.refresh_token_reuse_detected` is emitted with severity HIGH; PagerDuty alert fired.
4. The user is forced to re-authenticate; if the tenant has anomaly-triggered MFA, the next login requires step-up.

The presumption is that reuse means either a buggy client (legitimate but should be investigated) or a credential interception attack. The behaviour is identical in both cases — we cannot tell them apart at the moment of detection.

### 10.3 Production Safety

Initial 30 days of production: reuse detection **alerts** but does not auto-revoke; we collect baseline false-positive rate from real customer SDKs. After 30 days, auto-revoke is enabled. This caveat is the live-by-rule from AR-08.

---

### 11. Authorization Code Single-Use Enforcement

Authorization codes (Protocol OS-04) are:

- 256-bit cryptographically random, prefixed `qf_ac_`.
- HMAC-SHA256 hashed for storage.
- Stored in PostgreSQL `authorization_codes` with `client_id`, `redirect_uri`, `scope`, `code_challenge`, `tenant_id`, `created_at`, `expires_at`, `consumed_at`.
- Lifetime 60 s (Protocol OS-05).

The `/oauth/token` exchange transactionally:

1. Looks up the code by hash.
2. Verifies it is not consumed (`consumed_at IS NULL`).
3. Verifies it is not expired.
4. Verifies `client_id` matches the authenticated client.
5. Verifies `redirect_uri` matches exactly.
6. Verifies the PKCE `code_verifier` against the stored `code_challenge` (Protocol OS-01).
7. Atomically sets `consumed_at = now()` and proceeds to token issuance.

Step 7 uses `UPDATE ... WHERE consumed_at IS NULL` and checks `rows_affected = 1`. A second concurrent attempt sees `rows_affected = 0` and fails with `invalid_grant`. Also: a successful exchange where any later validation fails still marks the code consumed — never re-issue a token from a code that has been processed even once.

If a consumed code is re-presented, this is treated as a *code-interception signal* (Protocol EH-04):

- Revoke all tokens issued from that code.
- Emit `audit.security.authorization_code_reuse_detected`.
- Alert.

---

### 12. Cross-Service Authentication (mTLS Between Services)

Every internal call inside the Qeet ID VPC is mTLS — both sides present X.509 certificates issued by the Istio mesh CA. Service identity is derived from the Kubernetes ServiceAccount / Istio identity (`spiffe://qeetify.svc/ns/{ns}/sa/{sa}` form, anticipating SPIFFE v2.0).

In addition to mTLS, internal requests carry a **short-lived service token** in an `X-Qeetify-Service-Token` header:

- Issued by an internal token service (or the mesh itself) every 5 minutes.
- ES256-signed with internal keys (separate from public JWT keys; §5).
- Claims: `svc` (caller service id), `tenant_id` (propagated from inbound), `request_id` (correlation), `exp`.
- Validated by every receiver; rejected if missing, expired, or signed by an unknown key.

This double-layer (mTLS for transport + service token for application-layer identity propagation) is the Zero Trust posture: the network layer confirms *who is on the wire*; the application layer confirms *what claim they make about the request*. Detail is in [Security Architecture](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md).

---

### 13. Engine-Level Failure Modes & Degradation

| Scenario | Behaviour | Rationale |
| --- | --- | --- |
| RBAC Service unreachable when issuing token | Token issued with empty `qeetify/roles`/`qeetify/permissions`; `degraded` audit flag | Authorization is fail-closed at the resource server but token issuance must not fail |
| Tenant Service unreachable | Token issuance fails with `temporarily_unavailable` | Tenant config is on the critical path — cannot compose a correct token without it |
| KMS unavailable | New token issuance fails; existing JWKS still verifiable; refresh rotations stop | Operator must restore KMS; this is a P1 incident |
| MFA Service unavailable mid-challenge | User shown retry; if no MFA challenge can be issued for ≥ 60 s, fallback factor (if enrolled) prompted | NFR §5.5 graceful degradation |
| Audit log Kafka backpressure | Audit events buffered in service memory bounded queue; if queue full, request fails (NFR SL-08: no acceptable loss) | Audit completeness is a hard SLO |
| Postgres primary failover | All Token Service writes pause for ≤ 60 s during failover (NFR FO-04); read-only operations continue from replicas | Existing tokens still validate via JWKS during the outage |

---

### 14. Open Decisions Carried From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OQ-IDP-01 | Final base-layer choice (Hydra vs Keycloak vs Build) — ADR-011 | SA + CTO + Legal | Phase 2 Week 4 |
| OQ-IDP-02 | RS256 default vs ES256 default for new tenants | Security Architect | Phase 2 close |
| OQ-IDP-03 | Refresh-token rotation reuse-detect auto-revoke enable date | Backend Lead | 30 days post-launch |
| OQ-IDP-04 | Argon2id parameter re-tune review cadence (annual?) | Security Architect | Phase 2 close |
| OQ-IDP-05 | Default OAuth client_id token endpoint auth method order (private_key_jwt vs client_secret_post) | API Designer + SA | Phase 2 close |

---

### 15. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Backend Engineering Lead |  |  |  |
| Security Architect |  |  |  |
| Solution Architect |  |  |  |
| CISO |  |  |  |
| CTO |  |  |  |
| Legal Counsel (ADR-011 license posture) |  |  |  |
| QA Lead |  |  |  |

---

*This document is version controlled. The IdP Core Engine Design must be reviewed when the base-layer decision (ADR-011) closes, when key rotation cadence or algorithm changes, when a new credential type is added, when reuse-detection auto-revoke is enabled, or when Argon2id parameters are re-tuned. Any deviation during implementation requires an ADR reviewed by the Security Architect and CISO.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
