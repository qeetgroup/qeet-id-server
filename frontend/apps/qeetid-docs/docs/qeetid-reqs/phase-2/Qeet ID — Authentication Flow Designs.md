# Qeet ID — Authentication Flow Designs

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Authentication Flow Designs |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Solution Architect |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document describes — in step-by-step sequence form — every authentication and federation flow Qeet ID must implement at MVP. Each flow is presented as an ASCII sequence diagram with a numbered narrative, the components touched, the error paths, the security checkpoints, and the latency-budget allocation drawn from [NFR §4.4](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md).

Flows in scope (all P1 — Launch Blockers):

1. OAuth 2.0 Authorization Code + PKCE
2. OIDC Authentication with ID token issuance
3. SAML 2.0 SP-Initiated SSO
4. SAML 2.0 IdP-Initiated SSO
5. SAML Single Logout (SLO)
6. SCIM 2.0 User Provisioning
7. SCIM 2.0 User Deprovisioning (`active=false` < 60 s propagation)
8. Passkey Registration (WebAuthn)
9. Passkey Authentication
10. Cross-Device Passkey (Hybrid Transport / QR)
11. Email + Password Login + MFA
12. Magic Link / Email OTP
13. TOTP MFA Challenge
14. SMS OTP MFA Challenge
15. Step-Up Authentication
16. Token Refresh with Rotation
17. Client Credentials (M2M)
18. Account Recovery

This document depends on [IdP Core Engine Design](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md) for the lifecycle and credential-storage decisions, [Microservices Decomposition](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md) for service identities, and [Protocol Requirements](../phase-1/Qeet%20ID%20%E2%80%94%20Protocol%20Requirements%20Document.md) for the conformance constraints.

Notation in sequences:
- `RP` = Relying Party (customer application).
- `UA` = User-Agent (browser, native app, or SDK).
- `EG` = Edge (Cloudflare + ALB + API Gateway).
- `Auth` = Auth Service.
- `Token` = Token Service.
- `MFA` = MFA Service.
- `User` = User Service.
- `Tenant` = Tenant Service.
- `RBAC` = RBAC Service.
- `Session` = Session Service.
- `Guard` = Guard Service.
- `SAML` = SAML Service.
- `SCIM` = SCIM Service.
- `Notif` = Notification Service.
- `IdP` = External Identity Provider.
- `K` = Kafka.
- `DB` = PostgreSQL.
- `R` = Redis.

---

### 3. OAuth 2.0 Authorization Code + PKCE

**Trigger.** End user clicks "Log in" in RP. RP must use Authorization Code + PKCE — public clients have no other option (Protocol OS-01, PG-01, PG-02).

**Latency budget.** Authorization redirect ≤ 150 ms p95 (PF-01). Token exchange ≤ 200 ms p95 (PF-02). End-to-end first-time login ≤ 800 ms p95 (§4.4).

```
   UA          RP           EG          Auth        Token       User       Tenant    Session    Guard     DB / R
    │           │            │           │           │           │           │         │         │         │
    │  click    │            │           │           │           │           │         │         │         │
    ├──login──▶ │            │           │           │           │           │         │         │         │
    │           │ build      │           │           │           │           │         │         │         │
    │           │ /authorize │           │           │           │           │         │         │         │
    │           │ URL + PKCE │           │           │           │           │         │         │         │
    │ 302 ──────┤            │           │           │           │           │         │         │         │
    │           │            │           │           │           │           │         │         │         │
    │ GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid profile&
    │   state=xyz&code_challenge=ABC&code_challenge_method=S256                       │         │         │
    ├──────────────────────▶ │           │           │           │           │         │         │         │
    │           │            │ rate /    │           │           │           │         │         │         │
    │           │            │ bot check │           │           │           │         │         │         │
    │           │            ├──check───▶│           │           │           │         │         │         │
    │           │            │           │           │           │           │         │         │         │
    │           │            │ ┌─Validate client_id, redirect_uri (exact match), scopes              │     │
    │           │            │ │ Validate code_challenge_method == S256 (Protocol DC-14)            │     │
    │           │            │ │ Build login session (transient) and redirect to hosted login      │     │
    │ 302 to hosted login pages ──────────────────────────────────────────────────────────────────────────┤
    │ Render login page (passkey-first; email field has autofill conditional UI)                    │     │
    │                                                                                                 │     │
    │ User enters email; selects passkey OR password+MFA                                              │     │
    │ (see Flow 9 — Passkey Authentication, or Flow 11 — Email + Password + MFA)                      │     │
    │                                                                                                 │     │
    │ ON SUCCESS Auth Service emits internal authentication assertion to Token Service:               │     │
    │                                                                                                 │     │
    ├─POST /internal/assertion (svc-auth → svc-token, mTLS + service token)───────────────────────────▶     │
    │                                                                                                 │     │
    │ Token Service:                                                                                  │     │
    │   1. Verify assertion signature (ES256, internal key)                                           │     │
    │   2. Generate authorization_code (256-bit random; HMAC-SHA256 hash stored)                     │     │
    │   3. Insert authorization_codes row {tenant_id, user_id, client_id, redirect_uri, code_challenge,│    │
    │      scopes, exp = now+60s, consumed_at = NULL}                                                │     │
    │   4. Emit audit.token.code_issued                                                              │     │
    │   5. Return 302 to redirect_uri?code=...&state=xyz                                             │     │
    │                                                                                                 │     │
    │ 302 to redirect_uri?code=...&state=xyz                                                          │     │
    ◀────────────────────────────────────────────────────────────────────────────────────────────────┤     │
    │ RP receives code in callback. Validates state matches the one it sent.                          │     │
    │           │            │           │           │           │           │         │         │         │
    │           │ POST /oauth/token                                                                       │
    │           │   grant_type=authorization_code                                                         │
    │           │   code=...                                                                              │
    │           │   redirect_uri=...                                                                      │
    │           │   client_id=...                                                                         │
    │           │   code_verifier=...        (server now verifies SHA256(verifier) == stored challenge)  │
    │           ├──────────────────────────▶│           │           │           │         │         │     │
    │           │            │           │ Token Service:                                              │   │
    │           │            │           │ 1. Authenticate client (private_key_jwt|client_secret_post|│   │
    │           │            │           │    PKCE-only for public)                                   │   │
    │           │            │           │ 2. Look up code by HMAC hash; verify NOT consumed, NOT exp │   │
    │           │            │           │ 3. Verify redirect_uri match exact                         │   │
    │           │            │           │ 4. Verify PKCE: base64url(SHA256(code_verifier)) == challenge│ │
    │           │            │           │ 5. UPDATE authorization_codes SET consumed_at = now() WHERE│   │
    │           │            │           │    consumed_at IS NULL RETURNING * — exactly one row       │   │
    │           │            │           │    (atomic single-use; Protocol OS-04)                     │   │
    │           │            │           │ 6. Fetch User claims (svc-user) and Tenant policy (svc-tenant)│ │
    │           │            │           │ 7. Fetch roles/permissions (svc-rbac)                      │   │
    │           │            │           │ 8. Sign access JWT (RS256/ES256 from KMS-backed key)       │   │
    │           │            │           │ 9. Issue refresh_token (256-bit; HMAC hash stored)         │   │
    │           │            │           │10. If openid scope: sign ID token                          │   │
    │           │            │           │11. Emit audit.token.access_issued                          │   │
    │           ◀────────────┤           │           │           │           │         │         │       │
    │           │ 200 OK                  │                                                              │
    │           │ {                                                                                       │
    │           │   "access_token": "eyJ...",        TTL: 15 min                                         │
    │           │   "token_type": "Bearer",                                                              │
    │           │   "expires_in": 900,                                                                   │
    │           │   "refresh_token": "qf_rt_...",   TTL: 30 days                                          │
    │           │   "id_token": "eyJ...",            (if openid)                                          │
    │           │   "scope": "openid profile"                                                            │
    │           │ }                                                                                       │
    │           │                                                                                         │
    │           │ RP stores tokens (refresh in HttpOnly cookie or secure storage; access in memory)      │
```

**Components touched.** RP, UA, Edge (WAF + Gateway), Guard, Auth, Token, User, Tenant, RBAC, Session (created during auth), DB, KMS.

**Security checkpoints.**
- PKCE `code_challenge_method = S256` enforced — `plain` rejected (Protocol DC-14, OS-01).
- `state` round-trip checked by RP.
- Redirect URI exact match (Protocol OS-03).
- Authorization code single-use (atomic UPDATE; Protocol OS-04 / EH-04 reuse triggers entire chain revoke).
- Authorization code lifetime ≤ 60 s.
- `client_id` exists; client authenticated as configured.
- TLS 1.2+ on every hop (Protocol OS-12).
- Audit at every state transition.

**Error paths.**

| Step | Error | Response |
| --- | --- | --- |
| /authorize validation | Unknown client_id | `error=unauthorized_client`; no redirect (EH-01) |
| /authorize validation | Unregistered redirect_uri | `error=invalid_request`; no redirect (EH-02) |
| /authorize validation | code_challenge_method ≠ S256 | `error=invalid_request` |
| Login ceremony | Account locked | Return user to login page with `account_locked` banner |
| /token | Expired code | `error=invalid_grant` (EH-03) |
| /token | Reused code | `error=invalid_grant` + revoke chain + alert (EH-04) |
| /token | PKCE mismatch | `error=invalid_grant` |
| /token | redirect_uri mismatch | `error=invalid_grant` |

---

### 4. OIDC Authentication with ID Token Issuance

OIDC is OAuth 2.0 + the `openid` scope + ID-token issuance + the OIDC discovery and UserInfo endpoints. The wire flow is the same as Flow 3 with the differences below.

**Differences from Flow 3.**

- `scope` includes `openid` (mandatory).
- `nonce` parameter required on `/authorize`; verified inside the ID token.
- Token Service issues an `id_token` alongside the access token.
- ID token includes the OIDC standard claims (Protocol §5.4) plus Qeet ID custom claims (Protocol §5.6).
- After authentication, RP MAY call `GET /oidc/userinfo` with the access token to fetch profile claims (Protocol §5.5).

```
   ...identical to Flow 3 through code exchange...

   Token Service issues:
     access_token (JWT, RS256/ES256)
     id_token (JWT, RS256/ES256)
       Claims include:
         iss = https://{tenant}.qeetify.com
         sub = stable user UUID
         aud = client_id
         exp, iat, auth_time
         nonce = the nonce from /authorize (echoed and verified by RP)
         acr  = urn:qeetify:acr:2 (or appropriate)
         amr  = ["pwd","otp"] or ["webauthn"] etc.
         at_hash, c_hash
         qeetify/org_id, qeetify/user_id, qeetify/mfa_enrolled, qeetify/passkey_enrolled
     refresh_token (opaque)

   ─────────────────────────────────────────────
   Optional: RP calls /oidc/userinfo

   RP ──Bearer access_token──▶ Token Service /oidc/userinfo
   Token Service:
     1. Validate access token signature
     2. Resolve subject and tenant
     3. Build response with profile/email/phone claims per scope (Protocol §5.5)
   Token Service ──200 JSON──▶ RP
```

**Latency budget.** UserInfo p95 ≤ 120 ms (PF-05). Discovery and JWKS endpoints cache-friendly (PF-06, PF-07).

**Conformance.** Implementation must pass OpenID Foundation Basic OP certification before launch (Compliance CT-01, Protocol §5.1).

---

### 5. SAML 2.0 SP-Initiated SSO

**Context.** Qeet ID acts as **Service Provider (SP)**. The customer's enterprise IdP (Entra ID, Okta, Google Workspace, Ping) is the authentication authority. The Qeet ID-protected application redirects users into the enterprise IdP for authentication; the IdP posts a signed assertion back to Qeet ID.

**Latency budget.** AuthnRequest generation ≤ 200 ms p95 (PF-10). Assertion processing ≤ 400 ms p95 (PF-11). End-to-end network latency dominates.

```
   UA              RP              SAML(Qeet ID SP)    EG       IdP (Entra/Okta)       User       DB
    │              │                  │                │           │                    │           │
    │ click "Log in with SSO"                                                                        │
    ├──────────▶   │                                                                                  │
    │              │ Redirect to https://{tenant}.qeetify.com/auth/saml/{conn_id}/initiate            │
    │ 302 ─────────┤                                                                                  │
    │                                                                                                 │
    │ GET /auth/saml/{conn_id}/initiate                                                              │
    ├───────────────────────────────▶ │                                                              │
    │                                  │ Look up saml_connection by conn_id, get IdP metadata        │
    │                                  │ Generate AuthnRequest XML:                                  │
    │                                  │   ID = _<uuid>                                              │
    │                                  │   IssueInstant = now (UTC)                                  │
    │                                  │   Issuer = https://{tenant}.qeetify.com/saml/metadata       │
    │                                  │   AssertionConsumerServiceURL = our ACS URL                 │
    │                                  │   ProtocolBinding = HTTP-POST                               │
    │                                  │   NameIDPolicy / RequestedAuthnContext per connection config│
    │                                  │ Optionally sign with SP signing key (when IdP requires it)  │
    │                                  │ Deflate + Base64-encode for HTTP-Redirect binding (SB-01)   │
    │                                  │ Store AuthnRequest ID in Redis (TTL 10 min) — used for      │
    │                                  │   InResponseTo verification on the callback                 │
    │ 302 to IdP SSO endpoint                                                                          │
    ◀─────────────────────────────────┤                                                              │
    │                                                                                                 │
    │ GET (IdP SSO URL)?SAMLRequest=... → user authenticates at IdP                                  │
    ├────────────────────────────────────────────────────────▶                                       │
    │                                                                                                 │
    │ IdP authenticates user (their own login UX), then:                                              │
    │ Builds SAML Response (assertion signed; optionally encrypted)                                   │
    │ HTTP-POST binding: form auto-submits to ACS URL                                                 │
    │                                                                                                 │
    │ POST /auth/saml/{conn_id}/acs  Body: SAMLResponse=...&RelayState=...                            │
    ├───────────────────────────────▶ │                                                              │
    │                                  │ ┌────────────────────────────────────────────────────────┐ │
    │                                  │ │ ASSERTION VALIDATION (Protocol §6.5)                   │ │
    │                                  │ │ 1. XXE-safe XML parse (RA-13)                          │ │
    │                                  │ │ 2. XML signature validation full DOM (RA-12)           │ │
    │                                  │ │    - alg must be RSA-SHA256 or RSA-SHA512 (RA-02)       │ │
    │                                  │ │    - cert chains to IdP metadata trust anchor (RA-03)  │ │
    │                                  │ │    - cert not expired                                  │ │
    │                                  │ │ 3. InResponseTo matches stored AuthnRequest ID (RA-04) │ │
    │                                  │ │ 4. Conditions/NotBefore/NotOnOrAfter within ±2 min skew│ │
    │                                  │ │    (RA-05)                                             │ │
    │                                  │ │ 5. AudienceRestriction = our SP EntityID (RA-06)       │ │
    │                                  │ │ 6. SubjectConfirmation Bearer; Recipient = ACS;        │ │
    │                                  │ │    InResponseTo present (RA-08, RA-09)                 │ │
    │                                  │ │ 7. AssertionID not previously seen — replay guard      │ │
    │                                  │ │    (RA-07); store AssertionID for 5-min validity window│ │
    │                                  │ │ 8. Extract NameID + attributes per attribute mapping   │ │
    │                                  │ └────────────────────────────────────────────────────────┘ │
    │                                  │                                                            │
    │                                  │ ──upsert user via internal API──▶ User Service             │
    │                                  │       (JIT provisioning — create if not exists by externalId)
    │                                  │ ──assign roles via attribute map──▶ RBAC Service           │
    │                                  │                                                            │
    │                                  │ Build internal authentication assertion → Token Service    │
    │                                  │ (matches Flow 3 from this point — issue code or session)   │
    │                                  │                                                            │
    │                                  │ Emit audit.saml.assertion_accepted                         │
    │                                  │                                                            │
    │ 302 to RP redirect (or app home) │                                                            │
    ◀─────────────────────────────────┤                                                            │
```

**Security checkpoints.**
- XML signature verified on **full DOM** before extraction (RA-12).
- XXE disabled on parser (RA-13).
- `InResponseTo` matches our request; unsolicited assertions rejected (RA-04). IdP-initiated flow (next section) is the exception.
- `AssertionID` replay guard; reuse triggers audit + alert.
- `NotBefore` / `NotOnOrAfter` validated with 2-minute skew (RA-05).
- `AudienceRestriction` = our SP EntityID (RA-06).
- Attribute mapping per tenant config; no automatic admin grants.

**Error paths.**

| Step | Error | Response |
| --- | --- | --- |
| Signature | Invalid signature | HTTP 400; do not reveal detail (EH-08); alert if repeated |
| Conditions | Expired | HTTP 400; log replay attempt (EH-07) |
| InResponseTo | Missing AuthnRequest record | HTTP 400 |
| AssertionID | Already seen | HTTP 400; alert |

---

### 6. SAML 2.0 IdP-Initiated SSO

**Context.** User starts at the IdP's app launcher (e.g., Microsoft MyApps) and clicks the Qeet ID-protected app. The IdP posts an unsolicited assertion to our ACS. There is no AuthnRequest on our side, hence no `InResponseTo`.

```
   UA                  IdP                  SAML(Qeet ID SP)         RP
    │                   │                       │                     │
    │ click app tile                                                   │
    ├──────────────────▶│                                              │
    │ IdP authenticates (or already authenticated)                     │
    │ IdP builds unsolicited SAML Response (assertion signed)          │
    │ HTTP-POST to ACS URL with RelayState = pre-configured target URL │
    │                                                                  │
    │ POST /auth/saml/{conn_id}/acs   no InResponseTo                  │
    ├──────────────────────────────▶  │                                │
    │                                  │ Validation as in Flow 5,      │
    │                                  │ EXCEPT InResponseTo check is  │
    │                                  │ relaxed (no AuthnRequest).    │
    │                                  │ Connection must have          │
    │                                  │ "allow_idp_initiated": true   │
    │                                  │ (configured per-connection).  │
    │                                  │ Otherwise reject with HTTP 400│
    │                                  │ to discourage IdP-initiated by│
    │                                  │ default (defence in depth).   │
    │                                  │                               │
    │                                  │ JIT user upsert + role assign │
    │                                  │ Build internal auth assertion │
    │                                  │ Token issuance for RP         │
    │                                  │ Redirect to RelayState target │
    ◀─────────────────────────────────┤                                │
```

**Security checkpoint specific to IdP-initiated.** Tenant connection must opt into `allow_idp_initiated`. Default is **false**. This protects against unsolicited-assertion attacks by accident.

---

### 7. SAML Single Logout (SLO)

SLO terminates the user's session at the SP, the IdP, and all other SP sessions held against the same IdP session. Qeet ID supports both SP-initiated and IdP-initiated SLO (Protocol SP-PROF-04, SP-PROF-05).

```
   UA           RP/Qeet ID       SAML(Qeet ID)    IdP                  Other SPs
    │            │                 │                │                     │
    │ click logout                                                         │
    ├──────────▶ │                                                          │
    │ Qeet ID revokes local session (Session Service)                       │
    │ Generate LogoutRequest (SP-initiated SLO)                             │
    │ 302 to IdP SLO endpoint                                              │
    │            ├────────────────▶│                │                     │
    │ Forward LogoutRequest (signed) to IdP                                 │
    ◀──────────────────────────────────────────────▶                       │
    │ IdP terminates its session                                            │
    │ IdP fans out LogoutRequest to other SPs                              │
    │                                              ├──────────────────────▶│
    │                                                                       │
    │ Each SP responds with LogoutResponse                                  │
    │                                              ◀──────────────────────│
    │ IdP returns LogoutResponse to Qeet ID                                │
    ◀──────────────────────────────────────────────│                       │
    │            │ Validate LogoutResponse signature                        │
    │            │ Display logout-complete page                             │
```

For **IdP-initiated SLO**, Qeet ID receives a `LogoutRequest` from the IdP at the SLO ACS URL, terminates the local session (via `Session.revoke`), responds with `LogoutResponse`. The Session Service emits `auth.session.revoked` which propagates to Token Service (refresh-token chain revoked within 60 s).

**Edge cases.**
- Some IdPs (notably older Entra ID configurations) do not support SLO — Qeet ID falls back to local logout only, with a warning shown to the user that other apps may still be authenticated.
- Front-channel SLO is implemented via redirects; back-channel SLO (SOAP) is deferred to post-MVP.

---

### 8. SCIM 2.0 User Provisioning

**Context.** Enterprise customer's IdP (Okta, Entra) syncs users to Qeet ID automatically. The IdP is the SCIM client; Qeet ID SCIM Service is the SCIM server. Authentication via OAuth 2.0 bearer token (Client Credentials grant) with `qeetify:scim` scope (Protocol SS-01).

**Latency budget.** SCIM user create p95 ≤ 300 ms (PF-12).

```
   IdP(SCIM Client)        EG          SCIM         User        RBAC      K (Kafka)     DB
        │                   │            │            │           │           │           │
        │ POST /scim/v2/Users                                                              │
        │ Auth: Bearer <token>                                                             │
        │ Body: { schemas:[...User], userName:"alice@acme.com", emails:[...], ...}          │
        ├──────────────────▶│            │            │           │           │           │
        │                   │ rate limit │            │           │           │           │
        │                   │ tenant     │            │           │           │           │
        │                   │ validation │            │           │           │           │
        │                   ├──────────▶ │            │           │           │           │
        │                   │            │ Validate body schema (RFC 7643)                 │
        │                   │            │ Tenant context = bearer-token subject's org    │
        │                   │            │ Look up by (tenant_id, externalId) — if exists  │
        │                   │            │   return 409 Conflict (SS-05)                  │
        │                   │            │ Else proceed                                   │
        │                   │            ├───────────▶│           │           │           │
        │                   │            │            │ Create user (active, email verified
        │                   │            │            │  per source's email_verified flag) │
        │                   │            │            │ Insert into users + user_profiles  │
        │                   │            │            ◀───────────│           │           │
        │                   │            │            │           │           │           │
        │                   │            │ If groups in payload:                          │
        │                   │            │   PATCH-equivalent into RBAC role assignments  │
        │                   │            │ Emit user.created on Kafka                     │
        │                   │            │ Emit audit.scim.user_created                   │
        │                   │            │                                                │
        │                   │ 201 Created                                                  │
        │                   │ Location: /scim/v2/Users/{id}                                │
        │ ◀──────────────────│            │                                                │
```

**PATCH operations.** Protocol §7.5 — six operation types. Of these, the deprovisioning case is below.

---

### 9. SCIM 2.0 User Deprovisioning (`active=false`)

This flow is the make-or-break SCIM scenario for enterprise customers. The SLA is **all active sessions terminated within 60 seconds** (NFR DI-04 / Protocol SS-06).

```
   IdP                   SCIM         User         K              Session       Token       Audit
    │                     │            │            │              │             │           │
    │ PATCH /scim/v2/Users/{id}                                                                │
    │ Body: {"Operations":[{"op":"replace","path":"active","value":false}]}                    │
    ├───────────────────▶│            │            │              │             │           │
    │                     │ Validate, look up user                                              │
    │                     ├──────────▶│            │              │             │           │
    │                     │            │ UPDATE users SET status='suspended', deprovisioned_at=now()
    │                     │            ◀───────────│              │             │           │
    │                     │                                                                   │
    │                     ├─emit user.deprovisioned──▶ K topic 'scim.user.deprovisioned'      │
    │                     │   key = tenant_id; payload = {tenant_id, user_id, ...}            │
    │                     │                                                                   │
    │                     │ Synchronously call Session Service to start revocation:           │
    │                     ├────────────────────────────────────▶ │                            │
    │                     │                                       │ Look up sessions WHERE   │
    │                     │                                       │ user_id = X AND active   │
    │                     │                                       │ Bulk revoke (DB + Redis) │
    │                     │                                       │ Emit auth.session.revoked│
    │                     │                                       ◀─each session→ Token Svc  │
    │                     │                                                                   │
    │                     │                              Token Service (consumer):           │
    │                     │                              - revoke all refresh tokens for     │
    │                     │                                each revoked session              │
    │                     │                              - add to revocation list            │
    │                     │                                                                   │
    │                     │ Emit audit.scim.user_deprovisioned                               │
    │                     │                                                                   │
    │ 200 OK              │                                                                   │
    ◀────────────────────┤                                                                   │
```

**Why synchronous call to Session Service in addition to Kafka emit?** The 60-second SLA. Kafka delivery is at-least-once but not real-time. The synchronous call drives revocation in the same request; the Kafka event is the durable record and the trigger for downstream subscribers (audit, webhook, anomaly).

The end-to-end clock from the IdP PATCH response to the last refresh-token being unable to mint a new access token must be **< 60 seconds**. We measure this as an SLO (Observability §6).

**What happens to access tokens already in flight?** They remain valid until their 15-minute lifetime expires. For high-sensitivity resource servers, customer documentation recommends introspection rather than relying on JWT expiry alone — introspection consults the revocation list within seconds.

---

### 10. Passkey Registration (WebAuthn)

**Context.** User registering a passkey after sign-up or from account settings. Default at sign-up per Persona requirements (Protocol PK-01).

**Latency budget.** Browser-side ceremony dominates user-perceived time; server-side validation ≤ 300 ms p95.

```
   UA(browser)           RP / Hosted Login        Auth / MFA Service          DB
        │                       │                       │                     │
        │ click "Register passkey"                                              │
        ├──────────────────────▶│                                              │
        │                       │ POST /v1/mfa/enroll/passkey/options          │
        │                       ├──────────────────────▶│                     │
        │                       │                       │ Build PublicKeyCredentialCreationOptions:
        │                       │                       │   challenge = 128-bit random (single-use; store)
        │                       │                       │   rp = { id: tenant.qeetify.com, name: "Qeet ID" }
        │                       │                       │   user = { id: opaque user_handle, name, displayName }
        │                       │                       │   pubKeyCredParams = [ES256, RS256, EdDSA]
        │                       │                       │   authenticatorSelection = {
        │                       │                       │     residentKey: "preferred",
        │                       │                       │     userVerification: "required" }
        │                       │                       │   attestation = "direct" or "none" per tenant policy
        │                       │                       │   excludeCredentials = [existing creds for user]
        │                       │                       │ Persist challenge (Redis TTL 5 min)
        │                       │ ◀─────────────────────│                     │
        │ 200 JSON options       │                                              │
        ◀──────────────────────│                                              │
        │ navigator.credentials.create(options)                                │
        │ user verifies (biometric / PIN); device generates keypair             │
        │ Returns PublicKeyCredential { rawId, response: AttestationObject + clientDataJSON } │
        │ POST /v1/mfa/enroll/passkey/verify { credential }                    │
        ├──────────────────────────────────────────────▶ │                     │
        │                                                │ Validate (Protocol WR):
        │                                                │  1. Parse clientDataJSON; type=webauthn.create;
        │                                                │     challenge matches stored; origin matches RP
        │                                                │  2. Parse AttestationObject (CBOR)
        │                                                │  3. Verify rpIdHash == SHA256(rp.id)
        │                                                │  4. Verify UP flag; UV per policy
        │                                                │  5. Verify attestation statement (packed/tpm/apple/none)
        │                                                │     against FIDO MDS3 trust anchors
        │                                                │  6. Extract credentialId, public key (COSE), AAGUID,
        │                                                │     sign_count, BE/BS flags
        │                                                │  7. INSERT passkey_credentials
        │                                                │  8. Emit audit.security.passkey_registered
        │ 200 { id, nickname }                            │                     │
        ◀───────────────────────────────────────────────│                     │
```

**Storage.** Public key bytes (COSE), credential ID, AAGUID, sign-count, BE/BS, attestation format, optional attestation statement (retained for trust evaluation, not for re-verification), user-set nickname.

---

### 11. Passkey Authentication

**Latency budget.** End-to-end passkey login p95 ≤ 5 s including human interaction (UX-01). Server-side verification ≤ 300 ms (PF-09).

```
   UA(browser)              Auth(/MFA)                     DB
        │                       │                          │
        │ Visit login page                                  │
        │ navigator.credentials.get({mediation:"conditional", options}) — conditional UI prompts native picker
        │ Page also issues POST /v1/login/passkey/options
        ├──────────────────────▶ │                          │
        │                        │ Build PublicKeyCredentialRequestOptions:
        │                        │   challenge = 128-bit random (single-use)
        │                        │   rpId = tenant.qeetify.com
        │                        │   userVerification = "required" (per tenant policy)
        │                        │   allowCredentials = [] (empty = discoverable creds; resident key)
        │                        │ Persist challenge in Redis TTL 5 min
        │ ◀──────────────────────│                          │
        │ navigator.credentials.get returns assertion        │
        │ POST /v1/login/passkey/verify { credential }      │
        ├──────────────────────▶│                          │
        │                        │ Validation (Protocol WA):
        │                        │  1. Parse clientDataJSON; type=webauthn.get; challenge match; origin match
        │                        │  2. Parse authData; rpIdHash; flags (UP required; UV per policy)
        │                        │  3. Look up credential by credentialId
        │                        │  4. Verify signature over authData||clientDataHash with stored pub key
        │                        │  5. Sign-count check (skip for synced; verify increasing for device-bound)
        │                        │  6. Backup state policy check
        │                        │  7. Update last_used_at, sign_count
        │                        │  8. Issue internal authentication assertion → Token Service
        │                        │  9. Emit audit.authentication.passkey_succeeded
        │ 200 { auth-assertion or redirect to /authorize callback }
        ◀──────────────────────│                          │
```

---

### 12. Cross-Device Passkey (Hybrid Transport / QR)

User on a desktop browser without a registered platform authenticator wants to authenticate using a passkey stored on their phone. The browser shows a QR code; the phone scans, performs the ceremony locally, and tunnels the result back via Bluetooth-mediated proximity + CTAP 2.2 hybrid transport (Protocol AT-04).

```
   Desktop UA          Auth/MFA                  Phone UA (CTAP 2.2 client)
        │                  │                          │
        │ Click "use a passkey on another device"      │
        │ Server issues options; browser invokes hybrid transport
        │ Browser displays QR code (CTAP server data) │
        │                                              │
        │ Phone scans QR with camera                   │
        │                                              ◀── BLE proximity check ──
        │ Phone constructs hybrid client; opens secure tunnel via CTAP relay
        │ Phone performs WebAuthn ceremony locally     │
        │ User verifies biometric                      │
        │ Phone returns assertion via tunnel           │
        │ Desktop browser delivers assertion to server│
        ├────────────────▶│                          │
        │                  │ Validate as in Flow 11   │
        │ 200 success      │                          │
        ◀────────────────│                          │
```

From Qeet ID's server perspective this is identical to a standard passkey authentication. The complexity is browser-mediated; our responsibility is to emit correct options and validate the returned assertion.

---

### 13. Email + Password Login + MFA

**Latency budget.** End-to-end p95 ≤ 800 ms (NFR §4.4). Server-side application logic ≤ 150 ms (Argon2id dominates).

```
   UA           Auth          Guard         User         MFA          Token         DB
    │            │              │             │            │            │            │
    │ POST /v1/login {email, password, tenant_hint}                                    │
    ├──────────▶ │              │             │            │            │            │
    │            ├──guard.check─▶│             │            │            │            │
    │            │              │ Return rate / lockout state            │            │
    │            ◀──────────────│             │            │            │            │
    │            │ Resolve tenant from {hint or email domain or hosted login context} │
    │            ├──────────────────────────▶│            │            │            │
    │            │              │             │ Look up user by (tenant_id, email_hash)
    │            │              │             │ If not found → return constant-time fail
    │            │              │             │ If found, fetch password_hash
    │            ◀────────────────────────────│            │            │            │
    │            │ Argon2id verify against stored hash                                 │
    │            │ HIBP k-anonymity check on submitted password (background)            │
    │            │ If verify OK → check user.status active                              │
    │            │ If MFA required:                                                    │
    │            ├──────────────────────────────────────▶ │            │            │
    │            │ Decide factor (TOTP first if enrolled; else SMS; else email)        │
    │            │ Issue challenge                                                     │
    │            ◀──────────────────────────────────────│             │            │
    │ Respond with {status:"mfa_required", challenge_id, factor}                       │
    ◀────────── │                                                                     │
    │ UA prompts for MFA code; user enters; POST /v1/login/mfa/verify {challenge_id, code}
    ├──────────▶│                                                                     │
    │            ├──────────────────────────────────────▶ │            │            │
    │            │ MFA Service verifies (TOTP / OTP) — constant-time compare           │
    │            ◀──────────────────────────────────────│             │            │
    │            │ Build internal authentication assertion (acr 2, amr ["pwd","otp"]) │
    │            ├──────────────────────────────────────────────────▶│             │
    │            │                                                  Token Service:   │
    │            │                                                  - create session │
    │            │                                                  - issue tokens   │
    │            ◀──────────────────────────────────────────────────│             │
    │ 200 { tokens | redirect to /authorize callback }                                 │
    ◀──────────│                                                                     │
```

**Security checkpoints.**
- Constant-time path even when user not found (anti-enumeration).
- Argon2id parameter check on success; if parameters have been raised, re-hash with new params and update row.
- HIBP check on success too — a previously-OK password may have appeared in a recent breach (Compliance AS-04).
- Failed-attempt counter tick per (user) AND (ip).
- Lockout policy after 5 failures.

---

### 14. Magic Link / Email OTP

```
   UA               Auth              Notif            User           DB
    │                │                  │                │              │
    │ POST /v1/login/magic-link {email, tenant_hint}                     │
    ├──────────────▶│                  │                │              │
    │                ├─upsert-by-email─▶│                │              │  (Protocol EO-08 rate-limit)
    │                │ Generate magic-link JWT:                          │
    │                │   sub = user.id; tid = tenant_id; nonce = uuid;  │
    │                │   exp = now+15min; iat = now;                    │
    │                │   sign with magic-link key (RS256)               │
    │                │ Store nonce + token_hash row (single-use guard)  │
    │                ├──Notif.email────────────────────▶│              │
    │                │   "Click here to log in:                          │
    │                │    https://{tenant}.qeetify.com/login/magic?token=eyJ..."
    │                │                                                   │
    │ 202 Accepted (always — anti-enumeration; same response if email unknown)
    ◀──────────────│                                                   │
    │                │                                                   │
    │ user opens email; clicks link                                       │
    │ GET /login/magic?token=eyJ...                                       │
    ├──────────────▶ │                                                   │
    │                │ Verify JWT signature & claims                      │
    │                │ Verify nonce row exists and not consumed (atomic)  │
    │                │ Mark nonce consumed                                │
    │                │ Build internal auth assertion → Token Service     │
    │                │ Emit audit.authentication.magic_link_succeeded    │
    │ 302 to /authorize callback                                          │
    ◀──────────────│                                                   │
```

Email OTP variant: same flow, but the link is replaced with a 6-digit code shown in the email; the user pastes it into the login page. Same single-use semantics.

---

### 15. TOTP MFA Challenge

```
   UA               Auth          MFA            DB
    │                │             │              │
    │ POST /v1/login/mfa/verify {challenge_id, code}
    ├──────────────▶│             │              │
    │                ├─verify────▶│              │
    │                │             │ Look up totp_seed (decrypt via KMS-DEK)
    │                │             │ Compute expected codes for current/-1/+1 time steps
    │                │             │ Constant-time compare
    │                │             │ Verify code not in used-codes window (replay guard, TP-08)
    │                │             │ Mark code used (Redis TTL 90s)
    │                │             │ Increment success/fail counters
    │                ◀────────────│              │
    │ 200 OK                                       │
    ◀──────────────│                              │
```

Latency: MFA verify p95 ≤ 100 ms; dominated by KMS decryption of the per-tenant DEK (cached in-process 15 min).

---

### 16. SMS OTP MFA Challenge

```
   UA               Auth           MFA          Notif       Twilio       DB
    │                │              │             │            │            │
    │ POST /v1/login/mfa/sms/send {challenge_id}                            │
    ├──────────────▶│              │             │            │            │
    │                ├─issue──────▶│             │            │            │
    │                │              │ Generate 6-digit OTP (random, not sequential)
    │                │              │ Store hash with exp = now+10min, attempts=0
    │                │              │ Rate-limit per phone: 5/hour (SM-04)
    │                │              ├──Notif.sms─▶│            │            │
    │                │              │             ├──Twilio────▶│            │
    │ 202 Accepted   │              │             │            │            │
    ◀──────────────│              │             │            │            │
    │                │              │             │            │            │
    │ user receives SMS; enters code               │            │            │
    │ POST /v1/login/mfa/verify {challenge_id, code}                          │
    ├──────────────▶│              │             │            │            │
    │                ├─verify─────▶│             │            │            │
    │                │              │ Constant-time compare; attempts++; exp check
    │                │              │ If 3 failures → exponential backoff       │
    │                ◀─────────────│             │            │            │
    │ 200 OK                                       │            │            │
    ◀──────────────│              │             │            │            │
```

---

### 17. Step-Up Authentication

A high-sensitivity resource server requires `acr_values=urn:qeetify:acr:3` (passkey-strength) but the user authenticated only with password (`acr 1`).

```
   UA              RP            Auth         Token (already-issued)
    │               │             │             │
    │ User attempts privileged action                            │
    │ RP validates current token: aud / scope OK BUT acr < required
    │ RP returns 401 with WWW-Authenticate including required acr
    ◀──────────────│                            │
    │ UA redirects to /oauth/authorize with prompt=login and acr_values=urn:qeetify:acr:3
    ├──────────────────────────▶│              │
    │ Hosted login pages prompt step-up:
    │   "Confirm with passkey" or registered higher factor
    │ User completes ceremony (Flow 11)
    │ Auth Service builds new assertion with the upgraded ACR; session ACR updated
    │ New tokens issued
    ◀──────────────────────────│              │
```

The session ACR is upgraded in-place; the user does not lose their previous session, they just gain higher assurance until the session expires.

---

### 18. Token Refresh with Rotation

```
   RP                  Token                  DB
    │                    │                     │
    │ POST /oauth/token  grant_type=refresh_token&refresh_token=qf_rt_X&client_id=Y
    ├──────────────────▶│                     │
    │                    │ Authenticate client │
    │                    │ Look up refresh_token by HMAC-SHA256 hash
    │                    │ Verify NOT used_at, NOT revoked, exp valid, session active
    │                    │ BEGIN TRANSACTION
    │                    │ UPDATE refresh_tokens SET used_at=now() WHERE id=X AND used_at IS NULL
    │                    │   RETURNING * → rows_affected must = 1
    │                    │ Generate new refresh token (parent_id = X)
    │                    │ INSERT new refresh_tokens row
    │                    │ COMMIT
    │                    │ If rows_affected != 1 → reuse detected:
    │                    │   Revoke entire chain (rooted at oldest ancestor); revoke session; alert; return error
    │                    │ Fetch fresh claims (roles may have changed)
    │                    │ Issue new access token + new refresh token (+ new id_token if openid)
    │                    │ Emit audit.token.refresh_succeeded
    │ 200 OK { access_token, refresh_token, ... }
    ◀──────────────────│
```

**Critical invariant.** The presented refresh token is **marked used**, not deleted. Reuse detection depends on the row remaining queryable.

---

### 19. Client Credentials (M2M)

```
   Service Account       Token             DB
    (caller)              │                 │
    │                     │                 │
    │ POST /oauth/token   │                 │
    │ grant_type=client_credentials         │
    │ client_id=cc_...                      │
    │ Authentication: private_key_jwt OR client_secret_basic
    │ scope=resource:read resource:write     │
    ├──────────────────▶│                 │
    │                    │ Authenticate client per registered method
    │                    │ Validate requested scope ⊂ allowed scopes for client
    │                    │ Validate tenant is active
    │                    │ Issue access token only (no refresh token — Protocol CC-05)
    │                    │ Sub claim = service account id; not a user
    │                    │ Emit audit.token.client_credentials_issued
    │ 200 { access_token, expires_in:3600 }
    ◀──────────────────│                 │
```

No user interaction, no session, no refresh token. Service accounts re-authenticate when the access token expires.

---

### 20. Account Recovery

Recovery is initiated when the user cannot authenticate (lost device, forgot password). It is a high-sensitivity flow that must not become an authentication bypass.

```
   UA               Auth           User           Notif        MFA          DB
    │                │              │              │            │            │
    │ POST /v1/recover {email, tenant_hint}                                    │
    ├──────────────▶│              │              │            │            │
    │                ├─lookup──────▶│              │            │            │
    │                │ If user exists: issue recovery token (UUID + nonce; 30-min TTL)
    │                ├──Notif.email▶                            │            │
    │                │ "Reset your account: link with recovery token"          │
    │ 202 Accepted (always — same response if email unknown; anti-enumeration) │
    ◀──────────────│                                                          │
    │                                                                         │
    │ User clicks link → GET /recover/verify?token=...                        │
    ├──────────────▶│                                                          │
    │                │ Validate token (single-use, not expired)                │
    │                │ If user has registered passkey: require passkey assertion as recovery factor (Flow 11)
    │                │ Else if user has TOTP enrolled: require TOTP code (Flow 15)
    │                │ Else: send SMS OTP if phone verified
    │                │ Else: high-friction fallback — manual review queue (admin notified)
    │ Recovery factor verified → user can set new password OR register new passkey
    │ All existing sessions revoked (forced re-login)
    │ Emit audit.security.account_recovery_completed
    ◀──────────────│                                                          │
```

**Key principle.** Recovery is not weaker than the user's strongest enrolled factor. A user with a passkey cannot bypass to password reset via email alone — the recovery flow requires the passkey. This prevents email-account compromise from becoming a full-account compromise.

---

### 21. Flow → Component → SLO Mapping

| Flow | Hot-path services | Latency budget | SLO target |
| --- | --- | --- | --- |
| 3 OAuth Auth Code + PKCE (/token) | Token, User, Tenant, RBAC | 200 ms p95 | NFR SL-01/SL-02 |
| 4 OIDC | same + userinfo | 120 ms p95 (userinfo) | SL-01/SL-02 |
| 5 SAML SP-init | SAML, User, Token | 400 ms p95 (assert) | SL-04 |
| 6 SAML IdP-init | SAML, User, Token | 400 ms p95 | SL-04 |
| 7 SAML SLO | SAML, Session, Token | 800 ms p95 | — (best-effort) |
| 8 SCIM provision | SCIM, User, RBAC | 300 ms p95 | SL-05 |
| 9 SCIM deprovision | SCIM, User, Session, Token | <60 s end-to-end | DI-04 + SL-05 |
| 10 Passkey register | MFA | 300 ms server | — |
| 11 Passkey auth | Auth, MFA, Token | 300 ms server (5 s e2e UX-01) | — |
| 12 Cross-device passkey | same | server identical | — |
| 13 Pwd + MFA | Auth, MFA, Token, User | 500 ms p95 server | — |
| 14 Magic link | Auth, Notif, Token | 200 ms request + email | — |
| 15 TOTP | MFA | 100 ms p95 | — |
| 16 SMS OTP | MFA, Notif, Twilio | 200 ms server (SMS adds seconds) | — |
| 17 Step-up | Auth + ceremony | per chosen factor | — |
| 18 Refresh + rotation | Token | 150 ms p95 (PF-03) | SL-01 |
| 19 Client credentials | Token | 200 ms p95 (PF-02) | SL-01 |
| 20 Account recovery | Auth, MFA, Notif | per chosen factor | — |

---

### 22. Cross-Flow Security Invariants

1. **No flow ever returns `none` algorithm JWTs.** Enforced by signer library configuration (Protocol JT-03).
2. **Every flow that produces a session emits `audit.authentication.*`.** No silent authentication.
3. **Every authentication step that touches credentials is constant-time.** Anti-enumeration is platform-wide, not flow-specific.
4. **Every redirect target is whitelist-validated.** No open redirector vulnerability (NFR/Protocol OS-03, EH-02).
5. **Every challenge token (passkey, magic link, OTP) is single-use.** Replay is impossible by construction.
6. **Every assertion crossing trust boundaries is signed and signature-verified before extraction.** No "trust the body, verify later."
7. **Every flow that mutates state is idempotent or transactional.** Either via `Idempotency-Key` header or via `WHERE ... AND state = expected` transactional updates.
8. **TLS 1.2+ on every external hop; mTLS internal.**

---

### 23. Open Decisions Carried From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OQ-AF-01 | Default behaviour when SAML IdP does not support SLO — local logout only with banner vs forced logout with warning | Product + Federation | Phase 3 entry |
| OQ-AF-02 | Magic-link signing key cadence (90 days vs shorter for higher rotation hygiene) | Security Architect | Phase 2 close |
| OQ-AF-03 | Step-up: re-authenticate same factor vs require a stronger factor by default | Security Architect + Product | Phase 2 close |
| OQ-AF-04 | Account recovery fallback when user has no enrolled factors — manual review queue vs hard-fail | Product + Compliance | Phase 3 entry |

---

### 24. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Solution Architect |  |  |  |
| Backend Engineering Lead (Team Auth) |  |  |  |
| Team Federation Lead |  |  |  |
| Security Architect |  |  |  |
| CISO |  |  |  |
| QA Lead |  |  |  |
| UX Lead (passkey-first flows) |  |  |  |

---

*This document is version controlled. Authentication flows must be reviewed when a new authentication factor is introduced, when conformance certifications are added, when protocol RFCs update, or when a flow's security model is challenged by an incident. Any deviation in implementation requires an ADR signed by the Security Architect and Solution Architect.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
