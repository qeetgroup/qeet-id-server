# Qeetid — Protocol Conformance Status

Maps every protocol from [qeetid-reqs/phase-1/Qeetid — Protocol Requirements Document.md](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-1) to current implementation state. The Protocol Requirements doc enumerates **18 core protocols** for MVP/v1.0 plus post-launch extensions.

**Legend:** ✅ done · 🟡 partial · 🔴 not started · ⚪ post-MVP

---

## 1. OAuth 2.0 (RFC 6749 + RFC 9700)

| Sub-requirement | Status | Notes |
|---|:-:|---|
| Authorization Code grant (+ PKCE S256 mandatory) | 🔴 | `/oauth/authorize` endpoint not mounted. Code-grant branch in `/oauth/token` missing. PKCE validation logic absent. |
| Client Credentials grant (M2M) | ✅ | [backend/internal/principal/principal.go](../backend/internal/principal/principal.go) — `POST /v1/oauth/token` for service principals |
| Refresh Token grant + rotation | ✅ | [backend/internal/auth/service.go](../backend/internal/auth/service.go) — single-use, reuse-detection revokes session |
| Implicit grant — rejected | ✅ | Not implemented (correct) |
| Resource Owner Password grant — rejected | ✅ | Not implemented (correct) |
| State parameter (CSRF) validation | 🔴 | Awaits `/authorize` |
| Exact redirect URI matching | 🟡 | `oidc_clients.redirect_uris` stored as text[]; matching logic awaits `/authorize` |
| Authorization code 60-second TTL | 🔴 | No code storage yet |
| Single-use code invalidation | 🔴 | Same |
| `iss` parameter (mix-up attack prevention) | 🔴 | Awaits `/authorize` |
| Token audience validation | 🟡 | JWT issuer includes `aud`; downstream resource servers don't validate consistently |
| Confidential-client auth (client_secret_post/basic, private_key_jwt) | 🟡 | client_secret stored bcrypt-hashed; private_key_jwt not implemented |
| TLS 1.2 minimum | ⚪ | Edge-layer concern |
| Rate limiting on `/token` per client | 🟡 | Per-IP rate limit exists; per-client not implemented |
| Scope minimization | ✅ | OIDC client + service principal both have explicit scope arrays |
| Token Introspection (RFC 7662) | 🔴 | `/oauth/introspect` not implemented |
| Token Revocation (RFC 7009) | 🟡 | Session/refresh-token revocation exists; no public `/oauth/revoke` endpoint accepting opaque token |
| `/.well-known/oauth-authorization-server` metadata | 🟡 | OIDC discovery exists; OAuth-AS metadata not separately published |
| Endpoints: `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`, `/oauth/revoke` | 🟡 | Only `/token` (client_credentials) and refresh exist |

**Token specs per roadmap:**

| Token | Required | Implemented | Notes |
|---|---|---|---|
| Access token | JWT RS256/ES256, 15-min default | 🟡 | Algorithm config supports both; default is HS256 with static key |
| Refresh token | Opaque, HMAC-SHA256 reference, 30 days, stored as hash | ✅ | [backend/internal/platform/codes/](../backend/internal/platform/codes/) generates; stored as SHA-256 hash |
| ID token | JWT RS256/ES256, 1 hour | 🔴 | Not minted yet (no code flow) |
| Client-credentials access token | JWT, 1 hour | ✅ | Issued by service principal flow |

---

## 2. OpenID Connect (OIDC) Core 1.0 + Discovery 1.0 + Dynamic Client Registration 1.0

| Sub-requirement | Status | Notes |
|---|:-:|---|
| OIDC Core 1.0 (ID token issuance via code flow) | 🔴 | Awaits OAuth code flow |
| OIDC Discovery 1.0 | ✅ | `GET /.well-known/openid-configuration` at [backend/internal/oidc/oidc.go](../backend/internal/oidc/oidc.go) |
| OIDC Dynamic Client Registration 1.0 | ✅ | `POST /v1/oidc/clients` |
| OIDC Session Management 1.0 | ⚪ | Post-launch |
| Front-Channel Logout 1.0 | ⚪ | Post-launch |
| Back-Channel Logout 1.0 | ⚪ | Post-launch |
| FAPI 2.0 | ⚪ | v2.0 |
| OpenID Foundation Basic OP certification | 🔴 | Not initiated |

**Discovery document fields — verify all present:**

The current implementation publishes a discovery document. Audit needed to confirm all required fields:
`issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `registration_endpoint`, `scopes_supported`, `response_types_supported` (code only), `grant_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`, `token_endpoint_auth_methods_supported`, `claims_supported`, `code_challenge_methods_supported` (S256 only), `end_session_endpoint`, `revocation_endpoint`, `introspection_endpoint`, `acr_values_supported`.

**ID token claims — implementation status:**

| Claim | Required | Implementation Status |
|---|---|---|
| `iss`, `sub`, `aud`, `exp`, `iat` | Mandatory | 🟡 — present in service-principal tokens; user ID tokens not yet minted |
| `auth_time` | Conditional | 🔴 |
| `nonce` | Conditional | 🔴 |
| `acr`, `amr` | Recommended | 🔴 — no ACR mapping in code yet |
| `azp` | Conditional | 🔴 |
| `at_hash`, `c_hash` | Recommended | 🔴 |

**UserInfo endpoint claims by scope:**

| Scope | Required | Implementation Status |
|---|---|---|
| `openid` → `sub` | ✅ | [backend/internal/oidc/oidc.go](../backend/internal/oidc/oidc.go) |
| `profile` → name, given_name, family_name, picture, locale, … | 🟡 | Returns user display name; missing the broader profile claim set |
| `email` → email, email_verified | ✅ | Returned |
| `phone` → phone_number, phone_number_verified | 🟡 | Stored, not yet exposed via userinfo |
| `address` → address object | 🔴 | No address fields on user model |
| `offline_access` (refresh request) | ✅ | Refresh tokens issued |

**Custom Qeetid claims (`https://qeetid.com/claims`):**

| Claim | Required | Status |
|---|---|---|
| `qeetid/org_id` | Access + ID token | 🟡 — `tenant_id` present in service-principal access tokens |
| `qeetid/org_name` | ID token | 🔴 |
| `qeetid/roles` | Access token | 🔴 |
| `qeetid/permissions` | Access token | 🔴 |
| `qeetid/plan` | Access token | 🔴 |
| `qeetid/mfa_enrolled` | ID token | 🔴 |
| `qeetid/passkey_enrolled` | ID token | 🔴 |
| `qeetid/user_id` | Access + ID token | 🟡 — `sub` carries user_id |

**ACR values — none of `urn:qeetid:acr:1..4` are mapped in code yet.**

**JWKS endpoint:**

- `/jwks.json` is served from [backend/internal/oidc/oidc.go](../backend/internal/oidc/oidc.go).
- Static key set, no rotation.
- Requires: **two active keys at all times, 90-day rotation, kid header in every JWT, 1-hour cache-control header, retired keys retained 24 hours.** All five requirements are 🔴.

---

## 3. SAML 2.0 (OASIS)

| Sub-requirement | Status | Notes |
|---|:-:|---|
| Web Browser SSO Profile — SP (Qeetid as SP) | 🔴 | No SAML module |
| Web Browser SSO Profile — IdP (Qeetid as IdP) | 🔴 | Same |
| Single Logout Profile (SLO) — both directions | 🔴 | Same |
| Enhanced Client or Proxy (ECP) | ⚪ | v1.5 |
| Artifact Resolution Profile | ⚪ | v1.5 |
| HTTP-Redirect binding | 🔴 | — |
| HTTP-POST binding | 🔴 | — |
| HTTP-Artifact binding | ⚪ | v1.5 |
| SOAP binding | ⚪ | v1.5 |
| RSA-SHA256 minimum signing | 🔴 | — |
| Signature verification against IdP metadata | 🔴 | — |
| Assertion validity (NotBefore/NotOnOrAfter ±2 min) | 🔴 | — |
| Audience restriction | 🔴 | — |
| `InResponseTo` matching | 🔴 | — |
| AssertionID dedup (replay prevention) | 🔴 | — |
| XML signature-wrapping protection | 🔴 | — |
| XXE prevention | 🔴 | — |
| Assertion encryption (AES-256-CBC / AES-128-GCM) | 🔴 | — |
| Attribute mapping (email, given_name, family_name, groups, role) | 🔴 | — |
| SP metadata endpoint `/saml/metadata` | 🔴 | — |
| IdP metadata import (manual + URL) | 🔴 | — |
| Interop testing — Entra ID / Okta / Google Workspace | 🔴 | — |

**Recommendation:** Adopt `github.com/crewjam/saml` (battle-tested, supports both SP and IdP). New module `backend/internal/saml/` with a new `saml` schema for IdP metadata, replay cache, certificate pinning.

---

## 4. SCIM 2.0 (RFC 7642 / 7643 / 7644)

| Endpoint | Required | Status |
|---|---|:-:|
| `GET/POST /scim/v2/Users` | MVP | 🔴 |
| `GET/PUT/PATCH/DELETE /scim/v2/Users/{id}` | MVP | 🔴 |
| `GET/POST /scim/v2/Groups` | MVP | 🔴 |
| `GET/PUT/PATCH/DELETE /scim/v2/Groups/{id}` | MVP | 🔴 |
| `GET /scim/v2/ServiceProviderConfig` | MVP | 🔴 |
| `GET /scim/v2/ResourceTypes` | MVP | 🔴 |
| `GET /scim/v2/Schemas` | MVP | 🔴 |
| `POST /scim/v2/Bulk` | Post-launch | ⚪ |

**User resource attributes — all missing:** id, externalId, userName, name.*, displayName, emails[], phoneNumbers[], active, groups[], roles[], meta.*.

**Group resource attributes — all missing:** id, externalId, displayName, members[], meta.*.

**PATCH operations — all 8 lifecycle operations missing.**

**Security requirements:**
- OAuth 2.0 bearer token (qeetid:scim scope) — 🔴
- TLS 1.2 — ⚪ (edge)
- Tenant isolation (cross-tenant 403) — depends on impl
- Rate limiting per client — 🔴
- POST idempotency (409 on duplicate) — 🔴
- Deprovisioning immediacy (session termination within 60s) — 🔴
- Audit logging — 🟡 (infrastructure exists)

**Notes:** Internal user CRUD ([backend/internal/user/](../backend/internal/user/)) has many of the right primitives. Mapping them to a SCIM facade with PATCH-op semantics is the minimum lift.

---

## 5. WebAuthn / FIDO2 (W3C + FIDO Alliance)

| Sub-requirement | Status | Notes |
|---|:-:|---|
| WebAuthn Level 2 conformance | 🔴 | No ceremony |
| CTAP 2.1 support | 🔴 | Library not integrated |
| Platform authenticator (synced passkey) | 🔴 | — |
| Platform authenticator (device-bound) | 🔴 | — |
| Roaming authenticator (YubiKey, Titan) | 🔴 | — |
| Cross-device (Hybrid Transport, QR) | 🔴 | — |
| CTAP1/U2F legacy support | 🔴 | — |
| Registration ceremony | 🔴 | `/v1/passkeys/register/begin` returns 501 |
| Authentication ceremony | 🔴 | `/v1/passkeys/login/begin` returns 501 |
| Challenge (≥128-bit random, single-use) | 🔴 | — |
| Relying Party ID binding | 🔴 | — |
| User handle (opaque) | 🔴 | — |
| Exclude credentials (dedup) | 🔴 | — |
| Resident-key (discoverable) preferred | 🔴 | — |
| User verification required (default) | 🔴 | — |
| Attestation (packed/tpm/android/apple/none) | 🔴 | — |
| Attestation verified against FIDO MDS3 | 🔴 | — |
| Sign-count validation (device-bound only) | 🔴 | — |
| BE/BS flag tracking | 🔴 | — |
| COSE key formats (ES256, RS256, EdDSA) | 🔴 | — |
| Conditional UI / autofill (mediation: conditional) | 🔴 | Frontend concern |
| Storage layer (passkey_credentials table) | ✅ | [backend/migrations/0011_passkeys.up.sql](../backend/migrations/0011_passkeys.up.sql) |
| List / delete passkey endpoints | ✅ | [backend/internal/passkey/passkey.go](../backend/internal/passkey/passkey.go) |
| FIDO Alliance FIDO2 Server Certification | 🔴 | Required before launch |

**Recommendation:** Integrate `github.com/go-webauthn/webauthn`. Pass the storage `auth.passkey_credentials` schema through unchanged.

---

## 6. TOTP / HOTP (RFC 6238 / RFC 4226)

| Sub-requirement | Status | Notes |
|---|:-:|---|
| HMAC-SHA1 baseline | ✅ | [backend/internal/platform/totp/totp.go](../backend/internal/platform/totp/totp.go) |
| HMAC-SHA256/SHA512 support | 🟡 | SHA1 only currently |
| 30-second time step | ✅ | |
| 6-digit OTP | ✅ | |
| ±1 step clock-drift tolerance | ✅ | |
| 160-bit secret (base32) | ✅ | |
| AES-256 secret encryption at rest | 🔴 | Stored plaintext in `auth.mfa_totp.secret` — roadmap requires AES-256 encryption |
| QR provisioning URI (otpauth://) | ✅ | Provided once at enrollment |
| Replay prevention (used codes tracked) | 🔴 | Not enforced — same code can be reused within window |
| Backup codes (10 × 10-digit, bcrypt-hashed) | ✅ | [backend/internal/mfa/mfa.go](../backend/internal/mfa/mfa.go) |

**Gap:** Encrypt secret at rest, add replay-prevention `used_codes` cache.

---

## 7. JWT (RFC 7519 + JWS RFC 7515 + JWE RFC 7516)

| Sub-requirement | Status | Notes |
|---|:-:|---|
| Asymmetric signing for public-facing tokens (RS256/ES256) | 🟡 | Library supports it; default config HS256 |
| `none` algorithm rejection | ✅ | `golang-jwt/jwt/v5` rejects by default |
| Algorithm-confusion prevention | 🟡 | Need explicit per-route algorithm pinning audit |
| `kid` header always present | 🔴 | Not enforced in current issuer |
| `iss` claim validated against tenant URL | 🟡 | Set in token; downstream resource-server validation policy TBD |
| `aud` claim validated | 🟡 | Same |
| `exp` strict comparison | ✅ | Library default |
| `nbf` validation | ✅ | Library default |
| JWS compact serialization | ✅ | Library default |
| Minimum key sizes (RSA 2048, EC P-256) | ⚪ | Operational — depends on generated keys |

**Audit needed:** Confirm every signed token includes `kid`, and that production config flips to RS256/ES256.

---

## 8. PKCE (RFC 7636)

| Sub-requirement | Status | Notes |
|---|:-:|---|
| Mandatory for public clients | 🔴 | No `/authorize` to enforce |
| `code_challenge_method=S256` required | 🔴 | Same |
| `plain` method rejected | 🔴 | Same |
| 43–128 char `code_verifier` | 🔴 | Same |

---

## 9. Token Introspection (RFC 7662)

| Endpoint | Status |
|---|:-:|
| `POST /oauth/introspect` | 🔴 |

Not implemented.

---

## 10. Token Revocation (RFC 7009)

| Endpoint | Status |
|---|:-:|
| `POST /oauth/revoke` | 🔴 |
| Idempotent (200 on non-existent token) | 🔴 |
| Revocation propagation < 60 s | 🟡 — sessions/refresh revoke ≤ 60 s; no general endpoint |

---

## 11. Magic Links / Email OTP (Internal Standard)

| Sub-requirement | Status | Notes |
|---|:-:|---|
| JWT-based magic-link format | 🟡 | Current uses opaque token (32-byte) + DB lookup — equivalent security, different format |
| 15-minute link expiry | ✅ | [backend/internal/recovery/recovery.go](../backend/internal/recovery/recovery.go) |
| Single-use enforcement | ✅ | `used_at` timestamp |
| Nonce validation (server-side) | ✅ | Token hash stored, compared on use |
| Rate limit (5 per email per hour) | 🟡 | Per-IP rate limit only; per-email not implemented |
| Email OTP fallback (6-digit) | ✅ | [backend/internal/verification/](../backend/internal/verification/) |
| Delivery provider (SendGrid primary, SES failover) | 🔴 | Currently `LogSender` (stdout only) |

---

## 12. SMS OTP

| Sub-requirement | Status | Notes |
|---|:-:|---|
| 6-digit OTP | ✅ | Verification flow |
| 10-minute expiry | ✅ | |
| Cryptographically random | ✅ | |
| Rate limit (5/hour/phone, exp backoff after 3 fails) | 🟡 | Per-IP only; per-phone not implemented |
| Replay prevention | ✅ | `used_at` |
| Phone-verification prerequisite for MFA | 🟡 | Verification flow exists; MFA-step-up integration missing |
| Delivery provider (Twilio primary, SNS failover) | 🔴 | LogSender only |
| NIST SP 800-63B AAL2 documentation | 🔴 | Not documented |

---

## 13. M2M / Client Credentials + API Keys

**OAuth 2.0 Client Credentials:**

| Sub-requirement | Status | Notes |
|---|:-:|---|
| `client_credentials` grant | ✅ | [backend/internal/principal/principal.go](../backend/internal/principal/principal.go) |
| client_secret_post / basic / private_key_jwt | 🟡 | secret_post + basic ✅, private_key_jwt 🔴 |
| Explicit scope per service account | ✅ | `scopes` column on `auth.service_principals` |
| Short-lived JWT (1 hr default) | ✅ | TTL configurable |
| No refresh token | ✅ | Correct — clients re-auth on expiry |
| 32-byte cryptographically random secret | ✅ | |
| Dual-active secrets during rotation | 🟡 | Multiple principals possible; per-principal dual-secret not implemented |
| Per-tenant isolation | ✅ | tenant_id required |

**Qeetid API Keys:**

| Sub-requirement | Status | Notes |
|---|:-:|---|
| Key format `qf_{env}_{32-byte}` | 🟡 | Currently `qk_<prefix>.<secret>` — needs `qf_live_` / `qf_test_` prefix rename |
| HMAC-SHA256 hash storage | 🟡 | bcrypt hash used — change to HMAC-SHA256 per spec |
| Raw key shown once only | ✅ | |
| Prefix in plaintext (8 chars) | ✅ | |
| Per-key scoping | ✅ | |
| Optional expiry per key | ✅ | |
| Immediate revocation (< 60 s) | ✅ | |
| Rotation with overlap window | 🟡 | Multiple keys ok; explicit rotation flow not exposed |
| Env separation (test cannot access prod) | 🔴 | No environment scoping yet |
| Per-call usage logging | 🟡 | last_used_at only; per-call audit event not emitted |
| Secret-scanning program (GitHub/GitLab leak detection) | 🔴 | — |

---

## 14–18. Post-Launch & Extended Protocols

| Protocol | Status | Target |
|---|:-:|---|
| 14. DPoP (RFC 9449) | ⚪ | 3 months post-launch |
| 15. PAR (RFC 9126) | ⚪ | 3 months post-launch |
| 16. RAR (RFC 9396) | ⚪ | v2.0 |
| 17. Device Authorization (RFC 8628) | ⚪ | 6 months post-launch |
| 18. LDAP (RFC 4510–4519) | ⚪ | v1.5 |

---

## Certification Status

| Certification | Required | Status | Owner |
|---|---|:-:|---|
| OpenID Foundation Basic OP | Before launch | 🔴 | QA Lead + Eng |
| FIDO Alliance FIDO2 Server | Before launch | 🔴 | QA Lead + Eng |
| SAML 2.0 interop (Entra ID, Okta, Google) | Before launch | 🔴 | QA + SA |
| SCIM 2.0 (Okta SCIM validator) | Before launch | 🔴 | QA + Eng |
| OAuth 2.0 / RFC 9700 internal audit | Before launch | 🔴 | Security + QA |
| JWT (jwt.io + custom suite) | Before launch | 🔴 | Security + QA |

---

## Library Selection — Current vs Recommended

| Need | Recommendation (Phase 1 doc) | Current |
|---|---|---|
| JWT | `go-jose` | `github.com/golang-jwt/jwt/v5` (acceptable equivalent) |
| WebAuthn | FIDO Alliance reference | None — need `github.com/go-webauthn/webauthn` |
| SAML | Active, audited (e.g. `crewjam/saml`) | None |
| OAuth client | `golang.org/x/oauth2` for social | None |
| Password hashing | Argon2id (`golang.org/x/crypto/argon2`) | bcrypt — migrate |
| HMAC / random | stdlib | stdlib ✅ |

---

## Document Status

Generated: 2026-05-25.
Source: [Qeetid — Protocol Requirements Document](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs/phase-1) v1.0.
