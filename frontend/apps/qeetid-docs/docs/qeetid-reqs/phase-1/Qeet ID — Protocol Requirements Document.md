# Qeet ID — Protocol Requirements Document

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Protocol Requirements Document |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Solution Architect |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the complete protocol requirements for the Qeet ID Authentication and Authorization platform. It specifies every identity protocol that Qeet ID must implement, the technical conformance level required, the flows supported within each protocol, the security constraints that govern each implementation, and the inter-protocol dependencies that the engineering team must account for during system design.

Qeet ID is fundamentally a protocol platform. Every product line — Qeet ID Auth, Qeet ID ID, Qeet ID Access, Qeet ID Guard, Qeet ID Connect, and Qeet ID Keys — ultimately expresses its value through correct, secure, and interoperable protocol implementations. A flawed protocol implementation is not a bug — it is a security vulnerability and a compliance failure simultaneously.

This document is the authoritative reference for the Solution Architect, Security Architect, Backend Engineering Lead, and QA Lead during Phase 2 (System Design), Phase 4 (Development), and Phase 6 (Testing). No protocol implementation decision that deviates from the requirements stated here may proceed without a formal Architecture Decision Record (ADR) reviewed and signed off by the Solution Architect and CISO.

---

### 3. Protocol Portfolio Overview

### 3.1 Protocol Stack Summary

| # | Protocol | Standard Body | Version | Category | MVP | Tier |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | OAuth 2.0 | IETF | RFC 6749 + RFC 9700 (2.1 alignment) | Authorization Framework | Yes | Core |
| 2 | OpenID Connect (OIDC) | OpenID Foundation | Core 1.0 + Discovery 1.0 + Dynamic Registration 1.0 | Authentication Layer | Yes | Core |
| 3 | SAML 2.0 | OASIS | SAML 2.0 (2005) | Enterprise Federation | Yes | Core |
| 4 | SCIM 2.0 | IETF | RFC 7642 / 7643 / 7644 | Identity Provisioning | Yes | Core |
| 5 | WebAuthn / FIDO2 | W3C + FIDO Alliance | WebAuthn Level 2 + CTAP 2.1 | Passwordless Authentication | Yes | Core |
| 6 | TOTP / HOTP | IETF | RFC 6238 / RFC 4226 | Multi-Factor Authentication | Yes | Core |
| 7 | LDAP | IETF | RFC 4510–4519 (LDAPv3) | Directory Federation | No (v1.5) | Extended |
| 8 | JWT | IETF | RFC 7519 + RFC 7515 (JWS) + RFC 7516 (JWE) | Token Format | Yes | Core |
| 9 | PKCE | IETF | RFC 7636 | OAuth Security Extension | Yes | Core |
| 10 | DPoP | IETF | RFC 9449 | Token Binding | No (Post-Launch) | Extended |
| 11 | PAR | IETF | RFC 9126 | OAuth Security Extension | No (Post-Launch) | Extended |
| 12 | RAR | IETF | RFC 9396 | OAuth Rich Authorization | No (v2.0) | Extended |
| 13 | Token Introspection | IETF | RFC 7662 | Token Validation | Yes | Core |
| 14 | Token Revocation | IETF | RFC 7009 | Token Lifecycle | Yes | Core |
| 15 | OAuth 2.0 Device Authorization | IETF | RFC 8628 | IoT / CLI Auth | No (Post-Launch) | Extended |
| 16 | Magic Links / OTP (Email) | Internal Standard | Qeet ID Protocol Spec | Passwordless Authentication | Yes | Core |
| 17 | SMS OTP | Industry Practice | NIST SP 800-63B | Multi-Factor Authentication | Yes | Core |
| 18 | M2M / Client Credentials + API Keys | IETF + Internal | RFC 6749 §4.4 + Qeet ID Keys Spec | Machine-to-Machine Auth | Yes | Core |

---

### 3.2 Protocol Dependency Map

`WebAuthn / FIDO2  ──────────────────────────────────────────────────────────────┐
TOTP / HOTP  ───────────────────────────────────────────────────────────────┐   │
Magic Links / SMS OTP  ─────────────────────────────────────────────────┐  │   │
                                                                          ▼  ▼   ▼
                                                              ┌─────────────────────┐
                                                              │   Qeet ID Auth       │
                                                              │   (Auth Engine)      │
                                                              └──────────┬──────────┘
                                                                         │
               ┌─────────────────────────────────────────────────────────┤
               ▼                    ▼                    ▼                ▼
        ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   ┌──────────────┐
        │  OAuth 2.0  │    │   SAML 2.0   │    │  SCIM 2.0   │   │     JWT      │
        │  + PKCE     │    │  (Connect)   │    │ (Provision) │   │  (Tokens)   │
        └──────┬──────┘    └──────────────┘    └──────────────┘   └──────────────┘
               │
        ┌──────▼──────┐
        │    OIDC     │
        │   Core 1.0  │
        └─────────────┘
               │
   ┌───────────┼──────────────┐
   ▼           ▼              ▼
Token      Token           Discovery
Introspect Revocation      Document
(RFC 7662) (RFC 7009)      (OIDC)`

### 4. OAuth 2.0

### 4.1 Overview

OAuth 2.0 is the authorization framework upon which the entire Qeet ID authorization layer is built. Every token issued by Qeet ID — whether for end-user authorization, machine-to-machine authentication, or API access — is governed by the OAuth 2.0 specification. Qeet ID's OAuth 2.0 implementation aligns with both RFC 6749 (OAuth 2.0) and the security best practices codified in RFC 9700 (OAuth 2.1 draft alignment), which deprecates unsafe flows from the original specification.

---

### 4.2 Grant Types — Supported at MVP

| # | Grant Type | RFC | Use Case | Supported at MVP | Notes |
| --- | --- | --- | --- | --- | --- |
| GR-01 | Authorization Code + PKCE | RFC 6749 §4.1 + RFC 7636 | Web apps, mobile apps, SPAs | Yes | PKCE mandatory for all public clients — no exceptions |
| GR-02 | Client Credentials | RFC 6749 §4.4 | M2M / server-to-server / Qeet ID Keys | Yes | Used by Qeet ID Keys product line |
| GR-03 | Refresh Token | RFC 6749 §6 | Session continuity for all flows | Yes | Rotation mandatory on every use |
| GR-04 | Device Authorization | RFC 8628 | IoT devices, CLI tools, smart TVs | No (Post-Launch) | Deferred to post-MVP |

### 4.3 Grant Types — Explicitly Prohibited

| # | Grant Type | RFC | Reason for Prohibition |
| --- | --- | --- | --- |
| PG-01 | Implicit Grant | RFC 6749 §4.2 | Deprecated — tokens exposed in browser history and referrer headers; replaced by Auth Code + PKCE |
| PG-02 | Resource Owner Password Credentials (ROPC) | RFC 6749 §4.3 | Deprecated — requires client to handle user credentials directly; violates separation of trust |

---

### 4.4 Authorization Server Endpoints

| # | Endpoint | Path | Description | MVP |
| --- | --- | --- | --- | --- |
| EP-01 | Authorization Endpoint | /oauth/authorize | Initiates authorization code flow; accepts response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method | Yes |
| EP-02 | Token Endpoint | /oauth/token | Exchanges authorization code for tokens; issues access tokens, refresh tokens, ID tokens | Yes |
| EP-03 | Token Introspection Endpoint | /oauth/introspect | Validates token and returns metadata — RFC 7662 | Yes |
| EP-04 | Token Revocation Endpoint | /oauth/revoke | Revokes access or refresh tokens — RFC 7009 | Yes |
| EP-05 | Authorization Server Metadata | /.well-known/oauth-authorization-server | RFC 8414 — machine-readable server metadata | Yes |
| EP-06 | Pushed Authorization Request | /oauth/par | RFC 9126 — pre-registers authorization request server-side | No (Post-Launch) |

---

### 4.5 Token Requirements

| # | Token Type | Format | Signing Algorithm | Expiry | Storage | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| TK-01 | Access Token | JWT (RFC 7519) | RS256 or ES256 | 15 minutes (default); configurable per tenant from 5 min to 1 hour | Never stored server-side after issuance | Short-lived by design — reduces window of token misuse |
| TK-02 | Refresh Token | Opaque string | HMAC-SHA256 reference | 30 days (default); configurable per tenant from 1 day to 90 days | Stored as HMAC-SHA256 hash — never raw | Must be rotated on every use; previous token immediately invalidated |
| TK-03 | ID Token | JWT (RFC 7519) | RS256 or ES256 | 1 hour | Never stored — client-side only | Issued only via OIDC flows; not an access credential |
| TK-04 | Client Credentials Access Token | JWT (RFC 7519) | RS256 or ES256 | 1 hour (default); configurable per application | Never stored server-side | Scoped to specific API resources; no refresh token issued for client credentials |

### 4.6 Security Requirements — OAuth 2.0

| # | Requirement | Description | Priority |
| --- | --- | --- | --- |
| OS-01 | PKCE mandatory for all public clients | code_challenge and code_challenge_method=S256 required; plain method not accepted | P1 — Launch Blocker |
| OS-02 | State parameter validation | state parameter required and validated on callback — CSRF protection | P1 — Launch Blocker |
| OS-03 | Exact redirect URI matching | Redirect URI must match the pre-registered URI exactly — no wildcard, no partial match | P1 — Launch Blocker |
| OS-04 | Authorization code single use | Authorization code invalidated immediately after first use; duplicate use returns error and triggers alert | P1 — Launch Blocker |
| OS-05 | Authorization code expiry | Authorization code expires after 60 seconds maximum | P1 — Launch Blocker |
| OS-06 | Refresh token rotation | New refresh token issued on every use; previous token invalidated synchronously | P1 — Launch Blocker |
| OS-07 | Refresh token reuse detection | Reuse of an already-rotated refresh token triggers session revocation and security alert | P1 — Launch Blocker |
| OS-08 | Token endpoint rate limiting | Rate limiting on /oauth/token per client_id and per IP — brute force prevention | P1 — Launch Blocker |
| OS-09 | Client secret storage | Client secrets stored as bcrypt or Argon2id hashes — never in plaintext | P1 — Launch Blocker |
| OS-10 | Scope minimisation | Access tokens issued with minimum requested scopes — no implicit scope elevation | P1 — Launch Blocker |
| OS-11 | Token audience validation | aud claim in access token strictly validated by resource server — tokens not usable cross-resource | P1 — Launch Blocker |
| OS-12 | TLS enforcement on all endpoints | All OAuth endpoints require TLS 1.2 minimum; HTTP requests rejected with 400 | P1 — Launch Blocker |
| OS-13 | Client authentication on token endpoint | Confidential clients must authenticate with client_secret_post or client_secret_basic; public clients validated by PKCE only | P1 — Launch Blocker |
| OS-14 | No token in query string | Access tokens must never be passed as URL query parameters — Authorization header only | P1 — Launch Blocker |
| OS-15 | Mix-up attack prevention | iss parameter validated on authorization response to prevent IdP mix-up attacks | P2 — Pre-Launch |

---

### 4.7 Scope Design

| Scope | Description | Applicable Grant Types |
| --- | --- | --- |
| openid | Requests OIDC ID token — minimum scope for OIDC flows | Auth Code |
| profile | Returns standard profile claims: name, given_name, family_name, picture, website | Auth Code |
| email | Returns email and email_verified claims | Auth Code |
| phone | Returns phone_number and phone_number_verified claims | Auth Code |
| address | Returns address claim | Auth Code |
| offline_access | Requests refresh token issuance | Auth Code |
| [resource]:[action] | Custom resource scopes — e.g. documents:read, users:write — defined per application | All |
| qeetify:admin | Qeet ID platform administration scope — internal use only | Client Credentials |
| qeetify:scim | SCIM provisioning access — enterprise provisioning integrations | Client Credentials |
| qeetify:audit | Audit log read access | Client Credentials |

---

### 5. OpenID Connect (OIDC)

### 5.1 Overview

OpenID Connect is the authentication layer built on top of OAuth 2.0. Where OAuth 2.0 defines authorization (what a client is allowed to do), OIDC defines authentication (who the user is). Qeet ID implements OIDC Core 1.0 as the primary standard for user authentication across all flows. Every application integrating Qeet ID Auth for user login does so via OIDC — either directly using the protocol or via Qeet ID's SDKs which abstract the protocol complexity.

Qeet ID must achieve OpenID Foundation Certification for the Basic OP (OpenID Provider) profile before production launch. Certification for the Implicit OP and Hybrid OP profiles is not required as those flows are deprecated in Qeet ID's security model.

---

### 5.2 OIDC Specifications in Scope

| # | Specification | Version | Status | MVP |
| --- | --- | --- | --- | --- |
| OI-SPEC-01 | OpenID Connect Core 1.0 | Final | Mandatory | Yes |
| OI-SPEC-02 | OpenID Connect Discovery 1.0 | Final | Mandatory | Yes |
| OI-SPEC-03 | OpenID Connect Dynamic Client Registration 1.0 | Final | Recommended | Yes |
| OI-SPEC-04 | OpenID Connect Session Management 1.0 | Final | Recommended | Post-Launch |
| OI-SPEC-05 | OpenID Connect Front-Channel Logout 1.0 | Final | Recommended | Post-Launch |
| OI-SPEC-06 | OpenID Connect Back-Channel Logout 1.0 | Final | Recommended | Post-Launch |
| OI-SPEC-07 | FAPI 2.0 (Financial-grade API) | Draft | Optional | v2.0 |

### 5.3 Discovery Document Requirements

The OIDC Discovery document published at `/.well-known/openid-configuration` must include all of the following fields:

| # | Field | Value / Requirement |
| --- | --- | --- |
| DC-01 | issuer | Exact HTTPS URL of the Qeet ID tenant — must match iss in all tokens |
| DC-02 | authorization_endpoint | Full URL to /oauth/authorize |
| DC-03 | token_endpoint | Full URL to /oauth/token |
| DC-04 | userinfo_endpoint | Full URL to /oidc/userinfo |
| DC-05 | jwks_uri | Full URL to /.well-known/jwks.json |
| DC-06 | registration_endpoint | Full URL to /oidc/register (dynamic client registration) |
| DC-07 | scopes_supported | openid, profile, email, phone, address, offline_access |
| DC-08 | response_types_supported | code only — implicit and hybrid excluded |
| DC-09 | grant_types_supported | authorization_code, client_credentials, refresh_token |
| DC-10 | subject_types_supported | public, pairwise |
| DC-11 | id_token_signing_alg_values_supported | RS256, ES256 |
| DC-12 | token_endpoint_auth_methods_supported | client_secret_post, client_secret_basic, private_key_jwt, none (public clients) |
| DC-13 | claims_supported | All standard OIDC claims plus Qeet ID custom claims |
| DC-14 | code_challenge_methods_supported | S256 only — plain not supported |
| DC-15 | end_session_endpoint | Full URL to /oidc/logout |
| DC-16 | revocation_endpoint | Full URL to /oauth/revoke |
| DC-17 | introspection_endpoint | Full URL to /oauth/introspect |
| DC-18 | request_parameter_supported | true — JAR (JWT-secured authorization requests) |
| DC-19 | pushed_authorization_request_endpoint | Full URL to /oauth/par (Post-Launch) |
| DC-20 | acr_values_supported | urn:qeetify:acr:1 (password), urn:qeetify:acr:2 (MFA), urn:qeetify:acr:3 (passkey) |

---

### 5.4 ID Token Requirements

| # | Claim | Type | Required | Description |
| --- | --- | --- | --- | --- |
| ID-01 | iss | String | Mandatory | Issuer — exact HTTPS URL of Qeet ID tenant |
| ID-02 | sub | String | Mandatory | Subject — opaque, stable user identifier unique within issuer |
| ID-03 | aud | String / Array | Mandatory | Audience — client_id of the relying party; must be validated |
| ID-04 | exp | NumericDate | Mandatory | Expiration — token must be rejected after this time |
| ID-05 | iat | NumericDate | Mandatory | Issued at — token issue timestamp |
| ID-06 | auth_time | NumericDate | Conditional | Time of authentication — required when max_age is requested |
| ID-07 | nonce | String | Conditional | Must be present when nonce provided in authorization request; must match exactly |
| ID-08 | acr | String | Recommended | Authentication Context Class Reference — indicates authentication strength |
| ID-09 | amr | Array | Recommended | Authentication Methods References — e.g. ["pwd"], ["otp"], ["webauthn"] |
| ID-10 | azp | String | Conditional | Authorized party — when audience is a single client |
| ID-11 | at_hash | String | Recommended | Access token hash — half of the SHA-256 hash of the access token |
| ID-12 | c_hash | String | Conditional | Code hash — half of the SHA-256 hash of the authorization code |

---

### 5.5 UserInfo Endpoint Requirements

| # | Claim | Scope Required | Type | Notes |
| --- | --- | --- | --- | --- |
| UI-01 | sub | openid | String | Always returned — must match sub in ID token |
| UI-02 | name | profile | String | Full display name |
| UI-03 | given_name | profile | String | First name |
| UI-04 | family_name | profile | String | Last name |
| UI-05 | middle_name | profile | String | Middle name |
| UI-06 | nickname | profile | String | Casual name |
| UI-07 | preferred_username | profile | String | Shorthand name or username |
| UI-08 | profile | profile | String | URL to user's profile page |
| UI-09 | picture | profile | String | URL to user's profile photo |
| UI-10 | website | profile | String | URL to user's website |
| UI-11 | gender | profile | String |  |
| UI-12 | birthdate | profile | String | YYYY-MM-DD format |
| UI-13 | zoneinfo | profile | String | IANA time zone — e.g. Europe/London |
| UI-14 | locale | profile | String | BCP47 language tag — e.g. en-GB |
| UI-15 | updated_at | profile | NumericDate | Time profile was last updated |
| UI-16 | email | email | String | Primary email address |
| UI-17 | email_verified | email | Boolean | Whether email has been verified by Qeet ID |
| UI-18 | phone_number | phone | String | E.164 format — e.g. +447911123456 |
| UI-19 | phone_number_verified | phone | Boolean | Whether phone number has been verified |
| UI-20 | address | address | JSON Object | Structured address — street_address, locality, region, postal_code, country |

### 5.6 Custom Qeet ID Claims

| # | Claim | Namespace | Description | Included In |
| --- | --- | --- | --- | --- |
| CU-01 | qeetify/org_id | [https://qeetify.com/claims](https://qeetify.com/claims) | Organisation (tenant) ID the user belongs to | Access Token + ID Token |
| CU-02 | qeetify/org_name | [https://qeetify.com/claims](https://qeetify.com/claims) | Organisation display name | ID Token |
| CU-03 | qeetify/roles | [https://qeetify.com/claims](https://qeetify.com/claims) | Array of RBAC roles assigned to the user within the organisation | Access Token |
| CU-04 | qeetify/permissions | [https://qeetify.com/claims](https://qeetify.com/claims) | Array of explicit permissions granted to the user | Access Token |
| CU-05 | qeetify/plan | [https://qeetify.com/claims](https://qeetify.com/claims) | Subscription plan of the tenant — free, growth, enterprise | Access Token |
| CU-06 | qeetify/mfa_enrolled | [https://qeetify.com/claims](https://qeetify.com/claims) | Boolean — whether user has at least one MFA method enrolled | ID Token |
| CU-07 | qeetify/passkey_enrolled | [https://qeetify.com/claims](https://qeetify.com/claims) | Boolean — whether user has a registered passkey | ID Token |
| CU-08 | qeetify/user_id | [https://qeetify.com/claims](https://qeetify.com/claims) | Qeet ID internal user UUID — stable across all tenants for the same user | Access Token + ID Token |

---

### 5.7 Authentication Context Class References (ACR Values)

| ACR Value | Description | Methods That Qualify |
| --- | --- | --- |
| urn:qeetify:acr:0 | No authentication confidence — unauthenticated or anonymous | None |
| urn:qeetify:acr:1 | Single-factor authentication | Password only; magic link only; social login only |
| urn:qeetify:acr:2 | Multi-factor authentication | Password + TOTP; password + SMS OTP; password + email OTP |
| urn:qeetify:acr:3 | Passkey / hardware-backed authentication | WebAuthn / FIDO2 passkey; hardware security key |
| urn:qeetify:acr:4 | Step-up authenticated (session escalation) | Any ACR ≥ 2 after step-up re-authentication |

---

### 5.8 JWKS Endpoint Requirements

| # | Requirement | Description |
| --- | --- | --- |
| JW-01 | Key format | All keys published as JSON Web Key Set (JWKS) per RFC 7517 |
| JW-02 | Signing algorithm | RS256 (RSA 2048-bit minimum) and ES256 (ECDSA P-256) keys published |
| JW-03 | Key identifier | kid claim present in every key and every JWT header — enables key lookup without full set verification |
| JW-04 | Key rotation | Minimum two active signing keys published at all times — current key and previous key during rotation window |
| JW-05 | Rotation schedule | JWT signing keys rotated every 90 days; rotation must not break in-flight tokens |
| JW-06 | Cache-Control headers | JWKS endpoint responds with Cache-Control: max-age=3600 — reduces load while enabling timely key rotation pickup |
| JW-07 | Retired key retention | Retired signing keys retained in JWKS for 24 hours post-rotation to allow validation of tokens issued pre-rotation |

---

### 6. SAML 2.0

### 6.1 Overview

SAML 2.0 is the dominant enterprise federation protocol. It is the protocol that large organisations use to connect their workforce Identity Provider — most commonly Microsoft Entra ID, Okta, or Ping Identity — to external applications. Without SAML 2.0 support, Qeet ID cannot close enterprise deals. It is the protocol Sandra (Enterprise IT Admin) will evaluate first, and Omar (CISO) will expect to be implemented without exceptions or workarounds.

Qeet ID implements SAML 2.0 both as a **Service Provider (SP)** — to allow users to log in to Qeet ID-protected applications via their enterprise IdP — and as an **Identity Provider (IdP)** — to allow applications to use Qeet ID as their SAML IdP. Both roles must be fully implemented at MVP.

---

### 6.2 SAML 2.0 Profiles in Scope

| # | Profile | Role | Description | MVP |
| --- | --- | --- | --- | --- |
| SP-PROF-01 | Web Browser SSO Profile — SP-Initiated | Service Provider | User redirected from SP to IdP for authentication | Yes |
| SP-PROF-02 | Web Browser SSO Profile — IdP-Initiated | Service Provider | User initiates login from IdP portal; assertion posted to SP | Yes |
| SP-PROF-03 | Web Browser SSO Profile — SP-Initiated | Identity Provider | Qeet ID as IdP — relying party redirects to Qeet ID for SAML authentication | Yes |
| SP-PROF-04 | Single Logout Profile (SLO) — SP-Initiated | Both | SP initiates global logout across all active sessions | Yes |
| SP-PROF-05 | Single Logout Profile (SLO) — IdP-Initiated | Both | IdP terminates all SP sessions on logout | Yes |
| SP-PROF-06 | Enhanced Client or Proxy (ECP) Profile | Service Provider | SOAP-based — for non-browser clients | No (v1.5) |
| SP-PROF-07 | Artifact Resolution Profile | Both | Artifact binding for assertion retrieval | No (v1.5) |

---

### 6.3 SAML Bindings in Scope

| # | Binding | Description | MVP |
| --- | --- | --- | --- |
| SB-01 | HTTP Redirect Binding | AuthnRequest transmitted as URL-encoded deflate-compressed signed query parameter | Yes |
| SB-02 | HTTP POST Binding | Assertions and responses transmitted as Base64-encoded POST body parameters | Yes |
| SB-03 | HTTP Artifact Binding | Reference token exchanged via back-channel artifact resolution | No (v1.5) |
| SB-04 | SOAP Binding | Used for ECP profile and back-channel communications | No (v1.5) |

### 6.4 AuthnRequest Requirements

| # | Requirement | Description | Mandatory |
| --- | --- | --- | --- |
| AR-01 | ID attribute | Unique identifier for every AuthnRequest — format _[random-uuid] | Yes |
| AR-02 | IssueInstant | UTC timestamp of request generation — must be within 5-minute clock skew tolerance | Yes |
| AR-03 | Issuer | SP EntityID — must match the SP metadata registered with the IdP | Yes |
| AR-04 | AssertionConsumerServiceURL | URL where IdP posts the response — validated against registered ACS URLs | Yes |
| AR-05 | ProtocolBinding | urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST for ACS | Yes |
| AR-06 | RequestedAuthnContext | Authentication strength requested — maps to Qeet ID ACR values | Recommended |
| AR-07 | NameIDPolicy | Format requested — persistent, transient, or email | Recommended |
| AR-08 | ForceAuthn | Boolean — forces re-authentication even if valid IdP session exists | Optional |
| AR-09 | IsPassive | Boolean — no UI interaction permitted | Optional |
| AR-10 | Signature | AuthnRequest signed with SP private key when required by IdP configuration | Conditional |

---

### 6.5 SAML Response & Assertion Requirements

| # | Requirement | Description | Mandatory |
| --- | --- | --- | --- |
| RA-01 | Response signature | Response or Assertion must be signed — both recommended | Yes |
| RA-02 | Signature algorithm | RSA-SHA256 minimum — RSA-SHA1 rejected; RSA-SHA256 and RSA-SHA512 accepted | Yes |
| RA-03 | Certificate validation | Signing certificate validated against IdP metadata — expired or untrusted certificates rejected | Yes |
| RA-04 | InResponseTo | Must match the ID of the originating AuthnRequest — prevents unsolicited assertion injection | Yes |
| RA-05 | Assertion validity window | NotBefore and NotOnOrAfter validated — maximum 5-minute window; 2-minute clock skew tolerance | Yes |
| RA-06 | Audience restriction | Audience element must contain Qeet ID SP EntityID — cross-audience assertions rejected | Yes |
| RA-07 | AssertionID tracking | Every AssertionID stored for the duration of validity window — duplicate assertions rejected | Yes |
| RA-08 | SubjectConfirmation | Method must be urn:oasis:names:tc:SAML:2.0:cm:bearer | Yes |
| RA-09 | SubjectConfirmationData | Recipient URL matches ACS URL; NotOnOrAfter validated; InResponseTo present | Yes |
| RA-10 | NameID | NameID format, value, and qualifier extracted and mapped to Qeet ID user profile | Yes |
| RA-11 | Assertion encryption | AES-256-CBC or AES-128-GCM encryption of assertions when configured by enterprise customer | Recommended |
| RA-12 | XML signature wrapping protection | Full DOM validation applied before signature verification — XML signature wrapping attacks prevented | Yes |
| RA-13 | XXE prevention | XML parser configured with external entity expansion disabled | Yes |

---

### 6.6 Attribute Mapping

Qeet ID must support flexible attribute mapping from SAML assertions to the Qeet ID user profile model.

| # | SAML Attribute (Common) | Mapped Qeet ID Field | Configurable Per Tenant |
| --- | --- | --- | --- |
| AM-01 | NameID (any format) | sub / external_id | No — always mapped |
| AM-02 | [http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress](http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress) | email | Yes |
| AM-03 | [http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname](http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname) | given_name | Yes |
| AM-04 | [http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname](http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname) | family_name | Yes |
| AM-05 | [http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name](http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name) | name | Yes |
| AM-06 | [http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone](http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone) | phone_number | Yes |
| AM-07 | [http://schemas.microsoft.com/ws/2008/06/identity/claims/groups](http://schemas.microsoft.com/ws/2008/06/identity/claims/groups) | groups → Qeet ID roles | Yes |
| AM-08 | [http://schemas.microsoft.com/ws/2008/06/identity/claims/role](http://schemas.microsoft.com/ws/2008/06/identity/claims/role) | direct role assignment | Yes |
| AM-09 | Custom attributes (any namespace) | Custom claims in user metadata | Yes — via tenant attribute mapping configuration |

---

### 6.7 SAML Metadata Requirements

| # | Requirement | Description |
| --- | --- | --- |
| MD-01 | SP Metadata endpoint | Qeet ID publishes SAML SP metadata at /saml/metadata — downloadable XML |
| MD-02 | EntityID format | Qeet ID SP EntityID follows format: https://[tenant].qeetify.com/saml/metadata |
| MD-03 | ACS URL in metadata | AssertionConsumerService URL included — HTTP-POST binding |
| MD-04 | SLO URL in metadata | SingleLogoutService URL included — HTTP-POST and HTTP-Redirect bindings |
| MD-05 | SP signing certificate | SP public key certificate included in metadata — used by IdP to verify signed AuthnRequests |
| MD-06 | SP encryption certificate | SP public key certificate for assertion encryption included separately |
| MD-07 | Certificate rotation | Metadata supports dual-certificate periods during SP certificate rotation — no downtime |
| MD-08 | IdP metadata import | Qeet ID admin dashboard accepts IdP metadata XML — manual upload and URL-based auto-import |
| MD-09 | Metadata validation | Imported IdP metadata validated for completeness and certificate validity before activation |

### 7. SCIM 2.0

### 7.1 Overview

SCIM 2.0 (System for Cross-domain Identity Management) is the enterprise standard for automated user provisioning and deprovisioning. It is the protocol that allows an enterprise customer's HR system, Identity Provider, or directory (Okta, Entra ID, Workday) to automatically create, update, and deactivate users in Qeet ID as employees join, change roles, or leave the organisation. Without SCIM, enterprise customers must manage user lifecycle manually — a source of access over-provisioning, delayed deprovisioning, and security risk.

SCIM is a core requirement for Sandra (Enterprise IT Admin) and a standard evaluation criterion for Omar (CISO). Its absence disqualifies Qeet ID from mid-market and enterprise procurement processes.

---

### 7.2 SCIM Endpoints

| # | Endpoint | Method(s) | Description | MVP |
| --- | --- | --- | --- | --- |
| SC-EP-01 | /scim/v2/Users | GET, POST | List users; create user | Yes |
| SC-EP-02 | /scim/v2/Users/{id} | GET, PUT, PATCH, DELETE | Retrieve, replace, update, delete user | Yes |
| SC-EP-03 | /scim/v2/Groups | GET, POST | List groups; create group | Yes |
| SC-EP-04 | /scim/v2/Groups/{id} | GET, PUT, PATCH, DELETE | Retrieve, replace, update, delete group | Yes |
| SC-EP-05 | /scim/v2/ServiceProviderConfig | GET | Returns SCIM capability metadata | Yes |
| SC-EP-06 | /scim/v2/ResourceTypes | GET | Returns supported resource types | Yes |
| SC-EP-07 | /scim/v2/Schemas | GET | Returns supported schemas | Yes |
| SC-EP-08 | /scim/v2/Bulk | POST | Batch create/update/delete operations | No (Post-Launch) |

---

### 7.3 User Resource Schema

| # | Attribute | Type | Required | Description |
| --- | --- | --- | --- | --- |
| SU-01 | id | String | Yes | Qeet ID-assigned immutable user ID — returned on creation |
| SU-02 | externalId | String | No | External identifier from provisioning system (Okta user ID, Entra object ID) |
| SU-03 | userName | String | Yes | Unique identifier within tenant — typically email address |
| SU-04 | name.formatted | String | No | Full display name |
| SU-05 | name.familyName | String | Recommended | Last name |
| SU-06 | name.givenName | String | Recommended | First name |
| SU-07 | displayName | String | Recommended | Preferred display name |
| SU-08 | emails | Array | Yes | At least one email entry; primary flag required |
| SU-09 | phoneNumbers | Array | No | E.164 formatted phone numbers |
| SU-10 | active | Boolean | Yes | True = active user; False = suspended/deprovisioned |
| SU-11 | groups | Array | No | Group memberships — read-only on User resource; managed via Group resource |
| SU-12 | roles | Array | No | Qeet ID RBAC role assignments |
| SU-13 | meta.resourceType | String | Yes | Always "User" |
| SU-14 | meta.created | DateTime | Yes | ISO 8601 UTC — user creation timestamp |
| SU-15 | meta.lastModified | DateTime | Yes | ISO 8601 UTC — last modification timestamp |
| SU-16 | meta.location | URI | Yes | Full URL to the User resource |
| SU-17 | meta.version | String | Recommended | ETag-style version identifier for optimistic concurrency |

---

### 7.4 Group Resource Schema

| # | Attribute | Type | Required | Description |
| --- | --- | --- | --- | --- |
| SG-01 | id | String | Yes | Qeet ID-assigned immutable group ID |
| SG-02 | externalId | String | No | External group identifier from provisioning system |
| SG-03 | displayName | String | Yes | Group display name |
| SG-04 | members | Array | No | Array of member references — value (user ID) and display (user name) |
| SG-05 | meta.resourceType | String | Yes | Always "Group" |
| SG-06 | meta.created | DateTime | Yes | ISO 8601 UTC |
| SG-07 | meta.lastModified | DateTime | Yes | ISO 8601 UTC |
| SG-08 | meta.location | URI | Yes | Full URL to the Group resource |

### 7.5 SCIM PATCH Operations

PATCH operations are the most critical SCIM operations for enterprise provisioning. The most important use case is user deprovisioning — setting `active: false` must immediately terminate all active sessions for that user.

| # | PATCH Operation | path | value | Behaviour |
| --- | --- | --- | --- | --- |
| SP-01 | Deactivate user | active | false | Immediately terminates all active sessions; blocks all token refresh; suspends SCIM user record |
| SP-02 | Reactivate user | active | true | Re-enables login; existing SCIM record restored |
| SP-03 | Update email | emails[primary eq true].value | [new@email.com](mailto:new@email.com) | Updates primary email; triggers re-verification if configured |
| SP-04 | Update name | name.givenName / name.familyName | string | Updates user profile; reflected in OIDC UserInfo and ID token claims |
| SP-05 | Add group member | members | {value: userId} | Adds user to group; RBAC implications take effect immediately |
| SP-06 | Remove group member | members | {value: userId} | Removes user from group; RBAC permissions reduced immediately |
| SP-07 | Assign role | roles | {value: roleName} | Grants RBAC role — effective on next token issuance |
| SP-08 | Remove role | roles | {value: roleName} | Revokes RBAC role — existing tokens retain role until expiry |

---

### 7.6 SCIM Security Requirements

| # | Requirement | Description |
| --- | --- | --- |
| SS-01 | OAuth 2.0 bearer token authentication | All SCIM endpoints protected by OAuth 2.0 — client_credentials grant with qeetify:scim scope |
| SS-02 | TLS mandatory | All SCIM traffic over TLS 1.2 minimum — HTTP rejected |
| SS-03 | Tenant isolation | SCIM operations strictly scoped to the authenticated tenant — cross-tenant access returns 403 |
| SS-04 | Rate limiting | SCIM endpoints rate-limited per client — bulk provisioning bursts handled gracefully with 429 + Retry-After |
| SS-05 | Idempotency | POST operations return 409 Conflict if user already exists — no silent duplicate creation |
| SS-06 | Deprovisioning immediacy | active=false must terminate all sessions within 60 seconds — not eventual consistency |
| SS-07 | Audit logging | All SCIM operations logged — event type, actor (provisioner), target user/group, timestamp, result |

---

### 8. WebAuthn / FIDO2

### 8.1 Overview

WebAuthn (Web Authentication API) is the W3C specification that enables passkey and hardware security key authentication. FIDO2 is the umbrella term covering WebAuthn and the Client-to-Authenticator Protocol (CTAP 2.1). Together they enable phishing-resistant, passwordless authentication that is cryptographically bound to the origin — meaning credentials registered at qeetify.com can never be used to authenticate at a phishing domain.

Passkeys are the default authentication method at Qeet ID — not an optional feature, not a checkbox. This is a core product and architectural decision. Qeet ID positions itself as a passkey-first platform in a market where most competitors treat passkeys as an add-on.

---

### 8.2 Authenticator Types Supported

| # | Authenticator Type | Description | MVP |
| --- | --- | --- | --- |
| AT-01 | Platform Authenticator (Synced Passkey) | Built-in authenticator — Face ID, Touch ID, Windows Hello, Android biometric — credential synced via cloud (iCloud Keychain, Google Password Manager) | Yes |
| AT-02 | Platform Authenticator (Device-Bound) | Built-in authenticator — credential not synced; stays on device only | Yes |
| AT-03 | Roaming Authenticator (Hardware Key) | External FIDO2 security key — YubiKey, Titan Key — connected via USB, NFC, or BLE | Yes |
| AT-04 | Cross-Device Authentication (Hybrid Transport) | Phone used as authenticator for desktop browser — QR code scan flow | Yes |
| AT-05 | CTAP 1 / U2F Security Keys | Legacy hardware keys — WebAuthn layer provides backwards compatibility | Yes |

---

### 8.3 Registration Ceremony Requirements

| # | Requirement | Description |
| --- | --- | --- |
| WR-01 | Challenge generation | Server-generated challenge: minimum 128 bits of cryptographically random entropy; single-use |
| WR-02 | Relying Party ID | rpId bound to the registering origin's effective domain — cannot be a superdomain of the eTLD+1 |
| WR-03 | Relying Party name | Human-readable name included in credential creation options — displayed to user by authenticator UI |
| WR-04 | User handle | Unique, opaque user handle — must not contain PII; used for credential lookup without username |
| WR-05 | Exclude credentials | Previously registered credentials for the user passed in excludeCredentials — prevents duplicate registrations |
| WR-06 | Authenticator selection | Configurable per tenant — residentKey, userVerification, authenticatorAttachment requirements |
| WR-07 | Resident key (discoverableCredential) | Preferred by default — enables passwordless username-less flow at authentication |
| WR-08 | User verification | Required by default — biometric or PIN verification must occur during registration |
| WR-09 | Attestation | Supported attestation formats: packed, tpm, android-key, android-safetynet, fido-u2f, apple, none |
| WR-10 | Attestation verification | Attestation statement verified against FIDO Metadata Service (MDS3) for trust assessment |
| WR-11 | Public key storage | Credential public key, credential ID, AAGUID, sign count, backup eligibility (BE), and backup state (BS) flags stored |
| WR-12 | COSE key format | Credential public key stored in COSE format (RFC 8152) — supported algorithms: ES256 (P-256), RS256, EdDSA |

### 8.4 Authentication Ceremony Requirements

| # | Requirement | Description |
| --- | --- | --- |
| WA-01 | Challenge generation | Fresh server-generated challenge: minimum 128 bits of cryptographically random entropy; single-use |
| WA-02 | allowCredentials | List of acceptable credential IDs passed to navigator.credentials.get() for non-discoverable flows |
| WA-03 | User verification | Required by default — configurable per tenant to preferred or discouraged |
| WA-04 | Client data validation | clientDataJSON parsed and validated: type is webauthn.get, challenge matches, origin matches, tokenBinding checked |
| WA-05 | Authenticator data validation | rpIdHash validated against SHA-256 of rpId; flags checked: UP (user present) required; UV (user verified) checked per policy |
| WA-06 | Signature verification | Signature over authenticatorData + clientDataHash verified against stored public key using COSE algorithm |
| WA-07 | Sign count validation | storedSignCount must be less than authData.signCount for device-bound credentials — replay detection |
| WA-08 | Sign count — synced passkeys | Sign count of 0 is acceptable for synced passkeys (cloud-synced credentials do not maintain global counter) |
| WA-09 | Backup state handling | BS (backup state) and BE (backup eligible) flags tracked per credential — policy controls configurable per tenant |
| WA-10 | Cross-origin iframe | WebAuthn API calls from cross-origin iframes require allow="publickey-credentials-get" permission policy |

---

### 8.5 Passkey-First UX Requirements

These requirements bridge the protocol layer and the UX layer — they must be agreed between the Solution Architect and UX Designer before Phase 3 begins.

| # | Requirement | Description |
| --- | --- | --- |
| PK-01 | Passkey registration prompt at signup | After email verification, new users are immediately prompted to register a passkey before being shown any other screen |
| PK-02 | Conditional UI (autofill) | navigator.credentials.get() with mediation: conditional invoked on the login page — browser passkey suggestions appear natively in the email/username field |
| PK-03 | Discoverable credential default | Passkeys registered as discoverable (resident key) by default — enables username-less login |
| PK-04 | Cross-device QR flow | UI supports cross-device authentication — QR code displayed for users who want to authenticate with a different device |
| PK-05 | Fallback path | Password and OTP remain available as explicit fallback — not hidden, but not the default |
| PK-06 | Multiple passkey management | Users can register up to 10 passkeys per account — name them, view last used, delete individual passkeys from account settings |
| PK-07 | Passkey-first in SDKs | All Qeet ID SDKs expose passkey registration and authentication as the primary, first-documented method |

---

### 9. JWT — JSON Web Token

### 9.1 Overview

JWT is the token format that underpins every Qeet ID token type — access tokens, ID tokens, and internal service tokens. Correct JWT implementation is foundational. A misconfigured JWT implementation — accepting the none algorithm, trusting the alg header without server-side validation, or permitting RS256-to-HS256 algorithm confusion — is one of the most common and exploited authentication vulnerabilities in production systems.

---

### 9.2 JWT Signing Requirements

| # | Requirement | Description |
| --- | --- | --- |
| JT-01 | Asymmetric signing only for public-facing tokens | All access tokens and ID tokens signed with RS256 or ES256 — HS256 never used for tokens consumed by third-party resource servers |
| JT-02 | Algorithm header validation | Server always specifies and enforces the expected algorithm — alg header in received tokens never trusted blindly |
| JT-03 | None algorithm rejection | JWT library configured to reject tokens with alg: none — no exceptions |
| JT-04 | Algorithm confusion prevention | RS256 and HS256 never accepted on the same verification path — algorithm-specific verification logic enforced |
| JT-05 | Key ID (kid) | Every JWT includes a kid header parameter matching the signing key in the JWKS endpoint |
| JT-06 | Issuer claim (iss) | iss claim present and validated on every token — must match the tenant issuer URL exactly |
| JT-07 | Audience claim (aud) | aud claim present and validated — resource servers must validate aud before accepting token |
| JT-08 | Expiry validation | exp claim validated with strict comparison — expired tokens rejected; no grace period |
| JT-09 | Not-before validation | nbf claim validated when present — tokens rejected if processed before nbf |
| JT-10 | Compact serialization | All tokens issued in JWS compact serialization format — not JSON serialization |
| JT-11 | Minimum key sizes | RSA: 2048-bit minimum; ECDSA: P-256 minimum |

---

### 9.3 JWT Claims Validation Checklist (Resource Server Reference)

This checklist is published in Qeet ID documentation for developers building resource servers that validate Qeet ID access tokens.

| # | Validation Step | Description |
| --- | --- | --- |
| JV-01 | Verify signature | Fetch JWKS from jwks_uri in discovery document; verify signature using key matching kid header |
| JV-02 | Verify algorithm | Confirm alg is RS256 or ES256 — reject any other algorithm |
| JV-03 | Verify issuer | iss must match the Qeet ID tenant issuer URL exactly |
| JV-04 | Verify audience | aud must contain the resource server's identifier |
| JV-05 | Verify expiry | exp must be in the future — reject expired tokens |
| JV-06 | Verify not-before | If nbf is present, current time must be after nbf |
| JV-07 | Verify scope | Required scopes must be present in the scp or scope claim |
| JV-08 | Verify subject | sub must be present — identifies the user or service account |
| JV-09 | Check token revocation | High-sensitivity operations should verify token is not revoked via introspection endpoint |
|  |  |  |

### 10. MFA Protocol Requirements

### 10.1 TOTP — RFC 6238

| # | Requirement | Description |
| --- | --- | --- |
| TP-01 | Algorithm | HMAC-SHA1 (RFC 4226 baseline); HMAC-SHA256 and HMAC-SHA512 supported for compatible authenticator apps |
| TP-02 | Time step | 30 seconds (standard) |
| TP-03 | OTP length | 6 digits |
| TP-04 | Clock drift tolerance | ±1 time step (90-second total window) — balances usability and security |
| TP-05 | Secret generation | 160-bit random secret (20 bytes) generated per enrollment — Base32 encoded for display |
| TP-06 | Secret storage | TOTP seed encrypted with AES-256 at rest — never exposed after enrollment |
| TP-07 | QR code provisioning | otpauth:// URI format; QR code displayed once at enrollment; secret not displayable after enrollment completes |
| TP-08 | Replay prevention | Used OTP codes tracked within ±1 time step window — same code cannot be used twice |
| TP-09 | Backup codes | 8 single-use 10-digit backup codes generated at TOTP enrollment — stored as bcrypt hashes |
| TP-10 | Compatible apps | Google Authenticator, Authy, Microsoft Authenticator, 1Password, any RFC 6238-compliant TOTP app |

---

### 10.2 SMS OTP

| # | Requirement | Description |
| --- | --- | --- |
| SM-01 | OTP length | 6 digits |
| SM-02 | OTP expiry | 10 minutes |
| SM-03 | OTP entropy | Cryptographically random — not sequential, not predictable |
| SM-04 | Rate limiting | Maximum 5 OTP requests per phone number per hour; exponential backoff after 3 failed verifications |
| SM-05 | Replay prevention | OTP invalidated immediately after successful verification |
| SM-06 | Phone number verification | Phone number must be verified before SMS OTP is enabled for a user |
| SM-07 | Delivery provider | Twilio as primary provider — failover to AWS SNS (configured in Phase 2) |
| SM-08 | NIST guidance | SMS OTP implemented as per NIST SP 800-63B guidance — treated as restricted authenticator at AAL2 |
| SM-09 | SIM swap risk disclosure | Documented in security guidance — enterprise customers advised to enforce TOTP or WebAuthn for high-assurance contexts |

---

### 10.3 Email OTP / Magic Links

| # | Requirement | Description |
| --- | --- | --- |
| EO-01 | Magic link format | Signed JWT embedded in URL — contains user identifier, expiry, nonce, and tenant ID |
| EO-02 | Signing | Magic link JWT signed with RS256 using Qeet ID signing key |
| EO-03 | Link expiry | 15 minutes from generation |
| EO-04 | Single use | Link invalidated immediately on first click — second click returns 410 Gone |
| EO-05 | Email OTP fallback | 6-digit OTP alternative to link click — same expiry and single-use rules apply |
| EO-06 | Delivery provider | SendGrid as primary; AWS SES as failover |
| EO-07 | Nonce validation | Nonce stored server-side and validated on use — prevents link reuse even within expiry window |
| EO-08 | Rate limiting | Maximum 5 magic links per email address per hour |

---

### 11. Machine-to-Machine (M2M) — Qeet ID Keys

### 11.1 Protocol Design

M2M authentication in Qeet ID uses two complementary mechanisms. The first is OAuth 2.0 Client Credentials Grant — the standards-based approach where service accounts authenticate to the Qeet ID token endpoint with a client_id and client_secret to receive a short-lived JWT access token. The second is Qeet ID API Keys — a developer-friendly, opaque key model used for direct API authentication without the token exchange overhead.

---

### 11.2 OAuth 2.0 Client Credentials Requirements

| # | Requirement | Description |
| --- | --- | --- |
| CC-01 | Grant type | client_credentials — RFC 6749 §4.4 |
| CC-02 | Client authentication | client_secret_post, client_secret_basic, or private_key_jwt (RFC 7523) |
| CC-03 | Scope | Scopes explicitly defined per service account — no implicit scope inheritance |
| CC-04 | Access token format | Short-lived JWT — 1 hour default; configurable 5 minutes to 24 hours |
| CC-05 | No refresh token | Refresh tokens are not issued for client credentials grant — service must re-authenticate |
| CC-06 | Client secret strength | Client secrets generated as 32-byte cryptographically random values — Base64url encoded |
| CC-07 | Client secret rotation | Secret rotation supported without downtime — dual active secrets during rotation window |
| CC-08 | Service account isolation | Each service account scoped to a single tenant — no cross-tenant service accounts |

---

### 11.3 Qeet ID API Key Requirements

| # | Requirement | Description |
| --- | --- | --- |
| AK-01 | Key format | qf_{environment}_{32-byte-random} — e.g. qf_live_aBcDeFgH... — prefix enables key type identification and scanning |
| AK-02 | Key storage | API keys stored as HMAC-SHA256 hash — raw key shown exactly once at creation, never again |
| AK-03 | Key display | Full raw key shown exactly once in the dashboard at creation — must be copied immediately; no recovery |
| AK-04 | Key prefix storage | First 8 characters of raw key stored in plaintext for display and identification in dashboard — not sufficient to authenticate |
| AK-05 | Key scoping | Each API key scoped to specific permissions — no all-permissions master key |
| AK-06 | Key expiry | Optional expiry date configurable per key — expired keys rejected with 401 |
| AK-07 | Key revocation | Immediate revocation — revoked key rejected within 60 seconds of revocation action |
| AK-08 | Key rotation | Rotation creates new key before old key is revoked — overlap window configurable |
| AK-09 | Key environment separation | Live and test keys scoped to separate environments — test keys cannot access production resources |
| AK-10 | Usage logging | All API key usage logged — key prefix, endpoint accessed, IP address, timestamp, response code |
| AK-11 | Leak detection | Qeet ID operates a secret scanning program — GitHub, GitLab, and public repositories scanned for exposed Qeet ID API keys; owners notified and keys auto-revoked |

### 12. Protocol Conformance Testing

### 12.1 Conformance Test Requirements

| # | Protocol | Test Suite / Certification | Responsible | Required Before Launch |
| --- | --- | --- | --- | --- |
| CT-01 | OpenID Connect | OpenID Foundation Certification — Basic OP Profile | QA Lead + Engineering | Yes |
| CT-02 | FIDO2 / WebAuthn | FIDO Alliance FIDO2 Server Certification | QA Lead + Engineering | Yes |
| CT-03 | SAML 2.0 | Internal interoperability testing against Entra ID, Okta, Google Workspace, Ping Identity | QA + Solution Architect | Yes |
| CT-04 | SCIM 2.0 | SCIM compliance test suite (Okta SCIM validator + custom test suite) | QA + Engineering | Yes |
| CT-05 | OAuth 2.0 | RFC 6749 + RFC 9700 security checklist — internal audit | Security Architect + QA | Yes |
| CT-06 | JWT | jwt.io debugger + custom validation test suite — algorithm confusion tests, none algorithm rejection, key confusion | Security Engineer + QA | Yes |

---

### 12.2 Interoperability Testing Matrix

Qeet ID must be tested for interoperability with the following enterprise identity platforms before production launch:

| # | External Platform | Protocol(s) Tested | Test Scenario | Priority |
| --- | --- | --- | --- | --- |
| IT-01 | Microsoft Entra ID | SAML 2.0, OIDC, SCIM | SP-initiated SSO; IdP-initiated SSO; SCIM provisioning and deprovisioning; SLO | P1 |
| IT-02 | Okta | SAML 2.0, OIDC, SCIM | SP-initiated SSO; SCIM provisioning; attribute mapping | P1 |
| IT-03 | Google Workspace | SAML 2.0, OIDC | SP-initiated SSO; IdP-initiated SSO; OIDC social login | P1 |
| IT-04 | Ping Identity | SAML 2.0 | SP-initiated SSO; metadata exchange | P2 |
| IT-05 | Auth0 (as SP) | OIDC | Qeet ID as upstream IdP for Auth0-based applications | P2 |
| IT-06 | AWS IAM Identity Center | SAML 2.0, SCIM | SSO federation; automated provisioning | P2 |
| IT-07 | Apple Sign In | OIDC | Social login via Apple — special OIDC variant handling | P1 |
| IT-08 | Google Sign In | OIDC | Social login via Google Identity Platform | P1 |
| IT-09 | GitHub OAuth | OAuth 2.0 | Social login via GitHub | P1 |
| IT-10 | Microsoft Account | OIDC | Social login via Microsoft personal account | P1 |

---

### 13. Protocol Implementation — Engineering Constraints

### 13.1 Library Selection Principles

The following principles govern third-party library selection for protocol implementations:

| # | Principle | Rationale |
| --- | --- | --- |
| LI-01 | No custom cryptography | Cryptographic primitives must come from battle-tested libraries — no custom HMAC, hash, or signature implementations |
| LI-02 | No custom JWT libraries | JWT must be handled by well-maintained, security-audited libraries — jose (JavaScript), python-jose or PyJWT (Python), go-jose (Go) |
| LI-03 | No custom SAML parsers | SAML XML parsing must use libraries with active security maintenance histories — custom XML parsing introduces XXE and signature wrapping risk |
| LI-04 | Prefer FIDO Alliance reference implementations | WebAuthn server-side validation should use or validate against FIDO Alliance reference implementations |
| LI-05 | Regular dependency audits | All protocol libraries audited for CVEs quarterly — critical CVE patched within 72 hours of disclosure |

---

### 13.2 Protocol Error Handling Requirements

| # | Scenario | Required Response | Notes |
| --- | --- | --- | --- |
| EH-01 | Invalid client_id on authorization endpoint | error: unauthorized_client | Do not reveal whether client exists |
| EH-02 | Invalid redirect_uri | error: invalid_request — generic; no redirect | Never redirect to an unregistered URI — even with an error |
| EH-03 | Expired authorization code | error: invalid_grant | Code expired after 60 seconds |
| EH-04 | Reused authorization code | error: invalid_grant + revoke all tokens in that authorization session | Indicates possible code interception attack |
| EH-05 | Invalid or expired access token | HTTP 401 Unauthorized with WWW-Authenticate: Bearer error="invalid_token" |  |
| EH-06 | Insufficient scope | HTTP 403 Forbidden with WWW-Authenticate: Bearer error="insufficient_scope" |  |
| EH-07 | SAML assertion expired | HTTP 400 with structured SAML error response | Log attempted replay |
| EH-08 | SAML signature invalid | HTTP 400 — do not reveal signature details in error message | Alert security team if repeated |
| EH-09 | SCIM resource not found | HTTP 404 with SCIM error schema body |  |
| EH-10 | SCIM conflict (duplicate) | HTTP 409 Conflict with SCIM error schema body |  |
| EH-11 | WebAuthn ceremony failure | Structured error — NotAllowedError, InvalidStateError per W3C spec | Expose minimal detail to client |
| EH-12 | Rate limit exceeded | HTTP 429 Too Many Requests with Retry-After header |  |

### 14. Protocol Versioning & Deprecation Policy

| # | Policy | Description |
| --- | --- | --- |
| PV-01 | No breaking changes without 12-month notice | Changes that break existing protocol integrations require 12 months minimum deprecation notice |
| PV-02 | Dual-version support during transition | When a protocol version is deprecated, Qeet ID supports both old and new versions for the full deprecation window |
| PV-03 | Deprecated grant type communications | Removal of deprecated grant types (if any are later permitted for legacy support) communicated via email to all affected application owners and published in the changelog |
| PV-04 | Protocol security advisory | If a protocol-level vulnerability is discovered (e.g. a SAML vulnerability), Qeet ID issues a security advisory to all enterprise customers within 24 hours |
| PV-05 | RFC updates tracking | Solution Architect responsible for monitoring IETF and W3C working group updates relevant to protocols in use — change impact assessed quarterly |

---

### 15. Protocol Roadmap — Post-MVP

| # | Protocol / Extension | Standard | Planned For | Business Driver |
| --- | --- | --- | --- | --- |
| PR-01 | DPoP — Demonstrating Proof of Possession | RFC 9449 | 3 months post-launch | High-assurance applications; financial services |
| PR-02 | PAR — Pushed Authorization Requests | RFC 9126 | 3 months post-launch | Prevents authorization request tampering — fintech and enterprise requirement |
| PR-03 | Device Authorization Grant | RFC 8628 | 6 months post-launch | IoT, CLI tools, smart device market |
| PR-04 | LDAP federation (LDAPv3) | RFC 4510–4519 | v1.5 | Enterprises with on-premise Active Directory not yet migrated to Entra ID |
| PR-05 | SCIM Bulk Operations | RFC 7644 §3.7 | 6 months post-launch | Large-scale enterprise provisioning from Workday / SAP SuccessFactors |
| PR-06 | OIDC Back-Channel Logout | OIDC BC Logout 1.0 | 6 months post-launch | Reliable session termination for enterprise SSO |
| PR-07 | OIDC Front-Channel Logout | OIDC FC Logout 1.0 | 6 months post-launch | Browser-based session termination |
| PR-08 | FAPI 2.0 | FAPI 2.0 Security Profile | v2.0 | Financial-grade API — open banking, fintech, payment platforms |
| PR-09 | RAR — Rich Authorization Requests | RFC 9396 | v2.0 | Fine-grained transaction authorization for Qeet ID Access |
| PR-10 | SPIFFE / SPIRE | SPIFFE Standard | v2.0 | Zero-trust workload identity for Kubernetes and microservice environments |

---

### 16. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Solution Architect |  |  |  |
| Security Architect |  |  |  |
| CTO |  |  |  |
| Backend Engineering Lead |  |  |  |
| QA Lead |  |  |  |
| CISO |  |  |  |
| Compliance Officer |  |  |  |
| Product Manager |  |  |  |

---

*This document is version controlled. Protocol requirements are a living specification — they must be reviewed when RFCs are updated, when new security vulnerabilities in identity protocols are disclosed, when new enterprise customer segments demand additional protocol support, or when the product roadmap introduces new authentication flows. Any deviation from this document during engineering implementation requires a formal Architecture Decision Record (ADR) reviewed and approved by the Solution Architect and CISO before implementation proceeds.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*