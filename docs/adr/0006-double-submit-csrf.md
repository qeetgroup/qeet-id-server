# ADR-0006: Double-Submit Cookie for CSRF Protection

**Status:** Accepted  
**Date:** 2025-Q1  
**Deciders:** Qeet ID core team

---

## Context

Qeet ID's admin console and login app make cookie-authenticated requests from the browser. These requests are vulnerable to Cross-Site Request Forgery (CSRF) without explicit protection.

Mitigation strategies considered:

1. **SameSite=Strict cookie alone** — prevents cross-origin cookie sending in modern browsers, but insufficient for older browsers and certain proxy configurations. Not an explicit mechanism.
2. **Synchronizer token (server-stored CSRF token)** — classic approach; requires server-side token storage and lookup
3. **Double-submit cookie** — client reads a cookie and echoes it in a request header; CSRF attacker can't read the cookie due to same-origin policy
4. **HMAC-keyed double-submit (signed cookie)** — same as above but the cookie value is HMAC-signed, preventing an attacker from generating a valid cookie/header pair even if they can set cookies on a subdomain

## Decision

Use **HMAC-keyed double-submit cookie** (`qe_csrf`):

- On every GET, server generates: `base64url(32_random_bytes + HMAC-SHA256(key="qeet-csrf-v1", data=random_bytes))`
- Cookie: `qe_csrf`, `SameSite=Strict`, `HttpOnly=false` (JS must read it), `Secure`, 12-hour TTL
- Mutation requests (POST/PUT/PATCH/DELETE) must echo the cookie value in `X-CSRF-Token` header
- Server verifies header matches cookie using constant-time comparison
- Additionally: Origin header check (or Referer fallback) against the `ALLOWED_ORIGINS` whitelist

Implementation: `platform/api/rest/middleware/csrf.go`

**Exempt paths** (where CSRF protection does not apply):
- Bearer-token authenticated requests (no cookie; M2M cannot be CSRF'd)
- SAML ACS (`/saml/:conn/acs`) — receives cross-origin POST from IdP
- OAuth endpoints (`/v1/oauth/authorize`, `/v1/oauth/token`) — spec-defined cross-origin flows
- Pre-auth endpoints (login, signup, recovery) — no session yet

## Consequences

**Positive:**
- Stateless: no server-side token storage; the HMAC signature proves the cookie was issued by the server
- The keyed HMAC (`qeet-csrf-v1` prefix) allows future key rotation via a `/csrf/rotate` endpoint without invalidating all cookies immediately
- Constant-time comparison prevents timing oracle attacks
- Bearer-token bypass removes CSRF friction from API/SDK clients

**Negative / watch-outs:**
- `HttpOnly=false` is required for JS to read the cookie value — mitigated by `SameSite=Strict` limiting when the cookie is sent cross-origin
- The 12-hour cookie TTL means a CSRF token is valid for 12 hours after issuance; this is acceptable given `SameSite=Strict`
- Subdomain cookie injection attacks: an attacker who can set a cookie on a subdomain could forge a valid CSRF cookie. The HMAC key prevents this — they cannot compute a valid HMAC-signed value without the key
