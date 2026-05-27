# Security rules

> Anything in this file is **human-approval-required**. Don't make these changes unprompted.

This file is the hard line. If you (Claude) are about to touch any of the items below without an explicit human instruction to do so, stop and ask.

## Hard rules

- ❌ Never change a token signing algorithm without explicit approval. `RS256` / `ES256` **must not** silently become `HS256`.
- ❌ Never weaken a password hasher. argon2id parameters live in [internal/auth](../../backend/internal/auth/) — don't lower memory/time/parallelism.
- ❌ Never log a secret. That includes: passwords, raw bearer tokens, refresh tokens, session IDs, recovery codes, TOTP seeds, passkey credential IDs, social-IdP client secrets, webhook signing keys, API keys.
- ❌ Never commit `.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, or anything under `secrets/`. Already gitignored — verify before staging.
- ❌ Never disable TLS verification on outbound calls (`InsecureSkipVerify`, equivalent flags).
- ❌ Never widen CORS to `*` for credentialed requests. The dev value is set in [internal/config/config.go](../../backend/internal/config/config.go) — production overrides it via env.

## Authentication

- Sessions are cookie-based. Cookies are `HttpOnly`, `Secure` in non-dev, `SameSite=Lax` (or `Strict` where applicable).
- Refresh tokens are rotated on use. The old token is invalidated atomically — read the existing logic in `internal/auth` before changing.
- MFA enrolment and verification flows are rate-limited at the handler — don't remove the limiter "to make tests pass." Mock time instead.
- Passkeys use WebAuthn level 2. The challenge is one-shot and bound to the session. Don't cache it across requests.

## Authorization

- Every handler that touches business data resolves the actor's `(tenant_id, user_id, roles)` via middleware. Don't read those from the request body.
- RBAC checks happen in the service, not the handler. Reason: RBAC mistakes in handlers don't compose — middleware can miss a route, but a service call always goes through the policy gate.
- Cross-tenant access → 403, not 404. (404 reveals existence.)

## Crypto

- Use stdlib `crypto/*` and `golang.org/x/crypto/argon2`. Don't introduce a third-party crypto library.
- Random bytes from `crypto/rand`, never `math/rand`. Don't seed `math/rand` with `time.Now()` to make it "secure" — it isn't.
- Constant-time comparison for any secret comparison: `subtle.ConstantTimeCompare`.

## Webhooks

- Outbound webhook payloads are signed with HMAC-SHA256 over the body. The signing key is per-tenant. Don't make it global. Don't truncate it.
- Inbound webhook verification (for social-IdP callbacks, etc.) validates the signature **before** parsing the body. Order matters.

## Audit

- Security-relevant actions (login, logout, password change, MFA enrol, role grant, API key issuance, webhook config) **must** appear in [audit](../../backend/internal/audit/audit.go). If the audit row doesn't exist, the action didn't happen as far as compliance is concerned.

## Process

- A security-relevant change updates [documents/PROTOCOL-STATUS.md](../../documents/PROTOCOL-STATUS.md) and flags itself in the PR description with `**security**` in the title.
- The [qeetid-reviewer agent](../agents/qeetid-reviewer.md) checks the items above. Run it before opening the PR.

## Reporting

Real security issues go to [SECURITY.md](../../SECURITY.md), not the issue tracker.
