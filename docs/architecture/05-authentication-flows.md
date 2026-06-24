# Authentication Flows

All authentication flows are implemented in `domains/access/authentication` (`package auth`) and mounted at `/v1/auth/*` and `/v1/passkeys/*`. The hosted login app at `apps/login/` drives the browser-side UX.

## Email + password login

```
Client                     API (auth.Service.Login)
  │                               │
  ├─ POST /v1/auth/login ─────────►
  │  { email, password, tenant }  │
  │                               ├─ 1. Look up user + credential hash
  │                               ├─ 2. Verify bcrypt password
  │                               ├─ 3. Check account lockout state
  │                               ├─ 4. HIBP breach check (fail-open)
  │                               ├─ 5. Bot detection signal recording
  │                               ├─ 6. MFA gate (if enrolled)
  │                               │      └─ Return mfa_required challenge
  │                               ├─ 7. Auth hook (if configured) — signed POST
  │                               │      └─ fail-open or fail-closed per tenant
  │                               ├─ 8. Anomaly recording (threat-detection)
  │                               ├─ 9. Mint access token + refresh token (ES256)
  │◄──────────────────────────────┤
     { access_token, refresh_token, expires_in }
```

**Lockout:** After N consecutive failures (configurable per tenant, `migrations/0041_login_lockout`), the account enters a temporary lockout. Correct credentials during lockout still fail with `locked` error code.

**MFA challenge:** When `mfa_required` is returned, the client submits the TOTP code via `POST /v1/auth/mfa/verify` to complete the login and receive tokens.

## Token refresh

```
POST /v1/auth/refresh
{ refresh_token }
  → verify refresh token (not expired, not revoked)
  → mint new access token
  → optionally rotate refresh token
  → { access_token, refresh_token }
```

Access tokens are short-lived (default 15m). Refresh tokens are long-lived (default 30d) and single-use on rotation.

## Workspace switching

A user can belong to multiple tenants. Switching mints a fresh tenant-scoped token:

```
POST /v1/auth/switch-tenant
Authorization: Bearer <current_access_token>
{ tenant_id }
  → verify user is a member of target tenant
  → mint new access token scoped to target tenant
  → { access_token, refresh_token }
```

## Passkey (WebAuthn/FIDO2) flows

Passkeys are hardware-bound, phish-resistant credentials. Two ceremonies: registration and authentication.

### Registration (new passkey)

```
Client                         API (passkeys.Service)
  │                                │
  ├─ POST /v1/passkeys/register/begin ─►
  │                                ├─ Generate challenge (32 random bytes)
  │                                ├─ Store WebAuthn session (5-min TTL)
  │◄── { options: PublicKeyCredentialCreationOptions }
  │
  │ [Browser/device: user verifies biometric/PIN]
  │
  ├─ POST /v1/passkeys/register/complete ─►
  │  { credential: AuthenticatorAttestationResponse }
  │                                ├─ Verify attestation (go-webauthn)
  │                                ├─ Verify challenge freshness (session TTL)
  │                                ├─ Store passkey credential
  │◄── 201 Created
```

### Authentication (passkey login)

```
Client                         API (passkeys.Service)
  │                                │
  ├─ POST /v1/passkeys/login/begin ─►
  │  { email? }                    ├─ Generate assertion challenge
  │                                ├─ Store WebAuthn session (5-min TTL)
  │◄── { options: PublicKeyCredentialRequestOptions }
  │
  │ [Browser/device: user verifies biometric/PIN]
  │
  ├─ POST /v1/passkeys/login/complete ─►
  │  { credential: AuthenticatorAssertionResponse }
  │                                ├─ Verify assertion (go-webauthn)
  │                                ├─ Verify challenge freshness
  │                                ├─ Update last_used on credential
  │                                ├─ Apply same auth hook + anomaly gates as password login
  │◄── { access_token, refresh_token }
```

The 5-minute session TTL on WebAuthn challenges defends against replay attacks.

## Social OAuth

```
Client                    API                    Social Provider
  │                        │                           │
  ├─ GET /v1/social/:provider/start ─►
  │                        ├─ Generate state + PKCE verifier
  │                        ├─ Store OAuth session
  │◄── 302 → provider auth URL
  │                        │                           │
  │                        │◄── callback with code ────┤
  │                        ├─ Exchange code for tokens
  ├─ GET /v1/social/:provider/callback ─► (redirected by provider)
  │                        ├─ Fetch profile from provider
  │                        ├─ JIT provision user (if new)
  │                        ├─ Link social account to user
  │                        ├─ Mint Qeet ID tokens
  │◄── 302 → login app with tokens
```

Supported providers: Google, GitHub, and any OAuth 2.0-compatible provider. Provider credentials stored in `auth.social_providers` per tenant.

## Magic-link / OTP recovery

```
POST /v1/recovery/forgot-password
{ email }
  → Generate short-lived OTP (6 digits) or magic-link token
  → Send via SMTP (platform/messaging/notifier)
  → 202 Accepted (always — no user enumeration)

POST /v1/recovery/reset
{ token, new_password }
  → Verify token (not expired, not used)
  → Hash new password (bcrypt)
  → Invalidate all existing sessions
  → 200 OK
```

In development, OTP codes and magic-link tokens are printed to the backend log (no SMTP required).

## Auth hooks

Auth hooks are synchronous, tenant-configured webhooks that gate login completion. After credential verification and MFA, the hook is called before tokens are minted:

```
auth.Service.Login()
  │
  └─► authhook.Service.Run(event)
        ├─ POST <hook_url> with HMAC-signed payload
        │  { user_id, tenant_id, email, ip, user_agent }
        ├─ Wait for response (configurable timeout)
        │
        ├─ Response { allow: true }  → login proceeds
        ├─ Response { allow: false, reason: "..." } → 403 Forbidden
        └─ Timeout / error:
             ├─ FailOpen = true (default) → login proceeds
             └─ FailOpen = false → 503 Service Unavailable
```

Auth hooks are configured in the admin console under Developer → Auth Hooks.

## Bot detection

Bot scoring signals are recorded during login attempts. The `threat-detection/bot` domain analyzes request characteristics (rate patterns, user-agent entropy, IP reputation). High-confidence bot signals can trigger CAPTCHA challenges or temporary IP blocks.

## Signup flow

```
POST /v1/auth/signup
{ email, password, display_name }
  → Check self-registration policy (tenant may disable signup)
  → HIBP breach check on password (fail-open)
  → Hash password (bcrypt)
  → Create user (tenant-less initially)
  → Send verification email
  → 201 Created { user_id }
```

After signup, the user has no tenant. The first action is typically creating a workspace (`POST /v1/organizations`) which makes them the owner of a new tenant. The Admin console guides users through this on first login.
