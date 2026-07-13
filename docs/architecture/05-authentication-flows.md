# Authentication Flows

All authentication flows are implemented in `domains/access/authentication` (`package auth`) and mounted at `/v1/auth/*` and `/v1/passkeys/*`. The hosted login app at `apps/login/` drives the browser-side UX.

## Email + password login

```mermaid
sequenceDiagram
    participant Client
    participant API as API (auth.Service.Login)
    Client->>API: POST /v1/auth/login<br/>{ email, password, tenant }
    Note over API: 1. Look up user + credential hash<br/>2. Verify bcrypt password<br/>3. Check account lockout state<br/>4. HIBP breach check (fail-open)<br/>5. Bot detection signal recording<br/>6. MFA gate (if enrolled) → return mfa_required challenge<br/>7. Auth hook (if configured) — signed POST<br/>(fail-open or fail-closed per tenant)<br/>8. Anomaly recording (threat-detection)<br/>9. Mint access token + refresh token (ES256)
    API-->>Client: { access_token, refresh_token, expires_in }
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

```mermaid
sequenceDiagram
    participant Client
    participant API as API (passkeys.Service)
    Client->>API: POST /v1/passkeys/register/begin
    Note over API: Generate challenge (32 random bytes)<br/>Store WebAuthn session (5-min TTL)
    API-->>Client: { options: PublicKeyCredentialCreationOptions }
    Note over Client: Browser/device: user verifies biometric/PIN
    Client->>API: POST /v1/passkeys/register/complete<br/>{ credential: AuthenticatorAttestationResponse }
    Note over API: Verify attestation (go-webauthn)<br/>Verify challenge freshness (session TTL)<br/>Store passkey credential
    API-->>Client: 201 Created
```

### Authentication (passkey login)

```mermaid
sequenceDiagram
    participant Client
    participant API as API (passkeys.Service)
    Client->>API: POST /v1/passkeys/login/begin<br/>{ email? }
    Note over API: Generate assertion challenge<br/>Store WebAuthn session (5-min TTL)
    API-->>Client: { options: PublicKeyCredentialRequestOptions }
    Note over Client: Browser/device: user verifies biometric/PIN
    Client->>API: POST /v1/passkeys/login/complete<br/>{ credential: AuthenticatorAssertionResponse }
    Note over API: Verify assertion (go-webauthn)<br/>Verify challenge freshness<br/>Update last_used on credential<br/>Apply same auth hook + anomaly gates as password login
    API-->>Client: { access_token, refresh_token }
```

The 5-minute session TTL on WebAuthn challenges defends against replay attacks.

## Social OAuth

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Provider as Social Provider
    Client->>API: GET /v1/social/:provider/start
    Note over API: Generate state + PKCE verifier<br/>Store OAuth session
    API-->>Client: 302 → provider auth URL
    Provider->>API: callback with code
    Note over API: Exchange code for tokens
    Client->>API: GET /v1/social/:provider/callback<br/>(redirected by provider)
    Note over API: Fetch profile from provider<br/>JIT provision user (if new)<br/>Link social account to user<br/>Mint Qeet ID tokens
    API-->>Client: 302 → login app with tokens
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

```mermaid
flowchart TB
    login["auth.Service.Login()"]
    run["authhook.Service.Run(event)"]
    post["POST &lt;hook_url&gt; with HMAC-signed payload<br/>{ user_id, tenant_id, email, ip, user_agent }"]
    wait["Wait for response (configurable timeout)"]
    login --> run
    run --> post
    post --> wait
    wait -->|"Response { allow: true }"| proceed1["login proceeds"]
    wait -->|"Response { allow: false, reason: &quot;...&quot; }"| forbidden["403 Forbidden"]
    wait -->|"Timeout / error — FailOpen = true (default)"| proceed2["login proceeds"]
    wait -->|"Timeout / error — FailOpen = false"| unavailable["503 Service Unavailable"]
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
