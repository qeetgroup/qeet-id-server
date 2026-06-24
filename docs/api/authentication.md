# Authentication API

This document covers the token-minting endpoints. For the full OpenAPI spec, see [`api/openapi/`](../../api/openapi/).

## Email + password login

```
POST /v1/auth/login
Content-Type: application/json

{
  "email":        "alice@acme.test",
  "password":     "Password123!",
  "tenant_slug":  "acme"
}
```

**Success (no MFA):**
```json
{
  "access_token":  "<ES256 JWT>",
  "refresh_token": "<opaque>",
  "token_type":    "Bearer",
  "expires_in":    900
}
```

**MFA required:**
```json
{
  "mfa_required":   true,
  "mfa_token":      "<challenge token>",
  "mfa_methods":    ["totp"]
}
```
Follow up with `POST /v1/auth/mfa/verify` to complete login.

**Error codes:** `unauthorized` (bad credentials), `locked` (brute-force lockout), `hook_denied` (auth hook denied), `too_many_requests` (rate limited)

---

## MFA verification

```
POST /v1/auth/mfa/verify
Content-Type: application/json

{
  "mfa_token": "<challenge token from login>",
  "code":      "123456"
}
```

Returns the same token response as a successful login.

---

## Token refresh

```
POST /v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "<refresh token>"
}
```

Returns a new `access_token` (and optionally a new `refresh_token` if rotation is enabled). The old refresh token is invalidated immediately. If a stolen refresh token is replayed, the server invalidates the entire session.

---

## Workspace switching

A user can belong to multiple organizations. To switch context:

```
POST /v1/auth/switch-tenant
Authorization: Bearer <current access token>
Content-Type: application/json

{
  "tenant_id": "01J..."
}
```

Returns new tokens scoped to the target tenant. The previous access token remains valid until it expires.

---

## Passkey login

### Step 1: Get challenge options

```
POST /v1/passkeys/login/begin
Content-Type: application/json

{
  "email": "alice@acme.test"
}
```

Returns `PublicKeyCredentialRequestOptions` for the browser's `navigator.credentials.get()` call. The challenge is valid for **5 minutes**.

### Step 2: Complete authentication

```
POST /v1/passkeys/login/complete
Content-Type: application/json

{
  "credential": { /* AuthenticatorAssertionResponse from browser */ }
}
```

Returns the same token response as password login.

---

## Passkey registration

Requires an authenticated user session.

### Step 1: Begin registration

```
POST /v1/passkeys/register/begin
Authorization: Bearer <access token>
```

Returns `PublicKeyCredentialCreationOptions` for `navigator.credentials.create()`. Challenge valid for **5 minutes**.

### Step 2: Complete registration

```
POST /v1/passkeys/register/complete
Authorization: Bearer <access token>
Content-Type: application/json

{
  "credential": { /* AuthenticatorAttestationResponse from browser */ },
  "name": "MacBook Pro"
}
```

Returns `201 Created` with the new passkey record.

---

## Social OAuth

### Start social login

```
GET /v1/social/:provider/start?tenant_slug=acme&return_to=/dashboard
```

Returns HTTP 302 redirect to the provider's authorization URL. The `return_to` parameter determines where the user lands after successful login.

Supported `provider` values: `google`, `github`, and any configured social provider slug.

### OAuth callback (handled automatically)

```
GET /v1/social/:provider/callback?code=...&state=...
```

This endpoint is called by the provider; the client does not call it directly. On success, the user is redirected to `return_to` with tokens set as cookies for the login app to consume.

---

## Agent token mint

```
POST /v1/agents/token
Content-Type: application/json

{
  "agent_id":         "01J...",
  "agent_secret":     "agt_...",
  "requested_scopes": ["users:read", "audit:read"],
  "ttl_seconds":      300
}
```

Returns a short-lived access token with `actor_type = "agent"`. Not refreshable — mint a new token when needed. The granted scopes are the intersection of `requested_scopes` and the agent's configured `allowed_scopes`.

---

## Token introspection (RFC 7662)

```
POST /oauth/introspect
Content-Type: application/x-www-form-urlencoded

token=<access_token>
```

```json
{
  "active":      true,
  "uid":         "01J...",
  "tid":         "01J...",
  "scp":         ["users:read"],
  "actor_type":  "agent",
  "agent_id":    "01J...",
  "exp":         1750000900
}
```

Returns `{ "active": false }` for expired or invalid tokens.

---

## Token claims reference

| Claim | Description |
|---|---|
| `iss` | Token issuer (`APP_BASE_URL`) |
| `sub` | User ID (ULID) |
| `uid` | User ID (same as `sub`) |
| `tid` | Tenant ID (absent for tenant-less users) |
| `sid` | Session ID |
| `scp` | Space-separated scope list |
| `actor_type` | `"user"` / `"service"` / `"agent"` |
| `agent_id` | Agent definition ID (only when `actor_type = "agent"`) |
| `act` | RFC 8693 delegation chain (only for token-exchange tokens) |
| `exp` | Expiry (Unix timestamp) |
| `iat` | Issued at |
| `jti` | JWT ID (unique per token) |
