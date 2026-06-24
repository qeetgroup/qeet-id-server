# Token and Session Model

## JWT structure

Qeet ID issues **ES256 JWTs** (ECDSA P-256, asymmetric). All tokens are signed with the private key held in `platform/security/tokens`; the corresponding public key is published at `/jwks.json` for external verification (e.g., OIDC relying parties).

### Standard claims

```json
{
  "iss": "https://api.id.qeet.in",
  "sub": "01J...",
  "aud": ["https://api.id.qeet.in"],
  "iat": 1750000000,
  "exp": 1750000900,
  "jti": "01J..."
}
```

### Qeet ID custom claims

```json
{
  "uid":        "01J...",
  "tid":        "01J...",
  "sid":        "01J...",
  "scp":        ["users:read", "org:admin"],
  "actor_type": "user",
  "agent_id":   null,
  "act":        null
}
```

| Claim | Type | Description |
|---|---|---|
| `uid` | string | User ID (ULID) |
| `tid` | string | Tenant ID (ULID); absent on tenant-less tokens |
| `sid` | string | Session ID (ULID); used for refresh token binding |
| `scp` | []string | Granted OAuth 2.0 scopes |
| `actor_type` | string | `"user"` / `"service"` / `"agent"` |
| `agent_id` | string? | Set when `actor_type = "agent"`; identifies the agent definition |
| `act` | object? | RFC 8693 delegation chain; set by token exchange |

## Key ID (kid)

The `kid` JWT header field is the **RFC 7638 JWK thumbprint** of the signing key — a SHA-256 hash of the canonical JWK representation. This makes the key ID deterministic and stable:

- No out-of-band key ID registry needed
- Key rotation is transparent: clients fetch `/jwks.json` and match `kid`
- Algorithm-agile: the same scheme works for future ML-DSA keys

## Key rotation

1. Generate new EC P-256 signing keypair.
2. Add it to the active key set in `platform/security/tokens`.
3. The new key appears in `/jwks.json` alongside the old key.
4. New tokens are signed with the new key.
5. Old tokens (signed with the retired key) continue to verify during the **grace window** — the old key stays in JWKS for the duration of the longest-lived access token (15 minutes by default).
6. After the grace window expires, remove the old key from JWKS.

## Token types and TTLs

| Token type | Default TTL | Configurable | Notes |
|---|---|---|---|
| Access token | 15 minutes | Yes | Short-lived; bearer for API calls |
| Refresh token | 30 days | Yes | Long-lived; single-use on rotation |
| Agent token | 60s – 1 hour | Per-agent | Re-minted per request cycle |
| OIDC ID token | 15 minutes | — | Issued by OIDC flow; mirrors access token |

TTLs are configurable via environment variables in `platform/config`.

## Agent tokens (AI-agent identity)

AI agents receive **ephemeral actor tokens** with `actor_type = "agent"`. This enables the full agent/MCP stack:

```
POST /v1/agents/token
{ agent_id, requested_scopes[], ttl_seconds }
  → verify agent secret (agt_ prefix)
  → mint short-lived access token:
      actor_type = "agent"
      agent_id   = <id>
      scp        = <requested_scopes> ∩ <agent's allowed scopes>
      exp        = now + min(ttl, agent.max_ttl)
```

Agent tokens are **re-minted** per task — they are never refreshed. The short TTL bounds the blast radius of a leaked token. The `agent_id` claim is visible on `/oauth/introspect`, enabling downstream services to gate access to agent principals specifically.

## RFC 8693 token exchange (delegation)

Token exchange allows a service acting on behalf of a user to mint a downscoped token with an `act` claim:

```
POST /v1/oauth/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<user_access_token>
actor_token=<service_access_token>
requested_scopes=<downscoped>
```

The resulting token carries an `act` claim identifying the actor service:

```json
{
  "uid": "<user_id>",
  "act": { "sub": "<service_account_id>", "actor_type": "service" },
  "scp": ["<downscoped_permissions>"]
}
```

This is the foundation for AI-agent delegation: the agent can prove it is acting on behalf of a specific user without having access to the user's full permissions.

## MCP token introspection

The `/oauth/introspect` endpoint (RFC 7662) exposes full token claims including `actor_type` and `agent_id`. MCP servers and API gateways can use this to enforce agent-specific policies — e.g., blocking agent principals from sensitive mutations.

```
POST /oauth/introspect
{ token }

Response:
{
  "active": true,
  "uid": "...",
  "tid": "...",
  "actor_type": "agent",
  "agent_id": "...",
  "scp": ["..."],
  "exp": 1750000900
}
```

## Session model

Qeet ID uses **stateless JWT access tokens** — there is no server-side session store for access tokens. Revocation relies on token expiry for access tokens.

Refresh tokens are tracked in the database (`auth.sessions` table, `migrations/0042`). On token refresh:
1. The old refresh token is invalidated (single-use).
2. A new access token + refresh token pair is minted.
3. Refresh token theft detection: if an already-invalidated refresh token is presented, the entire session is revoked.

WebAuthn challenge sessions are tracked separately in `auth.webauthn_sessions` with a hard 5-minute TTL.
