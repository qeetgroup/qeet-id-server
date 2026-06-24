# Cryptography

## JWT signing

**Algorithm:** ES256 (ECDSA with NIST P-256)  
**Implementation:** `platform/security/tokens/jwt.go`

- Private key loaded from `JWT_SIGNING_KEY` environment variable (PEM or base64-encoded DER)
- Public key published at `/jwks.json`
- `kid` = RFC 7638 JWK thumbprint (SHA-256 of canonical JWK JSON — deterministic, enables transparent rotation)
- Signature: Go standard library `crypto/ecdsa` (uses CSPRNG for `k` parameter — no `k` reuse vulnerability)

**Key rotation:** Add new key → both keys in JWKS simultaneously → new tokens use new key → after grace window (≥15 min) remove old key. See [ADR-0005](../adr/0005-jwk-thumbprint-as-kid.md).

## Password hashing

**Algorithm:** bcrypt  
**Implementation:** `platform/security/encryption`

- Default cost factor: 12 (tuned to ~300ms on target hardware)
- Maximum input length: 72 bytes (bcrypt limitation; passwords longer than 72 bytes are silently truncated — validated and documented)
- Storage: `auth.credentials.hash` column

Bcrypt is chosen for its adaptive cost factor (can be increased as hardware improves) and widespread adoption in the Go ecosystem.

## CSRF token generation

**Implementation:** `platform/api/rest/httpx/csrf.go`

Token construction:
```
random_bytes = crypto/rand.Read(32 bytes)
hmac_key     = config.CSRFKey  (32 bytes from CSRF_KEY env var)
hmac_value   = HMAC-SHA256(key=hmac_key, data=random_bytes)
token        = base64url(random_bytes + hmac_value)
```

- Key label `"qeet-csrf-v1"` is prepended internally (for algorithm versioning)
- Cookie: `qe_csrf`, `SameSite=Strict`, `HttpOnly=false`, `Secure`, 12h TTL
- Verification: constant-time HMAC comparison (`subtle.ConstantTimeCompare`)
- The keyed HMAC prevents an attacker who can set cookies (e.g., subdomain cookie injection) from forging a valid token without knowing `CSRF_KEY`

## Secrets vault

**Implementation:** `domains/developer/credentials/secrets`

- Encryption: AES-256-GCM with a random 12-byte nonce per ciphertext
- Key provider: static (`StaticKeyProvider` — key from environment) or AWS KMS (`NewAWSKMSProvider`)
- Per-tenant key derivation: the master key is combined with the tenant ID via HKDF to produce a per-tenant AES key, ensuring that a single key compromise does not expose all tenants' secrets
- Storage: `platform.secrets` table stores `nonce + ciphertext` (base64)

AWS KMS path: the data encryption key (DEK) is generated locally, encrypted by KMS (envelope encryption), stored alongside the ciphertext. KMS is called only for key operations, not for bulk data.

## Audit log hash chain

**Implementation:** `domains/operations/audit/audit.go`

```
chain_input = canonical_json({
    prev_hash, tenant_id, actor_type, actor_id,
    action, resource_type, resource_id, created_at
})
hash = hex(SHA-256(chain_input))
```

- Deterministic JSON serialization ensures the same input always produces the same hash
- First event in a tenant's chain: `prev_hash = "0000...0000"` (64 zero hex chars)
- Each subsequent event: `prev_hash = previous_event.hash`
- Chain written inside the caller's pgx transaction (atomicity with business row)
- Verification: `audit.Verifier.Verify()` recomputes each hash and compares

## WebAuthn/passkey cryptography

**Implementation:** `domains/access/passkeys` (wraps `go-webauthn`)

- Attestation formats: none, packed, fido-u2f (device-dependent)
- Assertion signature: ES256 or RS256 (device-dependent; not server-controlled)
- Challenge: 32 random bytes from `crypto/rand`, stored in `auth.webauthn_sessions` (5-min TTL)
- Credential storage: `auth.passkey_credentials` — stores public key + sign count (sign count increments prevent credential cloning detection)

## TLS

TLS termination happens at the reverse proxy layer (Caddy in Compose, ingress controller in Kubernetes). The Go API server does **not** terminate TLS directly — it receives plain HTTP internally. In production, the ingress must enforce HTTPS and redirect HTTP → HTTPS.

The `APP_BASE_URL` safety gate ensures the service refuses to start without an `https://` base URL outside development.

## Entropy sources

All randomness uses `crypto/rand` (OS CSPRNG). This applies to:
- JWT `jti` (ULID with crypto random)
- CSRF token random component
- WebAuthn challenges
- API key secret generation (`qk_` prefix + 32 random bytes)
- Agent secret generation (`agt_` prefix + 32 random bytes)

`math/rand` is not used for any security-sensitive operation.
