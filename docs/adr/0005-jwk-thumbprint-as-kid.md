# ADR-0005: RFC 7638 JWK Thumbprint as JWT `kid`

**Status:** Accepted  
**Date:** 2025-Q1  
**Deciders:** Qeet ID core team

---

## Context

JWT tokens must carry a `kid` (key ID) header so verifiers can select the correct public key from a JWKS endpoint when multiple keys are active (e.g., during rotation). Options for generating `kid` values:

1. **Random UUID** — arbitrary, requires an out-of-band registry mapping UUID → key
2. **Sequential integer** — simple but fragile (conflicts if two services generate keys independently)
3. **RFC 7638 JWK Thumbprint** — deterministic SHA-256 hash of the canonical JWK representation

## Decision

Use the **RFC 7638 JWK Thumbprint** as the `kid` for all issued JWTs.

For a P-256 key, the thumbprint input is the canonical JSON of `{"crv":"P-256","kty":"EC","x":"<base64>","y":"<base64>"}` (keys sorted, no extra whitespace), SHA-256 hashed and base64url-encoded.

Implementation: `platform/security/jwt/jwt.go` — the `kid` is computed once at key load time and embedded in the signing header.

## Consequences

**Positive:**
- **Deterministic:** Given a public key, the `kid` is always the same value regardless of which system computed it — no registry required
- **Transparent rotation:** When a new key is generated, its `kid` is computed automatically. Old and new keys are in JWKS simultaneously during the grace window. Verifiers can match `kid` without any server-side lookup
- **Algorithm-agile:** The thumbprint scheme works for any JWK type (RSA, EC, OKP, ML-DSA) — migrating to post-quantum algorithms doesn't break the `kid` scheme
- **JWKS-compatible:** RFC 7638 is referenced by OIDC Discovery; verifiers that follow the spec will handle this correctly

**Negative / watch-outs:**
- Slightly longer `kid` values than integers (43 base64url characters vs. single digit) — negligible overhead
- The thumbprint depends only on the _public key_ parameters, not the algorithm. Two different algorithm configurations for the same key would share a `kid` — not a concern in practice since algorithm migrations create entirely new keys

**Key rotation flow:**
1. Generate new keypair → compute new thumbprint → new `kid`
2. Add new key to active set in `platform/security/jwt`
3. JWKS publishes both old and new keys
4. New tokens use new `kid`; old tokens with old `kid` verify against the old key still in JWKS
5. After grace window (≥ max access token TTL = 15 min), remove old key from JWKS
