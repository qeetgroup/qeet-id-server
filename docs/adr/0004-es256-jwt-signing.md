# ADR-0004: ES256 (ECDSA P-256) for JWT Signing

**Status:** Accepted  
**Date:** 2025-Q1  
**Deciders:** Qeet ID core team

---

## Context

Qeet ID issues JWTs for access and refresh tokens. The signing algorithm choice has significant implications for:

- **OIDC compliance** — OIDC requires the IdP to publish a public JWKS endpoint so relying parties can verify ID tokens without calling back to the IdP
- **Security** — symmetric algorithms (HS256) require sharing the secret with every verifier; asymmetric algorithms do not
- **Agility** — the identity space is moving toward post-quantum algorithms (ML-DSA / CRYSTALS-Dilithium)

Three candidates were considered:

| Algorithm | Type | Key size | Notes |
|---|---|---|---|
| `HS256` | Symmetric (HMAC-SHA256) | 256-bit secret | Simple; requires secret sharing with every verifier |
| `RS256` | Asymmetric (RSA-2048) | 2048-bit key | Industry standard; large key/signature size |
| `ES256` | Asymmetric (ECDSA P-256) | 256-bit key | Compact; NIST-approved; OIDC-compatible |

## Decision

Use **ES256 (ECDSA with P-256)** for all JWT signing.

- Private key is held exclusively by `platform/security/tokens`
- Public key is published at `/jwks.json` for external verification
- Key ID (`kid`) is the RFC 7638 JWK thumbprint (see ADR-0005)
- Key pair generation: `crypto/elliptic.P256()` in the Go standard library

## Consequences

**Positive:**
- OIDC-compliant: relying parties can verify tokens via `/jwks.json` without shared secrets
- Compact signatures (64 bytes vs. 256 bytes for RS256)
- No need to distribute signing secrets to every service that verifies tokens
- P-256 is NIST-approved and widely supported across all JWT libraries
- Algorithm-agile: the JWK thumbprint `kid` scheme (ADR-0005) allows future migration to ML-DSA without changing JWT format

**Negative / watch-outs:**
- Slightly more complex than HS256 for simple internal use cases (key generation, PEM handling)
- ECDSA has a known footgun: `k` value reuse reveals the private key. Go's `crypto/ecdsa` uses a CSPRNG for `k` by default, which is correct
- P-256 is not post-quantum secure. Migration to ML-DSA (Dilithium) is on the future roadmap; the JWK thumbprint scheme preserves the migration path

**Note on HS256:** A legacy `JWT_SECRET` environment variable exists in config for backward-compatible session validation. New tokens are always ES256. Do not use `JWT_SECRET` for new signing operations.
