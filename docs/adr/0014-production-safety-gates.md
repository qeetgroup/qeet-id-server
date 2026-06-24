# ADR-0014: Boot-Time Production Safety Gates

**Status:** Accepted  
**Date:** 2025-Q1  
**Deciders:** Qeet ID core team

---

## Context

A common operational failure mode: a service starts in production with insecure defaults that worked fine in development. Examples observed in the identity platform space:

- CSRF protection disabled (a `DISABLE_CSRF=true` env var accidentally carried from dev)
- JWT signing key unset (process falls back to a weak or default key)
- `ALLOWED_ORIGINS: "*"` (wildcard CORS left from development)
- Dev trust headers enabled (`X-Dev-User: alice@example.com` allows bypass of authentication)

These misconfigurations are often invisible until they cause an incident. A code review of configuration values is rarely as thorough as a test failure.

## Decision

`platform/config/config.go:Config.Validate()` is called on startup and **refuses to start** outside `SERVICE_ENV=dev` if any insecure configuration is present:

| Check | Blocked value |
|---|---|
| CSRF disabled | `DISABLE_CSRF=true` |
| Dev trust headers enabled | `ENABLE_DEV_HEADERS=true` |
| JWT signing key unset | empty `JWT_SIGNING_KEY` |
| JWT secret weak | `JWT_SECRET` shorter than 32 bytes |
| SAML signing cert missing | empty `SAML_SIGNING_CERT` |
| Wildcard CORS origins | `"*"` in `ALLOWED_ORIGINS` |
| Localhost base URL | `APP_BASE_URL` pointing to `localhost` |
| HIBP check disabled in prod | `DISABLE_HIBP=true` |

On validation failure, the server logs a descriptive error message and exits with code 1. The Helm migration Job and the Kubernetes readiness probe will correctly report the failure.

## Consequences

**Positive:**
- Eliminates the entire class of "works in dev, misconfigured in prod" failures
- Fast feedback: the misconfiguration is caught in seconds on deploy, not after an incident
- Self-documenting: the `Validate()` function is the authoritative list of required production configurations
- No runtime overhead: validation runs once at startup

**Negative / watch-outs:**
- A new required configuration that doesn't yet have a validation check is still vulnerable. Engineers adding new security-sensitive config must also add a validation check to `Validate()`
- `SERVICE_ENV=dev` bypasses all checks — this is intentional (local development must work without full production secrets). The bypass must never be used in staging or production deployments
- If a check is too strict (false positive), it will prevent a legitimate deployment. Checks must be precise — validate the presence and format of a key, not its semantic correctness

**Adding a new gate:** When adding a new production-required configuration, add both the environment variable definition to `config.go` and a corresponding check to `Validate()` in the same PR.
