# ADR-0011: Auth Hooks Default to Fail-Open

**Status:** Accepted  
**Date:** 2025-Q1 (implemented in migration 0059)  
**Deciders:** Qeet ID core team

---

## Context

Auth hooks are synchronous, tenant-configured webhooks that can allow or deny a login attempt. They run after credential verification but before token issuance. A tenant might use a hook to:
- Block logins from specific IP ranges
- Require additional context (risk score from an external system)
- Integrate with custom access policies

The hook is an external HTTP call. It can fail:
- The hook endpoint is temporarily down (deploy, restart)
- Network partition between Qeet ID and the hook server
- Hook response times out

When a hook fails, two policies are possible:

1. **Fail-open** — hook failure → login proceeds (hook unavailability doesn't cause lockout)
2. **Fail-closed** — hook failure → login denied (strictest security posture)

## Decision

**Default: fail-open.** Tenants can opt into fail-closed via a `FailOpen` flag in the hook configuration.

```go
// domains/developer/auth-hooks/authhook.go
type Config struct {
    URL      string
    Secret   string
    FailOpen bool // default: true
}
```

The fail-open behavior is **safe by default**: Qeet ID never takes a destructive action (locking out users) by default. Tenants who need strict enforcement can opt in to fail-closed explicitly.

**Timeout behavior:**
- Hook requests time out after a configurable deadline (default: 5 seconds)
- On timeout: FailOpen=true → login proceeds; FailOpen=false → 503 returned

## Consequences

**Positive:**
- A hook deployment or infrastructure issue never accidentally locks all users out of a tenant
- The safe default aligns with the principle that Qeet ID should not be a single point of failure for authentication
- Tenants with high-security requirements (financial, healthcare) can explicitly opt into fail-closed behavior with full awareness of the trade-off

**Negative / watch-outs:**
- With FailOpen=true, a compromised or unavailable hook endpoint means the hook's policy is not enforced during the outage. If the hook's purpose is to _block_ certain logins, that blocking is bypassed during failure
- Tenants must understand the FailOpen flag when configuring hooks; the admin UI should make the default and its implications explicit
- A malicious actor who can cause a hook endpoint to become unavailable could use that to bypass hook-based access controls (denial-of-hook attack). This is documented in the security model for tenants choosing FailOpen=true

**Recommendation for high-security tenants:** Use FailOpen=false when the hook implements access controls that must not be bypassed (e.g., blocking contractors outside business hours). Use FailOpen=true (default) when the hook implements enrichment or logging that should not block login.
