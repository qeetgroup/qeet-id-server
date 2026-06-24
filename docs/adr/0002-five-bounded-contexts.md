# ADR-0002: Five Bounded Contexts

**Status:** Accepted  
**Date:** 2025-Q1  
**Deciders:** Qeet ID core team

---

## Context

The Qeet ID feature surface spans many concerns: user management, authentication, authorization, federation protocols, developer tooling, and operational infrastructure. Without explicit boundaries, these concerns would blend together, making the codebase hard to navigate and change.

The team needed a domain partitioning that:
- Reflected natural ownership and change boundaries
- Prevented circular dependencies
- Scaled with team growth (each context could become a team's responsibility)
- Was enforced automatically, not just by convention

## Decision

Organize all business logic into **five bounded contexts** under `domains/<context>/`:

| Context | Core responsibility |
|---|---|
| `identity` | Who exists — users, organizations, groups |
| `access` | Security decisions — authentication, authorization, MFA, threat detection |
| `federation` | Protocol bridges — OIDC, SAML, SCIM, LDAP, social OAuth |
| `developer` | Machine-facing access — API keys, hooks, agents, webhooks |
| `operations` | Platform health — audit, billing, compliance, SIEM |

**Enforcement:**
- `tests/architecture/arch_test.go` verifies dependency rules (R1: `platform` does not import `domains`; R2: `domains` does not import `cmd` or the router)
- Cross-context calls are mediated by **consumer-declared interfaces** — concrete types from another context are never imported directly

## Consequences

**Positive:**
- Clear ownership: any file's context is obvious from its path
- Dependency graph is acyclic at the domain level
- A new developer can navigate to any feature by context name
- Architecture tests catch violations in CI before they ship

**Negative / watch-outs:**
- Some subdomains (`audit`, `users`) are referenced by nearly every other context — the interface overhead is real but manageable
- Context boundaries are somewhat coarse today (e.g., `access` contains both authentication and authorization); refining boundaries later is possible but requires updating the arch test

**Note:** Cross-context imports are not yet hard-blocked at the Go package level (several legitimate dependencies exist today: `operations/audit` and `identity/users` are used across contexts). The current constraint is enforced via interfaces in `buildDeps()`. A future tightening via `go-arch-lint` would add import-level enforcement.
