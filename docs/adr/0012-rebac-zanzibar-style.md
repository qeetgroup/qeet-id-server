# ADR-0012: Relationship-Based Authorization (ReBAC) alongside RBAC

**Status:** Accepted  
**Date:** 2025-Q2 (implemented in migration 0060)  
**Deciders:** Qeet ID core team

---

## Context

Qeet ID's initial authorization model is RBAC (roles + permissions, `migrations/0006`). RBAC works well for coarse-grained access (e.g., "admin can manage users") but is insufficient for fine-grained resource ownership:

- "User A can view Document D because A owns D"
- "User A can manage Resource R because A is a member of Group G, and G has editor access to R"
- "Agent X can act on behalf of User U for Resource R only"

These checks require tracking relationships between specific users and specific resources — not just role assignments. Google's Zanzibar paper (2019) describes a scalable relation-tuple approach used by Google Drive, YouTube, etc.

Options evaluated:
1. **Extend RBAC** — add resource-scoped permission rows. Gets complicated quickly.
2. **External authorization service (OPA, Cedar)** — adds an external dependency; complex policy language.
3. **Embedded ReBAC with relation tuples** — Zanzibar-style, built into the monolith.

## Decision

Implement an **embedded Zanzibar-style ReBAC engine** in `domains/access/authorization/rebac`:

- **`relation_tuples` table** (`migrations/0060_relation_tuples`): `(object_type, object_id, relation, subject_type, subject_id)` — e.g., `("document", "doc123", "viewer", "user", "user456")`
- **Recursive `Check()` function** with depth limit (cycle guard) — follows userset expansions to evaluate transitive access
- **Complements RBAC** — RBAC handles role-level access control; ReBAC handles resource-level fine-grained ownership and delegation

API surface:
- `POST /v1/rebac/tuples` — write a relation tuple
- `DELETE /v1/rebac/tuples` — remove a relation tuple
- `POST /v1/rebac/check` — check if subject has relation to object
- Admin console: Access → Relationships page

## Consequences

**Positive:**
- Fine-grained authorization without complex policy DSL
- Natural fit for resource ownership, team-level access, and delegation chains
- Complements existing RBAC: the two systems solve different problems
- Extensible: new object types and relations can be added without schema changes

**Negative / watch-outs:**
- Recursive queries (`CHECK`) can be slow for deep relation chains without caching. The depth limit (default: 10 hops) is a guardrail but also a correctness boundary
- Cycle detection is required: a circular relation chain (A → B → A) must not cause an infinite loop. The depth limit serves as the cycle guard
- Writing relation tuples correctly is the caller's responsibility; Qeet ID doesn't validate semantic correctness (e.g., does the referenced `object_id` actually exist?)
- For pre-1.0, the ReBAC implementation is intentionally minimal (no caching, no watch API, no namespace config). These are tracked improvements for post-1.0.
