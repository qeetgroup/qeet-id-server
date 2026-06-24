# ADR-0013: Short-Lived Ephemeral Tokens for AI Agents

**Status:** Accepted  
**Date:** 2025-Q3 (implemented in migration 0061)  
**Deciders:** Qeet ID core team

---

## Context

AI agents (LLM-based autonomous systems, MCP tool servers) need machine identity to interact with APIs on behalf of users or autonomously. Long-lived API keys (the traditional approach) carry significant risk:

- A leaked API key is valid until explicitly rotated
- Long-lived keys accumulate permissions over time
- There's no natural scope limit per task/session

The MCP (Model Context Protocol) ecosystem requires identity primitives that are:
- Short-lived (minimize blast radius of leaks)
- Scoped (minimal permissions per task)
- Auditable (agent_id visible in logs and introspection)
- Re-mintable (agents acquire new credentials per session)

## Decision

AI agents use **ephemeral actor tokens** with `actor_type = "agent"`:

**Agent definition** (stored in `platform.agents`):
```
id, name, tenant_id, secret_hash, allowed_scopes[], max_ttl_seconds
```
The agent secret has prefix `agt_` (32 random bytes, base64url).

**Token mint endpoint:**
```
POST /v1/agents/token
{ agent_id, agent_secret, requested_scopes[], ttl_seconds }
  → verify agt_ secret (bcrypt)
  → granted_scopes = requested_scopes ∩ allowed_scopes
  → ttl = min(requested_ttl, max_ttl, 3600)
  → mint ES256 JWT with:
      actor_type = "agent"
      agent_id   = <id>
      scp        = granted_scopes
      exp        = now + ttl
```

Tokens are **not refreshable** — agents mint a new token for each task. There is no refresh token.

**MCP introspection:** `POST /oauth/introspect` returns `actor_type` and `agent_id` so downstream services can gate agent-specific paths.

## Consequences

**Positive:**
- Short TTL (60s–1h) bounds the blast radius of a leaked token to its remaining lifetime
- Scoped: agents can only request scopes within their pre-authorized `allowed_scopes` set
- Auditable: `agent_id` is in every JWT claim and logged on every API request
- MCP-ready: `introspect` endpoint exposes agent identity for MCP server enforcement
- Pairs with RFC 8693 delegation (ADR — token exchange): an agent can hold a delegated token acting on behalf of a specific user

**Negative / watch-outs:**
- Agents must implement re-mint logic — they cannot rely on a long-lived credential. The SDK (`sdk/js/sdk`, `sdk/go`) provides a helper
- High-frequency agents that need to mint tokens very often will generate load on the token endpoint. The per-API-key rate limit applies to the agent mint endpoint
- The `agt_` secret is a long-lived credential (like a service account key). It must be protected with the same care as an API key. Rotation requires updating the agent configuration in the admin console
