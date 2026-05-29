# Sprint 7 — Machine Auth E2E + 🚀 AI-Agent Identity & Delegation (D7)

| | |
|---|---|
| **Window** | 2026-08-24 → 2026-09-04 (2 weeks) |
| **Theme** | Verify machine-to-machine auth, then lead the market on the 2026 problem: identity for AI agents |
| **Depends on** | Sprint 4 (RS256/JWKS, token explain), Sprint 5 (audit) |
| **Closes** | New differentiator **D7**; roadmap **#31 (AI-agent/MCP identity)**, advances **#30 (OAuth 2.1/DCR/token-exchange)** |
| **Status** | ⬜ Not started |

**Why:** 10–30% of auth traffic is becoming AI-agent traffic, and today agents typically **borrow a human's token** — unscoped, unattributable, unrevocable. The settling 2026 standard is OAuth 2.1 + Dynamic Client Registration + MCP with **delegated, scoped, auditable** agent credentials. We build this as a first-class primitive so Qeet ID is the safest place to run agents.

---

## Part A — 🧪 Test existing features (E2E)

### 🧪 SCENARIO 7.1 — API keys lifecycle
- **Steps:** `POST /v1/api-keys` (with scopes + expiry); use it as a bearer; list; `DELETE /v1/api-keys/{id}`; use it again.
- **Expect:** key works within scope; expired/revoked key → 401; secret shown once; `last_used_at` updates.
- **Pass:** [ ] scoped access enforced [ ] expiry honored (Test Clock) [ ] revoke immediate [ ] last-used tracked.

### 🧪 SCENARIO 7.2 — Service principals + client_credentials (re-verify under load)
- **Steps:** create principal; mint M2M token; call a scoped endpoint; disable principal; retry.
- **Expect:** token carries tenant + scopes; disabling principal blocks new tokens (and, if short-TTL, access within one TTL).
- **Pass:** [ ] scope enforcement [ ] disable stops issuance [ ] audit shows M2M actor.

### 🧪 SCENARIO 7.3 — Webhook delivery under burst
- **Steps:** generate a burst of events (simulating agent activity); confirm ordering/retry/DLQ behavior holds (re-run Sprint 6.2 at volume).
- **Pass:** [ ] no dropped events [ ] backpressure/retry stable.

**Part A exit:** green + in Newman (`FOLDER=ApiKeys`, `FOLDER=Principals`).

---

## Part B — 🚀 D7: AI-Agent Identity & Delegation (MCP-native)

### The problem nobody solves well
When a user lets an AI agent act for them (a coding agent, a shopping agent, an MCP tool server), the agent usually reuses the human's session/token. Consequences: you **can't tell agent actions from human actions** in the audit log, you **can't scope** the agent to "read calendar but not send money," and you **can't revoke just the agent**. Vendors are only starting here; nobody has the full delegation + consent + audit story.

### Our solution
1. **Agent identities via Dynamic Client Registration (DCR)**: an agent registers (or is pre-provisioned) as a distinct principal type `agent`, owned by a human or org, with metadata (model/tool name, publisher).
2. **Delegated tokens with actor chains**: when a human authorizes an agent, mint a token carrying **`sub = agent_id`, `act = { sub: human_id }`** (RFC 8693 token-exchange / actor claim). Resource APIs and the audit log record **both** — "agent X acting for human Y did Z."
3. **Scoped, time-boxed, revocable**: agent grants are minimal-scope, short-TTL, and independently revocable (`DELETE /v1/agents/{id}/grants/{grant}`) without touching the human's own sessions. A per-human/per-org **agent dashboard** lists active agents and one-click revokes.
4. **Human-in-the-loop consent for sensitive scopes**: scopes flagged `sensitive` (move money, delete data, change config) require **step-up human approval at use time** (push/email approval, ties to D10 step-up). The agent gets a one-shot, scope-bound capability token only after approval.
5. **MCP-native handshake**: expose an MCP-compatible authorization endpoint so MCP clients/servers can obtain delegated Qeet ID tokens through the standard flow; document the integration.
6. **Full attribution**: every agent action is auditable and shows the delegation chain (anchored via D5).

### Design / changes
**Backend**
- New module `internal/agent/` (or extend `principal`): agent principal type, DCR endpoint `POST /v1/agents/register`, grant model, delegated-token issuance via **token exchange** `POST /v1/oauth/token` (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`) producing `act` claims.
- Sensitive-scope approval flow: `POST /v1/agents/{id}/authorize-action` → pending approval → human approves (push/email) → one-shot capability token.
- Migration `0032_agents.up.sql`: `agent.identities`, `agent.grants`, `agent.action_approvals`.
- Audit + token-explain (D4) updated to render actor chains.

**Frontend**
- **Admin**: Agents registry (per tenant) + scope policy (which scopes are `sensitive`).
- **End-user/account**: "Connected Agents" dashboard — see what each agent can do, its actions (from audit), and revoke.
- Approval UI for sensitive actions.

**Docs**
- `content/docs/agents/index.mdx` (concepts + delegation model), `content/docs/agents/mcp.mdx` (MCP integration), update `api/tokens.mdx` for `act` claims and token-exchange.

### Acceptance criteria
- [ ] An agent can be registered and granted a minimal, time-boxed scope by a human.
- [ ] Delegated tokens carry `sub=agent, act=human`; resource calls and audit show both.
- [ ] Revoking the agent's grant stops the agent **without** affecting the human's own sessions.
- [ ] A `sensitive` scope triggers human approval at use time; denied/expired approval blocks the action.
- [ ] An MCP client can obtain a delegated token via the documented flow.

### 🧪 How you test D7
1. Register agent "calendar-bot"; as a human, grant `calendar:read` for 1h.
2. Call an API with the delegated token; confirm `/tokens/explain` shows the actor chain and the audit event names both agent and human.
3. Revoke the grant; agent calls fail; confirm your own session still works.
4. Grant a `payments:write` (sensitive) scope; agent attempts a charge → blocked pending approval; approve via the push/email prompt (Dev Inbox) → one-shot token issued; second attempt without re-approval → blocked.

---

## Definition of Done
- [ ] Part A: scenarios pass + in Newman.
- [ ] Part B: agent module, DCR, token-exchange with `act` claims, sensitive-scope approval, MCP endpoint, migrations, tests green.
- [ ] Admin Agents registry + scope policy; end-user Connected Agents dashboard + approval UI live.
- [ ] `agents/*` docs published; token docs updated.
- [ ] Roadmap: #31 checked, #30 advanced; D7 noted; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
