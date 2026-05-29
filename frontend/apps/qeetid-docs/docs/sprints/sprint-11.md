# Sprint 11 — Social OAuth (#2) + Account Linking (#26) + 🚀 Identity Graph & Auto-Merge (D11)

| | |
|---|---|
| **Window** | 2026-10-19 → 2026-10-30 (2 weeks) |
| **Theme** | Finish the social-login gap, then solve the duplicate-account problem no platform handles cleanly |
| **Depends on** | Sprint 4 (OIDC/tokens), Sprint 1 (Dev Inbox) |
| **Closes** | Gap **#2** (social OAuth), **#26** (account linking); New differentiator **D11** |
| **Status** | ⬜ Not started |

**Why first in the enterprise half:** social login is table-stakes and currently returns **501** (`internal/social/social.go:203,211`) even though provider config + identity storage already exist. Finishing it unblocks real users — and the moment you have multiple login methods, you get the **duplicate-identity** mess (same human as `google:alice`, `github:alice`, `password:alice@…`). We solve that with an Identity Graph.

---

## Part A — 🧪 Test existing + newly-built (E2E)

### 🧪 SCENARIO 11.1 — Provider config (already built) round-trips
- **Steps:** `POST /v1/social/providers` (Google), `GET /v1/tenants/{t}/social/providers`.
- **Pass:** [ ] upsert works [ ] secret stored encrypted [ ] list shows enabled providers.

### 🧪 SCENARIO 11.2 — Social login start → callback (newly built #2)
- **Steps:** `GET /v1/social/google/start` → redirect to Google → `GET /v1/social/google/callback?code=…&state=…`.
- **Expect:** state/PKCE validated; on success a Qeet ID session is created; external identity linked to a user (created if new).
- **Pass:** [ ] start returns correct authorize URL [ ] state mismatch rejected [ ] callback creates/links identity + session [ ] error from provider handled gracefully.

### 🧪 SCENARIO 11.3 — Identity link/unlink (already built + extended)
- **Steps:** `GET /v1/users/{u}/social/identities`; unlink one via `DELETE /v1/social/identities/{id}`.
- **Pass:** [ ] linked identities listed [ ] cannot unlink the **last** login method (lockout guard) [ ] unlink audited.

### 🧪 SCENARIO 11.4 — Account linking on matching verified email (#26)
- **Pre:** user signed up with password using alice@x.com (verified).
- **Steps:** later signs in with Google returning the same verified email.
- **Expect:** per tenant policy, the Google identity is **linked** to the existing user (not a new account), with a confirmation step.
- **Pass:** [ ] same verified email links (with confirmation) [ ] unverified email does **not** auto-link (anti-takeover) [ ] policy toggle respected.

**Part A exit:** green + in Newman (`FOLDER=Social`).

---

## Part B — 🚀 D11: Identity Graph & Auto-Merge

### The problem nobody solves well
Across password + multiple social providers + SSO, the same human ends up as several accounts. Auth0/Clerk have manual "account linking" but no proactive **detection** of duplicates, no **confidence scoring**, and no safe **merge** that preserves history. Support teams resolve these by hand; data integrity rots.

### Our solution
1. **Identity Graph**: model identities (password, social, SSO, passkey) as nodes linked to a canonical **person**. Edges carry match signals: verified-email equality, phone equality, provider `sub` history, device overlap, name similarity.
2. **Duplicate detection with confidence**: a scorer flags likely-same-person clusters (`GET /v1/identity-graph/duplicates`) with a confidence and the evidence behind it (reuses the D2 "explain" idea — show *why* we think they match).
3. **Safe merge**: `POST /v1/users/merge` consolidates accounts — unions roles/groups/identities/consents, keeps the audit trail of both, and records a reversible merge event. Guardrails: only merge on strong signals (e.g. ≥2 verified factors) or explicit admin/user confirmation; never silently merge on name alone.
4. **User-confirmed self-merge**: end users see "Is this you?" prompts to link/merge their own accounts.

### Design / changes
**Backend**
- `internal/social/`: implement `start`/`callback` per provider (OAuth2 + OIDC discovery), state+PKCE, identity upsert, account-linking policy. Use real secrets (encrypted).
- New module `internal/identitygraph/`: graph store, match scorer, duplicate query, merge orchestrator (transactional union + reversible merge log).
- Migration `0036_identity_graph.up.sql`: `identity.person`, `identity.edges`, `identity.merge_events`; add `person_id` FK to users/external_identities.
- Webhooks: `identity.linked`, `identity.merged`, `identity.duplicate_detected`.

**Frontend**
- **Admin**: "Continue with Google/GitHub/…" management; a **Duplicates** screen (clusters + evidence + one-click merge/dismiss); merge history.
- **End-user/account**: "Connected accounts" + "Is this you?" self-merge prompts.

**Docs**
- `content/docs/authentication/social-providers.mdx` (real setup), `content/docs/identity/account-linking.mdx`, `content/docs/identity/identity-graph.mdx`.

### Acceptance criteria
- [ ] Google + GitHub login work end-to-end (start→callback→session); state/PKCE enforced.
- [ ] Same verified email links to existing account (with confirmation); unverified does not.
- [ ] Duplicate detection surfaces a real cluster with confidence + evidence.
- [ ] Merge unions roles/groups/identities/consents and is reversible; both audit trails preserved.
- [ ] Last-login-method unlink is blocked.

### 🧪 How you test D11
1. Create `alice@x.com` via password (verify email). Log in with Google for the same verified email → linked to the same user (confirm prompt). 
2. Force a duplicate (e.g. GitHub returns a different but same-person email); check `/identity-graph/duplicates` shows the cluster with evidence.
3. Merge them; confirm roles/identities unioned, audit preserved, and a reversible merge event recorded.
4. Try to merge two clearly-different users on name only → blocked (insufficient signal).

---

## Definition of Done
- [ ] Part A: scenarios pass + in Newman.
- [ ] Part B: social start/callback (#2), account-linking (#26), identitygraph module + merge, migrations, tests green.
- [ ] Admin social mgmt + Duplicates/merge UI; end-user connected-accounts + self-merge live.
- [ ] `social-providers.mdx`, `identity/account-linking.mdx`, `identity/identity-graph.mdx` published.
- [ ] Roadmap: #2, #26 checked; D11 noted; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
