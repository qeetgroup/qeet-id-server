# Sprint 4 — OIDC/OAuth E2E + 🚀 Edge-Verifiable Tokens & Token Explain (D4)

| | |
|---|---|
| **Window** | 2026-07-13 → 2026-07-24 (2 weeks) |
| **Theme** | Prove the OIDC provider, finish the standards gaps, then make tokens verifiable at the edge and self-explaining |
| **Depends on** | Sprint 1. Pulls in roadmap **#3 (RS256/JWKS)** as a hard prerequisite for D4. |
| **Closes** | New differentiator **D4**; roadmap **#3** + OIDC completion (refresh/introspect/revoke/logout) |
| **Status** | ⬜ Not started |

**Why:** The OIDC Authorization-Code + PKCE flow already works, but it's signed with **HS256 and an empty JWKS**, so no external Relying Party can verify our tokens. Fix that (RS256 + JWKS), finish the missing OIDC endpoints, then ship something nobody else does well: tokens you can **verify at the edge without calling home** and a **decoder/explain endpoint** that demystifies any token.

---

## Part A — 🧪 Test existing features (E2E)

### 🧪 SCENARIO 4.1 — Discovery + JWKS
- **Steps:** `GET /.well-known/openid-configuration`; `GET /.well-known/jwks.json`.
- **Expect (today):** discovery lists endpoints; JWKS is **empty** (HS256). **After #3:** JWKS lists the active RS256 public key with a `kid`.
- **Pass:** [ ] discovery complete & correct issuer/endpoints [ ] (post-#3) JWKS non-empty & matches token `kid`.

### 🧪 SCENARIO 4.2 — Dynamic client registration
- **Steps:** `POST /v1/oidc/clients` (confidential + public).
- **Expect:** returns `client_id` (+ secret for confidential); redirect URIs stored.
- **Pass:** [ ] both client types register [ ] secret shown once.

### 🧪 SCENARIO 4.3 — Authorization Code + PKCE (S256)
- **Steps:**
  1. As a logged-in user, `GET /v1/oauth/authorize?response_type=code&client_id=…&redirect_uri=…&scope=openid%20profile&code_challenge=…&code_challenge_method=S256&state=…&nonce=…`.
  2. Exchange: `POST /v1/oauth/token-code` with `code` + `code_verifier`.
- **Expect:** authorize returns `code` to redirect_uri; exchange returns `access_token` + `id_token`; `nonce` echoed in id_token; wrong `code_verifier` → reject.
- **Pass:** [ ] code issued [ ] PKCE enforced (bad verifier fails) [ ] id_token has correct `aud`/`nonce`/`sub` [ ] code single-use.

### 🧪 SCENARIO 4.4 — userinfo
- **Steps:** `GET /v1/oauth/userinfo` with the access token.
- **Expect:** claims for the subject scoped to granted scopes.
- **Pass:** [ ] correct claims [ ] invalid token → 401.

### 🧪 SCENARIO 4.5 — client_credentials (M2M)
- **Steps:** create a service principal; `POST /v1/oauth/token` grant_type=client_credentials.
- **Expect:** JWT with tenant + scopes; bad secret → reject.
- **Pass:** [ ] token minted [ ] scopes honored [ ] revoke principal → token issuance fails.

**Part A exit:** green + in Newman (`FOLDER=OIDC`).

---

## Part B — 🚀 D4: Edge-Verifiable Tokens + Token Explain
*(prerequisite: roadmap #3 RS256/JWKS — do it first this sprint)*

### Finish the OIDC standards gaps (table-stakes, bundled here)
- **RS256/ES256 signing + JWKS rotation** (#3): real keys, `kid` header, 90-day rotation with overlap, populate `/.well-known/jwks.json`.
- **Refresh-token grant** for OIDC clients, **token introspection** (RFC 7662), **token revocation** (RFC 7009), **RP-initiated logout** + a minimal **consent screen**.

### The differentiator: tokens that verify at the edge + explain themselves

**The problem nobody solves well.** Two recurring pains:
1. **Edge verification** — to validate a token at a CDN edge / API gateway you either call introspection (a round-trip that kills edge latency) or you trust a JWT but can't cheaply check **revocation**. Stateless JWTs can't be revoked; stateful sessions need a call home.
2. **Tokens are opaque to developers** — debugging "why is this token rejected / what scopes does it carry / when does it expire / which key signed it" means pasting into jwt.io and guessing.

**Our solution.**
1. **Edge Verification Kit**: publish a tiny, dependency-free verifier (WASM + JS + Go) that validates Qeet ID JWTs **offline** using cached JWKS, **plus** a compact, signed **revocation epoch / bloom-filter** the edge can pull periodically (`GET /v1/tokens/revocations`) so revoked tokens are caught at the edge without a per-request call home. Short token TTL + revocation digest = near-real-time revocation with edge latency.
2. **`POST /v1/tokens/explain`**: paste any Qeet ID token → get a human-readable breakdown: header (alg/kid + "is this key still active in JWKS?"), claims (decoded + descriptions), validity window (with "expires in 4m"), scopes (with what each grants), signature status, and **revocation status**. Safe to expose in the admin "Token Inspector."

### Design / changes
**Backend**
- `internal/oidc/`: implement RS256 key management (migration `0029_signing_keys.up.sql`: `oidc.signing_keys` with rotation state), populate JWKS, refresh/introspect/revoke/logout endpoints, consent storage.
- `internal/tokens/`: `GET /v1/tokens/revocations` (signed revocation digest/epoch + optional bloom filter); `POST /v1/tokens/explain`.
- `packages/qeetid-edge-verify/` (new shared lib): offline verify + revocation-digest check; Go equivalent in `backend/pkg/edgeverify/`.

**Frontend**
- Admin **Connections → Signing Keys** (view/rotate keys). 
- Admin **Token Inspector** (calls `/tokens/explain`).

**Docs**
- `content/docs/edge.mdx` (exists) → flesh out with the Edge Verification Kit. New `content/docs/api/tokens.mdx`. Update `sso.mdx`/OIDC docs for refresh/introspect/revoke/logout.

### Acceptance criteria
- [ ] External RP can verify our id_token/access_token via published JWKS (RS256).
- [ ] Key rotation keeps old tokens verifiable during overlap; JWKS lists both `kid`s.
- [ ] Refresh/introspect/revoke/logout conform to their RFCs.
- [ ] Edge verifier validates a token offline and rejects one whose `jti`/epoch is in the revocation digest.
- [ ] `/tokens/explain` correctly reports expiry, scopes, signing key status, and revocation.

### 🧪 How you test D4
1. Register an external test RP (or use a sample SPA) and complete login against our `/authorize` — confirm it verifies the id_token via JWKS.
2. Rotate the signing key; confirm previously issued tokens still verify until overlap ends.
3. Revoke a token; pull `/tokens/revocations`; run the edge verifier offline → token rejected without an introspection call.
4. Paste a valid, an expired (Test Clock), and a revoked token into the Token Inspector → each diagnosis is correct.

---

## Definition of Done
- [ ] Part A: scenarios pass + in Newman.
- [ ] #3 + OIDC completion merged & conformance-tested.
- [ ] Edge verifier lib + revocation digest + `/tokens/explain` shipped.
- [ ] Admin Signing Keys + Token Inspector live.
- [ ] `edge.mdx`, `api/tokens.mdx`, OIDC docs updated.
- [ ] Roadmap: #3 + OIDC-completion checked; D4 noted; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
