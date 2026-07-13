# Qeet ID — React SPA example

A Vite single-page app that signs in with **Qeet ID**. Unlike the [Next.js example](../nextjs-app)
(which runs the OAuth flow on the server), a SPA has no server, so it authenticates as a **public
client** and runs the OAuth2 **Authorization Code + PKCE** flow entirely in the browser, then uses
[`@qeetid/react`](../../packages/qeetid-react) for the UI (the branded `<SignInWithQeet>` button,
`<SignedIn>`/`<SignedOut>`, `<UserButton>`).

The flow ([src/qeet.ts](./src/qeet.ts)):

1. `/login` → build a PKCE challenge and redirect to `/v1/oauth/authorize`.
2. Hosted login (:3004) authenticates the user and bounces back to `/callback?code=…`.
3. `/callback` → exchange the code at `/v1/oauth/token-code` (PKCE verifier, **no secret**), store the
   access token in `sessionStorage`, then load `/v1/oauth/userinfo`.
4. `/logout` → clear the token and hit `/v1/oauth/logout`.

## Prerequisites

- Node ≥ 24 (`nvm use`); run `pnpm install` from `frontend/`.
- The Qeet ID backend running locally **with the dev seed applied** (creates the public
  `qci_example_spa` client this app uses).
- **`ALLOWED_ORIGINS` must include `http://localhost:3020`.** The browser calls the token + userinfo
  endpoints cross-origin, so the SPA's origin must be allowed for CORS. It's already in
  [backend/.env.example](../../../backend/.env.example); if your existing `backend/.env` predates this,
  add `http://localhost:3020` to its `ALLOWED_ORIGINS` and restart the backend.

## Run it

From the repo root (`qeet-id/`):

```bash
# 1. Database + seed (creates the qci_example_spa public client + demo users)
make -C backend db-up migrate-up seed-reset

# 2. Backend (:4001) + hosted login (:3004)
make dev-backend
make dev-login
```

Then, in `frontend/examples/react-app/`:

```bash
cp .env.example .env.local        # values already match the seeded public client
make -C ../../.. dev-example-react   # or: pnpm --filter @qeetid/example-react dev
```

> First run only: build the SDK once so the workspace import resolves —
> `pnpm --filter @qeetid/react build` (from `frontend/`).

Open **http://localhost:3020** and click **Sign in with Qeet** → sign in with a seeded account:

```
saibabu@qeet.in  /  Password123!
```

You'll return to the app signed in, showing your profile + access token.

## Configuration

Vite exposes only `VITE_`-prefixed vars to the browser (see [.env.example](./.env.example)):

| Variable | Purpose |
| --- | --- |
| `VITE_QEETID_API_URL` | Qeet ID backend base URL (`http://localhost:4001`). |
| `VITE_QEETID_CLIENT_ID` | The seeded **public** client (`qci_example_spa`). |
| `VITE_QEETID_REDIRECT_URI` | This app's callback — must match the client's registered redirect URI. |
| `VITE_QEETID_POST_LOGOUT_URI` | Where to return after logout. |
| `VITE_QEETID_SCOPES` | OIDC scopes (`openid profile email`). |

A public client holds **no secret** — security comes from PKCE + the exact redirect-URI match + the
CORS origin allowlist. For production, register your own public client and serve the SPA over HTTPS.

> **Tokens in the browser:** this example keeps the access token in `sessionStorage` for simplicity.
> Production SPAs commonly prefer a backend-for-frontend (like the [Next.js example](../nextjs-app))
> so tokens never touch JavaScript.
