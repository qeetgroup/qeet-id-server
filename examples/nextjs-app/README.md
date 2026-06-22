# Qeet ID — Next.js example app

A minimal Next.js (App Router) app that authenticates users with **Qeet ID** using
[`@qeetid/nextjs`](../../packages/qeetid-nextjs) (route handlers + middleware) and
[`@qeetid/react`](../../packages/qeetid-react) (provider, branded `<SignInWithQeet>` button,
`<UserButton>`). It demonstrates the full OIDC Authorization-Code + PKCE flow end to end:

- `/` — public landing page with **Sign in with Qeet**.
- `/api/auth/[...qeetid]` — `handleAuth()` serves `/login`, `/callback`, `/logout`.
- `middleware.ts` — protects every route except `/` and refreshes the session.
- `/dashboard` — protected page showing your OIDC profile + access token.

## Prerequisites

- Node ≥ 20.9 (`nvm use v22.20.0`) and the repo's `pnpm` (run `pnpm install` from `frontend/`).
- The Qeet ID backend running locally **with the dev seed applied** (the seed creates the
  `qci_example_app` OAuth client this example uses).

## Run it

From the repo root (`qeet-id/`):

```bash
# 1. Database + seed (creates the demo OAuth client + demo users)
make -C backend db-up migrate-up seed-reset

# 2. Backend (:4001) + hosted login (:3004). `make dev` starts everything, or run them individually:
make dev-backend
make dev-login
```

Then, in `frontend/examples/nextjs-app/`:

```bash
cp .env.example .env.local        # values already match the seeded demo client
make -C ../../.. dev-example      # or: pnpm --filter @qeetid/example-nextjs dev
```

> First run only: build the SDK packages once so the workspace imports resolve —
> `pnpm --filter @qeetid/react --filter @qeetid/nextjs --filter @qeetid/sdk build` (from `frontend/`).

Open **http://localhost:3010** and click **Sign in with Qeet**. You'll be sent to the hosted login
(:3004); sign in with a seeded account:

```
owner@acme.test  /  Password123!
```

Approve the consent screen and you'll land back on `/dashboard` with your profile and access token.

## Configuration

All config is read from the environment (see [.env.example](./.env.example)):

| Variable | Purpose |
| --- | --- |
| `QEETID_CLIENT_ID` / `QEETID_CLIENT_SECRET` | The seeded `qci_example_app` OAuth client. |
| `QEETID_API_URL` | Qeet ID backend base URL (`http://localhost:4001`). |
| `QEETID_APP_URL` | This app's URL — must match the client's registered redirect URI. |
| `QEETID_COOKIE_SECRET` | ≥32-char secret encrypting the session cookie (dev value provided). |
| `QEETID_SCOPES` | OIDC scopes (`openid profile email`). |

These are **dev-only** values. For your own app, register a client in the admin console
(Auth → Connections → OIDC) and use its credentials + your own cookie secret.
