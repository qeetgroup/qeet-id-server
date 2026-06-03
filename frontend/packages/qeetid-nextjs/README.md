# @qeetid/nextjs

[Qeet ID](https://qeetid.com) for Next.js (App Router). Protect routes, run the
hosted-login OAuth flow, and read the signed-in user — in a few lines.

```bash
pnpm add @qeetid/nextjs
```

## 1. Environment

```bash
QEETID_CLIENT_ID=qci_…
QEETID_CLIENT_SECRET=…
QEETID_API_URL=https://api.qeetid.com
QEETID_APP_URL=https://app.acme.com        # this app's URL
QEETID_COOKIE_SECRET=…                      # ≥32 random chars
# QEETID_SCOPES="openid profile email"      # optional
```

Register `${QEETID_APP_URL}/api/auth/callback` as a redirect URI, and
`${QEETID_APP_URL}` as a post-logout URI, on your Qeet ID OIDC client.

## 2. Mount the auth routes

`app/api/auth/[...qeetid]/route.ts`:

```ts
import { handleAuth } from "@qeetid/nextjs";
export const GET = handleAuth(); // /api/auth/login | /callback | /logout
```

## 3. Protect routes

`middleware.ts`:

```ts
// Import from the /middleware subpath — it's Edge-runtime safe (Web Crypto only).
import { qeetidMiddleware } from "@qeetid/nextjs/middleware";

export default qeetidMiddleware({ publicRoutes: ["/", "/pricing"] });

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
```

Unauthenticated requests to protected routes are redirected to the hosted login
(`/api/auth/login` → Qeet ID), then back to where they started. The middleware
also **silently refreshes** a near-expiry session — calling the token endpoint,
persisting the rotated refresh token, and re-running the request with the fresh
cookie — so users aren't bounced to login when the short-lived access token
expires.

## 4. Read the user (Server Components / Route Handlers / Actions)

```ts
import { auth, currentUser } from "@qeetid/nextjs";

export default async function Page() {
  const { isAuthenticated, userId, tenantId } = await auth();
  if (!isAuthenticated) return null; // middleware already gated this

  const user = await currentUser(); // OIDC userinfo, or null
  return <p>Hello {user?.sub}</p>;
}
```

Sign-out: link to `/api/auth/logout` (clears the session and triggers
RP-initiated logout at Qeet ID).

## How it works

- **Hosted login.** `/api/auth/login` starts the OAuth Authorization Code + PKCE
  flow against Qeet ID's hosted login; `/api/auth/callback` exchanges the code
  for tokens and stores an **encrypted, HttpOnly session cookie** (AES-256-GCM).
- **Middleware (Edge runtime)** gates routes and **silently refreshes** the
  session before the access token expires, persisting the rotated refresh token.
  It uses Web Crypto only, so it never pulls Node-only code into the Edge bundle.
- **`auth()` (Node runtime)** does the cryptographic check: decrypts the cookie
  and verifies the access token's ES256 signature against the published JWKS
  (via `@qeetid/sdk`). Because middleware refreshes proactively, the token
  `auth()` sees is valid.

## API

| Export | Use |
| --- | --- |
| `handleAuth()` | Route handler for `/api/auth/[...qeetid]`. |
| `qeetidMiddleware(opts)` | Route protection middleware. |
| `auth()` | `{ isAuthenticated, userId, tenantId, sessionId, accessToken }`. |
| `currentUser()` | OIDC userinfo for the signed-in user, or `null`. |
| `getToken()` | Current access token (to call your own APIs), or `null`. |
