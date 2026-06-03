# @qeetid/sdk

Server-side TypeScript SDK for [Qeet ID](https://qeetid.com). Manage users and
tenants, run authorization checks, and verify sessions — from your backend.

> **Server-side only.** Authenticate with a secret API key (`qk_…`). Never ship
> it to a browser. For the web app, use `@qeetid/nextjs` / `@qeetid/react`.

Zero runtime dependencies — uses the built-in `fetch` and `node:crypto`
(Node ≥ 18).

## Install

```bash
pnpm add @qeetid/sdk
```

## Quick start

```ts
import { Qeetid } from "@qeetid/sdk";

const qeetid = new Qeetid({ apiKey: process.env.QEETID_API_KEY! });

// Verify the caller's access token (local — checks the ES256 signature against
// the published JWKS, then expiry/issuer/audience). No network call after the
// keys are cached.
const claims = await qeetid.sessions.verify(accessToken);

// Authorization
if (await qeetid.can({ user: claims.userId, tenant: claims.tenantId!, permission: "billing:write" })) {
  // …
}

// Manage users / tenants
const user = await qeetid.users.create({ email: "new@acme.com", display_name: "New User" });
for await (const u of qeetid.users.listAll({ tenant: "acme" })) {
  console.log(u.email);
}
```

## API

| Call | Description |
| --- | --- |
| `qeetid.sessions.verify(token, opts?)` | Verify an ES256 token against JWKS; returns `SessionClaims`. |
| `qeetid.can({ user, tenant, permission })` | Single RBAC permission check → `boolean`. |
| `qeetid.canAll(user, tenant, permissions[])` | True only if all pass (parallel). |
| `qeetid.users.{create,get,update,delete,setPassword,list,listAll}` | User management. |
| `qeetid.tenants.{create,get,update,delete,list}` | Tenant management. |

## Errors

Every failed call throws a `QeetidError` (or subclass) carrying `status`,
`code`, and `requestId`:

```ts
import { RateLimitError, InvalidCredentialsError } from "@qeetid/sdk";

try {
  await qeetid.users.get("usr_missing");
} catch (err) {
  if (err instanceof RateLimitError) await wait(err.retryAfterSeconds);
  else if (err instanceof InvalidCredentialsError) rotateApiKey();
  else throw err;
}
```

429 and 5xx (for idempotent calls) are retried automatically with backoff,
honoring `Retry-After`.

## Configuration

```ts
new Qeetid({
  apiKey: "qk_…",                 // required
  baseUrl: "https://api.qeetid.com", // default
  timeoutMs: 10_000,
  maxRetries: 2,
  fetch: customFetch,             // optional (e.g. a proxy agent)
});
```

## Roadmap

API keys, magic links, and audit-log resources; parity Go module
(`github.com/qeetgroup/qeetid-go`); and the `@qeetid/nextjs` + `@qeetid/react`
integrations for the hosted-login flow.
