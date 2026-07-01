# @qeet-id/client

Framework-agnostic **browser** client for [Qeet ID](https://id.qeet.in). Cookie- +
CSRF-aware, dependency-free. It drives the hosted-login auth flows directly
against the Qeet ID API and powers both the hosted login app and the embedded
[`@qeet-id/react`](../react) components/hooks.

> For **server-side** use (API keys, user/tenant management, JWT verification),
> use [`@qeet-id/node`](../node) instead.

## Install

```bash
pnpm add @qeet-id/client
```

## Usage

```ts
import { QeetIDClient } from "@qeet-id/client";

const qeet = new QeetIDClient({ apiUrl: "https://api.id.qeet.in" });

// Password sign-in (handles the MFA step-up)
const res = await qeet.signIn({ email, password });
if (res.status === "needs_mfa") {
  await qeet.verifyMfa({ mfaToken: res.mfaToken, code });
}

// Passwordless
await qeet.passkeys.login();
await qeet.magicLink.start({ email });

// Session
const user = await qeet.currentUser(); // null when signed out
await qeet.signOut();
```

## Surface

| Area | Methods |
| --- | --- |
| Password | `signIn`, `verifyMfa`, `signUp` |
| Passwordless | `passkeys.login`/`register`/`list`/`delete`, `magicLink.start`/`consume` |
| Recovery | `forgotPassword`, `resetPassword` |
| Session | `currentUser`, `signOut`, `switchTenant`, `sessions.list`/`revoke` |
| Social / hosted | `socialStartUrl`, `loginContext` |

All methods throw `QeetIDApiError` (with `status`/`code`) on failure; passkey
ceremonies throw `WebAuthnError` (`unsupported` / `cancelled` / `failed`).
