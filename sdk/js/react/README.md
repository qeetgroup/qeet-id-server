# @qeetid/react

React client components & hooks for [Qeet ID](https://qeetid.com): the branded
**"Sign in / Sign up / Continue with Qeet"** buttons, plus `<SignedIn>`,
`<SignedOut>`, `<UserButton>`, `useUser()`, `useAuth()`, and the provider for the
hosted-login flow.

Qeet ID is a full OpenID Connect provider, so "Sign in with Qeet" works exactly
like "Sign in with Google" — the button sends the browser to your login route,
which redirects to Qeet's hosted login + consent.

```bash
pnpm add @qeetid/react
```

Framework-agnostic React (no Next.js dependency). With Next.js, pair it with
`@qeetid/nextjs` to compute the initial state on the server.

> Zero runtime dependencies (only `react` as a peer). The buttons are
> self-contained — the Qeet logo is inlined and styles ship inline, so they
> render correctly with no extra CSS setup.

## Provider

The provider takes server-computed `initialState`, so the UI is correct on first
paint and the HttpOnly session cookie is never read in the browser.

```tsx
// app/layout.tsx (Server Component)
import { auth, currentUser } from "@qeetid/nextjs";
import { QeetidProvider } from "@qeetid/react";

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, userId, tenantId, sessionId } = await auth();
  const user = isAuthenticated ? await currentUser() : null;
  return (
    <html>
      <body>
        <QeetidProvider initialState={{ isAuthenticated, userId, tenantId, sessionId, user }}>
          {children}
        </QeetidProvider>
      </body>
    </html>
  );
}
```

## Branded "Sign in with Qeet" buttons

```tsx
"use client";
import { SignInWithQeet, SignUpWithQeet, ContinueWithQeet } from "@qeetid/react";

<SignInWithQeet />
<SignUpWithQeet />
<ContinueWithQeet theme="dark" shape="pill" />
```

`SignInWithQeet` / `ContinueWithQeet` send the browser to `loginUrl`;
`SignUpWithQeet` sends it to `signUpUrl` (configure both on `<QeetidProvider>`).

Props (`QeetAuthButtonProps`):

| Prop | Type | Default | Notes |
| --- | --- | --- | --- |
| `theme` | `"light" \| "dark" \| "auto"` | `"light"` | `auto` follows `prefers-color-scheme`. |
| `shape` | `"rounded" \| "pill"` | `"rounded"` | Corner radius. |
| `fullWidth` | `boolean` | `true` | Stretch to container width. |
| `returnTo` | `string` | current URL | Where to land after the flow. |
| `children` | `ReactNode` | label | Override the button text. |
| `className` / `style` / `disabled` | — | — | Your `className` wins over the defaults. |

## Components & hooks

```tsx
"use client";
import { SignedIn, SignedOut, SignInButton, SignOutButton, useUser } from "@qeetid/react";

export function Header() {
  const { user } = useUser();
  return (
    <header>
      <SignedOut>
        <SignInButton>Log in</SignInButton>
      </SignedOut>
      <SignedIn>
        <span>{user?.email}</span>
        <SignOutButton />
      </SignedIn>
    </header>
  );
}
```

| Export | Description |
| --- | --- |
| `<QeetidProvider initialState loginUrl? signUpUrl? logoutUrl?>` | Supplies auth context. |
| `<SignInWithQeet>` / `<SignUpWithQeet>` / `<ContinueWithQeet>` | Branded buttons with the Qeet logo. |
| `<SignedIn>` / `<SignedOut>` | Conditionally render by auth state. |
| `<SignInButton>` / `<SignOutButton>` | Unstyled redirect to the hosted login / logout. |
| `<UserButton>` | Avatar + account menu with a sign-out action. |
| `useUser()` | `{ isLoaded, isAuthenticated, user }`. |
| `useAuth()` | `{ isLoaded, isAuthenticated, userId, tenantId, sessionId }`. |

## Non-React apps (plain HTML)

Not using React? Style a link as the button and point `href` at your login
endpoint (which redirects to Qeet's hosted login). Use the dark-surface mark on
dark backgrounds.

```html
<a href="/api/auth/login" class="qeet-btn">
  <img src="https://assets.qeet.in/qeet-logo-on-light.svg" alt="" width="18" height="18" />
  <span>Sign in with Qeet</span>
</a>

<style>
  .qeet-btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 10px;
    padding: 10px 16px; border: 1px solid rgba(0, 0, 0, 0.16); border-radius: 8px;
    background: #fff; color: #1f1f1f; text-decoration: none;
    font: 500 14px/1 system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    transition: background 0.15s ease, border-color 0.15s ease;
  }
  .qeet-btn:hover { background: #f7f8f8; border-color: rgba(0, 0, 0, 0.24); }
  .qeet-btn:focus-visible { outline: 2px solid #f26d0e; outline-offset: 2px; }
</style>
```
