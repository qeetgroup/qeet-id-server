# @qeetid/react

React client components & hooks for [Qeet ID](https://qeetid.com): `<SignedIn>`,
`<SignedOut>`, `useUser()`, `useAuth()`, and sign-in/out buttons for the
hosted-login flow.

```bash
pnpm add @qeetid/react
```

Framework-agnostic React (no Next.js dependency). With Next.js, pair it with
`@qeetid/nextjs` to compute the initial state on the server.

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
| `<QeetidProvider initialState loginUrl? logoutUrl?>` | Supplies auth context. |
| `<SignedIn>` / `<SignedOut>` | Conditionally render by auth state. |
| `<SignInButton>` / `<SignOutButton>` | Redirect to the hosted login / logout. |
| `useUser()` | `{ isLoaded, isAuthenticated, user }`. |
| `useAuth()` | `{ isLoaded, isAuthenticated, userId, tenantId, sessionId }`. |
