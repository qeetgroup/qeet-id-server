import Link from "next/link";

import { currentUser, getToken } from "@qeetid/nextjs";
import { SignOutButton } from "@qeetid/react";

// Reached only when signed in — qeetidMiddleware redirects anonymous visitors to
// the hosted login before this server component runs.
export default async function Dashboard() {
  const user = await currentUser();
  const token = await getToken();

  return (
    <main className="container">
      <h1>Dashboard</h1>
      <p className="muted">
        This route is protected by <code>qeetidMiddleware</code> — only signed-in users reach it.
      </p>

      <h2>Your profile (OIDC userinfo)</h2>
      <pre className="code">{JSON.stringify(user, null, 2)}</pre>

      <h2>Access token</h2>
      <p className="muted">
        Dev only — copy this bearer token to test a resource-server / API example.
      </p>
      <pre className="code token">{token ?? "(none)"}</pre>

      <div className="row">
        <Link href="/" className="link-btn">
          ← Home
        </Link>
        <SignOutButton className="link-btn" />
      </div>
    </main>
  );
}
