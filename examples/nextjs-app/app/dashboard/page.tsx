import Link from "next/link";

import { auth, currentUser, getToken } from "@qeet-id/nextjs";
import { SignOutButton } from "@qeet-id/react";

import { qeetid } from "../../lib/qeetid-server";
import { McpDemo } from "./mcp-demo";

// Reached only when signed in — qeetidMiddleware redirects anonymous visitors to
// the hosted login before this server component runs.
export default async function Dashboard() {
  const user = await currentUser();
  const token = await getToken();
  const { tenantId } = await auth();

  // Fetch agents for the signed-in tenant (M5 demo).
  const agents = tenantId ? await qeetid.agents.list(tenantId).catch(() => []) : [];

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

      {/* ── M5: AI agents ── */}
      <h2>AI Agents (M5 demo)</h2>
      <p className="muted">
        Agents are non-human identities that receive short-lived JWT access tokens via{" "}
        <code>qeetid.agents.token()</code>. They carry an <code>actor_type=agent</code> claim so
        your resource servers can distinguish them from human users.
      </p>
      {agents.length === 0 ? (
        <p className="muted">No agents yet. Use the API to create one:</p>
      ) : (
        <pre className="code">{JSON.stringify(agents, null, 2)}</pre>
      )}
      <pre className="code">{`POST /api/agents
{ "name": "my-agent", "scopes": ["read", "billing:read"] }
→ { agent: { id, name, scopes, … }, token: { access_token, expires_in } }`}</pre>

      {/* ── M5: MCP guard demo ── */}
      <h2>MCP Token Guard (M5 demo)</h2>
      <p className="muted">
        Resource servers and MCP tool handlers call <code>qeetid.oauth.verify(token, scope?)</code>{" "}
        to confirm a caller is authenticated. Paste your access token above into the demo below.
      </p>
      <McpDemo initialToken={token ?? ""} />

      <div className="row" style={{ marginTop: "2rem" }}>
        <Link href="/" className="link-btn">
          ← Home
        </Link>
        <SignOutButton className="link-btn" />
      </div>
    </main>
  );
}
