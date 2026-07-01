// Example: AI agent management via @qeet-id/node
//
// GET  /api/agents          → list agents for the tenant
// POST /api/agents          → create an agent + mint its first token
//
// In production, gate these routes with admin-role checks.

import { type NextRequest, NextResponse } from "next/server";
import { auth } from "@qeet-id/nextjs";
import { qeetid } from "../../../lib/qeetid-server";

export async function GET() {
  const { tenantId } = await auth();
  if (!tenantId) return NextResponse.json({ error: "unauthenticated" }, { status: 401 });

  const agents = await qeetid.agents.list(tenantId);
  return NextResponse.json({ agents });
}

export async function POST(req: NextRequest) {
  const { tenantId } = await auth();
  if (!tenantId) return NextResponse.json({ error: "unauthenticated" }, { status: 401 });

  const body = (await req.json()) as { name?: string; scopes?: string[] };
  if (!body.name) return NextResponse.json({ error: "name is required" }, { status: 400 });

  // Create the agent identity record.
  const agent = await qeetid.agents.create(tenantId, {
    name: body.name,
    scopes: body.scopes ?? ["read"],
    token_ttl_seconds: 3600,
  });

  // Immediately mint a short-lived token using the one-time secret.
  const tokenResult = agent.secret
    ? await qeetid.agents.token(tenantId, agent.id, agent.secret)
    : null;

  return NextResponse.json({ agent, token: tokenResult }, { status: 201 });
}
