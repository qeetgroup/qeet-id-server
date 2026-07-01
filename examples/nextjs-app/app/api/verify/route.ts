// Example: MCP token guard — the pattern a tool server uses to verify
// caller identity before executing a tool.
//
// POST /api/verify
//   Authorization: Bearer <access_token>
//   Body: { scope?: string }   ← optional required scope to check
//
// Returns the token's introspect claims if active, or 401/403 on failure.
// Paste an access token from the /dashboard page to try it out.

import { type NextRequest, NextResponse } from "next/server";
import { qeetid } from "../../../lib/qeetid-server";

export async function POST(req: NextRequest) {
  const authHeader = req.headers.get("authorization") ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "").trim();
  if (!token) {
    return NextResponse.json({ error: "Missing Authorization: Bearer <token>" }, { status: 400 });
  }

  const body = await req.json().catch(() => ({})) as { scope?: string };

  try {
    // oauth.verify() introspects the token and throws if inactive or scope missing.
    const claims = await qeetid.oauth.verify(token, body.scope);
    return NextResponse.json({ active: true, claims });
  } catch (err: unknown) {
    const e = err as { status?: number; code?: string; message?: string };
    return NextResponse.json(
      { active: false, error: e.code ?? "verification_failed", message: e.message },
      { status: e.status ?? 500 },
    );
  }
}
