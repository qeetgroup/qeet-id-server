import { createHash, randomBytes } from "node:crypto";

import { Sessions } from "@qeetid/sdk";
import { NextResponse, type NextRequest } from "next/server";

import { callbackUrl, getConfig, PKCE_COOKIE, SESSION_COOKIE, type QeetidConfig } from "./config.js";
import { open, seal } from "./cookies.js";
import type { SessionData } from "./types.js";

interface PkceState {
  state: string;
  verifier: string;
  returnTo: string;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
}

/**
 * handleAuth returns the GET route handler for `app/api/auth/[...qeetid]/route.ts`:
 *
 *   import { handleAuth } from "@qeetid/nextjs";
 *   export const GET = handleAuth();
 *
 * It serves /api/auth/login, /api/auth/callback, and /api/auth/logout.
 */
export function handleAuth() {
  return async function GET(
    req: NextRequest,
    ctx: { params: Promise<{ qeetid?: string[] }> },
  ): Promise<Response> {
    const cfg = getConfig();
    const segments = (await ctx.params).qeetid ?? [];
    switch (segments[segments.length - 1]) {
      case "login":
        return startLogin(req, cfg);
      case "callback":
        return handleCallback(req, cfg);
      case "logout":
        return handleLogout(cfg);
      default:
        return new NextResponse("not found", { status: 404 });
    }
  };
}

function b64url(b: Buffer): string {
  return b.toString("base64url");
}

function isSecure(cfg: QeetidConfig): boolean {
  return cfg.appUrl.startsWith("https");
}

// Only allow local absolute paths as post-login destinations (open-redirect guard).
function safeReturn(raw: string | null): string {
  return raw && raw.startsWith("/") && !raw.startsWith("//") ? raw : "/";
}

function startLogin(req: NextRequest, cfg: QeetidConfig): NextResponse {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const state = b64url(randomBytes(16));
  const returnTo = safeReturn(req.nextUrl.searchParams.get("return_to"));

  const authorize = new URL(`${cfg.apiUrl}/v1/oauth/authorize`);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", cfg.clientId);
  authorize.searchParams.set("redirect_uri", callbackUrl(cfg));
  authorize.searchParams.set("scope", cfg.scopes);
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");

  const pkce: PkceState = { state, verifier, returnTo };
  const res = NextResponse.redirect(authorize);
  res.cookies.set(PKCE_COOKIE, seal(pkce, cfg.cookieSecret), {
    httpOnly: true,
    secure: isSecure(cfg),
    sameSite: "lax",
    path: "/",
    maxAge: 600,
  });
  return res;
}

async function handleCallback(req: NextRequest, cfg: QeetidConfig): Promise<NextResponse> {
  const params = req.nextUrl.searchParams;
  const fail = (reason: string) =>
    NextResponse.redirect(new URL(`/?auth_error=${encodeURIComponent(reason)}`, cfg.appUrl));

  if (params.get("error")) return fail(params.get("error") ?? "denied");

  const code = params.get("code");
  const state = params.get("state");
  const pkceRaw = req.cookies.get(PKCE_COOKIE)?.value;
  const pkce = pkceRaw ? open<PkceState>(pkceRaw, cfg.cookieSecret) : null;
  if (!code || !state || !pkce || pkce.state !== state) return fail("invalid_state");

  const tokenRes = await fetch(`${cfg.apiUrl}/v1/oauth/token-code`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: callbackUrl(cfg),
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      code_verifier: pkce.verifier,
    }).toString(),
  });
  if (!tokenRes.ok) return fail("token_exchange");
  const tokens = (await tokenRes.json()) as TokenResponse;

  let session: SessionData;
  try {
    const sessions = new Sessions(cfg.apiUrl, globalThis.fetch);
    const claims = await sessions.verify(tokens.access_token);
    session = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      idToken: tokens.id_token,
      expiresAt: claims.expiresAt,
      userId: claims.userId,
      tenantId: claims.tenantId,
      sessionId: claims.sessionId,
    };
  } catch {
    return fail("verify");
  }

  const res = NextResponse.redirect(new URL(pkce.returnTo, cfg.appUrl));
  res.cookies.set(SESSION_COOKIE, seal(session, cfg.cookieSecret), {
    httpOnly: true,
    secure: isSecure(cfg),
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
  });
  res.cookies.delete(PKCE_COOKIE);
  return res;
}

function handleLogout(cfg: QeetidConfig): NextResponse {
  const logout = new URL(`${cfg.apiUrl}/v1/oauth/logout`);
  logout.searchParams.set("client_id", cfg.clientId);
  logout.searchParams.set("post_logout_redirect_uri", cfg.appUrl);
  const res = NextResponse.redirect(logout);
  res.cookies.delete(SESSION_COOKIE);
  return res;
}
