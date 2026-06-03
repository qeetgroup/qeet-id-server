import { Sessions } from "@qeetid/sdk";
import { cookies } from "next/headers";

import { getConfig, SESSION_COOKIE } from "./config.js";
import { open } from "./cookies.js";
import type { AuthState, SessionData } from "./types.js";

/**
 * auth reads the session cookie and verifies the access token against the JWKS.
 * Call it in Server Components, Route Handlers, or Server Actions.
 *
 *   const { isAuthenticated, userId, tenantId } = await auth();
 */
export async function auth(): Promise<AuthState> {
  const cfg = getConfig();
  const store = await cookies();
  const raw = store.get(SESSION_COOKIE)?.value;
  if (!raw) return { isAuthenticated: false };

  const data = await open<SessionData>(raw, cfg.cookieSecret);
  if (!data?.accessToken) return { isAuthenticated: false };

  try {
    const sessions = new Sessions(cfg.apiUrl, globalThis.fetch);
    const claims = await sessions.verify(data.accessToken);
    return {
      isAuthenticated: true,
      userId: claims.userId,
      tenantId: claims.tenantId,
      sessionId: claims.sessionId,
      accessToken: data.accessToken,
    };
  } catch {
    // Expired or invalid — treat as signed out (middleware refreshes on nav).
    return { isAuthenticated: false };
  }
}

export interface CurrentUser {
  sub: string;
  tenant_id?: string;
  [key: string]: unknown;
}

/** currentUser fetches the OIDC userinfo for the signed-in user, or null. */
export async function currentUser(): Promise<CurrentUser | null> {
  const state = await auth();
  if (!state.isAuthenticated || !state.accessToken) return null;
  const cfg = getConfig();
  const res = await fetch(`${cfg.apiUrl}/v1/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${state.accessToken}`, Accept: "application/json" },
  });
  if (!res.ok) return null;
  return (await res.json()) as CurrentUser;
}

/** getToken returns the current access token (for calling your own APIs), or null. */
export async function getToken(): Promise<string | null> {
  const state = await auth();
  return state.isAuthenticated ? (state.accessToken ?? null) : null;
}
