import type { QeetidConfig } from "./config.js";
import type { SessionData } from "./types.js";

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
}

// refreshSession exchanges the refresh token for a fresh token set and returns
// updated SessionData (carrying the ROTATED refresh token), or null on failure.
//
// Persisting the rotated refresh token is essential: Qeet ID rotates refresh
// tokens with reuse detection, so reusing the old one would revoke the chain.
// Edge-safe (fetch only) so it can run in middleware.
export async function refreshSession(cfg: QeetidConfig, data: SessionData): Promise<SessionData | null> {
  if (!data.refreshToken) return null;
  try {
    const res = await fetch(`${cfg.apiUrl}/v1/oauth/token-code`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: data.refreshToken,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
      }).toString(),
    });
    if (!res.ok) return null;
    const t = (await res.json()) as TokenResponse;
    if (!t.access_token) return null;
    return {
      accessToken: t.access_token,
      refreshToken: t.refresh_token ?? data.refreshToken,
      idToken: t.id_token ?? data.idToken,
      expiresAt: Math.floor(Date.now() / 1000) + (t.expires_in ?? 900),
      userId: data.userId,
      tenantId: data.tenantId,
      sessionId: data.sessionId,
    };
  } catch {
    return null;
  }
}
