// Minimal client-side OAuth2 Authorization-Code + PKCE for a PUBLIC client.
//
// A single-page app has no server to hold a client secret, so it authenticates
// as a *public* client: it proves possession of the auth code with a PKCE
// verifier instead of a secret. Qeet ID's token endpoint (/v1/oauth/token-code)
// is CSRF-exempt and CORS-enabled, so the browser can exchange the code directly
// — as long as this app's origin is listed in the backend's ALLOWED_ORIGINS.

const API = import.meta.env.VITE_QEETID_API_URL;
const CLIENT_ID = import.meta.env.VITE_QEETID_CLIENT_ID;
const REDIRECT_URI = import.meta.env.VITE_QEETID_REDIRECT_URI;
const SCOPES = import.meta.env.VITE_QEETID_SCOPES ?? "openid profile email";
const POST_LOGOUT = import.meta.env.VITE_QEETID_POST_LOGOUT_URI ?? window.location.origin;

const TOKEN_KEY = "qeetid_spa_token";
const PKCE_KEY = "qeetid_spa_pkce";

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomToken(bytes = 32): string {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return b64url(a);
}

async function sha256(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return b64url(digest);
}

export interface StoredToken {
  accessToken: string;
  expiresAt: number; // unix seconds
}

/** The current (non-expired) access token, or null. */
export function getStoredToken(): StoredToken | null {
  const raw = sessionStorage.getItem(TOKEN_KEY);
  if (!raw) return null;
  try {
    const t = JSON.parse(raw) as StoredToken;
    if (t.expiresAt <= Math.floor(Date.now() / 1000)) {
      sessionStorage.removeItem(TOKEN_KEY);
      return null;
    }
    return t;
  } catch {
    return null;
  }
}

/** Start login: build a PKCE challenge and redirect to the authorize endpoint. */
export async function login(returnTo = "/"): Promise<void> {
  const verifier = randomToken(32);
  const challenge = await sha256(verifier);
  const state = randomToken(16);
  sessionStorage.setItem(PKCE_KEY, JSON.stringify({ verifier, state, returnTo }));

  const url = new URL(`${API}/v1/oauth/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", SCOPES);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  window.location.assign(url.toString());
}

/** Handle the /callback redirect: validate state, exchange the code for a token. */
export async function handleCallback(): Promise<string> {
  const params = new URLSearchParams(window.location.search);
  const err = params.get("error");
  if (err) throw new Error(`Authorization failed: ${err}`);

  const code = params.get("code");
  const state = params.get("state");
  const raw = sessionStorage.getItem(PKCE_KEY);
  if (!code || !state || !raw) throw new Error("Missing code, state, or PKCE state");

  const pkce = JSON.parse(raw) as { verifier: string; state: string; returnTo: string };
  if (pkce.state !== state) throw new Error("State mismatch (possible CSRF)");

  const res = await fetch(`${API}/v1/oauth/token-code`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: pkce.verifier,
      // Public client: no client_secret.
    }).toString(),
  });
  if (!res.ok) throw new Error(`Token exchange failed (HTTP ${res.status})`);

  const tok = (await res.json()) as { access_token: string; expires_in?: number };
  const token: StoredToken = {
    accessToken: tok.access_token,
    expiresAt: Math.floor(Date.now() / 1000) + (tok.expires_in ?? 3600),
  };
  sessionStorage.setItem(TOKEN_KEY, JSON.stringify(token));
  sessionStorage.removeItem(PKCE_KEY);
  return pkce.returnTo || "/";
}

export interface UserInfo {
  sub: string;
  [key: string]: unknown;
}

/** Fetch the signed-in user's OIDC profile, or null. */
export async function fetchUserInfo(accessToken: string): Promise<UserInfo | null> {
  const res = await fetch(`${API}/v1/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
  });
  if (!res.ok) return null;
  return (await res.json()) as UserInfo;
}

/** Clear the local token and end the Qeet session (RP-initiated logout). */
export function logout(): void {
  sessionStorage.removeItem(TOKEN_KEY);
  const url = new URL(`${API}/v1/oauth/logout`);
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("post_logout_redirect_uri", POST_LOGOUT);
  window.location.assign(url.toString());
}
