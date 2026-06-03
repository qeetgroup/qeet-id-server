// Resolved Qeet ID configuration, read once from the environment.

export interface QeetidConfig {
  /** OIDC client id registered in Qeet ID. */
  clientId: string;
  /** OIDC client secret (server-only). */
  clientSecret: string;
  /** Qeet ID API base URL, e.g. https://api.qeetid.com. */
  apiUrl: string;
  /** This app's own base URL, e.g. https://app.acme.com. */
  appUrl: string;
  /** ≥32-char secret used to encrypt the session cookie. */
  cookieSecret: string;
  /** Space-separated OIDC scopes. */
  scopes: string;
}

export const SESSION_COOKIE = "qeetid_session";
export const PKCE_COOKIE = "qeetid_pkce";

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`@qeetid/nextjs: ${name} is required`);
  return v;
}

let cached: QeetidConfig | undefined;

export function getConfig(): QeetidConfig {
  if (cached) return cached;
  const cookieSecret = required("QEETID_COOKIE_SECRET");
  if (cookieSecret.length < 32) {
    throw new Error("@qeetid/nextjs: QEETID_COOKIE_SECRET must be at least 32 characters");
  }
  cached = {
    clientId: required("QEETID_CLIENT_ID"),
    clientSecret: required("QEETID_CLIENT_SECRET"),
    apiUrl: required("QEETID_API_URL").replace(/\/+$/, ""),
    appUrl: required("QEETID_APP_URL").replace(/\/+$/, ""),
    cookieSecret,
    scopes: process.env.QEETID_SCOPES ?? "openid profile email",
  };
  return cached;
}

/** The OAuth redirect URI this integration handles (must be registered on the client). */
export function callbackUrl(cfg: QeetidConfig): string {
  return `${cfg.appUrl}/api/auth/callback`;
}
