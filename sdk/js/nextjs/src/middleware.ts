import { NextResponse, type NextRequest } from "next/server";

import { getConfig, SESSION_COOKIE, type QeetidConfig } from "./config.js";
import { open, seal } from "./cookies.js";
import { refreshSession } from "./refresh.js";
import type { SessionData } from "./types.js";

export interface MiddlewareOptions {
  /**
   * Paths that don't require authentication. Strings match by exact value or
   * prefix; RegExps are tested against the pathname.
   */
  publicRoutes?: (string | RegExp)[];
}

// Refresh this many seconds before the access token expires, so the in-flight
// request still has a valid token while the browser gets a fresh cookie.
const REFRESH_SKEW_SECONDS = 60;

/**
 * qeetidMiddleware protects routes and keeps the session fresh. It runs in the
 * Edge runtime (Web Crypto only), so import it from "@qeetid/nextjs/middleware".
 *
 *   import { qeetidMiddleware } from "@qeetid/nextjs/middleware";
 *   export default qeetidMiddleware({ publicRoutes: ["/", "/pricing"] });
 *   export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
 *
 * On each request it: redirects unauthenticated users to the hosted login;
 * proactively refreshes a near-expiry token (persisting the rotated refresh
 * token); and, if the token had already expired, redirects to the same URL so
 * the request re-runs with the fresh cookie.
 */
export function qeetidMiddleware(options: MiddlewareOptions = {}) {
  const publicRoutes = options.publicRoutes ?? [];
  return async function middleware(req: NextRequest): Promise<NextResponse> {
    const { pathname } = req.nextUrl;
    const publicPath = pathname.startsWith("/api/auth/") || isPublic(pathname, publicRoutes);
    const raw = req.cookies.get(SESSION_COOKIE)?.value;

    if (raw) {
      const cfg = getConfig();
      const data = await open<SessionData>(raw, cfg.cookieSecret);
      if (data) {
        const now = Math.floor(Date.now() / 1000);
        if (data.refreshToken && data.expiresAt - REFRESH_SKEW_SECONDS <= now) {
          const refreshed = await refreshSession(cfg, data);
          if (refreshed) {
            // If the old token had already expired, re-run this request with the
            // fresh cookie; otherwise it's still valid for the current render.
            const res = data.expiresAt <= now ? NextResponse.redirect(req.url) : NextResponse.next();
            res.cookies.set(SESSION_COOKIE, await seal(refreshed, cfg.cookieSecret), cookieOptions(cfg));
            return res;
          }
          // Refresh failed → drop the dead session.
          const res = publicPath ? NextResponse.next() : redirectToLogin(req);
          res.cookies.delete(SESSION_COOKIE);
          return res;
        }
        return NextResponse.next(); // valid and not near expiry
      }
      // Unparseable/tampered cookie → fall through to the unauthenticated path.
    }

    if (publicPath) return NextResponse.next();
    return redirectToLogin(req);
  };
}

function cookieOptions(cfg: QeetidConfig) {
  return {
    httpOnly: true,
    secure: cfg.appUrl.startsWith("https"),
    sameSite: "lax" as const,
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
  };
}

function redirectToLogin(req: NextRequest): NextResponse {
  const login = new URL("/api/auth/login", req.url);
  login.searchParams.set("return_to", req.nextUrl.pathname + req.nextUrl.search);
  return NextResponse.redirect(login);
}

function isPublic(pathname: string, routes: (string | RegExp)[]): boolean {
  return routes.some((r) =>
    typeof r === "string" ? pathname === r || pathname.startsWith(r) : r.test(pathname),
  );
}
