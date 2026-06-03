import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE } from "./config.js";

export interface MiddlewareOptions {
  /**
   * Paths that don't require authentication. Strings match by exact value or
   * prefix; RegExps are tested against the pathname.
   */
  publicRoutes?: (string | RegExp)[];
}

/**
 * qeetidMiddleware gates routes for `middleware.ts`. It is a coarse, edge-safe
 * gate: it only checks for the presence of the session cookie and redirects to
 * the hosted login when it's missing. The page's `auth()` performs the real
 * cryptographic verification in the Node runtime.
 *
 *   import { qeetidMiddleware } from "@qeetid/nextjs";
 *   export default qeetidMiddleware({ publicRoutes: ["/", "/pricing"] });
 *   export const config = { matcher: ["/((?!_next|favicon.ico).*)"] };
 */
export function qeetidMiddleware(options: MiddlewareOptions = {}) {
  const publicRoutes = options.publicRoutes ?? [];
  return function middleware(req: NextRequest): NextResponse {
    const { pathname, search } = req.nextUrl;
    if (pathname.startsWith("/api/auth/") || isPublic(pathname, publicRoutes)) {
      return NextResponse.next();
    }
    if (req.cookies.has(SESSION_COOKIE)) {
      return NextResponse.next();
    }
    const login = new URL("/api/auth/login", req.url);
    login.searchParams.set("return_to", pathname + search);
    return NextResponse.redirect(login);
  };
}

function isPublic(pathname: string, routes: (string | RegExp)[]): boolean {
  return routes.some((r) =>
    typeof r === "string" ? pathname === r || pathname.startsWith(r) : r.test(pathname),
  );
}
