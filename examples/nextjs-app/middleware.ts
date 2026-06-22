import { qeetidMiddleware } from "@qeetid/nextjs/middleware";

// Only the home page ("/") is public; everything else (e.g. /dashboard) requires
// a session and is redirected to the hosted login. `/api/auth/*` is always public
// (handled inside the middleware). The exact-match regex avoids the prefix trap —
// a plain "/" string would make every path public.
export default qeetidMiddleware({ publicRoutes: [/^\/$/] });

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
