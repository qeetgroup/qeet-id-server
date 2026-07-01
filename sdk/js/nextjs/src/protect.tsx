import type { ReactNode } from "react";

import { auth } from "./server.js";

export interface ProtectProps {
  children: ReactNode;
  /** Rendered when the user is signed out (default: nothing). */
  fallback?: ReactNode;
}

/**
 * <Protect/> is a React Server Component that renders children only when the
 * request is authenticated. Drop it anywhere in a Server Component tree:
 *
 *   <Protect fallback={<SignInButton />}>
 *     <Dashboard />
 *   </Protect>
 *
 * It does NOT redirect — use `protect()` from "@qeet-id/nextjs" when you want
 * an automatic redirect for page-level protection.
 */
export async function Protect({ children, fallback = null }: ProtectProps): Promise<ReactNode> {
  const { isAuthenticated } = await auth();
  return isAuthenticated ? children : fallback;
}
