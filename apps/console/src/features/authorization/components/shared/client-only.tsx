import { type ReactNode, useEffect, useState } from "react";

/**
 * Renders children only after the component has mounted on the client. The
 * console is server-rendered (TanStack Start), and React Flow / Monaco both
 * touch `window`/`document` at module or render time — wrapping them here keeps
 * the server render (and the first hydration pass) safe, showing `fallback`
 * until the browser takes over.
 */
export function ClientOnly({
  children,
  fallback = null,
}: {
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  return <>{mounted ? children : fallback}</>;
}
