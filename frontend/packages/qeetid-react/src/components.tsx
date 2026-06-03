"use client";

import type { ReactNode } from "react";

import { usePaths, useQeetidState } from "./context.js";

/** Renders children only when the user is signed in. */
export function SignedIn({ children }: { children: ReactNode }) {
  return useQeetidState().isAuthenticated ? <>{children}</> : null;
}

/** Renders children only when the user is signed out. */
export function SignedOut({ children }: { children: ReactNode }) {
  return useQeetidState().isAuthenticated ? null : <>{children}</>;
}

function navigate(url: string, returnTo?: string): void {
  const u = new URL(url, window.location.origin);
  if (returnTo !== undefined) u.searchParams.set("return_to", returnTo);
  window.location.href = u.toString();
}

export interface AuthButtonProps {
  children?: ReactNode;
  className?: string;
  /** Path to return to after sign-in (defaults to the current location). */
  returnTo?: string;
}

/** A button that sends the browser to the hosted login. */
export function SignInButton({ children, className, returnTo }: AuthButtonProps) {
  const { loginUrl } = usePaths();
  return (
    <button
      type="button"
      className={className}
      onClick={() => navigate(loginUrl, returnTo ?? window.location.pathname + window.location.search)}
    >
      {children ?? "Sign in"}
    </button>
  );
}

/** A button that signs the user out (clears the session + RP-initiated logout). */
export function SignOutButton({ children, className }: AuthButtonProps) {
  const { logoutUrl } = usePaths();
  return (
    <button type="button" className={className} onClick={() => navigate(logoutUrl)}>
      {children ?? "Sign out"}
    </button>
  );
}
