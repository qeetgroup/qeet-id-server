"use client";

import { createContext, useContext, type ReactNode } from "react";

import type { QeetidState, QeetidUser } from "./types.js";

const StateContext = createContext<QeetidState>({ isLoaded: false, isAuthenticated: false });
const PathsContext = createContext<{ loginUrl: string; logoutUrl: string }>({
  loginUrl: "/api/auth/login",
  logoutUrl: "/api/auth/logout",
});

export interface QeetidProviderProps {
  children: ReactNode;
  /**
   * Auth state computed on the server (e.g. from `@qeetid/nextjs`'s `auth()` and
   * `currentUser()`), passed down so the client renders correctly on first
   * paint without reading the HttpOnly cookie.
   */
  initialState?: Partial<QeetidState>;
  /** Where <SignInButton> sends the browser. Default /api/auth/login. */
  loginUrl?: string;
  /** Where <SignOutButton> sends the browser. Default /api/auth/logout. */
  logoutUrl?: string;
}

export function QeetidProvider({
  children,
  initialState,
  loginUrl = "/api/auth/login",
  logoutUrl = "/api/auth/logout",
}: QeetidProviderProps) {
  const state: QeetidState = {
    isLoaded: true,
    isAuthenticated: initialState?.isAuthenticated ?? false,
    userId: initialState?.userId,
    tenantId: initialState?.tenantId,
    sessionId: initialState?.sessionId,
    user: initialState?.user ?? null,
  };
  return (
    <PathsContext.Provider value={{ loginUrl, logoutUrl }}>
      <StateContext.Provider value={state}>{children}</StateContext.Provider>
    </PathsContext.Provider>
  );
}

/** useAuth returns the session identity (no profile). */
export function useAuth() {
  const s = useContext(StateContext);
  return {
    isLoaded: s.isLoaded,
    isAuthenticated: s.isAuthenticated,
    userId: s.userId,
    tenantId: s.tenantId,
    sessionId: s.sessionId,
  };
}

/** useUser returns the signed-in user's profile (or null). */
export function useUser(): { isLoaded: boolean; isAuthenticated: boolean; user: QeetidUser | null } {
  const s = useContext(StateContext);
  return { isLoaded: s.isLoaded, isAuthenticated: s.isAuthenticated, user: s.user ?? null };
}

// Internal helpers shared with the components module.
export function useQeetidState(): QeetidState {
  return useContext(StateContext);
}
export function usePaths(): { loginUrl: string; logoutUrl: string } {
  return useContext(PathsContext);
}
