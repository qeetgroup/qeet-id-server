"use client";

import { createContext, useContext, useMemo, type ReactNode } from "react";

import { QeetIDClient } from "@qeet-id/client";

import type { Appearance } from "./embedded/types.js";
import type { QeetIDState, QeetIDUser } from "./types.js";

const StateContext = createContext<QeetIDState>({ isLoaded: false, isAuthenticated: false });
const PathsContext = createContext<{ loginUrl: string; logoutUrl: string; signUpUrl: string }>({
  loginUrl: "/api/auth/login",
  logoutUrl: "/api/auth/logout",
  signUpUrl: "/api/auth/sign-up",
});
const ClientContext = createContext<QeetIDClient | null>(null);
const AppearanceContext = createContext<Appearance | undefined>(undefined);

export interface QeetIDProviderProps {
  children: ReactNode;
  /**
   * Auth state computed on the server (e.g. from `@qeet-id/nextjs`'s `auth()` and
   * `currentUser()`), passed down so the client renders correctly on first
   * paint without reading the HttpOnly cookie.
   */
  initialState?: Partial<QeetIDState>;
  /** Where <SignInButton> / <SignInWithQeet> send the browser. Default /api/auth/login. */
  loginUrl?: string;
  /** Where <SignOutButton> sends the browser. Default /api/auth/logout. */
  logoutUrl?: string;
  /** Where <SignUpButton> / <SignUpWithQeet> send the browser. Default /api/auth/sign-up. */
  signUpUrl?: string;
  /**
   * Publishable key for embedded mode. When provided together with `apiUrl`,
   * `<SignIn/>`, `<SignUp/>` and the headless hooks drive authentication
   * directly without redirecting to the hosted login.
   */
  publishableKey?: string;
  /**
   * Qeet ID API base URL for embedded mode (e.g. https://api.id.qeet.in).
   * Required when `publishableKey` is set.
   */
  apiUrl?: string;
  /** Appearance/theming overrides for prebuilt components. */
  appearance?: Appearance;
}

export function QeetIDProvider({
  children,
  initialState,
  loginUrl = "/api/auth/login",
  logoutUrl = "/api/auth/logout",
  signUpUrl = "/api/auth/sign-up",
  publishableKey,
  apiUrl,
  appearance,
}: QeetIDProviderProps) {
  const state: QeetIDState = {
    isLoaded: true,
    isAuthenticated: initialState?.isAuthenticated ?? false,
    userId: initialState?.userId,
    tenantId: initialState?.tenantId,
    sessionId: initialState?.sessionId,
    user: initialState?.user ?? null,
  };

  const client = useMemo(
    () => (apiUrl ? new QeetIDClient({ apiUrl }) : null),
    // publishableKey reserved for future use (analytics/key rotation)
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [apiUrl],
  );

  return (
    <AppearanceContext.Provider value={appearance}>
      <ClientContext.Provider value={client}>
        <PathsContext.Provider value={{ loginUrl, logoutUrl, signUpUrl }}>
          <StateContext.Provider value={state}>{children}</StateContext.Provider>
        </PathsContext.Provider>
      </ClientContext.Provider>
    </AppearanceContext.Provider>
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
export function useUser(): { isLoaded: boolean; isAuthenticated: boolean; user: QeetIDUser | null } {
  const s = useContext(StateContext);
  return { isLoaded: s.isLoaded, isAuthenticated: s.isAuthenticated, user: s.user ?? null };
}

// Internal helpers shared with components and hooks.
export function useQeetIDState(): QeetIDState {
  return useContext(StateContext);
}
export function usePaths(): { loginUrl: string; logoutUrl: string; signUpUrl: string } {
  return useContext(PathsContext);
}
export function useQeetIDClient(): QeetIDClient | null {
  return useContext(ClientContext);
}
export function useAppearance(): Appearance | undefined {
  return useContext(AppearanceContext);
}
