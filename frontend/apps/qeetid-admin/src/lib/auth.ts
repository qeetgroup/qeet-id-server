// Auth hooks built on top of the api() client. Login / signup mutations
// persist the access token, refresh token, tenant_id and user_id so every
// downstream useQuery call sees a Bearer header automatically.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";

import { api, tokenStore } from "./api";

type TokenPair = {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_at: string;
  user_id: string;
  session_id: string;
};

type User = {
  id: string;
  tenant_id: string;
  email: string;
  display_name?: string | null;
  status: string;
};

type Tenant = {
  id: string;
  slug: string;
  name: string;
  plan: string;
  region: string;
};

type LoginInput = { email: string; password: string };
type LoginResponse = TokenPair & { tenant_id?: string };

export function useLogin() {
  const navigate = useNavigate();
  return useMutation({
    mutationFn: (in_: LoginInput) =>
      api<LoginResponse>("/v1/auth/login", { method: "POST", body: in_, anonymous: true }),
    onSuccess: (pair) => {
      tokenStore.set(pair.access_token);
      tokenStore.setRefresh(pair.refresh_token);
      if (pair.tenant_id) tokenStore.setTenantId(pair.tenant_id);
      tokenStore.setUserId(pair.user_id);
      navigate({ to: "/dashboard" });
    },
  });
}

/**
 * Kick off a password-reset email. Endpoint returns 200 regardless of
 * whether the email exists (constant-time no-leak design), so the
 * caller can unconditionally show "check your inbox" UX. The mutation
 * is marked silent so failures don't surface a toast — surfacing a
 * "user not found" error would defeat the enumeration-protection
 * design of the endpoint.
 */
export function useForgotPassword() {
  return useMutation({
    mutationFn: (in_: { email: string }) =>
      api<void>("/v1/auth/forgot-password", { method: "POST", body: in_, anonymous: true }),
    meta: { silent: true },
  });
}

type SignupInput = {
  email: string;
  password: string;
  display_name?: string;
};

type SignupResponse = TokenPair & {
  user: User;
  tenant: Tenant;
  tenant_id: string;
  roles: string[];
};

export function useSignup() {
  const navigate = useNavigate();
  return useMutation({
    mutationFn: (in_: SignupInput) =>
      api<SignupResponse>("/v1/auth/signup", { method: "POST", body: in_, anonymous: true }),
    onSuccess: (res) => {
      tokenStore.set(res.access_token);
      tokenStore.setRefresh(res.refresh_token);
      tokenStore.setTenantId(res.tenant.id);
      tokenStore.setUserId(res.user_id);
      navigate({ to: "/dashboard" });
    },
  });
}

export function useLogout() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<void>("/v1/auth/logout", { method: "POST" }).catch(() => undefined),
    onSettled: () => {
      tokenStore.clear();
      qc.clear();
      navigate({ to: "/sign-in" });
    },
  });
}

/** Returns the current tenant id stashed in localStorage. */
export function useTenantId(): string | null {
  if (typeof window === "undefined") return null;
  return tokenStore.getTenantId();
}

/** Whether the user has a stored access token. Read synchronously for guards. */
export function isAuthenticated(): boolean {
  return !!tokenStore.get();
}

// ---------------------------------------------------------------------------
// JWT introspection
//
// We never trust the JWT payload for authorization decisions (the server
// re-validates on every request). We DO read it client-side to drive
// UX-only signals — e.g. the impersonation banner, which checks for the
// RFC 8693 `act` claim and surfaces who the admin is acting as.
// ---------------------------------------------------------------------------

function base64UrlDecode(s: string): string {
  let b = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b.length % 4) b += "=";
  try {
    return atob(b);
  } catch {
    return "";
  }
}

interface AccessClaims {
  /** RFC 8693 actor claim — present iff this token was issued by an
   *  impersonation grant. `sub` identifies the admin doing the acting. */
  act?: {
    sub?: string;
    email?: string;
    display_name?: string;
  };
  sub?: string;
  email?: string;
  tenant_id?: string;
  exp?: number;
  [k: string]: unknown;
}

function decodeAccessToken(): AccessClaims | null {
  const raw = tokenStore.get();
  if (!raw) return null;
  const parts = raw.split(".");
  if (parts.length !== 3) return null;
  const payload = base64UrlDecode(parts[1]);
  if (!payload) return null;
  try {
    return JSON.parse(payload) as AccessClaims;
  } catch {
    return null;
  }
}

export interface ImpersonationActor {
  /** The user being impersonated (the `sub` of the current token). */
  targetSubject: string;
  /** The admin doing the impersonating. */
  actorSubject: string;
  actorEmail?: string;
  actorDisplayName?: string;
}

/**
 * Returns the impersonation context if the current access token was
 * issued via an impersonation grant (RFC 8693 `act` claim present),
 * otherwise null. UI-only signal — server is the source of truth.
 */
export function useImpersonationActor(): ImpersonationActor | null {
  const claims = decodeAccessToken();
  if (!claims?.act?.sub || !claims.sub) return null;
  return {
    targetSubject: claims.sub,
    actorSubject: claims.act.sub,
    actorEmail: claims.act.email,
    actorDisplayName: claims.act.display_name,
  };
}

type Me = {
  id: string;
  tenant_id: string;
  email: string;
  display_name?: string | null;
  status: string;
};

/**
 * Fetch the current user via `GET /v1/users/{user_id}` using the user_id
 * persisted at login/signup time. We don't have a `GET /v1/users/me`
 * endpoint yet — this round-trip is one extra request but lets us show
 * the real email + display name in the header without re-issuing JWTs.
 */
export function useMe() {
  const userId = tokenStore.getUserId();
  return useQuery({
    queryKey: ["me", userId],
    queryFn: () => api<Me>(`/v1/users/${userId}`),
    enabled: !!userId,
    staleTime: 60_000,
  });
}
