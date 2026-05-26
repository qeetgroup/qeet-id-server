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
