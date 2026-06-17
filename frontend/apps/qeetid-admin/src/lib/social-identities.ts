// Connected-account (social identity) self-service data layer. Lists the
// external identities linked to the current user and unlinks them. Backed by
// GET /v1/users/{userID}/social/identities and DELETE /v1/social/identities/{id}.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, api, tokenStore } from "./api";

export interface SocialIdentity {
  id: string;
  provider: string;
  email?: string | null;
  linked_at: string;
}

const KEY = ["social-identities"];

// useSocialIdentities lists the current user's linked social accounts. There is
// no "me" variant of the endpoint, so we scope by the persisted user id; the
// list returns [] gracefully when the endpoint is absent so the card still
// renders its empty state.
export function useSocialIdentities() {
  const userId = tokenStore.getUserId();
  return useQuery({
    queryKey: [...KEY, userId],
    queryFn: async (): Promise<{ items: SocialIdentity[] }> => {
      try {
        return await api<{ items: SocialIdentity[] }>(`/v1/users/${userId}/social/identities`);
      } catch (err) {
        if (err instanceof ApiError && (err.status === 404 || err.status === 501)) {
          return { items: [] };
        }
        throw err;
      }
    },
    enabled: !!userId,
    staleTime: 60_000,
    meta: { silent: true },
    retry: false,
  });
}

export function useUnlinkIdentity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/v1/social/identities/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
