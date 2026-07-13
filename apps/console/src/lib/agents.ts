// AI-agent identity data layer (Developer → Agent Governance). Agents authenticate
// with their secret at POST /v1/agents/token and receive a short-lived, scoped
// token marked actor_type="agent". Backed by /v1/tenants/{tenantID}/agents.
// The secret is returned only once, on create.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface Agent {
  id: string;
  name: string;
  scopes: string[];
  token_ttl_seconds: number;
  status: "active" | "suspended" | "decommissioned";
  disabled: boolean;
  /** The named human owner accountable for this agent. Absent only for
   * agents created before the sponsor model existed. */
  sponsor_user_id?: string;
  created_at: string;
  /** Present only in the create response. */
  secret?: string;
}

const KEY = ["agents"];

export function useAgents() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, tenantId],
    queryFn: () => api<{ items: Agent[] }>(`/v1/tenants/${tenantId}/agents`),
    enabled: !!tenantId,
  });
}

export function useCreateAgent() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      name: string;
      scopes: string[];
      token_ttl_seconds: number;
      sponsor_user_id: string;
    }) => api<Agent>(`/v1/tenants/${tenantId}/agents`, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useDeleteAgent() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/agents/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useSetAgentDisabled() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, disabled }: { id: string; disabled: boolean }) =>
      api<void>(`/v1/tenants/${tenantId}/agents/${id}`, {
        method: "PATCH",
        body: { disabled },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useKillAllAgents() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api<{ suspended: number }>(`/v1/tenants/${tenantId}/agents/kill-all`, {
        method: "POST",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** Agents currently sponsored by a given user — used by the sponsor-transfer
 * tool to show what's about to move before the admin confirms. */
export function useAgentsSponsoredBy(userId: string | null) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, "sponsored-by", tenantId, userId],
    queryFn: () => api<{ items: Agent[] }>(`/v1/tenants/${tenantId}/agents/sponsored-by/${userId}`),
    enabled: !!tenantId && !!userId,
  });
}

/** Reassigns every agent sponsored by fromUserId to toUserId in one call —
 * the offboarding path: a departing sponsor's agents don't go orphaned. */
export function useTransferSponsor() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ fromUserId, toUserId }: { fromUserId: string; toUserId: string }) =>
      api<{ transferred: number }>(
        `/v1/tenants/${tenantId}/agents/sponsored-by/${fromUserId}/transfer`,
        { method: "POST", body: { to_user_id: toUserId } },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
