// AI-agent identity data layer (Developer → AI Agents). Agents authenticate
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
  disabled: boolean;
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
    mutationFn: (body: { name: string; scopes: string[]; token_ttl_seconds: number }) =>
      api<Agent>(`/v1/tenants/${tenantId}/agents`, { method: "POST", body }),
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
