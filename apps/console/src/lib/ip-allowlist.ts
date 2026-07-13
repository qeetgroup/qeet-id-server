// IP allow/deny rule data layer. Rules are CIDR ranges (or bare IPs); deny wins
// over allow, and if any allow rule exists an address must match one. A
// per-tenant enable flag gates enforcement so a tenant can't lock itself out by
// accident.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export type IpAction = "allow" | "deny";

export interface IpRule {
  id: string;
  tenant_id: string;
  cidr: string;
  label: string;
  action: IpAction;
  created_at: string;
}

export function useIpRules() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["ip-rules", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ enabled: boolean; items: IpRule[] }>(`/v1/tenants/${tenantId}/ip-rules`),
  });
}

export function useSetIpEnforcement() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (enabled: boolean) =>
      api<{ enabled: boolean }>(`/v1/tenants/${tenantId}/ip-rules/config`, {
        method: "PUT",
        body: { enabled },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ip-rules"] }),
    meta: { successMessage: "Enforcement updated" },
  });
}

export function useAddIpRule() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { cidr: string; label: string; action: IpAction }) =>
      api<IpRule>(`/v1/tenants/${tenantId}/ip-rules`, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ip-rules"] }),
    meta: { successMessage: "Rule added" },
  });
}

export function useDeleteIpRule() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/ip-rules/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ip-rules"] }),
    meta: { successMessage: "Rule removed" },
  });
}

export function useCheckIp() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: (ip: string) =>
      api<{ enabled: boolean; allowed: boolean; reason: string }>(
        `/v1/tenants/${tenantId}/ip-rules/check`,
        { method: "POST", body: { ip } },
      ),
  });
}
