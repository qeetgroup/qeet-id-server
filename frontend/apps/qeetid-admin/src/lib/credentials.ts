// Verifiable Credentials data layer (Developer → Verifiable Credentials). Qeet
// issues ES256-signed W3C JWT-VCs; relying parties verify them at
// /v1/credentials/verify. Backed by /v1/tenants/{tenantID}/credentials.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface Credential {
  id: string;
  subject: string;
  type: string;
  issued_at: string;
  expires_at?: string | null;
  revoked: boolean;
}

export interface IssueResult {
  credential_id: string;
  jwt: string;
  expires_at?: string | null;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
  subject?: string;
  issuer?: string;
  vc?: Record<string, unknown>;
}

const KEY = ["credentials"];

export function useCredentials() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: [...KEY, tenantId],
    queryFn: () => api<{ items: Credential[] }>(`/v1/tenants/${tenantId}/credentials`),
    enabled: !!tenantId,
  });
}

export function useIssueCredential() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      subject: string;
      type: string;
      claims: Record<string, unknown>;
      ttl_seconds: number;
    }) => api<IssueResult>(`/v1/tenants/${tenantId}/credentials`, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useRevokeCredential() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<void>(`/v1/tenants/${tenantId}/credentials/${id}/revoke`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useVerifyCredential() {
  return useMutation({
    mutationFn: (credential: string) =>
      api<VerifyResult>(`/v1/credentials/verify`, { method: "POST", body: { credential } }),
  });
}
