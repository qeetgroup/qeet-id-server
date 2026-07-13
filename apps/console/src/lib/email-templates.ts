// Transactional email template data layer. The catalog (keys + default
// subject/body + variables) lives server-side; tenants store overrides. A
// missing override means the built-in default is used (custom=false).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";
import { useTenantId } from "./auth";

export interface EmailTemplate {
  key: string;
  name: string;
  description: string;
  subject: string;
  body: string;
  variables: string[];
  custom: boolean;
}

export function useEmailTemplates() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["email-templates", tenantId],
    enabled: !!tenantId,
    queryFn: () => api<{ items: EmailTemplate[] }>(`/v1/tenants/${tenantId}/email-templates`),
  });
}

export function useUpsertEmailTemplate() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ key, subject, body }: { key: string; subject: string; body: string }) =>
      api<EmailTemplate>(`/v1/tenants/${tenantId}/email-templates/${key}`, {
        method: "PUT",
        body: { subject, body },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["email-templates"] }),
    meta: { successMessage: "Template saved" },
  });
}

export function useResetEmailTemplate() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (key: string) =>
      api<EmailTemplate>(`/v1/tenants/${tenantId}/email-templates/${key}`, {
        method: "DELETE",
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["email-templates"] }),
    meta: { successMessage: "Reverted to default" },
  });
}

export function usePreviewEmailTemplate() {
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: ({ key, vars }: { key: string; vars: Record<string, string> }) =>
      api<{ subject: string; body: string }>(
        `/v1/tenants/${tenantId}/email-templates/${key}/preview`,
        { method: "POST", body: { vars } },
      ),
  });
}

/** A representative sample value for a template variable, used in previews. */
export function sampleVar(name: string): string {
  if (name.endsWith("_url")) return "https://auth.acme.com/...";
  if (name === "code") return "482913";
  if (name === "ttl") return "10 minutes";
  if (name === "tenant_name") return "Acme";
  return name;
}
