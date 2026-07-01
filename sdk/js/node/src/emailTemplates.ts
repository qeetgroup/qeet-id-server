import type { HttpClient } from "./client.js";

export type EmailTemplateType =
  | "welcome"
  | "verify-email"
  | "reset-password"
  | "magic-link"
  | "invite"
  | "mfa-code";

export interface EmailTemplate {
  tenant_id: string;
  type: EmailTemplateType;
  subject: string;
  html_body: string;
  text_body?: string;
  from_name?: string;
  from_address?: string;
  updated_at?: string;
}

export interface UpdateEmailTemplateInput {
  subject?: string;
  html_body?: string;
  text_body?: string;
  from_name?: string;
  from_address?: string;
}

export class EmailTemplates {
  constructor(private readonly http: HttpClient) {}

  get(tenantId: string, type: EmailTemplateType): Promise<EmailTemplate> {
    return this.http.get<EmailTemplate>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/email-templates/${encodeURIComponent(type)}`,
    );
  }

  update(
    tenantId: string,
    type: EmailTemplateType,
    input: UpdateEmailTemplateInput,
  ): Promise<EmailTemplate> {
    return this.http.request<EmailTemplate>(
      "PUT",
      `/v1/tenants/${encodeURIComponent(tenantId)}/email-templates/${encodeURIComponent(type)}`,
      { body: input },
    );
  }

  preview(tenantId: string, type: EmailTemplateType, to: string): Promise<{ sent: boolean }> {
    return this.http.post<{ sent: boolean }>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/email-templates/${encodeURIComponent(type)}/preview`,
      { to },
    );
  }
}
