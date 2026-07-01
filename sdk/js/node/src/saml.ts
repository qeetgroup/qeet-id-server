import type { HttpClient } from "./client.js";

export interface SamlConnection {
  id: string;
  tenant_id: string;
  name: string;
  enabled: boolean;
  idp_entity_id?: string;
  idp_sso_url?: string;
  idp_certificate?: string;
  sp_entity_id?: string;
  sp_acs_url?: string;
  attribute_mapping?: Record<string, string>;
  created_at: string;
  updated_at?: string;
}

export interface CreateSamlConnectionInput {
  name: string;
  idp_entity_id?: string;
  idp_sso_url?: string;
  idp_certificate?: string;
  attribute_mapping?: Record<string, string>;
  enabled?: boolean;
}

export interface UpdateSamlConnectionInput {
  name?: string;
  idp_entity_id?: string;
  idp_sso_url?: string;
  idp_certificate?: string;
  attribute_mapping?: Record<string, string>;
  enabled?: boolean;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
}

export class Saml {
  constructor(private readonly http: HttpClient) {}

  create(tenantId: string, input: CreateSamlConnectionInput): Promise<SamlConnection> {
    return this.http.post<SamlConnection>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/saml`,
      input,
    );
  }

  get(tenantId: string, id: string): Promise<SamlConnection> {
    return this.http.get<SamlConnection>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/saml/${encodeURIComponent(id)}`,
    );
  }

  update(tenantId: string, id: string, input: UpdateSamlConnectionInput): Promise<SamlConnection> {
    return this.http.patch<SamlConnection>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/saml/${encodeURIComponent(id)}`,
      input,
    );
  }

  delete(tenantId: string, id: string): Promise<void> {
    return this.http.delete<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/saml/${encodeURIComponent(id)}`,
    );
  }

  test(tenantId: string, id: string): Promise<{ success: boolean; error?: string }> {
    return this.http.post<{ success: boolean; error?: string }>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/saml/${encodeURIComponent(id)}/test`,
      {},
    );
  }

  async list(tenantId: string): Promise<SamlConnection[]> {
    const res = await this.http.get<ListEnvelope<SamlConnection>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/saml`,
    );
    return res.items ?? res.data ?? [];
  }
}
