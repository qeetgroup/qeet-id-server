import type { HttpClient } from "./client.js";

export interface Domain {
  id: string;
  tenant_id: string;
  domain: string;
  verified: boolean;
  verification_token?: string;
  created_at: string;
  updated_at?: string;
}

export interface CreateDomainInput {
  domain: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
}

export class Domains {
  constructor(private readonly http: HttpClient) {}

  create(tenantId: string, input: CreateDomainInput): Promise<Domain> {
    return this.http.post<Domain>(`/v1/tenants/${encodeURIComponent(tenantId)}/domains`, input);
  }

  get(tenantId: string, id: string): Promise<Domain> {
    return this.http.get<Domain>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/domains/${encodeURIComponent(id)}`,
    );
  }

  delete(tenantId: string, id: string): Promise<void> {
    return this.http.delete<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/domains/${encodeURIComponent(id)}`,
    );
  }

  verify(tenantId: string, id: string): Promise<Domain> {
    return this.http.post<Domain>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/domains/${encodeURIComponent(id)}/verify`,
      {},
    );
  }

  async list(tenantId: string): Promise<Domain[]> {
    const res = await this.http.get<ListEnvelope<Domain>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/domains`,
    );
    return res.items ?? res.data ?? [];
  }
}
