import type { HttpClient } from "./client.js";

export interface IpRule {
  id: string;
  tenant_id: string;
  cidr: string;
  action: string;
  description?: string;
  created_at: string;
}

export interface CreateIpRuleInput {
  cidr: string;
  action: "allow" | "deny";
  description?: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
}

export class IpRules {
  constructor(private readonly http: HttpClient) {}

  create(tenantId: string, input: CreateIpRuleInput): Promise<IpRule> {
    return this.http.post<IpRule>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/ip-rules`,
      input,
    );
  }

  delete(tenantId: string, id: string): Promise<void> {
    return this.http.delete<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/ip-rules/${encodeURIComponent(id)}`,
    );
  }

  async list(tenantId: string): Promise<IpRule[]> {
    const res = await this.http.get<ListEnvelope<IpRule>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/ip-rules`,
    );
    return res.items ?? res.data ?? [];
  }
}
