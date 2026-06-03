import type { HttpClient } from "./client.js";
import type { ListParams, Page } from "./users.js";

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  region?: string;
  created_at: string;
  updated_at?: string;
}

export interface CreateTenantInput {
  name: string;
  slug: string;
  region?: string;
}

export interface UpdateTenantInput {
  name?: string;
  region?: string;
}

interface ListEnvelope {
  items?: Tenant[];
  data?: Tenant[];
  next_cursor?: string;
}

export class Tenants {
  constructor(private readonly http: HttpClient) {}

  create(input: CreateTenantInput): Promise<Tenant> {
    return this.http.post<Tenant>("/v1/tenants", input);
  }

  get(id: string): Promise<Tenant> {
    return this.http.get<Tenant>(`/v1/tenants/${encodeURIComponent(id)}`);
  }

  update(id: string, input: UpdateTenantInput): Promise<Tenant> {
    return this.http.patch<Tenant>(`/v1/tenants/${encodeURIComponent(id)}`, input);
  }

  delete(id: string): Promise<void> {
    return this.http.delete<void>(`/v1/tenants/${encodeURIComponent(id)}`);
  }

  async list(params: Omit<ListParams, "tenant"> = {}): Promise<Page<Tenant>> {
    const res = await this.http.get<ListEnvelope>("/v1/tenants", {
      query: { limit: params.limit, cursor: params.cursor },
    });
    return { data: res.items ?? res.data ?? [], nextCursor: res.next_cursor };
  }
}
