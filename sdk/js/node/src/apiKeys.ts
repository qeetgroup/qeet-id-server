import type { HttpClient } from "./client.js";
import type { ListParams, Page } from "./users.js";

export interface ApiKey {
  id: string;
  tenant_id?: string;
  name: string;
  prefix: string;
  scopes?: string[];
  expires_at?: string;
  last_used_at?: string;
  created_at: string;
}

export interface CreateApiKeyInput {
  name: string;
  tenant_id?: string;
  scopes?: string[];
  expires_in_days?: number;
}

export interface RotateApiKeyResult {
  key: ApiKey;
  secret: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
  next_cursor?: string;
}

export class ApiKeys {
  constructor(private readonly http: HttpClient) {}

  create(input: CreateApiKeyInput): Promise<{ key: ApiKey; secret: string }> {
    return this.http.post<{ key: ApiKey; secret: string }>("/v1/api-keys", input);
  }

  get(id: string): Promise<ApiKey> {
    return this.http.get<ApiKey>(`/v1/api-keys/${encodeURIComponent(id)}`);
  }

  delete(id: string): Promise<void> {
    return this.http.delete<void>(`/v1/api-keys/${encodeURIComponent(id)}`);
  }

  rotate(id: string): Promise<RotateApiKeyResult> {
    return this.http.post<RotateApiKeyResult>(`/v1/api-keys/${encodeURIComponent(id)}/rotate`, {});
  }

  async list(params: ListParams = {}): Promise<Page<ApiKey>> {
    const res = await this.http.get<ListEnvelope<ApiKey>>("/v1/api-keys", {
      query: { tenant: params.tenant, limit: params.limit, cursor: params.cursor },
    });
    return { data: res.items ?? res.data ?? [], nextCursor: res.next_cursor };
  }

  async *listAll(params: ListParams = {}): AsyncGenerator<ApiKey> {
    let cursor = params.cursor;
    do {
      const page = await this.list({ ...params, cursor });
      for (const item of page.data) yield item;
      cursor = page.nextCursor;
    } while (cursor);
  }
}
