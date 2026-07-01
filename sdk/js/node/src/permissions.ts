import type { HttpClient } from "./client.js";
import type { ListParams, Page } from "./users.js";

export interface Permission {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at?: string;
}

export interface CreatePermissionInput {
  name: string;
  description?: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
  next_cursor?: string;
}

export class Permissions {
  constructor(private readonly http: HttpClient) {}

  create(input: CreatePermissionInput): Promise<Permission> {
    return this.http.post<Permission>("/v1/rbac/permissions", input);
  }

  get(id: string): Promise<Permission> {
    return this.http.get<Permission>(`/v1/rbac/permissions/${encodeURIComponent(id)}`);
  }

  delete(id: string): Promise<void> {
    return this.http.delete<void>(`/v1/rbac/permissions/${encodeURIComponent(id)}`);
  }

  async list(params: ListParams = {}): Promise<Page<Permission>> {
    const res = await this.http.get<ListEnvelope<Permission>>("/v1/rbac/permissions", {
      query: { tenant: params.tenant, limit: params.limit, cursor: params.cursor },
    });
    return { data: res.items ?? res.data ?? [], nextCursor: res.next_cursor };
  }

  async *listAll(params: ListParams = {}): AsyncGenerator<Permission> {
    let cursor = params.cursor;
    do {
      const page = await this.list({ ...params, cursor });
      for (const item of page.data) yield item;
      cursor = page.nextCursor;
    } while (cursor);
  }
}
