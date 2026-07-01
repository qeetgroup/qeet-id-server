import type { HttpClient } from "./client.js";
import type { ListParams, Page } from "./users.js";

export interface Role {
  id: string;
  tenant_id?: string;
  name: string;
  description?: string;
  permissions?: string[];
  created_at: string;
  updated_at?: string;
}

export interface CreateRoleInput {
  name: string;
  tenant_id?: string;
  description?: string;
  permissions?: string[];
}

export interface UpdateRoleInput {
  name?: string;
  description?: string;
  permissions?: string[];
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
  next_cursor?: string;
}

export class Roles {
  constructor(private readonly http: HttpClient) {}

  create(input: CreateRoleInput): Promise<Role> {
    return this.http.post<Role>("/v1/rbac/roles", input);
  }

  get(id: string): Promise<Role> {
    return this.http.get<Role>(`/v1/rbac/roles/${encodeURIComponent(id)}`);
  }

  update(id: string, input: UpdateRoleInput): Promise<Role> {
    return this.http.patch<Role>(`/v1/rbac/roles/${encodeURIComponent(id)}`, input);
  }

  delete(id: string): Promise<void> {
    return this.http.delete<void>(`/v1/rbac/roles/${encodeURIComponent(id)}`);
  }

  assignToUser(roleId: string, userId: string, tenantId: string): Promise<void> {
    return this.http.post<void>(`/v1/rbac/roles/${encodeURIComponent(roleId)}/assign`, {
      user_id: userId,
      tenant_id: tenantId,
    });
  }

  removeFromUser(roleId: string, userId: string, tenantId: string): Promise<void> {
    return this.http.post<void>(`/v1/rbac/roles/${encodeURIComponent(roleId)}/remove`, {
      user_id: userId,
      tenant_id: tenantId,
    });
  }

  async list(params: ListParams = {}): Promise<Page<Role>> {
    const res = await this.http.get<ListEnvelope<Role>>("/v1/rbac/roles", {
      query: { tenant: params.tenant, limit: params.limit, cursor: params.cursor },
    });
    return { data: res.items ?? res.data ?? [], nextCursor: res.next_cursor };
  }

  async *listAll(params: ListParams = {}): AsyncGenerator<Role> {
    let cursor = params.cursor;
    do {
      const page = await this.list({ ...params, cursor });
      for (const item of page.data) yield item;
      cursor = page.nextCursor;
    } while (cursor);
  }
}
