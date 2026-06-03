import type { HttpClient } from "./client.js";

export interface User {
  id: string;
  tenant_id?: string | null;
  email: string;
  display_name?: string;
  status: string;
  phone?: string | null;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at?: string;
}

export interface CreateUserInput {
  email: string;
  display_name?: string;
  phone?: string;
  password?: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateUserInput {
  display_name?: string;
  phone?: string;
  status?: string;
  metadata?: Record<string, unknown>;
}

export interface ListParams {
  tenant?: string;
  limit?: number;
  cursor?: string;
}

export interface Page<T> {
  data: T[];
  nextCursor?: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
  next_cursor?: string;
}

export class Users {
  constructor(private readonly http: HttpClient) {}

  create(input: CreateUserInput): Promise<User> {
    return this.http.post<User>("/v1/users", input);
  }

  get(id: string): Promise<User> {
    return this.http.get<User>(`/v1/users/${encodeURIComponent(id)}`);
  }

  update(id: string, input: UpdateUserInput): Promise<User> {
    return this.http.patch<User>(`/v1/users/${encodeURIComponent(id)}`, input);
  }

  delete(id: string): Promise<void> {
    return this.http.delete<void>(`/v1/users/${encodeURIComponent(id)}`);
  }

  setPassword(id: string, password: string): Promise<void> {
    return this.http.post<void>(`/v1/users/${encodeURIComponent(id)}/password`, { password });
  }

  async list(params: ListParams = {}): Promise<Page<User>> {
    const res = await this.http.get<ListEnvelope<User>>("/v1/users", {
      query: { tenant: params.tenant, limit: params.limit, cursor: params.cursor },
    });
    return { data: res.items ?? res.data ?? [], nextCursor: res.next_cursor };
  }

  /** Auto-paginate every page into a single async stream. */
  async *listAll(params: ListParams = {}): AsyncGenerator<User> {
    let cursor = params.cursor;
    do {
      const page = await this.list({ ...params, cursor });
      for (const user of page.data) yield user;
      cursor = page.nextCursor;
    } while (cursor);
  }
}
