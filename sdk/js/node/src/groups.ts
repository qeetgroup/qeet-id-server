import type { HttpClient } from "./client.js";
import type { ListParams, Page } from "./users.js";

export interface Group {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at?: string;
}

export interface CreateGroupInput {
  name: string;
  tenant_id?: string;
  description?: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateGroupInput {
  name?: string;
  description?: string;
  metadata?: Record<string, unknown>;
}

export interface GroupMember {
  user_id: string;
  group_id: string;
  added_at: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
  next_cursor?: string;
}

export class Groups {
  constructor(private readonly http: HttpClient) {}

  create(input: CreateGroupInput): Promise<Group> {
    return this.http.post<Group>("/v1/groups", input);
  }

  get(id: string): Promise<Group> {
    return this.http.get<Group>(`/v1/groups/${encodeURIComponent(id)}`);
  }

  update(id: string, input: UpdateGroupInput): Promise<Group> {
    return this.http.patch<Group>(`/v1/groups/${encodeURIComponent(id)}`, input);
  }

  delete(id: string): Promise<void> {
    return this.http.delete<void>(`/v1/groups/${encodeURIComponent(id)}`);
  }

  async list(params: ListParams = {}): Promise<Page<Group>> {
    const res = await this.http.get<ListEnvelope<Group>>("/v1/groups", {
      query: { tenant: params.tenant, limit: params.limit, cursor: params.cursor },
    });
    return { data: res.items ?? res.data ?? [], nextCursor: res.next_cursor };
  }

  async *listAll(params: ListParams = {}): AsyncGenerator<Group> {
    let cursor = params.cursor;
    do {
      const page = await this.list({ ...params, cursor });
      for (const item of page.data) yield item;
      cursor = page.nextCursor;
    } while (cursor);
  }

  addMember(groupId: string, userId: string): Promise<void> {
    return this.http.post<void>(`/v1/groups/${encodeURIComponent(groupId)}/members`, { user_id: userId });
  }

  removeMember(groupId: string, userId: string): Promise<void> {
    return this.http.delete<void>(
      `/v1/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`,
    );
  }

  async listMembers(groupId: string): Promise<GroupMember[]> {
    const res = await this.http.get<ListEnvelope<GroupMember>>(
      `/v1/groups/${encodeURIComponent(groupId)}/members`,
    );
    return res.items ?? res.data ?? [];
  }
}
