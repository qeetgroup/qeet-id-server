import type { HttpClient } from "./client.js";
import type { ListParams, Page } from "./users.js";

export interface Invitation {
  id: string;
  tenant_id: string;
  email: string;
  role?: string;
  status: string;
  invited_by?: string;
  expires_at?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at?: string;
}

export interface CreateInvitationInput {
  email: string;
  tenant_id: string;
  role?: string;
  expires_in_days?: number;
  metadata?: Record<string, unknown>;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
  next_cursor?: string;
}

export class Invitations {
  constructor(private readonly http: HttpClient) {}

  create(input: CreateInvitationInput): Promise<Invitation> {
    return this.http.post<Invitation>("/v1/invites", input);
  }

  get(id: string): Promise<Invitation> {
    return this.http.get<Invitation>(`/v1/invites/${encodeURIComponent(id)}`);
  }

  delete(id: string): Promise<void> {
    return this.http.delete<void>(`/v1/invites/${encodeURIComponent(id)}`);
  }

  resend(id: string): Promise<void> {
    return this.http.post<void>(`/v1/invites/${encodeURIComponent(id)}/resend`, {});
  }

  async list(params: ListParams = {}): Promise<Page<Invitation>> {
    const res = await this.http.get<ListEnvelope<Invitation>>("/v1/invites", {
      query: { tenant: params.tenant, limit: params.limit, cursor: params.cursor },
    });
    return { data: res.items ?? res.data ?? [], nextCursor: res.next_cursor };
  }

  async *listAll(params: ListParams = {}): AsyncGenerator<Invitation> {
    let cursor = params.cursor;
    do {
      const page = await this.list({ ...params, cursor });
      for (const item of page.data) yield item;
      cursor = page.nextCursor;
    } while (cursor);
  }
}
