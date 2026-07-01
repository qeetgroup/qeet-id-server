import type { HttpClient } from "./client.js";

export interface AuditLog {
  id: string;
  tenant_id: string;
  actor_id?: string;
  actor_type?: string;
  event: string;
  resource_type?: string;
  resource_id?: string;
  ip_address?: string;
  user_agent?: string;
  metadata?: Record<string, unknown>;
  hash?: string;
  created_at: string;
}

export interface AuditLogListParams {
  tenant?: string;
  event?: string;
  actor_id?: string;
  from?: string;
  to?: string;
  limit?: number;
  cursor?: string;
}

export interface AuditLogPage {
  data: AuditLog[];
  nextCursor?: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
  next_cursor?: string;
}

export class AuditLogs {
  constructor(private readonly http: HttpClient) {}

  async list(tenantId: string, params: AuditLogListParams = {}): Promise<AuditLogPage> {
    const res = await this.http.get<ListEnvelope<AuditLog>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/audit`,
      {
        query: {
          event: params.event,
          actor_id: params.actor_id,
          from: params.from,
          to: params.to,
          limit: params.limit,
          cursor: params.cursor,
        },
      },
    );
    return { data: res.items ?? res.data ?? [], nextCursor: res.next_cursor };
  }

  async *listAll(tenantId: string, params: AuditLogListParams = {}): AsyncGenerator<AuditLog> {
    let cursor = params.cursor;
    do {
      const page = await this.list(tenantId, { ...params, cursor });
      for (const entry of page.data) yield entry;
      cursor = page.nextCursor;
    } while (cursor);
  }

  verify(tenantId: string, entryId: string): Promise<{ valid: boolean }> {
    return this.http.post<{ valid: boolean }>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/audit/${encodeURIComponent(entryId)}/verify`,
      {},
    );
  }
}
