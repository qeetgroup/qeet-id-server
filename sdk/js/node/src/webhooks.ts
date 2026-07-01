import type { HttpClient } from "./client.js";

export interface Webhook {
  id: string;
  tenant_id: string;
  url: string;
  events: string[];
  enabled: boolean;
  secret?: string;
  created_at: string;
  updated_at?: string;
}

export interface CreateWebhookInput {
  url: string;
  events: string[];
  enabled?: boolean;
}

export interface UpdateWebhookInput {
  url?: string;
  events?: string[];
  enabled?: boolean;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event: string;
  status: string;
  response_status?: number;
  created_at: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
}

export class Webhooks {
  constructor(private readonly http: HttpClient) {}

  create(tenantId: string, input: CreateWebhookInput): Promise<Webhook> {
    return this.http.post<Webhook>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/webhooks`,
      input,
    );
  }

  get(tenantId: string, id: string): Promise<Webhook> {
    return this.http.get<Webhook>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/webhooks/${encodeURIComponent(id)}`,
    );
  }

  update(tenantId: string, id: string, input: UpdateWebhookInput): Promise<Webhook> {
    return this.http.patch<Webhook>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/webhooks/${encodeURIComponent(id)}`,
      input,
    );
  }

  delete(tenantId: string, id: string): Promise<void> {
    return this.http.delete<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/webhooks/${encodeURIComponent(id)}`,
    );
  }

  test(tenantId: string, id: string): Promise<void> {
    return this.http.post<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/webhooks/${encodeURIComponent(id)}/test`,
      {},
    );
  }

  async list(tenantId: string): Promise<Webhook[]> {
    const res = await this.http.get<ListEnvelope<Webhook>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/webhooks`,
    );
    return res.items ?? res.data ?? [];
  }

  async listDeliveries(tenantId: string, webhookId: string): Promise<WebhookDelivery[]> {
    const res = await this.http.get<ListEnvelope<WebhookDelivery>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/webhooks/${encodeURIComponent(webhookId)}/deliveries`,
    );
    return res.items ?? res.data ?? [];
  }

  retryDelivery(tenantId: string, webhookId: string, deliveryId: string): Promise<void> {
    return this.http.post<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/webhooks/${encodeURIComponent(webhookId)}/deliveries/${encodeURIComponent(deliveryId)}/retry`,
      {},
    );
  }
}
