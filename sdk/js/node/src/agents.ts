import type { HttpClient } from "./client.js";

export interface Agent {
  id: string;
  tenant_id: string;
  name: string;
  scopes: string[];
  token_ttl_seconds: number;
  disabled: boolean;
  created_at: string;
  /** Only present immediately after create. */
  secret?: string;
}

export interface CreateAgentInput {
  name: string;
  scopes?: string[];
  token_ttl_seconds?: number;
}

export interface AgentTokenResult {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
}

export class Agents {
  constructor(private readonly http: HttpClient) {}

  create(tenantId: string, input: CreateAgentInput): Promise<Agent> {
    return this.http.post<Agent>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/agents`,
      input,
    );
  }

  delete(tenantId: string, id: string): Promise<void> {
    return this.http.delete<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/agents/${encodeURIComponent(id)}`,
    );
  }

  async list(tenantId: string): Promise<Agent[]> {
    const res = await this.http.get<ListEnvelope<Agent>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/agents`,
    );
    return res.items ?? res.data ?? [];
  }

  /** Mint a short-lived access token for an AI agent. */
  token(tenantId: string, agentId: string, secret: string, scope?: string): Promise<AgentTokenResult> {
    return this.http.post<AgentTokenResult>("/v1/agents/token", {
      tenant_id: tenantId,
      agent_id: agentId,
      secret,
      ...(scope ? { scope } : {}),
    });
  }
}
