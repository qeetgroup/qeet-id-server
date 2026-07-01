import type { HttpClient } from "./client.js";

export interface Secret {
  id: string;
  name: string;
  scope: string;
  last4: string;
  created_at: string;
  updated_at: string;
}

export interface CreateSecretInput {
  name: string;
  scope: string;
  value: string;
}

export interface UpdateSecretInput {
  scope?: string;
  value?: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
}

export class Vault {
  constructor(private readonly http: HttpClient) {}

  /** Agent-scoped: fetch the value of a vault secret by name. */
  get(name: string): Promise<{ value: string }> {
    return this.http.get<{ value: string }>(`/v1/vault/${encodeURIComponent(name)}`);
  }

  /** Admin: list secrets for a tenant (values are masked to last 4 chars). */
  async listSecrets(tenantId: string): Promise<Secret[]> {
    const res = await this.http.get<ListEnvelope<Secret>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/secrets`,
    );
    return res.items ?? res.data ?? [];
  }

  /** Admin: create a new secret for a tenant. */
  createSecret(tenantId: string, input: CreateSecretInput): Promise<Secret> {
    return this.http.post<Secret>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/secrets`,
      input,
    );
  }

  /** Admin: update scope or rotate the value of a secret. */
  updateSecret(tenantId: string, id: string, input: UpdateSecretInput): Promise<Secret> {
    return this.http.patch<Secret>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/secrets/${encodeURIComponent(id)}`,
      input,
    );
  }

  /** Admin: reveal the full plaintext value of a secret. */
  revealSecret(tenantId: string, id: string): Promise<{ value: string }> {
    return this.http.post<{ value: string }>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/secrets/${encodeURIComponent(id)}/reveal`,
      {},
    );
  }

  /** Admin: delete a secret. */
  deleteSecret(tenantId: string, id: string): Promise<void> {
    return this.http.delete<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/secrets/${encodeURIComponent(id)}`,
    );
  }
}
