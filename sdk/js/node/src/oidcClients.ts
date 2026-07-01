import type { HttpClient } from "./client.js";
import type { ListParams, Page } from "./users.js";

export interface OidcClient {
  id: string;
  tenant_id?: string;
  name: string;
  client_id: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
  token_endpoint_auth_method?: string;
  created_at: string;
  updated_at?: string;
}

export interface CreateOidcClientInput {
  name: string;
  tenant_id?: string;
  redirect_uris: string[];
  grant_types?: string[];
  scopes?: string[];
  token_endpoint_auth_method?: string;
}

export interface UpdateOidcClientInput {
  name?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  scopes?: string[];
  token_endpoint_auth_method?: string;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
  next_cursor?: string;
}

export class OidcClients {
  constructor(private readonly http: HttpClient) {}

  create(input: CreateOidcClientInput): Promise<OidcClient> {
    return this.http.post<OidcClient>("/v1/oidc/clients", input);
  }

  get(id: string): Promise<OidcClient> {
    return this.http.get<OidcClient>(`/v1/oidc/clients/${encodeURIComponent(id)}`);
  }

  update(id: string, input: UpdateOidcClientInput): Promise<OidcClient> {
    return this.http.patch<OidcClient>(`/v1/oidc/clients/${encodeURIComponent(id)}`, input);
  }

  delete(id: string): Promise<void> {
    return this.http.delete<void>(`/v1/oidc/clients/${encodeURIComponent(id)}`);
  }

  rotateSecret(id: string): Promise<{ client_id: string; client_secret: string }> {
    return this.http.post<{ client_id: string; client_secret: string }>(
      `/v1/oidc/clients/${encodeURIComponent(id)}/rotate-secret`,
      {},
    );
  }

  async list(params: ListParams = {}): Promise<Page<OidcClient>> {
    const res = await this.http.get<ListEnvelope<OidcClient>>("/v1/oidc/clients", {
      query: { tenant: params.tenant, limit: params.limit, cursor: params.cursor },
    });
    return { data: res.items ?? res.data ?? [], nextCursor: res.next_cursor };
  }
}
