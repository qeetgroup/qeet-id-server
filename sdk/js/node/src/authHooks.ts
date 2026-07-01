import type { HttpClient } from "./client.js";

export interface AuthHookSettings {
  tenant_id: string;
  pre_login_url?: string;
  post_login_url?: string;
  pre_signup_url?: string;
  enabled: boolean;
  timeout_ms?: number;
  updated_at?: string;
}

export interface UpdateAuthHookInput {
  pre_login_url?: string;
  post_login_url?: string;
  pre_signup_url?: string;
  enabled?: boolean;
  timeout_ms?: number;
}

export class AuthHooks {
  constructor(private readonly http: HttpClient) {}

  get(tenantId: string): Promise<AuthHookSettings> {
    return this.http.get<AuthHookSettings>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/auth-hooks`,
    );
  }

  update(tenantId: string, input: UpdateAuthHookInput): Promise<AuthHookSettings> {
    return this.http.request<AuthHookSettings>(
      "PUT",
      `/v1/tenants/${encodeURIComponent(tenantId)}/auth-hooks`,
      { body: input },
    );
  }
}
