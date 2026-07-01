import type { HttpClient } from "./client.js";

export interface AuthPolicySettings {
  tenant_id: string;
  password_min_length?: number;
  password_require_uppercase?: boolean;
  password_require_numbers?: boolean;
  password_require_symbols?: boolean;
  allowed_login_methods?: string[];
  mfa_required?: boolean;
  session_duration_seconds?: number;
  updated_at?: string;
}

export interface UpdateAuthPolicyInput {
  password_min_length?: number;
  password_require_uppercase?: boolean;
  password_require_numbers?: boolean;
  password_require_symbols?: boolean;
  allowed_login_methods?: string[];
  mfa_required?: boolean;
  session_duration_seconds?: number;
}

export class AuthPolicy {
  constructor(private readonly http: HttpClient) {}

  get(tenantId: string): Promise<AuthPolicySettings> {
    return this.http.get<AuthPolicySettings>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/auth-policy`,
    );
  }

  update(tenantId: string, input: UpdateAuthPolicyInput): Promise<AuthPolicySettings> {
    return this.http.request<AuthPolicySettings>(
      "PUT",
      `/v1/tenants/${encodeURIComponent(tenantId)}/auth-policy`,
      { body: input },
    );
  }
}
