import type { HttpClient } from "./client.js";

export interface MfaFactor {
  id: string;
  user_id: string;
  type: string;
  status: string;
  created_at: string;
}

export class MfaAdmin {
  constructor(private readonly http: HttpClient) {}

  async list(userId: string): Promise<MfaFactor[]> {
    const res = await this.http.get<{ items?: MfaFactor[]; data?: MfaFactor[] }>(
      `/v1/users/${encodeURIComponent(userId)}/mfa`,
    );
    return res.items ?? res.data ?? [];
  }

  reset(userId: string): Promise<void> {
    return this.http.delete<void>(`/v1/users/${encodeURIComponent(userId)}/mfa`);
  }

  require(userId: string, tenantId: string): Promise<void> {
    return this.http.post<void>(`/v1/users/${encodeURIComponent(userId)}/mfa/require`, {
      tenant_id: tenantId,
    });
  }
}
