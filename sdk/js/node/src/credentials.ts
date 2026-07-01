import type { HttpClient } from "./client.js";

export interface Credential {
  id: string;
  subject: string;
  type: string;
  issued_at: string;
  expires_at?: string;
  revoked: boolean;
}

export interface IssueCredentialInput {
  subject: string;
  type: string;
  claims?: Record<string, unknown>;
  ttl_seconds?: number;
}

export interface IssueCredentialResult {
  credential_id: string;
  jwt: string;
  expires_at?: string;
}

export interface VerifyCredentialResult {
  valid: boolean;
  reason?: string;
  subject?: string;
  issuer?: string;
  vc?: Record<string, unknown>;
}

interface ListEnvelope<T> {
  items?: T[];
  data?: T[];
}

export class Credentials {
  constructor(private readonly http: HttpClient) {}

  /** Issue a new W3C JWT-VC for a subject. */
  issue(tenantId: string, input: IssueCredentialInput): Promise<IssueCredentialResult> {
    return this.http.post<IssueCredentialResult>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/credentials`,
      input,
    );
  }

  /** List issued credentials for a tenant. */
  async list(tenantId: string): Promise<Credential[]> {
    const res = await this.http.get<ListEnvelope<Credential>>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/credentials`,
    );
    return res.items ?? res.data ?? [];
  }

  /** Revoke a credential. */
  revoke(tenantId: string, id: string): Promise<void> {
    return this.http.post<void>(
      `/v1/tenants/${encodeURIComponent(tenantId)}/credentials/${encodeURIComponent(id)}/revoke`,
      {},
    );
  }

  /**
   * Verify a presented JWT-VC. Public endpoint — no API key required.
   * Relying parties call this to confirm authenticity + revocation status.
   */
  verify(jwt: string): Promise<VerifyCredentialResult> {
    return this.http.post<VerifyCredentialResult>("/v1/credentials/verify", {
      credential: jwt,
    });
  }
}
