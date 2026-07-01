import type { HttpClient } from "./client.js";

export interface BrandingSettings {
  tenant_id: string;
  logo_url?: string;
  primary_color?: string;
  secondary_color?: string;
  custom_domain?: string;
  favicon_url?: string;
  updated_at?: string;
}

export interface UpdateBrandingInput {
  logo_url?: string;
  primary_color?: string;
  secondary_color?: string;
  custom_domain?: string;
  favicon_url?: string;
}

export class Branding {
  constructor(private readonly http: HttpClient) {}

  get(tenantId: string): Promise<BrandingSettings> {
    return this.http.get<BrandingSettings>(`/v1/tenants/${encodeURIComponent(tenantId)}/branding`);
  }

  update(tenantId: string, input: UpdateBrandingInput): Promise<BrandingSettings> {
    return this.http.request<BrandingSettings>(
      "PUT",
      `/v1/tenants/${encodeURIComponent(tenantId)}/branding`,
      { body: input },
    );
  }
}
