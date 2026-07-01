package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type BrandingSettings struct {
	TenantID       string `json:"tenant_id"`
	LogoURL        string `json:"logo_url,omitempty"`
	PrimaryColor   string `json:"primary_color,omitempty"`
	SecondaryColor string `json:"secondary_color,omitempty"`
	CustomDomain   string `json:"custom_domain,omitempty"`
	FaviconURL     string `json:"favicon_url,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

type UpdateBrandingInput struct {
	LogoURL        *string `json:"logo_url,omitempty"`
	PrimaryColor   *string `json:"primary_color,omitempty"`
	SecondaryColor *string `json:"secondary_color,omitempty"`
	CustomDomain   *string `json:"custom_domain,omitempty"`
	FaviconURL     *string `json:"favicon_url,omitempty"`
}

type Branding struct{ http *httpClient }

func (r *Branding) Get(ctx context.Context, tenantID string) (*BrandingSettings, error) {
	var out BrandingSettings
	err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/branding", nil, nil, &out, true)
	return &out, err
}

func (r *Branding) Update(ctx context.Context, tenantID string, in UpdateBrandingInput) (*BrandingSettings, error) {
	var out BrandingSettings
	err := r.http.do(ctx, http.MethodPut, "/v1/tenants/"+url.PathEscape(tenantID)+"/branding", nil, in, &out, false)
	return &out, err
}
