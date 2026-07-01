package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type SAMLConnection struct {
	ID               string            `json:"id"`
	TenantID         string            `json:"tenant_id"`
	Name             string            `json:"name"`
	Enabled          bool              `json:"enabled"`
	IdpEntityID      string            `json:"idp_entity_id,omitempty"`
	IdpSSOURL        string            `json:"idp_sso_url,omitempty"`
	IdpCertificate   string            `json:"idp_certificate,omitempty"`
	SpEntityID       string            `json:"sp_entity_id,omitempty"`
	SpACSURL         string            `json:"sp_acs_url,omitempty"`
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	CreatedAt        string            `json:"created_at"`
	UpdatedAt        string            `json:"updated_at,omitempty"`
}

type CreateSAMLConnectionInput struct {
	Name             string            `json:"name"`
	IdpEntityID      string            `json:"idp_entity_id,omitempty"`
	IdpSSOURL        string            `json:"idp_sso_url,omitempty"`
	IdpCertificate   string            `json:"idp_certificate,omitempty"`
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	Enabled          *bool             `json:"enabled,omitempty"`
}

type UpdateSAMLConnectionInput struct {
	Name             *string           `json:"name,omitempty"`
	IdpEntityID      *string           `json:"idp_entity_id,omitempty"`
	IdpSSOURL        *string           `json:"idp_sso_url,omitempty"`
	IdpCertificate   *string           `json:"idp_certificate,omitempty"`
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	Enabled          *bool             `json:"enabled,omitempty"`
}

type SAMLTestResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type SAML struct{ http *httpClient }

func (r *SAML) Create(ctx context.Context, tenantID string, in CreateSAMLConnectionInput) (*SAMLConnection, error) {
	var out SAMLConnection
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/saml", nil, in, &out, false)
	return &out, err
}

func (r *SAML) Get(ctx context.Context, tenantID, id string) (*SAMLConnection, error) {
	var out SAMLConnection
	err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/saml/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (r *SAML) Update(ctx context.Context, tenantID, id string, in UpdateSAMLConnectionInput) (*SAMLConnection, error) {
	var out SAMLConnection
	err := r.http.do(ctx, http.MethodPatch, "/v1/tenants/"+url.PathEscape(tenantID)+"/saml/"+url.PathEscape(id), nil, in, &out, false)
	return &out, err
}

func (r *SAML) Delete(ctx context.Context, tenantID, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/tenants/"+url.PathEscape(tenantID)+"/saml/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *SAML) Test(ctx context.Context, tenantID, id string) (*SAMLTestResult, error) {
	var out SAMLTestResult
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/saml/"+url.PathEscape(id)+"/test", nil, struct{}{}, &out, false)
	return &out, err
}

func (r *SAML) List(ctx context.Context, tenantID string) ([]SAMLConnection, error) {
	var env struct {
		Items []SAMLConnection `json:"items"`
		Data  []SAMLConnection `json:"data"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/saml", nil, nil, &env, true); err != nil {
		return nil, err
	}
	if env.Items != nil {
		return env.Items, nil
	}
	return env.Data, nil
}
