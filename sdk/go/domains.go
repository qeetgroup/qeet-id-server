package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type Domain struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	Domain            string `json:"domain"`
	Verified          bool   `json:"verified"`
	VerificationToken string `json:"verification_token,omitempty"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at,omitempty"`
}

type CreateDomainInput struct {
	Domain string `json:"domain"`
}

type Domains struct{ http *httpClient }

func (r *Domains) Create(ctx context.Context, tenantID string, in CreateDomainInput) (*Domain, error) {
	var out Domain
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/domains", nil, in, &out, false)
	return &out, err
}

func (r *Domains) Get(ctx context.Context, tenantID, id string) (*Domain, error) {
	var out Domain
	err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/domains/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (r *Domains) Delete(ctx context.Context, tenantID, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/tenants/"+url.PathEscape(tenantID)+"/domains/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *Domains) Verify(ctx context.Context, tenantID, id string) (*Domain, error) {
	var out Domain
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/domains/"+url.PathEscape(id)+"/verify", nil, struct{}{}, &out, false)
	return &out, err
}

func (r *Domains) List(ctx context.Context, tenantID string) ([]Domain, error) {
	var env struct {
		Items []Domain `json:"items"`
		Data  []Domain `json:"data"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/domains", nil, nil, &env, true); err != nil {
		return nil, err
	}
	if env.Items != nil {
		return env.Items, nil
	}
	return env.Data, nil
}
