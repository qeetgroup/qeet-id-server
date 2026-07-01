package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type Secret struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Last4     string `json:"last4"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type CreateSecretInput struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
	Value string `json:"value"`
}

type UpdateSecretInput struct {
	Scope *string `json:"scope,omitempty"`
	Value *string `json:"value,omitempty"`
}

type VaultGetResult struct {
	Value string `json:"value"`
}

type Vault struct{ http *httpClient }

// Get fetches the value of a vault secret by name (agent-scoped endpoint).
func (r *Vault) Get(ctx context.Context, name string) (*VaultGetResult, error) {
	var out VaultGetResult
	err := r.http.do(ctx, http.MethodGet, "/v1/vault/"+url.PathEscape(name), nil, nil, &out, true)
	return &out, err
}

func (r *Vault) ListSecrets(ctx context.Context, tenantID string) ([]Secret, error) {
	var env struct {
		Items []Secret `json:"items"`
		Data  []Secret `json:"data"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/secrets", nil, nil, &env, true); err != nil {
		return nil, err
	}
	if env.Items != nil {
		return env.Items, nil
	}
	return env.Data, nil
}

func (r *Vault) CreateSecret(ctx context.Context, tenantID string, in CreateSecretInput) (*Secret, error) {
	var out Secret
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/secrets", nil, in, &out, false)
	return &out, err
}

func (r *Vault) UpdateSecret(ctx context.Context, tenantID, id string, in UpdateSecretInput) (*Secret, error) {
	var out Secret
	err := r.http.do(ctx, http.MethodPatch, "/v1/tenants/"+url.PathEscape(tenantID)+"/secrets/"+url.PathEscape(id), nil, in, &out, false)
	return &out, err
}

func (r *Vault) RevealSecret(ctx context.Context, tenantID, id string) (*VaultGetResult, error) {
	var out VaultGetResult
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/secrets/"+url.PathEscape(id)+"/reveal", nil, struct{}{}, &out, false)
	return &out, err
}

func (r *Vault) DeleteSecret(ctx context.Context, tenantID, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/tenants/"+url.PathEscape(tenantID)+"/secrets/"+url.PathEscape(id), nil, nil, nil, true)
}
