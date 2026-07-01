package qeetid

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type OIDCClient struct {
	ID                      string   `json:"id"`
	TenantID                string   `json:"tenant_id,omitempty"`
	Name                    string   `json:"name"`
	ClientID                string   `json:"client_id"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	Scopes                  []string `json:"scopes"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	CreatedAt               string   `json:"created_at"`
	UpdatedAt               string   `json:"updated_at,omitempty"`
}

type CreateOIDCClientInput struct {
	Name                    string   `json:"name"`
	TenantID                string   `json:"tenant_id,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

type UpdateOIDCClientInput struct {
	Name                    *string  `json:"name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method,omitempty"`
}

type OIDCClientPage struct {
	Data       []OIDCClient
	NextCursor string
}

type OIDCRotateSecretResult struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type OIDCClients struct{ http *httpClient }

func (r *OIDCClients) Create(ctx context.Context, in CreateOIDCClientInput) (*OIDCClient, error) {
	var out OIDCClient
	err := r.http.do(ctx, http.MethodPost, "/v1/oidc/clients", nil, in, &out, false)
	return &out, err
}

func (r *OIDCClients) Get(ctx context.Context, id string) (*OIDCClient, error) {
	var out OIDCClient
	err := r.http.do(ctx, http.MethodGet, "/v1/oidc/clients/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (r *OIDCClients) Update(ctx context.Context, id string, in UpdateOIDCClientInput) (*OIDCClient, error) {
	var out OIDCClient
	err := r.http.do(ctx, http.MethodPatch, "/v1/oidc/clients/"+url.PathEscape(id), nil, in, &out, false)
	return &out, err
}

func (r *OIDCClients) Delete(ctx context.Context, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/oidc/clients/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *OIDCClients) RotateSecret(ctx context.Context, id string) (*OIDCRotateSecretResult, error) {
	var out OIDCRotateSecretResult
	err := r.http.do(ctx, http.MethodPost, "/v1/oidc/clients/"+url.PathEscape(id)+"/rotate-secret", nil, struct{}{}, &out, false)
	return &out, err
}

func (r *OIDCClients) List(ctx context.Context, params ListParams) (*OIDCClientPage, error) {
	q := url.Values{}
	if params.Tenant != "" {
		q.Set("tenant", params.Tenant)
	}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.Cursor != "" {
		q.Set("cursor", params.Cursor)
	}
	var env struct {
		Items      []OIDCClient `json:"items"`
		Data       []OIDCClient `json:"data"`
		NextCursor string       `json:"next_cursor"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/oidc/clients", q, nil, &env, true); err != nil {
		return nil, err
	}
	items := env.Items
	if items == nil {
		items = env.Data
	}
	return &OIDCClientPage{Data: items, NextCursor: env.NextCursor}, nil
}
