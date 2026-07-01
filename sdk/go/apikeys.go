package qeetid

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type APIKey struct {
	ID         string   `json:"id"`
	TenantID   string   `json:"tenant_id,omitempty"`
	Name       string   `json:"name"`
	Prefix     string   `json:"prefix"`
	Scopes     []string `json:"scopes,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	LastUsedAt string   `json:"last_used_at,omitempty"`
	CreatedAt  string   `json:"created_at"`
}

type CreateAPIKeyInput struct {
	Name         string   `json:"name"`
	TenantID     string   `json:"tenant_id,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	ExpiresInDays int     `json:"expires_in_days,omitempty"`
}

type CreateAPIKeyResult struct {
	Key    APIKey `json:"key"`
	Secret string `json:"secret"`
}

type RotateAPIKeyResult struct {
	Key    APIKey `json:"key"`
	Secret string `json:"secret"`
}

type APIKeyPage struct {
	Data       []APIKey
	NextCursor string
}

type APIKeys struct{ http *httpClient }

func (r *APIKeys) Create(ctx context.Context, in CreateAPIKeyInput) (*CreateAPIKeyResult, error) {
	var out CreateAPIKeyResult
	err := r.http.do(ctx, http.MethodPost, "/v1/api-keys", nil, in, &out, false)
	return &out, err
}

func (r *APIKeys) Get(ctx context.Context, id string) (*APIKey, error) {
	var out APIKey
	err := r.http.do(ctx, http.MethodGet, "/v1/api-keys/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (r *APIKeys) Delete(ctx context.Context, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/api-keys/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *APIKeys) Rotate(ctx context.Context, id string) (*RotateAPIKeyResult, error) {
	var out RotateAPIKeyResult
	err := r.http.do(ctx, http.MethodPost, "/v1/api-keys/"+url.PathEscape(id)+"/rotate", nil, struct{}{}, &out, false)
	return &out, err
}

func (r *APIKeys) List(ctx context.Context, params ListParams) (*APIKeyPage, error) {
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
		Items      []APIKey `json:"items"`
		Data       []APIKey `json:"data"`
		NextCursor string   `json:"next_cursor"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/api-keys", q, nil, &env, true); err != nil {
		return nil, err
	}
	items := env.Items
	if items == nil {
		items = env.Data
	}
	return &APIKeyPage{Data: items, NextCursor: env.NextCursor}, nil
}
