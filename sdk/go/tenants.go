package qeetid

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type Tenant struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Region    string `json:"region,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type CreateTenantInput struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Region string `json:"region,omitempty"`
}

type UpdateTenantInput struct {
	Name   *string `json:"name,omitempty"`
	Region *string `json:"region,omitempty"`
}

type TenantPage struct {
	Data       []Tenant
	NextCursor string
}

type Tenants struct{ http *httpClient }

func (t *Tenants) Create(ctx context.Context, in CreateTenantInput) (*Tenant, error) {
	var out Tenant
	err := t.http.do(ctx, http.MethodPost, "/v1/tenants", nil, in, &out, false)
	return &out, err
}

func (t *Tenants) Get(ctx context.Context, id string) (*Tenant, error) {
	var out Tenant
	err := t.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (t *Tenants) Update(ctx context.Context, id string, in UpdateTenantInput) (*Tenant, error) {
	var out Tenant
	err := t.http.do(ctx, http.MethodPatch, "/v1/tenants/"+url.PathEscape(id), nil, in, &out, false)
	return &out, err
}

func (t *Tenants) Delete(ctx context.Context, id string) error {
	return t.http.do(ctx, http.MethodDelete, "/v1/tenants/"+url.PathEscape(id), nil, nil, nil, true)
}

func (t *Tenants) List(ctx context.Context, limit int, cursor string) (*TenantPage, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	var env struct {
		Items      []Tenant `json:"items"`
		Data       []Tenant `json:"data"`
		NextCursor string   `json:"next_cursor"`
	}
	if err := t.http.do(ctx, http.MethodGet, "/v1/tenants", q, nil, &env, true); err != nil {
		return nil, err
	}
	items := env.Items
	if items == nil {
		items = env.Data
	}
	return &TenantPage{Data: items, NextCursor: env.NextCursor}, nil
}
