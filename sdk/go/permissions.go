package qeetid

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type Permission struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

type CreatePermissionInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type PermissionPage struct {
	Data       []Permission
	NextCursor string
}

type Permissions struct{ http *httpClient }

func (r *Permissions) Create(ctx context.Context, in CreatePermissionInput) (*Permission, error) {
	var out Permission
	err := r.http.do(ctx, http.MethodPost, "/v1/rbac/permissions", nil, in, &out, false)
	return &out, err
}

func (r *Permissions) Get(ctx context.Context, id string) (*Permission, error) {
	var out Permission
	err := r.http.do(ctx, http.MethodGet, "/v1/rbac/permissions/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (r *Permissions) Delete(ctx context.Context, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/rbac/permissions/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *Permissions) List(ctx context.Context, params ListParams) (*PermissionPage, error) {
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
		Items      []Permission `json:"items"`
		Data       []Permission `json:"data"`
		NextCursor string       `json:"next_cursor"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/rbac/permissions", q, nil, &env, true); err != nil {
		return nil, err
	}
	items := env.Items
	if items == nil {
		items = env.Data
	}
	return &PermissionPage{Data: items, NextCursor: env.NextCursor}, nil
}
