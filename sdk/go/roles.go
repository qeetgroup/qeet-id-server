package qeetid

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type Role struct {
	ID          string   `json:"id"`
	TenantID    string   `json:"tenant_id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

type CreateRoleInput struct {
	Name        string   `json:"name"`
	TenantID    string   `json:"tenant_id,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type UpdateRoleInput struct {
	Name        *string  `json:"name,omitempty"`
	Description *string  `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type RolePage struct {
	Data       []Role
	NextCursor string
}

type Roles struct{ http *httpClient }

func (r *Roles) Create(ctx context.Context, in CreateRoleInput) (*Role, error) {
	var out Role
	err := r.http.do(ctx, http.MethodPost, "/v1/rbac/roles", nil, in, &out, false)
	return &out, err
}

func (r *Roles) Get(ctx context.Context, id string) (*Role, error) {
	var out Role
	err := r.http.do(ctx, http.MethodGet, "/v1/rbac/roles/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (r *Roles) Update(ctx context.Context, id string, in UpdateRoleInput) (*Role, error) {
	var out Role
	err := r.http.do(ctx, http.MethodPatch, "/v1/rbac/roles/"+url.PathEscape(id), nil, in, &out, false)
	return &out, err
}

func (r *Roles) Delete(ctx context.Context, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/rbac/roles/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *Roles) AssignToUser(ctx context.Context, roleID, userID, tenantID string) error {
	body := map[string]string{"user_id": userID, "tenant_id": tenantID}
	return r.http.do(ctx, http.MethodPost, "/v1/rbac/roles/"+url.PathEscape(roleID)+"/assign", nil, body, nil, false)
}

func (r *Roles) RemoveFromUser(ctx context.Context, roleID, userID, tenantID string) error {
	body := map[string]string{"user_id": userID, "tenant_id": tenantID}
	return r.http.do(ctx, http.MethodPost, "/v1/rbac/roles/"+url.PathEscape(roleID)+"/remove", nil, body, nil, false)
}

func (r *Roles) List(ctx context.Context, params ListParams) (*RolePage, error) {
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
		Items      []Role `json:"items"`
		Data       []Role `json:"data"`
		NextCursor string `json:"next_cursor"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/rbac/roles", q, nil, &env, true); err != nil {
		return nil, err
	}
	items := env.Items
	if items == nil {
		items = env.Data
	}
	return &RolePage{Data: items, NextCursor: env.NextCursor}, nil
}
