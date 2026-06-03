package qeetid

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type User struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Email       string         `json:"email"`
	DisplayName string         `json:"display_name,omitempty"`
	Status      string         `json:"status"`
	Phone       string         `json:"phone,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at,omitempty"`
}

type CreateUserInput struct {
	Email       string         `json:"email"`
	DisplayName string         `json:"display_name,omitempty"`
	Phone       string         `json:"phone,omitempty"`
	Password    string         `json:"password,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type UpdateUserInput struct {
	DisplayName *string        `json:"display_name,omitempty"`
	Phone       *string        `json:"phone,omitempty"`
	Status      *string        `json:"status,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type ListParams struct {
	Tenant string
	Limit  int
	Cursor string
}

type UserPage struct {
	Data       []User
	NextCursor string
}

type Users struct{ http *httpClient }

func (u *Users) Create(ctx context.Context, in CreateUserInput) (*User, error) {
	var out User
	err := u.http.do(ctx, http.MethodPost, "/v1/users", nil, in, &out, false)
	return &out, err
}

func (u *Users) Get(ctx context.Context, id string) (*User, error) {
	var out User
	err := u.http.do(ctx, http.MethodGet, "/v1/users/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (u *Users) Update(ctx context.Context, id string, in UpdateUserInput) (*User, error) {
	var out User
	err := u.http.do(ctx, http.MethodPatch, "/v1/users/"+url.PathEscape(id), nil, in, &out, false)
	return &out, err
}

func (u *Users) Delete(ctx context.Context, id string) error {
	return u.http.do(ctx, http.MethodDelete, "/v1/users/"+url.PathEscape(id), nil, nil, nil, true)
}

func (u *Users) SetPassword(ctx context.Context, id, password string) error {
	body := map[string]string{"password": password}
	return u.http.do(ctx, http.MethodPost, "/v1/users/"+url.PathEscape(id)+"/password", nil, body, nil, false)
}

func (u *Users) List(ctx context.Context, params ListParams) (*UserPage, error) {
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
		Items      []User `json:"items"`
		Data       []User `json:"data"`
		NextCursor string `json:"next_cursor"`
	}
	if err := u.http.do(ctx, http.MethodGet, "/v1/users", q, nil, &env, true); err != nil {
		return nil, err
	}
	items := env.Items
	if items == nil {
		items = env.Data
	}
	return &UserPage{Data: items, NextCursor: env.NextCursor}, nil
}
