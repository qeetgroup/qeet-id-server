package qeetid

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type Group struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at,omitempty"`
}

type CreateGroupInput struct {
	Name        string         `json:"name"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Description string         `json:"description,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type UpdateGroupInput struct {
	Name        *string        `json:"name,omitempty"`
	Description *string        `json:"description,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type GroupMember struct {
	UserID  string `json:"user_id"`
	GroupID string `json:"group_id"`
	AddedAt string `json:"added_at"`
}

type GroupPage struct {
	Data       []Group
	NextCursor string
}

type Groups struct{ http *httpClient }

func (r *Groups) Create(ctx context.Context, in CreateGroupInput) (*Group, error) {
	var out Group
	err := r.http.do(ctx, http.MethodPost, "/v1/groups", nil, in, &out, false)
	return &out, err
}

func (r *Groups) Get(ctx context.Context, id string) (*Group, error) {
	var out Group
	err := r.http.do(ctx, http.MethodGet, "/v1/groups/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (r *Groups) Update(ctx context.Context, id string, in UpdateGroupInput) (*Group, error) {
	var out Group
	err := r.http.do(ctx, http.MethodPatch, "/v1/groups/"+url.PathEscape(id), nil, in, &out, false)
	return &out, err
}

func (r *Groups) Delete(ctx context.Context, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/groups/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *Groups) List(ctx context.Context, params ListParams) (*GroupPage, error) {
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
		Items      []Group `json:"items"`
		Data       []Group `json:"data"`
		NextCursor string  `json:"next_cursor"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/groups", q, nil, &env, true); err != nil {
		return nil, err
	}
	items := env.Items
	if items == nil {
		items = env.Data
	}
	return &GroupPage{Data: items, NextCursor: env.NextCursor}, nil
}

func (r *Groups) AddMember(ctx context.Context, groupID, userID string) error {
	body := map[string]string{"user_id": userID}
	return r.http.do(ctx, http.MethodPost, "/v1/groups/"+url.PathEscape(groupID)+"/members", nil, body, nil, false)
}

func (r *Groups) RemoveMember(ctx context.Context, groupID, userID string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/groups/"+url.PathEscape(groupID)+"/members/"+url.PathEscape(userID), nil, nil, nil, true)
}

func (r *Groups) ListMembers(ctx context.Context, groupID string) ([]GroupMember, error) {
	var env struct {
		Items []GroupMember `json:"items"`
		Data  []GroupMember `json:"data"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/groups/"+url.PathEscape(groupID)+"/members", nil, nil, &env, true); err != nil {
		return nil, err
	}
	if env.Items != nil {
		return env.Items, nil
	}
	return env.Data, nil
}
