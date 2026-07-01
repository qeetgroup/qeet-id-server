package qeetid

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type Invitation struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	Email       string         `json:"email"`
	Role        string         `json:"role,omitempty"`
	Status      string         `json:"status"`
	InvitedBy   string         `json:"invited_by,omitempty"`
	ExpiresAt   string         `json:"expires_at,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at,omitempty"`
}

type CreateInvitationInput struct {
	Email         string         `json:"email"`
	TenantID      string         `json:"tenant_id"`
	Role          string         `json:"role,omitempty"`
	ExpiresInDays int            `json:"expires_in_days,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type InvitationPage struct {
	Data       []Invitation
	NextCursor string
}

type Invitations struct{ http *httpClient }

func (r *Invitations) Create(ctx context.Context, in CreateInvitationInput) (*Invitation, error) {
	var out Invitation
	err := r.http.do(ctx, http.MethodPost, "/v1/invites", nil, in, &out, false)
	return &out, err
}

func (r *Invitations) Get(ctx context.Context, id string) (*Invitation, error) {
	var out Invitation
	err := r.http.do(ctx, http.MethodGet, "/v1/invites/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (r *Invitations) Delete(ctx context.Context, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/invites/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *Invitations) Resend(ctx context.Context, id string) error {
	return r.http.do(ctx, http.MethodPost, "/v1/invites/"+url.PathEscape(id)+"/resend", nil, struct{}{}, nil, false)
}

func (r *Invitations) List(ctx context.Context, params ListParams) (*InvitationPage, error) {
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
		Items      []Invitation `json:"items"`
		Data       []Invitation `json:"data"`
		NextCursor string       `json:"next_cursor"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/invites", q, nil, &env, true); err != nil {
		return nil, err
	}
	items := env.Items
	if items == nil {
		items = env.Data
	}
	return &InvitationPage{Data: items, NextCursor: env.NextCursor}, nil
}
