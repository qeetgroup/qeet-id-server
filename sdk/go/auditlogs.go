package qeetid

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type AuditLog struct {
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id"`
	ActorID      string         `json:"actor_id,omitempty"`
	ActorType    string         `json:"actor_type,omitempty"`
	Event        string         `json:"event"`
	ResourceType string         `json:"resource_type,omitempty"`
	ResourceID   string         `json:"resource_id,omitempty"`
	IPAddress    string         `json:"ip_address,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	Hash         string         `json:"hash,omitempty"`
	CreatedAt    string         `json:"created_at"`
}

type AuditLogListParams struct {
	Event   string
	ActorID string
	From    string
	To      string
	Limit   int
	Cursor  string
}

type AuditLogPage struct {
	Data       []AuditLog
	NextCursor string
}

type AuditLogs struct{ http *httpClient }

func (r *AuditLogs) List(ctx context.Context, tenantID string, params AuditLogListParams) (*AuditLogPage, error) {
	q := url.Values{}
	if params.Event != "" {
		q.Set("event", params.Event)
	}
	if params.ActorID != "" {
		q.Set("actor_id", params.ActorID)
	}
	if params.From != "" {
		q.Set("from", params.From)
	}
	if params.To != "" {
		q.Set("to", params.To)
	}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.Cursor != "" {
		q.Set("cursor", params.Cursor)
	}
	var env struct {
		Items      []AuditLog `json:"items"`
		Data       []AuditLog `json:"data"`
		NextCursor string     `json:"next_cursor"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/audit", q, nil, &env, true); err != nil {
		return nil, err
	}
	items := env.Items
	if items == nil {
		items = env.Data
	}
	return &AuditLogPage{Data: items, NextCursor: env.NextCursor}, nil
}

func (r *AuditLogs) Verify(ctx context.Context, tenantID, entryID string) (bool, error) {
	var res struct {
		Valid bool `json:"valid"`
	}
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/audit/"+url.PathEscape(entryID)+"/verify", nil, struct{}{}, &res, false)
	return res.Valid, err
}
