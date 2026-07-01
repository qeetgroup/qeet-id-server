package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type AuthHookSettings struct {
	TenantID      string `json:"tenant_id"`
	PreLoginURL   string `json:"pre_login_url,omitempty"`
	PostLoginURL  string `json:"post_login_url,omitempty"`
	PreSignupURL  string `json:"pre_signup_url,omitempty"`
	Enabled       bool   `json:"enabled"`
	TimeoutMs     int    `json:"timeout_ms,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

type UpdateAuthHookInput struct {
	PreLoginURL  *string `json:"pre_login_url,omitempty"`
	PostLoginURL *string `json:"post_login_url,omitempty"`
	PreSignupURL *string `json:"pre_signup_url,omitempty"`
	Enabled      *bool   `json:"enabled,omitempty"`
	TimeoutMs    *int    `json:"timeout_ms,omitempty"`
}

type AuthHooks struct{ http *httpClient }

func (r *AuthHooks) Get(ctx context.Context, tenantID string) (*AuthHookSettings, error) {
	var out AuthHookSettings
	err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/auth-hooks", nil, nil, &out, true)
	return &out, err
}

func (r *AuthHooks) Update(ctx context.Context, tenantID string, in UpdateAuthHookInput) (*AuthHookSettings, error) {
	var out AuthHookSettings
	err := r.http.do(ctx, http.MethodPut, "/v1/tenants/"+url.PathEscape(tenantID)+"/auth-hooks", nil, in, &out, false)
	return &out, err
}
