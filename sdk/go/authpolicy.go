package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type AuthPolicySettings struct {
	TenantID                string   `json:"tenant_id"`
	PasswordMinLength       int      `json:"password_min_length,omitempty"`
	PasswordRequireUppercase bool    `json:"password_require_uppercase,omitempty"`
	PasswordRequireNumbers  bool     `json:"password_require_numbers,omitempty"`
	PasswordRequireSymbols  bool     `json:"password_require_symbols,omitempty"`
	AllowedLoginMethods     []string `json:"allowed_login_methods,omitempty"`
	MfaRequired             bool     `json:"mfa_required,omitempty"`
	SessionDurationSeconds  int      `json:"session_duration_seconds,omitempty"`
	UpdatedAt               string   `json:"updated_at,omitempty"`
}

type UpdateAuthPolicyInput struct {
	PasswordMinLength        *int     `json:"password_min_length,omitempty"`
	PasswordRequireUppercase *bool    `json:"password_require_uppercase,omitempty"`
	PasswordRequireNumbers   *bool    `json:"password_require_numbers,omitempty"`
	PasswordRequireSymbols   *bool    `json:"password_require_symbols,omitempty"`
	AllowedLoginMethods      []string `json:"allowed_login_methods,omitempty"`
	MfaRequired              *bool    `json:"mfa_required,omitempty"`
	SessionDurationSeconds   *int     `json:"session_duration_seconds,omitempty"`
}

type AuthPolicy struct{ http *httpClient }

func (r *AuthPolicy) Get(ctx context.Context, tenantID string) (*AuthPolicySettings, error) {
	var out AuthPolicySettings
	err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/auth-policy", nil, nil, &out, true)
	return &out, err
}

func (r *AuthPolicy) Update(ctx context.Context, tenantID string, in UpdateAuthPolicyInput) (*AuthPolicySettings, error) {
	var out AuthPolicySettings
	err := r.http.do(ctx, http.MethodPut, "/v1/tenants/"+url.PathEscape(tenantID)+"/auth-policy", nil, in, &out, false)
	return &out, err
}
