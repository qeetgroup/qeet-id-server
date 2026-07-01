package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type MfaFactor struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type MfaAdmin struct{ http *httpClient }

func (r *MfaAdmin) List(ctx context.Context, userID string) ([]MfaFactor, error) {
	var env struct {
		Items []MfaFactor `json:"items"`
		Data  []MfaFactor `json:"data"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/users/"+url.PathEscape(userID)+"/mfa", nil, nil, &env, true); err != nil {
		return nil, err
	}
	if env.Items != nil {
		return env.Items, nil
	}
	return env.Data, nil
}

func (r *MfaAdmin) Reset(ctx context.Context, userID string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/users/"+url.PathEscape(userID)+"/mfa", nil, nil, nil, true)
}

func (r *MfaAdmin) Require(ctx context.Context, userID, tenantID string) error {
	body := map[string]string{"tenant_id": tenantID}
	return r.http.do(ctx, http.MethodPost, "/v1/users/"+url.PathEscape(userID)+"/mfa/require", nil, body, nil, false)
}
