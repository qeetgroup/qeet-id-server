package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type IPRule struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	CIDR        string `json:"cidr"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type CreateIPRuleInput struct {
	CIDR        string `json:"cidr"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
}

type IPRules struct{ http *httpClient }

func (r *IPRules) Create(ctx context.Context, tenantID string, in CreateIPRuleInput) (*IPRule, error) {
	var out IPRule
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/ip-rules", nil, in, &out, false)
	return &out, err
}

func (r *IPRules) Delete(ctx context.Context, tenantID, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/tenants/"+url.PathEscape(tenantID)+"/ip-rules/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *IPRules) List(ctx context.Context, tenantID string) ([]IPRule, error) {
	var env struct {
		Items []IPRule `json:"items"`
		Data  []IPRule `json:"data"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/ip-rules", nil, nil, &env, true); err != nil {
		return nil, err
	}
	if env.Items != nil {
		return env.Items, nil
	}
	return env.Data, nil
}
