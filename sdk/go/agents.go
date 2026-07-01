package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type Agent struct {
	ID              string   `json:"id"`
	TenantID        string   `json:"tenant_id"`
	Name            string   `json:"name"`
	Scopes          []string `json:"scopes"`
	TokenTTLSeconds int      `json:"token_ttl_seconds"`
	Disabled        bool     `json:"disabled"`
	CreatedAt       string   `json:"created_at"`
	Secret          string   `json:"secret,omitempty"` // only on create
}

type CreateAgentInput struct {
	Name            string   `json:"name"`
	Scopes          []string `json:"scopes,omitempty"`
	TokenTTLSeconds int      `json:"token_ttl_seconds,omitempty"`
}

type AgentTokenResult struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type Agents struct{ http *httpClient }

func (r *Agents) Create(ctx context.Context, tenantID string, in CreateAgentInput) (*Agent, error) {
	var out Agent
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/agents", nil, in, &out, false)
	return &out, err
}

func (r *Agents) Delete(ctx context.Context, tenantID, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/tenants/"+url.PathEscape(tenantID)+"/agents/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *Agents) List(ctx context.Context, tenantID string) ([]Agent, error) {
	var env struct {
		Items []Agent `json:"items"`
		Data  []Agent `json:"data"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/agents", nil, nil, &env, true); err != nil {
		return nil, err
	}
	if env.Items != nil {
		return env.Items, nil
	}
	return env.Data, nil
}

// Token mints a short-lived access token for an AI agent.
func (r *Agents) Token(ctx context.Context, tenantID, agentID, secret, scope string) (*AgentTokenResult, error) {
	body := map[string]string{
		"tenant_id": tenantID,
		"agent_id":  agentID,
		"secret":    secret,
	}
	if scope != "" {
		body["scope"] = scope
	}
	var out AgentTokenResult
	err := r.http.do(ctx, http.MethodPost, "/v1/agents/token", nil, body, &out, false)
	return &out, err
}
