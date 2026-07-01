package qeetid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TokenExchangeInput struct {
	ClientID      string
	ClientSecret  string
	SubjectToken  string
	Scope         string // optional downscoped permissions
	ActorToken    string // optional — for RFC 8693 delegation
	ActorTokenType string
}

type TokenExchangeResult struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope,omitempty"`
	IssuedTokenType  string `json:"issued_token_type,omitempty"`
}

type IntrospectResult struct {
	Active    bool     `json:"active"`
	Sub       string   `json:"sub,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	TenantID  string   `json:"tenant_id,omitempty"`
	ActorType string   `json:"actor_type,omitempty"`
	AgentID   string   `json:"agent_id,omitempty"`
}

// OAuth provides RFC 8693 token exchange, RFC 7662 token introspection, and
// an MCP token guard. Unlike other resources it uses form-encoded requests
// with OIDC client credentials rather than the shared API-key transport.
type OAuth struct {
	baseURL string
	hc      *http.Client
}

func newOAuth(baseURL string, hc *http.Client) *OAuth {
	return &OAuth{baseURL: baseURL, hc: hc}
}

// TokenExchange implements RFC 8693 downscoping and delegation.
func (o *OAuth) TokenExchange(ctx context.Context, in TokenExchangeInput) (*TokenExchangeResult, error) {
	params := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {in.SubjectToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
	if in.Scope != "" {
		params.Set("scope", in.Scope)
	}
	if in.ActorToken != "" {
		params.Set("actor_token", in.ActorToken)
		typ := in.ActorTokenType
		if typ == "" {
			typ = "urn:ietf:params:oauth:token-type:access_token"
		}
		params.Set("actor_token_type", typ)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/v1/oauth/token", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("qeetid oauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(in.ClientID, in.ClientSecret)

	res, err := o.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qeetid oauth: token exchange: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var out TokenExchangeResult
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("qeetid oauth: decode response: %w", err)
	}
	if res.StatusCode >= 300 {
		return nil, parseError(res.StatusCode, body, res.Header.Get("X-Request-Id"), 0)
	}
	return &out, nil
}

// Introspect implements RFC 7662 token introspection.
func (o *OAuth) Introspect(ctx context.Context, token string) (*IntrospectResult, error) {
	params := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/v1/oauth/introspect", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("qeetid oauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := o.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qeetid oauth: introspect: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return nil, parseError(res.StatusCode, body, res.Header.Get("X-Request-Id"), 0)
	}
	var out IntrospectResult
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("qeetid oauth: decode response: %w", err)
	}
	return &out, nil
}

// Verify is an MCP token guard: introspects the token and returns an error if
// it is inactive or does not carry requiredScope (empty string skips scope check).
func (o *OAuth) Verify(ctx context.Context, token, requiredScope string) (*IntrospectResult, error) {
	result, err := o.Introspect(ctx, token)
	if err != nil {
		return nil, err
	}
	if !result.Active {
		return nil, &Error{Status: 401, Code: "token_inactive", Message: "token is not active"}
	}
	if requiredScope != "" {
		scopes := strings.Fields(result.Scope)
		found := false
		for _, s := range scopes {
			if s == requiredScope {
				found = true
				break
			}
		}
		if !found {
			return nil, &Error{Status: 403, Code: "insufficient_scope", Message: "required scope: " + requiredScope}
		}
	}
	return result, nil
}
