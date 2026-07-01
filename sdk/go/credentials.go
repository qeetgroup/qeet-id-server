package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type Credential struct {
	ID        string `json:"id"`
	Subject   string `json:"subject"`
	Type      string `json:"type"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Revoked   bool   `json:"revoked"`
}

type IssueCredentialInput struct {
	Subject    string         `json:"subject"`
	Type       string         `json:"type"`
	Claims     map[string]any `json:"claims,omitempty"`
	TTLSeconds int            `json:"ttl_seconds,omitempty"`
}

type IssueCredentialResult struct {
	CredentialID string `json:"credential_id"`
	JWT          string `json:"jwt"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

type VerifyCredentialResult struct {
	Valid   bool           `json:"valid"`
	Reason  string         `json:"reason,omitempty"`
	Subject string         `json:"subject,omitempty"`
	Issuer  string         `json:"issuer,omitempty"`
	VC      map[string]any `json:"vc,omitempty"`
}

type Credentials struct{ http *httpClient }

func (r *Credentials) Issue(ctx context.Context, tenantID string, in IssueCredentialInput) (*IssueCredentialResult, error) {
	var out IssueCredentialResult
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/credentials", nil, in, &out, false)
	return &out, err
}

func (r *Credentials) List(ctx context.Context, tenantID string) ([]Credential, error) {
	var env struct {
		Items []Credential `json:"items"`
		Data  []Credential `json:"data"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/credentials", nil, nil, &env, true); err != nil {
		return nil, err
	}
	if env.Items != nil {
		return env.Items, nil
	}
	return env.Data, nil
}

func (r *Credentials) Revoke(ctx context.Context, tenantID, id string) error {
	return r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/credentials/"+url.PathEscape(id)+"/revoke", nil, struct{}{}, nil, false)
}

// Verify is the public endpoint — no API key required. Relying parties call
// this to confirm a presented JWT-VC is authentic and not revoked.
func (r *Credentials) Verify(ctx context.Context, jwt string) (*VerifyCredentialResult, error) {
	var out VerifyCredentialResult
	body := map[string]string{"credential": jwt}
	err := r.http.do(ctx, http.MethodPost, "/v1/credentials/verify", nil, body, &out, false)
	return &out, err
}
