// Package qeetid is the server-side Go SDK for Qeet ID: manage users and
// tenants, run authorization checks, and verify sessions/JWTs.
//
// Authenticate with a secret API key (`qk_…`); never embed it in client code.
// The package has no third-party dependencies — only the standard library.
//
//	qeetid := qeetidsdk.New(qeetidsdk.Options{APIKey: os.Getenv("QEETID_API_KEY")})
//	claims, err := qeetid.Sessions.Verify(ctx, token)
//	ok, err := qeetid.Can(ctx, qeetidsdk.PermissionCheck{
//		User: claims.UserID, Tenant: claims.TenantID, Permission: "billing:write",
//	})
//
// (Import as `qeetidsdk` so the client value can be named `qeetid` without
// shadowing the package.)
package qeetid

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the Qeet ID API client. Construct once with New and reuse it; it is
// safe for concurrent use.
type Client struct {
	Users       *Users
	Tenants     *Tenants
	Sessions    *Sessions
	Groups      *Groups
	Invitations *Invitations
	Branding    *Branding
	Domains     *Domains
	Roles       *Roles
	Permissions *Permissions
	Mfa         *MfaAdmin
	AuthPolicy  *AuthPolicy
	IPRules     *IPRules
	APIKeys     *APIKeys
	Webhooks    *Webhooks
	AuthHooks   *AuthHooks
	SAML           *SAML
	OIDCClients    *OIDCClients
	AuditLogs      *AuditLogs
	EmailTemplates *EmailTemplates
	Agents     *Agents
	Vault      *Vault
	OAuth      *OAuth
	Credentials *Credentials

	http *httpClient
}

// New builds a client. APIKey is required.
func New(opts Options) *Client {
	base := opts.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	base = strings.TrimRight(base, "/")

	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	maxRetries := opts.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 2
	}

	h := &httpClient{apiKey: opts.APIKey, baseURL: base, hc: hc, maxRetries: maxRetries}
	return &Client{
		http:        h,
		Users:       &Users{http: h},
		Tenants:     &Tenants{http: h},
		Sessions:    newSessions(base, hc),
		Groups:      &Groups{http: h},
		Invitations: &Invitations{http: h},
		Branding:    &Branding{http: h},
		Domains:     &Domains{http: h},
		Roles:       &Roles{http: h},
		Permissions: &Permissions{http: h},
		Mfa:         &MfaAdmin{http: h},
		AuthPolicy:  &AuthPolicy{http: h},
		IPRules:     &IPRules{http: h},
		APIKeys:     &APIKeys{http: h},
		Webhooks:    &Webhooks{http: h},
		AuthHooks:   &AuthHooks{http: h},
		SAML:           &SAML{http: h},
		OIDCClients:    &OIDCClients{http: h},
		AuditLogs:      &AuditLogs{http: h},
		EmailTemplates: &EmailTemplates{http: h},
		Agents:      &Agents{http: h},
		Vault:       &Vault{http: h},
		OAuth:       newOAuth(base, hc),
		Credentials: &Credentials{http: h},
	}
}

// PermissionCheck is a single RBAC authorization query (maps to GET /v1/check).
type PermissionCheck struct {
	User       string
	Tenant     string
	Permission string
}

// Can resolves a single permission check.
func (c *Client) Can(ctx context.Context, check PermissionCheck) (bool, error) {
	q := url.Values{}
	q.Set("user_id", check.User)
	q.Set("tenant_id", check.Tenant)
	q.Set("permission", check.Permission)
	var res struct {
		Allowed bool `json:"allowed"`
	}
	if err := c.http.do(ctx, http.MethodGet, "/v1/check", q, nil, &res, true); err != nil {
		return false, err
	}
	return res.Allowed, nil
}

// CanAll returns true only if every permission passes.
func (c *Client) CanAll(ctx context.Context, user, tenant string, permissions []string) (bool, error) {
	for _, p := range permissions {
		ok, err := c.Can(ctx, PermissionCheck{User: user, Tenant: tenant, Permission: p})
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}
