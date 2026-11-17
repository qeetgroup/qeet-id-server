// Package oidcsso signs people in through an organisation's own OpenID Connect
// identity provider, such as Microsoft Entra ID, Okta or Google Workspace: an
// authorization-code sign-in with PKCE, state and nonce, bound to the browser
// that began it, whose ID token is checked against the provider's published
// keys. Accounts are linked and adopted by the rules SAML sign-in follows.
package oidcsso

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcsso/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/returnto"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const (
	provider      = "oidc"            // the external identities' provider, and the sessions' sign-in method
	secretPurpose = "oidc-connection" // envelope purpose of a connection's client secret
	planFeature   = "sso"             // the plan feature a connection needs
	maxScopes     = 20
	maxTenantIDs  = 50
	maxClaimLen   = 200
)

// defaultScopes are asked for when a connection names none.
var defaultScopes = []string{"openid", "email", "profile"}

// ClaimMapping names the ID token claims a sign-in reads; "" reads none, except
// for Email, which is required.
type ClaimMapping struct {
	Email      string `json:"email"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Groups     string `json:"groups"`
}

// Connection is an organisation's connection to its own OpenID Connect
// provider. The client secret is never returned. RedirectURI is where the
// provider must send the browser back, filled in by the handler.
type Connection struct {
	ID                  uuid.UUID    `json:"id"`
	TenantID            uuid.UUID    `json:"tenant_id"`
	Name                string       `json:"name"`
	Issuer              string       `json:"issuer"`
	DiscoveryURL        string       `json:"discovery_url"`
	ClientID            string       `json:"client_id"`
	Scopes              []string     `json:"scopes"`
	AllowedIdPTenantIDs []string     `json:"allowed_idp_tenant_ids"`
	ClaimMapping        ClaimMapping `json:"claim_mapping"`
	Status              string       `json:"status"`
	RedirectURI         string       `json:"redirect_uri,omitempty"`
	CreatedAt           time.Time    `json:"created_at"`
	UpdatedAt           time.Time    `json:"updated_at"`
	LastLoginAt         *time.Time   `json:"last_login_at"`
}

// discoveryURL is where the provider's discovery document is read.
func (c *Connection) discoveryURL() string {
	if c.DiscoveryURL != "" {
		return c.DiscoveryURL
	}
	return strings.TrimRight(c.Issuer, "/") + "/.well-known/openid-configuration"
}

// PlanGate reports whether a plan-gated boolean feature is included in the
// tenant's plan. Satisfied by *entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

// Service manages an organisation's OpenID Connect connections and signs
// people in through them. A nil gate leaves connection creation ungated.
type Service struct {
	pool       *pgxpool.Pool
	q          *dbgen.Queries
	auth       *auth.Service
	box        *envelope.Cipher
	gate       PlanGate
	egress     *egress.Policy
	providers  *providerClient
	appBaseURL string
	nextSweep  atomic.Int64 // when this replica next deletes expired states and codes
	// The hosted login's origin and the addresses a sign-in it starts may return to (SetHostedLogin).
	loginBaseURL string
	returnTo     returnto.Allowed
}

// SetHostedLogin lets a sign-in start on the hosted login: its answer goes back to
// loginBaseURL's sign-in page, and its return_to must be a path or on one of origins.
func (s *Service) SetHostedLogin(loginBaseURL string, origins ...string) {
	s.loginBaseURL = strings.TrimRight(loginBaseURL, "/")
	s.returnTo = returnto.Origins(origins...)
}

// NewService returns the service. Outbound requests to providers follow the
// first policy given, else the default public-only one.
func NewService(pool *pgxpool.Pool, authSvc *auth.Service, appBaseURL string, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	return &Service{
		pool:       pool,
		q:          dbgen.New(pool),
		auth:       authSvc,
		egress:     policy,
		providers:  newProviderClient(policy),
		appBaseURL: strings.TrimRight(appBaseURL, "/"),
	}
}

// SetCipher sets the cipher that seals client secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (s *Service) SetPlanGate(g PlanGate) { s.gate = g }

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// RequireSSO refuses with ErrUpgradeRequired when the tenant's plan doesn't
// include enterprise single sign-on. It reads on the pool, so a handler runs
// it before opening the transaction Create joins.
func (s *Service) RequireSSO(ctx context.Context, tenantID uuid.UUID) error {
	if s.gate == nil {
		return nil
	}
	ok, err := s.gate.FeatureAllowed(ctx, tenantID, planFeature)
	if err != nil {
		return err
	}
	if !ok {
		return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": planFeature})
	}
	return nil
}

// toConnection maps a generated row to a Connection. The other connection
// queries return rows with the same fields, which convert to GetOidcConnectionRow.
func toConnection(r dbgen.GetOidcConnectionRow) *Connection {
	var lastLogin *time.Time
	if r.LastLoginAt.Valid {
		v := r.LastLoginAt.Time
		lastLogin = &v
	}
	return &Connection{
		ID:                  r.ID,
		TenantID:            r.TenantID,
		Name:                r.Name,
		Issuer:              r.Issuer,
		DiscoveryURL:        r.DiscoveryUrl,
		ClientID:            r.ClientID,
		Scopes:              r.Scopes,
		AllowedIdPTenantIDs: r.AllowedIdpTenantIds,
		ClaimMapping: ClaimMapping{
			Email:      r.EmailClaim,
			Name:       r.NameClaim,
			GivenName:  r.GivenNameClaim,
			FamilyName: r.FamilyNameClaim,
			Groups:     r.GroupsClaim,
		},
		Status:      r.Status,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		LastLoginAt: lastLogin,
	}
}

// ClaimMappingInput changes a connection's claim mapping; a nil field keeps
// the current claim, or the default on create.
type ClaimMappingInput struct {
	Email      *string `json:"email"`
	Name       *string `json:"name"`
	GivenName  *string `json:"given_name"`
	FamilyName *string `json:"family_name"`
	Groups     *string `json:"groups"`
}

// check trims each claim given and requires it to be a claim name, and the
// email claim not to be empty.
func (in *ClaimMappingInput) check() error {
	if in == nil {
		return nil
	}
	for _, claim := range []*string{in.Email, in.Name, in.GivenName, in.FamilyName, in.Groups} {
		if claim == nil {
			continue
		}
		*claim = strings.TrimSpace(*claim)
		if !validClaimName(*claim) {
			return errs.ErrOIDCSSOClaimInvalid
		}
	}
	if in.Email != nil && *in.Email == "" {
		return errs.ErrOIDCSSOClaimInvalid
	}
	return nil
}

// validClaimName reports whether name is "" or a claim name: up to
// maxClaimLen printable characters with no space. Namespaced claims such as
// https://example.com/groups are allowed.
func validClaimName(name string) bool {
	if len(name) > maxClaimLen || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// CreateInput is what Create takes. Scopes defaults to openid, email and
// profile; openid is always asked for.
type CreateInput struct {
	Name                string             `json:"name"`
	Issuer              string             `json:"issuer"`
	DiscoveryURL        string             `json:"discovery_url"`
	ClientID            string             `json:"client_id"`
	ClientSecret        string             `json:"client_secret"`
	Scopes              []string           `json:"scopes"`
	AllowedIdPTenantIDs []string           `json:"allowed_idp_tenant_ids"`
	ClaimMapping        *ClaimMappingInput `json:"claim_mapping"`
	Status              string             `json:"status"`
}

// check trims and normalises the input, then refuses one with a field missing
// or invalid, whichever API sent it.
func (in *CreateInput) check(policy *egress.Policy) error {
	in.Name = strings.TrimSpace(in.Name)
	in.ClientID = strings.TrimSpace(in.ClientID)
	if in.Name == "" || strings.TrimSpace(in.Issuer) == "" || in.ClientID == "" || in.ClientSecret == "" {
		return errs.ErrOIDCSSOFieldsRequired
	}
	if in.Status != "" && !validStatus(in.Status) {
		return errs.ErrOIDCSSOStatusInvalid
	}
	var err error
	if in.Issuer, err = checkIssuer(policy, in.Issuer); err != nil {
		return err
	}
	if in.DiscoveryURL, err = checkDiscoveryURL(policy, in.DiscoveryURL); err != nil {
		return err
	}
	if in.Scopes, err = normaliseScopes(in.Scopes); err != nil {
		return err
	}
	if in.AllowedIdPTenantIDs, err = normaliseTenantIDs(in.AllowedIdPTenantIDs); err != nil {
		return err
	}
	if err := in.ClaimMapping.check(); err != nil {
		return err
	}
	return requireTenantIDs(in.Issuer, in.AllowedIdPTenantIDs)
}

// validStatus reports whether status is one a connection can have.
func validStatus(status string) bool {
	return status == "draft" || status == "active" || status == "disabled"
}

// checkIssuer returns raw trimmed when it is an issuer identifier: an allowed
// outbound URL (https, outside development) with no query or fragment.
func checkIssuer(policy *egress.Policy, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := policy.ValidateHTTPURL(raw)
	if err != nil || u.RawQuery != "" || strings.Contains(raw, "#") {
		return "", errs.ErrOIDCSSOIssuerInvalid
	}
	return raw, nil
}

// checkDiscoveryURL returns raw trimmed when it is "" (read discovery from the
// issuer) or an allowed outbound URL.
func checkDiscoveryURL(policy *egress.Policy, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if _, err := policy.ValidateHTTPURL(raw); err != nil {
		return "", errs.ErrOIDCSSODiscoveryURLInvalid
	}
	return raw, nil
}

// normaliseScopes returns scopes without repeats, with openid first, or the
// defaults for none. Each must be an RFC 6749 scope token.
func normaliseScopes(scopes []string) ([]string, error) {
	if scopes == nil {
		return slices.Clone(defaultScopes), nil
	}
	out := []string{"openid"}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !validScopeToken(scope) {
			return nil, errs.ErrOIDCSSOScopesInvalid
		}
		if !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}
	if len(out) > maxScopes {
		return nil, errs.ErrOIDCSSOScopesInvalid
	}
	return out, nil
}

// validScopeToken reports whether s is a non-empty run of the characters RFC
// 6749 §3.3 allows in a scope: printable ASCII except space, " and \.
func validScopeToken(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// normaliseTenantIDs returns the identity-provider tenant IDs lower-cased and
// without repeats, refusing any that isn't a GUID.
func normaliseTenantIDs(ids []string) ([]string, error) {
	out := []string{}
	for _, id := range ids {
		parsed, err := uuid.Parse(strings.TrimSpace(id))
		if err != nil {
			return nil, errs.ErrOIDCSSOTenantIDsInvalid
		}
		if s := parsed.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) > maxTenantIDs {
		return nil, errs.ErrOIDCSSOTenantIDsInvalid
	}
	return out, nil
}

// requireTenantIDs refuses a Microsoft issuer that signs in every
// organisation's accounts (common, organizations, consumers) unless the
// connection lists the tenants it accepts, or anyone with a Microsoft account
// could sign in.
func requireTenantIDs(issuer string, tenantIDs []string) error {
	if len(tenantIDs) > 0 {
		return nil
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return errs.ErrOIDCSSOIssuerInvalid
	}
	switch strings.ToLower(u.Hostname()) {
	case "login.microsoftonline.com", "login.microsoft.com", "login.windows.net":
	default:
		return nil
	}
	first, _, _ := strings.Cut(strings.Trim(u.Path, "/"), "/")
	switch strings.ToLower(first) {
	case "common", "organizations", "consumers":
		return errs.ErrOIDCSSOTenantIDsRequired
	}
	return nil
}

// Create stores a connection in tenantID within tx, sealing its client secret.
// Callers check the plan first, with RequireSSO.
func (s *Service) Create(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, in CreateInput) (*Connection, error) {
	if err := in.check(s.egress); err != nil {
		return nil, err
	}
	if s.box == nil {
		return nil, errs.ErrOIDCSSOSecretEncryptionMissing
	}
	id := uuid.New()
	ciphertext, nonce, err := s.box.Seal(tenantID, secretPurpose, id.String(), []byte(in.ClientSecret))
	if err != nil {
		return nil, err
	}
	mapping := ClaimMapping{Email: "email", Name: "name", GivenName: "given_name", FamilyName: "family_name"}
	if m := in.ClaimMapping; m != nil {
		for _, f := range []struct {
			dst *string
			src *string
		}{{&mapping.Email, m.Email}, {&mapping.Name, m.Name}, {&mapping.GivenName, m.GivenName}, {&mapping.FamilyName, m.FamilyName}, {&mapping.Groups, m.Groups}} {
			if f.src != nil {
				*f.dst = *f.src
			}
		}
	}
	status := in.Status
	if status == "" {
		status = "draft"
	}
	row, err := s.q.WithTx(tx).InsertOidcConnection(ctx, dbgen.InsertOidcConnectionParams{
		ID:                  id,
		TenantID:            tenantID,
		Name:                in.Name,
		Issuer:              in.Issuer,
		DiscoveryUrl:        in.DiscoveryURL,
		ClientID:            in.ClientID,
		ClientSecretCt:      ciphertext,
		ClientSecretNonce:   nonce,
		Scopes:              in.Scopes,
		AllowedIdpTenantIds: in.AllowedIdPTenantIDs,
		EmailClaim:          mapping.Email,
		NameClaim:           mapping.Name,
		GivenNameClaim:      mapping.GivenName,
		FamilyNameClaim:     mapping.FamilyName,
		GroupsClaim:         mapping.Groups,
		Status:              status,
	})
	if err != nil {
		return nil, err
	}
	return toConnection(dbgen.GetOidcConnectionRow(row)), nil
}

// List returns the tenant's connections.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Connection, error) {
	rows, err := s.q.ListOidcConnections(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, len(rows))
	for i, r := range rows {
		out[i] = *toConnection(dbgen.GetOidcConnectionRow(r))
	}
	return out, nil
}

// Get returns one of the tenant's connections.
func (s *Service) Get(ctx context.Context, id, tenantID uuid.UUID) (*Connection, error) {
	r, err := s.q.GetOidcConnection(ctx, dbgen.GetOidcConnectionParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toConnection(r), nil
}

// UpdateInput changes a connection; a nil field is kept, as is the client
// secret when ClientSecret is nil or "".
type UpdateInput struct {
	Name                *string            `json:"name"`
	Issuer              *string            `json:"issuer"`
	DiscoveryURL        *string            `json:"discovery_url"`
	ClientID            *string            `json:"client_id"`
	ClientSecret        *string            `json:"client_secret"`
	Scopes              []string           `json:"scopes"`
	AllowedIdPTenantIDs []string           `json:"allowed_idp_tenant_ids"`
	ClaimMapping        *ClaimMappingInput `json:"claim_mapping"`
	Status              *string            `json:"status"`
}

// ChangesTrust reports whether in changes what c trusts: its issuer, where its
// keys are found, the client its tokens are for, or which tenants of a
// multi-tenant identity provider it accepts.
func (in UpdateInput) ChangesTrust(c *Connection) bool {
	differs := func(p *string, current string) bool { return p != nil && strings.TrimSpace(*p) != current }
	if differs(in.Issuer, c.Issuer) || differs(in.DiscoveryURL, c.DiscoveryURL) || differs(in.ClientID, c.ClientID) {
		return true
	}
	return in.AllowedIdPTenantIDs != nil && !slices.Equal(in.AllowedIdPTenantIDs, c.AllowedIdPTenantIDs)
}

// check applies CreateInput's checks to the fields being changed.
func (in *UpdateInput) check(policy *egress.Policy) error {
	trimmed := func(p *string) bool {
		if p == nil {
			return true
		}
		*p = strings.TrimSpace(*p)
		return *p != ""
	}
	if !trimmed(in.Name) || !trimmed(in.ClientID) {
		return errs.ErrOIDCSSOFieldsRequired
	}
	if in.Status != nil && !validStatus(*in.Status) {
		return errs.ErrOIDCSSOStatusInvalid
	}
	if in.Issuer != nil {
		issuer, err := checkIssuer(policy, *in.Issuer)
		if err != nil {
			return err
		}
		in.Issuer = &issuer
	}
	if in.DiscoveryURL != nil {
		discovery, err := checkDiscoveryURL(policy, *in.DiscoveryURL)
		if err != nil {
			return err
		}
		in.DiscoveryURL = &discovery
	}
	var err error
	if in.Scopes != nil {
		if in.Scopes, err = normaliseScopes(in.Scopes); err != nil {
			return err
		}
	}
	if in.AllowedIdPTenantIDs != nil {
		if in.AllowedIdPTenantIDs, err = normaliseTenantIDs(in.AllowedIdPTenantIDs); err != nil {
			return err
		}
	}
	return in.ClaimMapping.check()
}

// changed names the fields an update changes, for its audit record.
func (in *UpdateInput) changed() []string {
	var fields []string
	add := func(set bool, name string) {
		if set {
			fields = append(fields, name)
		}
	}
	add(in.Name != nil, "name")
	add(in.Issuer != nil, "issuer")
	add(in.DiscoveryURL != nil, "discovery_url")
	add(in.ClientID != nil, "client_id")
	add(in.ClientSecret != nil && *in.ClientSecret != "", "client_secret")
	add(in.Scopes != nil, "scopes")
	add(in.AllowedIdPTenantIDs != nil, "allowed_idp_tenant_ids")
	add(in.ClaimMapping != nil, "claim_mapping")
	add(in.Status != nil, "status")
	return fields
}

// Update changes the given fields of a connection in tenantID within tx,
// refusing input that fails check, or a result that would let a multi-tenant
// issuer sign in any organisation's accounts.
func (s *Service) Update(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID, in UpdateInput) (*Connection, error) {
	if err := in.check(s.egress); err != nil {
		return nil, err
	}
	params := dbgen.UpdateOidcConnectionParams{
		ID:                  id,
		TenantID:            tenantID,
		Name:                in.Name,
		Issuer:              in.Issuer,
		DiscoveryUrl:        in.DiscoveryURL,
		ClientID:            in.ClientID,
		Scopes:              in.Scopes,
		AllowedIdpTenantIds: in.AllowedIdPTenantIDs,
		Status:              in.Status,
	}
	if m := in.ClaimMapping; m != nil {
		params.EmailClaim, params.NameClaim, params.GivenNameClaim = m.Email, m.Name, m.GivenName
		params.FamilyNameClaim, params.GroupsClaim = m.FamilyName, m.Groups
	}
	if in.ClientSecret != nil && *in.ClientSecret != "" {
		if s.box == nil {
			return nil, errs.ErrOIDCSSOSecretEncryptionMissing
		}
		ciphertext, nonce, err := s.box.Seal(tenantID, secretPurpose, id.String(), []byte(*in.ClientSecret))
		if err != nil {
			return nil, err
		}
		params.ClientSecretCt, params.ClientSecretNonce = ciphertext, nonce
	}
	r, err := s.q.WithTx(tx).UpdateOidcConnection(ctx, params)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := requireTenantIDs(r.Issuer, r.AllowedIdpTenantIds); err != nil {
		return nil, err
	}
	return toConnection(dbgen.GetOidcConnectionRow(r)), nil
}

// Delete removes one of the tenant's connections, and with it the sign-ins
// and login codes it has in flight.
func (s *Service) Delete(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) error {
	n, err := s.q.WithTx(tx).DeleteOidcConnection(ctx, dbgen.DeleteOidcConnectionParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// signInConnection is a connection being signed in through, with its client
// secret opened.
type signInConnection struct {
	Connection
	clientSecret string
}

// loadForSignIn loads a connection by ID alone, for the public sign-in
// endpoints, and refuses one that isn't active: a draft one is still being
// set up, so it signs nobody in until an administrator turns it on.
func (s *Service) loadForSignIn(ctx context.Context, id uuid.UUID) (*signInConnection, error) {
	r, err := s.q.GetOidcConnectionForSignIn(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c := &signInConnection{Connection: *toConnection(dbgen.GetOidcConnectionRow{
		ID: r.ID, TenantID: r.TenantID, Name: r.Name, Issuer: r.Issuer, DiscoveryUrl: r.DiscoveryUrl,
		ClientID: r.ClientID, Scopes: r.Scopes, AllowedIdpTenantIds: r.AllowedIdpTenantIds,
		EmailClaim: r.EmailClaim, NameClaim: r.NameClaim, GivenNameClaim: r.GivenNameClaim,
		FamilyNameClaim: r.FamilyNameClaim, GroupsClaim: r.GroupsClaim, Status: r.Status,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLoginAt: r.LastLoginAt,
	})}
	if err := signInStatus(c.Status); err != nil {
		return c, err
	}
	if s.box == nil {
		return c, errs.ErrOIDCSSOSecretEncryptionMissing
	}
	plain, err := s.box.Open(c.TenantID, secretPurpose, c.ID.String(), r.ClientSecretCt, r.ClientSecretNonce)
	if err != nil {
		return c, errs.ErrOIDCSSOMisconfigured.Wrap(err)
	}
	c.clientSecret = string(plain)
	return c, nil
}

// signInStatus refuses a sign-in through a connection that isn't active.
func signInStatus(status string) error {
	switch status {
	case "active":
		return nil
	case "draft":
		return errs.ErrOIDCSSOConnectionDraft
	}
	return errs.ErrOIDCSSOConnectionDisabled
}

// touchLastLogin stamps the connection's last sign-in. Best effort.
func (s *Service) touchLastLogin(ctx context.Context, c *signInConnection) {
	_ = s.q.TouchOidcConnectionLastLogin(ctx, dbgen.TouchOidcConnectionLastLoginParams{ID: c.ID, TenantID: c.TenantID})
}

// pgUUID is id as a nullable UUID column value.
func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }
