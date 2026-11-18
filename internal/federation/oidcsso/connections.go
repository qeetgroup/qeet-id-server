package oidcsso

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcsso/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

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
			return ErrClaimInvalid
		}
	}
	if in.Email != nil && *in.Email == "" {
		return ErrClaimInvalid
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
		return ErrFieldsRequired
	}
	if in.Status != "" && !validStatus(in.Status) {
		return ErrStatusInvalid
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
		return "", ErrIssuerInvalid
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
		return "", ErrDiscoveryURLInvalid
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
			return nil, ErrScopesInvalid
		}
		if !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}
	if len(out) > maxScopes {
		return nil, ErrScopesInvalid
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
			return nil, ErrTenantIDsInvalid
		}
		if s := parsed.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) > maxTenantIDs {
		return nil, ErrTenantIDsInvalid
	}
	return out, nil
}

// requireTenantIDs refuses a Microsoft issuer that signs in every
// organization's accounts (common, organizations, consumers) unless the
// connection lists the tenants it accepts, or anyone with a Microsoft account
// could sign in.
func requireTenantIDs(issuer string, organizationIDs []string) error {
	if len(organizationIDs) > 0 {
		return nil
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return ErrIssuerInvalid
	}
	switch strings.ToLower(u.Hostname()) {
	case "login.microsoftonline.com", "login.microsoft.com", "login.windows.net":
	default:
		return nil
	}
	first, _, _ := strings.Cut(strings.Trim(u.Path, "/"), "/")
	switch strings.ToLower(first) {
	case "common", "organizations", "consumers":
		return ErrTenantIDsRequired
	}
	return nil
}

// Create stores a connection in organizationID, sealing its client secret, and
// records it as actor's. Callers check the plan first, with RequireSSO.
func (s *Service) Create(ctx context.Context, organizationID uuid.UUID, in CreateInput, actor audit.Actor) (*Connection, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	conn, err := s.insert(ctx, tx, organizationID, in)
	if err != nil {
		return nil, err
	}
	meta := map[string]any{"name": conn.Name, "issuer": conn.Issuer, "status": conn.Status}
	if err := recordChange(ctx, tx, actor, organizationID, conn.ID, "oidc_connection.created", meta); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

// recordChange audits, in tx, actor's change to organizationID's connection id.
func recordChange(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, id uuid.UUID, action string, meta map[string]any) error {
	return audit.Record(ctx, tx, actor.Event(organizationID, action, "oidc_connection", id, meta))
}

// insert stores a connection in organizationID within tx, sealing its client
// secret.
func (s *Service) insert(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, in CreateInput) (*Connection, error) {
	if err := in.check(s.egress); err != nil {
		return nil, err
	}
	id := uuid.New()
	ciphertext, nonce, err := s.box.Seal(organizationID, secretPurpose, id.String(), []byte(in.ClientSecret))
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
		OrganizationID:      organizationID,
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

// List returns the organization's connections.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Connection, error) {
	rows, err := s.q.ListOidcConnections(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, len(rows))
	for i, r := range rows {
		out[i] = *toConnection(dbgen.GetOidcConnectionRow(r))
	}
	return out, nil
}

// Get returns one of the organization's connections.
func (s *Service) Get(ctx context.Context, id, organizationID uuid.UUID) (*Connection, error) {
	r, err := s.q.GetOidcConnection(ctx, dbgen.GetOidcConnectionParams{ID: id, OrganizationID: organizationID})
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
// keys are found, the client its tokens are for, or which organizations of a
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
		return ErrFieldsRequired
	}
	if in.Status != nil && !validStatus(*in.Status) {
		return ErrStatusInvalid
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

// Update changes the given fields of a connection in organizationID, recorded as
// actor's, refusing input that fails check, or a result that would let a
// multi-tenant issuer sign in any organization's accounts.
func (s *Service) Update(ctx context.Context, id, organizationID uuid.UUID, in UpdateInput, actor audit.Actor) (*Connection, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	conn, err := s.update(ctx, tx, id, organizationID, in)
	if err != nil {
		return nil, err
	}
	meta := map[string]any{"fields": in.changed(), "status": conn.Status}
	if err := recordChange(ctx, tx, actor, organizationID, conn.ID, "oidc_connection.updated", meta); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

// update changes the given fields of a connection in organizationID within tx.
func (s *Service) update(ctx context.Context, tx pgx.Tx, id, organizationID uuid.UUID, in UpdateInput) (*Connection, error) {
	if err := in.check(s.egress); err != nil {
		return nil, err
	}
	params := dbgen.UpdateOidcConnectionParams{
		ID:                  id,
		OrganizationID:      organizationID,
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
		ciphertext, nonce, err := s.box.Seal(organizationID, secretPurpose, id.String(), []byte(*in.ClientSecret))
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

// Delete removes one of the organization's connections, and with it the sign-ins
// and login codes it has in flight, recorded as actor's.
func (s *Service) Delete(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteOidcConnection(ctx, dbgen.DeleteOidcConnectionParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := recordChange(ctx, tx, actor, organizationID, id, "oidc_connection.deleted", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
