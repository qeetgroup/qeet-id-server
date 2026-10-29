// Package saml implements SAML 2.0 single sign-on in both directions. As a
// service provider it signs people in through a tenant's IdP connection, using
// gosaml2 and goxmldsig to validate assertions; as an identity provider
// (idp.go) it issues signed assertions to the tenant's registered SPs.
package saml

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	saml2 "github.com/russellhaering/gosaml2"
	samltypes "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const (
	provider        = "saml"
	loginCodeTTL    = 5 * time.Minute
	authnRequestTTL = 10 * time.Minute
	replayIDTTL     = 24 * time.Hour
)

// Connection is a tenant's connection to an external SAML IdP.
// AllowIdPInitiated and GroupsAttribute aren't in the generated connection
// queries, so they are read separately. GroupsAttribute names the attribute
// carrying a person's groups; "" reads the common ones (assertedGroups).
// Certificates are every signing certificate it trusts; IdpCertificate is the
// oldest of them. MetadataURL is where it refreshes its IdP settings from.
type Connection struct {
	ID                uuid.UUID     `json:"id"`
	TenantID          uuid.UUID     `json:"tenant_id"`
	Name              string        `json:"name"`
	IdpEntityID       string        `json:"idp_entity_id"`
	IdpSSOURL         string        `json:"idp_sso_url"`
	IdpCertificate    string        `json:"idp_certificate"`
	Certificates      []Certificate `json:"certificates"`
	MetadataURL       *string       `json:"metadata_url"`
	RefreshedAt       *time.Time    `json:"metadata_refreshed_at"`
	MetadataError     *string       `json:"metadata_error"`
	EmailAttribute    string        `json:"email_attribute"`
	NameAttribute     string        `json:"name_attribute"`
	GroupsAttribute   string        `json:"groups_attribute"`
	Status            string        `json:"status"`
	AllowIdPInitiated bool          `json:"allow_idp_initiated"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
	LastLoginAt       *time.Time    `json:"last_login_at"`
}

// Service manages a tenant's IdP connections and runs SP-initiated sign-in.
// nextRequestSweep and nextReplaySweep throttle deleting expired AuthnRequest and
// replay rows, separately so a busy login or ACS path can't starve the other.
// IdP metadata is fetched with metadataHTTP, within the egress policy; box
// seals the connections' SP keys.
type Service struct {
	pool             *pgxpool.Pool
	q                *dbgen.Queries
	auth             *auth.Service
	appBaseURL       string
	gate             PlanGate
	nextRequestSweep atomic.Int64
	nextReplaySweep  atomic.Int64
	egress           *egress.Policy
	metadataHTTP     *http.Client
	box              *envelope.Cipher
}

// replaySweepInterval is how often any one replica collects expired SAML
// correlation and replay rows.
const replaySweepInterval = 5 * time.Minute

// sweepDue reports whether this replica should collect now, and claims the
// slot if so. Replicas sweeping independently is harmless: the deletes are
// idempotent and touch only rows that are already past their expiry.
func sweepDue(next *atomic.Int64) bool {
	now := time.Now().Unix()
	due := next.Load()
	return now >= due && next.CompareAndSwap(due, now+int64(replaySweepInterval.Seconds()))
}

// NewService returns the SAML service.
func NewService(pool *pgxpool.Pool, authSvc *auth.Service, appBaseURL string) *Service {
	s := &Service{
		pool:       pool,
		q:          dbgen.New(pool),
		auth:       authSvc,
		appBaseURL: strings.TrimRight(appBaseURL, "/"),
	}
	s.SetEgressPolicy(egress.PublicPolicy())
	return s
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (s *Service) SetPlanGate(g PlanGate) { s.gate = g }

// RequireSSO refuses with errs.ErrUpgradeRequired when the tenant's plan
// doesn't include enterprise SSO: setting up a connection and every sign-in
// through one need it. It reads on the pool, so callers run it before they
// open the transaction Create joins.
func (s *Service) RequireSSO(ctx context.Context, tenantID uuid.UUID) error {
	return requireSSO(ctx, s.gate, tenantID)
}

// toConnection maps a sqlc-generated row to the API-facing Connection type.
// The other connection queries return rows with the same fields, which
// convert to dbgen.GetSamlConnectionRow.
func toConnection(r dbgen.GetSamlConnectionRow) *Connection {
	var lastLogin *time.Time
	if r.LastLoginAt.Valid {
		v := r.LastLoginAt.Time
		lastLogin = &v
	}
	return &Connection{
		ID:             r.ID,
		TenantID:       r.TenantID,
		Name:           r.Name,
		IdpEntityID:    r.IdpEntityID,
		IdpSSOURL:      r.IdpSsoUrl,
		IdpCertificate: r.IdpCertificate,
		Certificates:   []Certificate{},
		EmailAttribute: r.EmailAttribute,
		NameAttribute:  r.NameAttribute,
		Status:         r.Status,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
		LastLoginAt:    lastLogin,
	}
}

// CreateInput is what Create takes.
type CreateInput struct {
	Name            string `json:"name"`
	IdpEntityID     string `json:"idp_entity_id"`
	IdpSSOURL       string `json:"idp_sso_url"`
	IdpCertificate  string `json:"idp_certificate"`
	EmailAttribute  string `json:"email_attribute"`
	NameAttribute   string `json:"name_attribute"`
	GroupsAttribute string `json:"groups_attribute"`
	Status          string `json:"status"`
}

// errGroupsAttributeInvalid refuses a groups attribute over 256 characters.
var errGroupsAttributeInvalid = errs.ErrValidationFailed.WithFields([]errs.FieldError{{
	Field: "groups_attribute", Code: "too_long", Message: "Name the groups attribute in up to 256 characters.",
}})

// validGroupsAttribute trims attribute and reports whether it fits.
func validGroupsAttribute(attribute *string) bool {
	*attribute = strings.TrimSpace(*attribute)
	return utf8.RuneCountInString(*attribute) <= 256
}

// check trims the IdP SSO URL, then requires it to pass validIdPSSOURL, the
// certificate to parse, the status, if given, to be a known one and the groups
// attribute to fit.
func (in *CreateInput) check() error {
	if in.Status != "" && !validStatus(in.Status) {
		return errs.ErrSAMLStatusInvalid
	}
	if !validGroupsAttribute(&in.GroupsAttribute) {
		return errGroupsAttributeInvalid
	}
	in.IdpSSOURL = strings.TrimSpace(in.IdpSSOURL)
	if !validIdPSSOURL(in.IdpSSOURL) {
		return errs.ErrSAMLSSOURLInvalid
	}
	if _, err := parseCertificate(in.IdpCertificate); err != nil {
		return errs.ErrSAMLCertificateInvalid
	}
	return nil
}

// validStatus reports whether status is one a connection or service provider
// can have.
func validStatus(status string) bool {
	return status == "draft" || status == "active" || status == "disabled"
}

// Create stores a connection in tenantID within tx, refusing input that fails
// check whichever API sent it.
func (s *Service) Create(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, in CreateInput) (*Connection, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	status := in.Status
	if status == "" {
		status = "draft"
	}
	q := s.q.WithTx(tx)
	row, err := q.InsertSamlConnection(ctx, dbgen.InsertSamlConnectionParams{
		TenantID:       tenantID,
		Name:           in.Name,
		IdpEntityID:    in.IdpEntityID,
		IdpSsoUrl:      in.IdpSSOURL,
		IdpCertificate: in.IdpCertificate,
		EmailAttribute: in.EmailAttribute,
		NameAttribute:  in.NameAttribute,
		Status:         status,
	})
	if err != nil {
		return nil, err
	}
	cert, err := parseCertificate(in.IdpCertificate)
	if err != nil {
		return nil, errs.ErrSAMLCertificateInvalid
	}
	if err := replaceCertificates(ctx, q, row.ID, tenantID, cert); err != nil {
		return nil, err
	}
	out := toConnection(dbgen.GetSamlConnectionRow(row))
	if out.Certificates, err = listCertificates(ctx, q, row.ID, tenantID); err != nil {
		return nil, err
	}
	if in.GroupsAttribute != "" {
		if err := q.SetSamlGroupsAttribute(ctx, dbgen.SetSamlGroupsAttributeParams{
			ID: out.ID, TenantID: tenantID, GroupsAttribute: in.GroupsAttribute,
		}); err != nil {
			return nil, err
		}
		out.GroupsAttribute = in.GroupsAttribute
	}
	return out, nil
}

// List returns the tenant's SAML connections.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Connection, error) {
	rows, err := s.q.ListSamlConnections(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, len(rows))
	for i, r := range rows {
		out[i] = *toConnection(dbgen.GetSamlConnectionRow(r))
	}
	flags, err := s.idpInitiatedFlags(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	attributes, err := s.q.ListSamlGroupsAttributes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	groups := make(map[uuid.UUID]string, len(attributes))
	for _, a := range attributes {
		groups[a.ID] = a.GroupsAttribute
	}
	certs, err := s.q.ListSamlCertificatesForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	byConnection := map[uuid.UUID][]Certificate{}
	for _, c := range certs {
		byConnection[c.ConnectionID] = append(byConnection[c.ConnectionID], toCertificate(c))
	}
	for i := range out {
		out[i].AllowIdPInitiated = flags[out[i].ID]
		out[i].GroupsAttribute = groups[out[i].ID]
		if c := byConnection[out[i].ID]; c != nil {
			out[i].Certificates = c
		}
	}
	if err := s.withMetadataSources(ctx, tenantID, out); err != nil {
		return nil, err
	}
	return out, nil
}

// idpInitiatedFlags loads the whole tenant's opt-in state in one round trip so
// List doesn't issue a query per connection.
func (s *Service) idpInitiatedFlags(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID]bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, allow_idp_initiated FROM tenant.saml_connections WHERE tenant_id = $1
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	flags := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		var allowed bool
		if err := rows.Scan(&id, &allowed); err != nil {
			return nil, err
		}
		flags[id] = allowed
	}
	return flags, rows.Err()
}

// Get returns one of the tenant's SAML connections.
func (s *Service) Get(ctx context.Context, id, tenantID uuid.UUID) (*Connection, error) {
	r, err := s.q.GetSamlConnection(ctx, dbgen.GetSamlConnectionParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := toConnection(r)
	out.AllowIdPInitiated, err = s.AllowsIdPInitiated(ctx, id)
	if err != nil {
		return nil, err
	}
	out.GroupsAttribute, err = s.groupsAttribute(ctx, out)
	if err != nil {
		return nil, err
	}
	if out.Certificates, err = listCertificates(ctx, s.q, id, tenantID); err != nil {
		return nil, err
	}
	if err := withMetadataSource(ctx, s.q, out); err != nil {
		return nil, err
	}
	return out, nil
}

// groupsAttribute returns the attribute conn reads a person's groups from.
func (s *Service) groupsAttribute(ctx context.Context, conn *Connection) (string, error) {
	return s.q.GetSamlGroupsAttribute(ctx, dbgen.GetSamlGroupsAttributeParams{ID: conn.ID, TenantID: conn.TenantID})
}

// getByID loads a connection without tenant scoping, for the public SSO
// endpoints, where the unguessable connection ID in the path is the key.
func (s *Service) getByID(ctx context.Context, id uuid.UUID) (*Connection, error) {
	r, err := s.q.GetSamlConnectionByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toConnection(dbgen.GetSamlConnectionRow(r)), nil
}

// UpdateInput changes a connection; a nil field is kept. AllowIdPInitiated opts
// into unsolicited assertions (see AllowsIdPInitiated). IdpCertificate becomes
// the only certificate the connection trusts.
type UpdateInput struct {
	Name              *string `json:"name"`
	IdpEntityID       *string `json:"idp_entity_id"`
	IdpSSOURL         *string `json:"idp_sso_url"`
	IdpCertificate    *string `json:"idp_certificate"`
	EmailAttribute    *string `json:"email_attribute"`
	NameAttribute     *string `json:"name_attribute"`
	GroupsAttribute   *string `json:"groups_attribute"`
	Status            *string `json:"status"`
	AllowIdPInitiated *bool   `json:"allow_idp_initiated"`
}

// check applies CreateInput's checks to the fields being changed.
func (in *UpdateInput) check() error {
	if in.IdpSSOURL != nil {
		sso := strings.TrimSpace(*in.IdpSSOURL)
		if !validIdPSSOURL(sso) {
			return errs.ErrSAMLSSOURLInvalid
		}
		in.IdpSSOURL = &sso
	}
	if in.IdpCertificate != nil {
		if _, err := parseCertificate(*in.IdpCertificate); err != nil {
			return errs.ErrSAMLCertificateInvalid
		}
	}
	if in.GroupsAttribute != nil && !validGroupsAttribute(in.GroupsAttribute) {
		return errGroupsAttributeInvalid
	}
	return nil
}

// Update changes the given fields of a connection in tenantID within tx,
// refusing input that fails check whichever API sent it.
func (s *Service) Update(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID, in UpdateInput) (*Connection, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	q := s.q.WithTx(tx)
	r, err := q.UpdateSamlConnection(ctx, dbgen.UpdateSamlConnectionParams{
		ID:             id,
		TenantID:       tenantID,
		Name:           in.Name,
		IdpEntityID:    in.IdpEntityID,
		IdpSsoUrl:      in.IdpSSOURL,
		IdpCertificate: in.IdpCertificate,
		EmailAttribute: in.EmailAttribute,
		NameAttribute:  in.NameAttribute,
		Status:         in.Status,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if in.IdpCertificate != nil {
		cert, err := parseCertificate(*in.IdpCertificate)
		if err != nil {
			return nil, errs.ErrSAMLCertificateInvalid
		}
		if err := replaceCertificates(ctx, q, id, tenantID, cert); err != nil {
			return nil, err
		}
	}
	// The generated update doesn't include allow_idp_initiated.
	if in.AllowIdPInitiated != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE tenant.saml_connections
			SET allow_idp_initiated = $3, updated_at = NOW()
			WHERE id = $1 AND tenant_id = $2
		`, id, tenantID, *in.AllowIdPInitiated); err != nil {
			return nil, err
		}
	}
	if in.GroupsAttribute != nil {
		if err := s.q.WithTx(tx).SetSamlGroupsAttribute(ctx, dbgen.SetSamlGroupsAttributeParams{
			ID: id, TenantID: tenantID, GroupsAttribute: *in.GroupsAttribute,
		}); err != nil {
			return nil, err
		}
	}
	out := toConnection(dbgen.GetSamlConnectionRow(r))
	if out.GroupsAttribute, err = s.q.WithTx(tx).GetSamlGroupsAttribute(ctx, dbgen.GetSamlGroupsAttributeParams{
		ID: id, TenantID: tenantID,
	}); err != nil {
		return nil, err
	}
	if in.AllowIdPInitiated != nil {
		out.AllowIdPInitiated = *in.AllowIdPInitiated
	} else if err := tx.QueryRow(ctx, `
		SELECT allow_idp_initiated FROM tenant.saml_connections WHERE id = $1 AND tenant_id = $2
	`, id, tenantID).Scan(&out.AllowIdPInitiated); err != nil {
		return nil, err
	}
	if out.Certificates, err = listCertificates(ctx, q, id, tenantID); err != nil {
		return nil, err
	}
	if err := withMetadataSource(ctx, q, out); err != nil {
		return nil, err
	}
	return out, nil
}

// AllowsIdPInitiated reports whether the connection accepts an assertion with no
// InResponseTo, sent by the IdP unasked. The opt-in relaxes only request
// correlation: every other check still runs, and replayed IDs are still refused.
func (s *Service) AllowsIdPInitiated(ctx context.Context, connectionID uuid.UUID) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `
		SELECT allow_idp_initiated FROM tenant.saml_connections WHERE id = $1
	`, connectionID).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, errs.ErrNotFound
	}
	return allowed, err
}

// Delete removes one of the tenant's SAML connections.
func (s *Service) Delete(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) error {
	n, err := s.q.WithTx(tx).DeleteSamlConnection(ctx, dbgen.DeleteSamlConnectionParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// --- SAML SP construction ---

// TestCheck is one preflight check in a connection test.
type TestCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// TestResult is the outcome of a SAML connection preflight: OK only when every
// check passed.
type TestResult struct {
	OK     bool        `json:"ok"`
	Checks []TestCheck `json:"checks"`
}

// TestConnection runs an offline preflight over a SAML connection's config so an
// admin can catch the common misconfigurations (missing entity ID, a non-https
// SSO URL, an unparseable or expired signing certificate, no email mapping)
// before turning the connection on for real logins. It performs no network I/O.
func (s *Service) TestConnection(ctx context.Context, id, tenantID uuid.UUID) (*TestResult, error) {
	c, err := s.Get(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}
	res := &TestResult{OK: true}
	add := func(name string, ok bool, detail string) {
		res.Checks = append(res.Checks, TestCheck{Name: name, OK: ok, Detail: detail})
		if !ok {
			res.OK = false
		}
	}

	add("IdP entity ID", strings.TrimSpace(c.IdpEntityID) != "", "The IdP's entity ID (issuer) must be set.")
	add("IdP SSO URL", validIdPSSOURL(strings.TrimSpace(c.IdpSSOURL)), "Must be an absolute https:// URL.")

	parsed := len(c.Certificates) > 0
	for _, cert := range c.Certificates {
		parsed = parsed && cert.NotAfter != nil
	}
	add("Signing certificate", parsed, "Each must be a valid PEM block or base64-encoded DER certificate.")
	if parsed {
		// Valid while any certificate is; report the furthest expiry.
		now := time.Now()
		var valid bool
		var until, latest time.Time
		for _, cert := range c.Certificates {
			if now.After(*cert.NotBefore) && now.Before(*cert.NotAfter) {
				valid = true
				until = later(until, *cert.NotAfter)
			}
			latest = later(latest, *cert.NotAfter)
		}
		detail := "Valid until " + until.Format("2006-01-02") + "."
		if !valid {
			detail = "Certificate is expired or not yet valid (expires " + latest.Format("2006-01-02") + ")."
		}
		add("Certificate validity period", valid, detail)
	}

	add("Email attribute mapping", strings.TrimSpace(c.EmailAttribute) != "", "Needed to resolve each user's email from the SAML assertion.")

	return res, nil
}

// later returns whichever of a and b is later.
func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// parseCertificate accepts a PEM block or bare base64 DER and returns the cert.
func parseCertificate(raw string) (*x509.Certificate, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("invalid PEM certificate")
		}
		return x509.ParseCertificate(block.Bytes)
	}
	// Bare base64 DER (as found in IdP metadata <X509Certificate>): strip
	// any whitespace the copy-paste introduced.
	clean := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(raw)
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("certificate is neither PEM nor base64 DER: %w", err)
	}
	return x509.ParseCertificate(der)
}

// validIdPSSOURL reports whether raw is an absolute https URL with a host and
// no userinfo, as the IdP SSO endpoint a browser is sent to must be.
func validIdPSSOURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil
}

// publicBase returns the origin SAML entity IDs and endpoint URLs are built on.
func (h *Handler) publicBase(r *http.Request) string {
	return httpx.PublicOrigin(r, h.PublicBaseURL)
}

func spEntityID(base string, id uuid.UUID) string { return base + "/saml/metadata/" + id.String() }
func acsURL(base string, id uuid.UUID) string     { return base + "/saml/acs/" + id.String() }

// SPAddresses are what an IdP is told about a connection's service provider:
// its entity ID, where it receives assertions, and where its metadata is.
type SPAddresses struct {
	EntityID    string `json:"sp_entity_id"`
	ACSURL      string `json:"acs_url"`
	MetadataURL string `json:"sp_metadata_url"`
}

// Addresses returns connection id's service provider addresses on base, the
// API's public origin. The entity ID is the metadata's own URL.
func Addresses(base string, id uuid.UUID) SPAddresses {
	return SPAddresses{EntityID: spEntityID(base, id), ACSURL: acsURL(base, id), MetadataURL: spEntityID(base, id)}
}

// buildSP returns the gosaml2 service provider for conn, with its entity ID,
// audience and ACS URL built on base, trusting signatures by certs.
func (s *Service) buildSP(base string, conn *Connection, certs []*x509.Certificate) *saml2.SAMLServiceProvider {
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      conn.IdpSSOURL,
		IdentityProviderIssuer:      conn.IdpEntityID,
		ServiceProviderIssuer:       spEntityID(base, conn.ID),
		AssertionConsumerServiceURL: acsURL(base, conn.ID),
		AudienceURI:                 spEntityID(base, conn.ID),
		SignAuthnRequests:           false,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: certs},
	}
}

// assertionClockSkew is how far the IdP's clock may be from ours: an assertion
// is accepted this long before its NotBefore and after its NotOnOrAfter.
const assertionClockSkew = 3 * time.Minute

// validateResponse checks the encoded SAMLResponse against each of the IdP's
// certificates valid at now in turn, so one signed with any of them is
// accepted, and returns the response and its assertion. Each attempt trusts a
// single certificate, so a signature without KeyInfo is checked against each.
//
// gosaml2 checks the expiry times on a clock assertionClockSkew behind now, and
// withinValidity the whole window either way; the signature, issuer, audience,
// recipient and destination checks are unchanged. key, when not nil, decrypts
// an EncryptedAssertion, which must still be signed. A signed assertion whose
// conditions fail comes back with ErrSAMLAssertionConditions, for a test
// sign-in to report what it asserted.
func (s *Service) validateResponse(base string, conn *Connection, certs []*x509.Certificate, key *tls.Certificate, encoded string, now time.Time) (*samltypes.Response, *saml2.AssertionInfo, error) {
	var failures []error
	for _, cert := range certs {
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			failures = append(failures, fmt.Errorf("certificate %s is outside its validity period", fingerprint(cert)))
			continue
		}
		sp := s.buildSP(base, conn, []*x509.Certificate{cert})
		sp.Clock = dsig.NewFakeClockAt(now.Add(-assertionClockSkew))
		if key != nil {
			sp.SPKeyStore = dsig.TLSCertKeyStore(*key)
		}
		response, err := sp.ValidateEncodedResponse(encoded)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		info, err := sp.RetrieveAssertionInfo(encoded)
		if err != nil {
			slog.Warn("saml acs: assertion validation failed", "err", err, "connection", conn.ID)
			return nil, nil, errs.ErrSAMLAssertionInvalid.Wrap(err)
		}
		current := withinValidity(info.Assertions, now)
		elsewhere := info.WarningInfo != nil && info.WarningInfo.NotInAudience
		if !current || elsewhere {
			slog.Warn("saml acs: assertion conditions not met", "connection", conn.ID,
				"invalid_time", !current, "not_in_audience", elsewhere)
			why := "the assertion is outside its validity period"
			if elsewhere {
				why = "the assertion's audience isn't this connection's SP entity ID"
			}
			return response, info, errs.ErrSAMLAssertionConditions.Wrap(errors.New(why))
		}
		return response, info, nil
	}
	slog.Warn("saml acs: response validation failed", "err", errors.Join(failures...), "connection", conn.ID)
	return nil, nil, errs.ErrSAMLAssertionInvalid.Wrap(errors.Join(failures...))
}

// withinValidity reports whether every assertion's Conditions hold at now,
// allowing assertionClockSkew either way.
func withinValidity(assertions []samltypes.Assertion, now time.Time) bool {
	if len(assertions) == 0 {
		return false
	}
	for _, a := range assertions {
		if a.Conditions == nil {
			return false
		}
		notBefore, err := time.Parse(time.RFC3339, a.Conditions.NotBefore)
		if err != nil {
			return false
		}
		notOnOrAfter, err := time.Parse(time.RFC3339, a.Conditions.NotOnOrAfter)
		if err != nil {
			return false
		}
		if now.Add(assertionClockSkew).Before(notBefore) || !now.Add(-assertionClockSkew).Before(notOnOrAfter) {
			return false
		}
	}
	return true
}

func (s *Service) storeAuthnRequest(ctx context.Context, connectionID uuid.UUID, requestID string) error {
	if strings.TrimSpace(requestID) == "" || len(requestID) > 1024 {
		return errs.ErrSAMLRequestInvalid
	}
	if sweepDue(&s.nextRequestSweep) {
		if _, err := s.pool.Exec(ctx, `DELETE FROM auth.saml_authn_requests WHERE expires_at <= NOW()`); err != nil {
			return err
		}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth.saml_authn_requests (request_id, connection_id, expires_at)
		VALUES ($1, $2, $3)
	`, requestID, connectionID, time.Now().UTC().Add(authnRequestTTL))
	return err
}

// ConsumeValidatedResponse atomically reserves the response and assertion IDs
// against replay and consumes the matching AuthnRequest. Call it only after the
// signature and conditions are validated. An empty requestID (IdP-initiated) is
// refused with ErrSAMLRequestCorrelation unless allowIdPInitiated.
func (s *Service) ConsumeValidatedResponse(ctx context.Context, connectionID uuid.UUID, requestID, responseID string, assertionIDs []string, allowIdPInitiated bool) error {
	idpInitiated := strings.TrimSpace(requestID) == ""
	if idpInitiated && !allowIdPInitiated {
		return errs.ErrSAMLRequestCorrelation
	}
	if !idpInitiated && len(requestID) > 1024 {
		return errs.ErrSAMLRequestCorrelation
	}
	if strings.TrimSpace(responseID) == "" || len(responseID) > 1024 || len(assertionIDs) == 0 || len(assertionIDs) > 16 {
		return errs.ErrSAMLAssertionInvalid
	}
	ids := make([]struct{ kind, id string }, 0, len(assertionIDs)+1)
	ids = append(ids, struct{ kind, id string }{"response", responseID})
	for _, assertionID := range assertionIDs {
		if strings.TrimSpace(assertionID) == "" || len(assertionID) > 1024 {
			return errs.ErrSAMLAssertionInvalid
		}
		ids = append(ids, struct{ kind, id string }{"assertion", assertionID})
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if sweepDue(&s.nextReplaySweep) {
		if _, err := tx.Exec(ctx, `DELETE FROM auth.saml_replay_ids WHERE expires_at <= NOW()`); err != nil {
			return err
		}
	}
	for _, candidate := range ids {
		tag, err := tx.Exec(ctx, `
			INSERT INTO auth.saml_replay_ids (connection_id, kind, saml_id, expires_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING
		`, connectionID, candidate.kind, candidate.id, time.Now().UTC().Add(replayIDTTL))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errs.ErrSAMLReplayDetected
		}
	}
	// Correlation is consumed only for SP-initiated responses. An opted-in
	// IdP-initiated response has no AuthnRequest to match by definition, so
	// running this would find no row and reject every one of them. The replay
	// reservations above still ran, which is what actually stops a resend.
	if !idpInitiated {
		tag, err := tx.Exec(ctx, `
			DELETE FROM auth.saml_authn_requests
			WHERE request_id = $1 AND connection_id = $2 AND expires_at > NOW()
		`, requestID, connectionID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errs.ErrSAMLRequestCorrelation
		}
	}
	return tx.Commit(ctx)
}

// signInStatus refuses a sign-in through a connection that isn't active: a
// draft one is still being set up, so it signs nobody in until an
// administrator turns it on.
func signInStatus(status string) error {
	switch status {
	case "active":
		return nil
	case "draft":
		return errs.ErrSAMLConnectionDraft
	}
	return errs.ErrSAMLConnectionDisabled
}

// assertion is what a validated SAML assertion says about the person it signs
// in: groupsWithheld means the IdP left their groups out (assertedGroups).
type assertion struct {
	subject, email, name string
	groups               []string
	groupsWithheld       bool
}

// findOrCreateUser returns the user the connection linked to the NameID
// subject, else the user with the asserted email, else a new user, and links
// the subject to the connection. An address is adopted or given an account
// only on a domain the organisation manages, a new account only where that
// domain has just-in-time provisioning on, and an adopted account must have
// tenantID as its home, a verified address, and not administer the
// organisation. The account's profile and groups are then brought in step
// with the assertion (ssosync.Apply), recorded as actor's. One transaction,
// so concurrent logins can't duplicate rows.
func (s *Service) findOrCreateUser(ctx context.Context, tenantID, connID uuid.UUID, a assertion, actor audit.Actor) (uuid.UUID, error) {
	subject, email, name := a.subject, a.email, a.name
	// Read before the transaction: it reads every organisation's domains.
	domain, managed, err := domainverify.ManagingDomain(postgres.AcrossTenants(ctx), s.pool, email)
	if err != nil {
		return uuid.Nil, err
	}
	manager := domain.TenantID
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	sync := func(userID uuid.UUID) error {
		return ssosync.Apply(ctx, tx, ssosync.SignIn{
			TenantID: tenantID, UserID: userID, ConnectionID: connID, Provider: provider,
			DisplayName: name, Email: email, EmailManaged: managed && manager == tenantID,
			Groups: a.groups, GroupsWithheld: a.groupsWithheld, Actor: actor,
		})
	}

	userID, err := q.GetExternalIdentityUser(ctx, dbgen.GetExternalIdentityUserParams{
		TenantID:     tenantID,
		Provider:     provider,
		ConnectionID: connID,
		Subject:      subject,
	})
	if err == nil {
		// A linked subject signs in only while this organisation is still the
		// account's home.
		home, herr := identitylink.HomeIn(ctx, tx, userID, tenantID)
		if herr != nil {
			return uuid.Nil, herr
		}
		if !home {
			return uuid.Nil, errs.ErrSAMLUserTenantMismatch
		}
		if err := sync(userID); err != nil {
			return uuid.Nil, err
		}
		return userID, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	// The assertion proves only that this connection's IdP vouched for the
	// address. Anyone who can configure a connection runs one, so it speaks
	// only for the organisation's own domains.
	if !managed || manager != tenantID {
		return uuid.Nil, errs.ErrSAMLEmailDomainUnverified
	}

	userID, err = q.GetUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		if !domain.JIT {
			return uuid.Nil, errs.ErrSAMLJITNotAllowed
		}
		var displayName *string
		if name != "" {
			displayName = &name
		}
		userID, err = q.InsertUserWithEmail(ctx, dbgen.InsertUserWithEmailParams{
			TenantID:    pgtype.UUID{Bytes: tenantID, Valid: true},
			Email:       email,
			DisplayName: displayName,
		})
		if err != nil {
			return uuid.Nil, err
		}
	} else if err != nil {
		return uuid.Nil, err
	} else {
		// Emails are globally unique, so the address may be another tenant's
		// user's; and an administrator keeps the credentials they have, or the
		// connection's IdP could take over an owner.
		home, herr := identitylink.HomeIn(ctx, tx, userID, tenantID)
		if herr != nil {
			return uuid.Nil, herr
		}
		if !home {
			return uuid.Nil, errs.ErrSAMLUserTenantMismatch
		}
		verified, verr := identitylink.AddressVerified(ctx, tx, userID)
		if verr != nil {
			return uuid.Nil, verr
		}
		if !verified {
			return uuid.Nil, errs.ErrSAMLAccountUnverified
		}
		if err := identitylink.MarkAddressVerified(ctx, tx, userID); err != nil {
			return uuid.Nil, err
		}
		admin, aerr := identitylink.Administers(ctx, tx, userID, tenantID)
		if aerr != nil {
			return uuid.Nil, aerr
		}
		if admin {
			return uuid.Nil, errs.ErrSAMLAccountAdministers
		}
	}

	if err := q.LinkExternalIdentity(ctx, dbgen.LinkExternalIdentityParams{
		UserID:       userID,
		TenantID:     tenantID,
		Provider:     provider,
		ConnectionID: connID,
		Subject:      subject,
		Email:        &email,
	}); err != nil {
		return uuid.Nil, err
	}
	if err := sync(userID); err != nil {
		return uuid.Nil, err
	}
	return userID, tx.Commit(ctx)
}

// ExchangeLogin trades a one-time SAML login code for a Qeet token pair.
func (s *Service) ExchangeLogin(ctx context.Context, rawCode, ip, ua string) (*auth.TokenPair, error) {
	if rawCode == "" {
		return nil, errs.ErrSAMLLoginCodeRequired
	}
	codeHash := codes.Hash(rawCode)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)

	row, err := q.ConsumeSamlLoginCode(ctx, codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrSAMLLoginCodeInvalid
	}
	if err != nil {
		return nil, err
	}
	if row.UsedAt.Valid {
		return nil, errs.ErrSAMLLoginCodeUsed
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, errs.ErrSAMLLoginCodeExpired
	}
	if err := q.MarkSamlLoginCodeUsed(ctx, codeHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, row.UserID, row.TenantID, ip, ua, provider)
}

// insertLoginCode persists a one-time code issued at the ACS endpoint.
func (s *Service) insertLoginCode(ctx context.Context, codeHash string, userID, tenantID uuid.UUID, expiresAt time.Time) error {
	return s.q.InsertSamlLoginCode(ctx, dbgen.InsertSamlLoginCodeParams{
		CodeHash:  codeHash,
		UserID:    userID,
		TenantID:  tenantID,
		ExpiresAt: expiresAt,
	})
}

// touchLastLogin stamps last_login_at on the SP connection after a successful
// ACS assertion. Fire-and-forget.
func (s *Service) touchLastLogin(ctx context.Context, connID uuid.UUID) {
	_ = s.q.TouchSamlLastLogin(ctx, connID)
}

// Handler serves both SAML sides. IdP is optional: when nil, the /saml/idp/*
// endpoints fail with ErrSAMLIdPNotConfigured and the SP-registry admin routes
// aren't mounted. PublicBaseURL is this API's public origin, or "" to build SAML
// URLs from the request's Host.
type Handler struct {
	Service       *Service
	IdP           *IdP
	PublicBaseURL string
	CookieSecure  bool // the browser-binding cookie's Secure attribute; off only in development
}

// binding ties an SP-initiated sign-in to the browser that began it, so the
// ACS completes it only there, or whoever began one could post its answer
// from someone else's browser and sign them in as themselves. SameSite=None,
// as the IdP posts its answer cross-site; Lax where the cookie can't be Secure
// (development).
func (h *Handler) binding() httpx.BindingCookie {
	sameSite := http.SameSiteNoneMode
	if !h.CookieSecure {
		sameSite = http.SameSiteLaxMode
	}
	return httpx.BindingCookie{Name: "qe_saml", Secure: h.CookieSecure, SameSite: sameSite, MaxAge: authnRequestTTL}
}

// Mount registers the SAML routes on r.
func (h *Handler) Mount(r chi.Router) {
	// SP side: external-IdP connections Qeet consumes.
	r.Get("/tenants/{tenantID}/saml", h.list)
	r.Post("/tenants/{tenantID}/saml", h.create)
	r.Get("/tenants/{tenantID}/saml/{id}", h.get)
	r.Patch("/tenants/{tenantID}/saml/{id}", h.update)
	r.Post("/tenants/{tenantID}/saml/{id}/test", h.test)
	r.Delete("/tenants/{tenantID}/saml/{id}", h.del)
	r.Post("/tenants/{tenantID}/saml/import", h.importConnection)
	r.Post("/tenants/{tenantID}/saml/{id}/metadata", h.applyMetadata)
	r.Post("/tenants/{tenantID}/saml/{id}/certificates", h.addCertificate)
	r.Delete("/tenants/{tenantID}/saml/{id}/certificates/{certificateID}", h.removeCertificate)

	// IdP side: downstream Service Providers that consume Qeet as their IdP.
	if h.IdP != nil {
		r.Get("/tenants/{tenantID}/saml-providers", h.listSP)
		r.Post("/tenants/{tenantID}/saml-providers", h.createSP)
		r.Get("/tenants/{tenantID}/saml-providers/{id}", h.getSP)
		r.Patch("/tenants/{tenantID}/saml-providers/{id}", h.updateSP)
		r.Delete("/tenants/{tenantID}/saml-providers/{id}", h.delSP)
		r.Get("/tenants/{tenantID}/saml-providers/{id}/assignments", h.listSPAssignments)
		r.Post("/tenants/{tenantID}/saml-providers/{id}/assignments/users/{userID}", h.assignSPUser)
		r.Delete("/tenants/{tenantID}/saml-providers/{id}/assignments/users/{userID}", h.unassignSPUser)
		r.Post("/tenants/{tenantID}/saml-providers/{id}/assignments/groups/{groupID}", h.assignSPGroup)
		r.Delete("/tenants/{tenantID}/saml-providers/{id}/assignments/groups/{groupID}", h.unassignSPGroup)
	}
}

// MountPublic registers the browser/IdP-facing SSO ceremony (no user JWT).
func (h *Handler) MountPublic(r chi.Router) {
	// SP side (Qeet as SP): metadata, login redirect, ACS, code exchange.
	r.Get("/saml/metadata/{id}", h.metadata)
	r.Get("/saml/login/{id}", h.login)
	r.Post("/saml/acs/{id}", h.acs) // CSRF-exempt (see router.go); validated by signature
	r.Post("/saml/exchange", h.exchange)

	// IdP side (Qeet as IdP), per organisation: metadata + SingleSignOnService
	// (redirect + POST).
	r.Get("/saml/idp/{tenantID}/metadata", h.idpMetadata)
	r.Get("/saml/idp/{tenantID}/certificate", h.idpCertificate)
	r.Get("/saml/idp/{tenantID}/sso", h.idpSSO)
	r.Post("/saml/idp/{tenantID}/sso", h.idpSSO) // CSRF-exempt (see router.go); SP-initiated cross-origin POST
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	return httpx.PathTenantOr(r, errs.ErrSAMLTenantIDInvalid, errs.ErrSAMLTenantMismatch)
}

func (h *Handler) recordAudit(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID, resourceID uuid.UUID, action string, meta map[string]any) error {
	actorID, actorType := audit.ActorOf(r).Identity()
	tid := tenantID
	rid := resourceID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: "saml_connection",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
	})
}

// --- admin CRUD handlers ---

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.IdpEntityID = strings.TrimSpace(in.IdpEntityID)
	in.IdpSSOURL = strings.TrimSpace(in.IdpSSOURL)
	if in.Name == "" || in.IdpEntityID == "" || in.IdpSSOURL == "" || strings.TrimSpace(in.IdpCertificate) == "" {
		httpx.WriteError(w, r, errs.ErrSAMLConnectionFieldsRequired)
		return
	}
	if err := in.check(); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	if err := h.Service.RequireSSO(ctx, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	conn, err := h.Service.Create(ctx, tx, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, tenantID, conn.ID, "saml.connection_created", map[string]any{"name": conn.Name, "idp": conn.IdpEntityID}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, conn)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrSAMLIDInvalid)
		return
	}
	conn, err := h.Service.Get(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conn)
}

// test runs a config preflight over a SAML connection and returns per-check
// results so the admin can fix issues before enabling it.
func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrSAMLIDInvalid)
		return
	}
	res, err := h.Service.TestConnection(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrSAMLIDInvalid)
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Status != nil && *in.Status != "draft" && *in.Status != "active" && *in.Status != "disabled" {
		httpx.WriteError(w, r, errs.ErrSAMLStatusInvalid)
		return
	}
	if err := in.check(); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	conn, err := h.Service.Update(ctx, tx, id, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, tenantID, conn.ID, "saml.connection_updated", map[string]any{"status": conn.Status}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conn)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrSAMLIDInvalid)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.Delete(ctx, tx, id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, tenantID, id, "saml.connection_deleted", nil); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- public SSO ceremony ---
//
// These endpoints are browser- and IdP-facing. Success returns SAML XML or a
// redirect; errors use the standard JSON error envelope (httpx.WriteError).

func (h *Handler) metadata(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrSAMLIDInvalid)
		return
	}
	conn, err := h.Service.getByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	encryption, err := h.Service.encryptionCertificate(r.Context(), conn)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	keyDescriptor := ""
	if encryption != "" {
		keyDescriptor = fmt.Sprintf(spEncryptionKeyDescriptor, encryption)
	}
	base := h.publicBase(r)
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">%s
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="1" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>`, spEntityID(base, id), keyDescriptor, acsURL(base, id))
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Disposition", `attachment; filename="sp-metadata.xml"`)
	_, _ = w.Write([]byte(xml)) // #nosec G705 -- XML download, not rendered as HTML
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrSAMLIDInvalid)
		return
	}
	conn, err := h.Service.getByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := signInStatus(conn.Status); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RequireSSO(r.Context(), conn.TenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !validIdPSSOURL(conn.IdpSSOURL) {
		slog.Error("saml login: IdP SSO URL is not an absolute https URL", "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrSAMLConnectionMisconfigured)
		return
	}
	certs, err := h.Service.signingCertificates(r.Context(), conn)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if len(certs) == 0 {
		slog.Error("saml login: no readable IdP certificate", "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrSAMLConnectionMisconfigured)
		return
	}
	sp := h.Service.buildSP(h.publicBase(r), conn, certs)
	doc, err := sp.BuildAuthRequestDocument()
	if err != nil {
		slog.Error("saml login: build auth request", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	if doc.Root() == nil {
		slog.Error("saml login: generated auth request has no root", "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	requestID := doc.Root().SelectAttrValue("ID", "")
	authURL, err := sp.BuildAuthURLFromDocument(r.URL.Query().Get("relay"), doc)
	if err != nil {
		slog.Error("saml login: build auth url", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	if err := h.Service.storeAuthnRequest(r.Context(), conn.ID, requestID); err != nil {
		slog.Error("saml login: persist request", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	h.binding().Add(w, r, requestID)
	http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710 -- IdP SSO URL checked by validIdPSSOURL on save and above
}

func (h *Handler) acs(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrSAMLIDInvalid)
		return
	}
	conn, err := h.Service.getByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// The answer to a test sign-in is reported, and signs nobody in.
	if h.answerTestSignIn(w, r, conn) {
		return
	}
	if err := signInStatus(conn.Status); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// The plan is checked when the assertion arrives too, so a connection set
	// up on a plan that has since lapsed signs no one in.
	if err := h.Service.RequireSSO(r.Context(), conn.TenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := httpx.ParseForm(r, httpx.MaxSAMLBodyBytes); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	encoded := r.PostFormValue("SAMLResponse")
	if encoded == "" {
		httpx.WriteError(w, r, errs.ErrSAMLResponseMissing)
		return
	}
	certs, err := h.Service.signingCertificates(r.Context(), conn)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if len(certs) == 0 {
		slog.Error("saml acs: no readable IdP certificate", "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrSAMLConnectionMisconfigured)
		return
	}
	key, err := h.Service.decryptionKey(r.Context(), conn)
	if err != nil {
		// An unencrypted assertion doesn't need the key; an encrypted one fails.
		slog.Error("saml acs: SP encryption key unusable", "err", err, "connection", conn.ID)
	}
	response, info, err := h.Service.validateResponse(h.publicBase(r), conn, certs, key, encoded, time.Now())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	email := info.NameID
	if conn.EmailAttribute != "" {
		if v := info.Values.Get(conn.EmailAttribute); v != "" {
			email = v
		}
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		httpx.WriteError(w, r, errs.ErrSAMLAssertionNoEmail)
		return
	}
	requestID, assertionIDs, err := trustedCorrelation(response)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	allowIdPInitiated, err := h.Service.AllowsIdPInitiated(r.Context(), conn.ID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.ConsumeValidatedResponse(r.Context(), conn.ID, requestID, response.ID, assertionIDs, allowIdPInitiated); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// An answer to a request completes only in the browser that sent it, and
	// spends the request either way. One the IdP sends unasked has no request
	// to bind, so it is opt-in.
	if requestID != "" {
		if !h.binding().Holds(r, requestID) {
			httpx.WriteError(w, r, errs.ErrSAMLOtherBrowser)
			return
		}
		h.binding().Remove(w, r, requestID)
	}
	ctx := r.Context()
	groupsAttribute, err := h.Service.groupsAttribute(ctx, conn)
	if err != nil {
		slog.Error("saml acs: read the groups attribute", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	groups, withheld := assertedGroups(info.Values, groupsAttribute)
	userID, err := h.Service.findOrCreateUser(ctx, conn.TenantID, conn.ID, assertion{
		subject: info.NameID, email: email, name: assertedName(info.Values, conn.NameAttribute),
		groups: groups, groupsWithheld: withheld,
	}, audit.Actor{Type: provider, IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)})
	if e := errs.As(err); e != nil && e.Code != errs.CodeInternal {
		httpx.WriteError(w, r, err)
		return
	}
	if err != nil {
		slog.Error("saml acs: provisioning failed", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}

	rawCode, codeHash, err := codes.URLToken()
	if err != nil {
		slog.Error("saml acs: generate login code", "err", err)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	if err := h.Service.insertLoginCode(ctx, codeHash, userID, conn.TenantID, time.Now().UTC().Add(loginCodeTTL)); err != nil {
		slog.Error("saml acs: persist login code", "err", err)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	h.Service.touchLastLogin(ctx, conn.ID)

	// Hand the SPA the one-time code in the URL fragment (never sent to a
	// server / proxy log); the SPA trades it at /saml/exchange.
	target := h.Service.appBaseURL + "/sso/callback#saml_code=" + rawCode
	http.Redirect(w, r, target, http.StatusFound)
}

func trustedCorrelation(response *samltypes.Response) (string, []string, error) {
	requestID := ""
	if response.SignatureValidated {
		requestID = response.InResponseTo
	}
	assertionIDs := make([]string, 0, len(response.Assertions))
	for _, assertion := range response.Assertions {
		assertionIDs = append(assertionIDs, assertion.ID)
		if assertion.Subject == nil || assertion.Subject.SubjectConfirmation == nil ||
			assertion.Subject.SubjectConfirmation.SubjectConfirmationData == nil {
			continue
		}
		candidate := assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo
		if candidate == "" || (!response.SignatureValidated && !assertion.SignatureValidated) {
			continue
		}
		if requestID == "" {
			requestID = candidate
		} else if requestID != candidate {
			return "", nil, errs.ErrSAMLRequestCorrelation
		}
	}
	return requestID, assertionIDs, nil
}

func (h *Handler) exchange(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.Service.ExchangeLogin(r.Context(), body.Code, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}
