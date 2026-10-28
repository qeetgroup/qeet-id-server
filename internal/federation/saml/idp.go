package saml

// Qeet ID as a SAML identity provider: a tenant's registered SP sends the user to
// /saml/idp/{tenantID}/sso, the hosted-login SSO cookie authenticates them, and an
// assertion signed with goxmldsig (RSA-SHA256, exclusive c14n) is POSTed to the
// SP's ACS. Each tenant is its own IdP entity; one signing key serves them all.

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	dsig "github.com/russellhaering/goxmldsig"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const (
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"

	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	nameIDEmail         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	statusSuccess       = "urn:oasis:names:tc:SAML:2.0:status:Success"
	confirmationBearer  = "urn:oasis:names:tc:SAML:2.0:cm:bearer"                             // #nosec G101 -- SAML URN, not a credential
	authnCtxPassword    = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" // #nosec G101 -- SAML URN, not a credential
	attrNameFormatBasic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

	assertionTTL = 5 * time.Minute
	clockSkew    = 1 * time.Minute
)

// =====================================================================
// Signing key
// =====================================================================

// idpSigner holds the RSA key + X.509 cert used to sign assertions.
type idpSigner struct {
	key     *rsa.PrivateKey
	certDER []byte
	certB64 string
}

func newIdPSigner(keyPEM, certPEM string) (*idpSigner, error) {
	kb, _ := pem.Decode([]byte(keyPEM))
	if kb == nil {
		return nil, errors.New("saml idp: invalid private-key PEM")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(kb.Bytes); err == nil {
		key = k
	} else if k8, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err == nil {
		rk, ok := k8.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("saml idp: signing key is not RSA")
		}
		key = rk
	} else {
		return nil, errors.New("saml idp: unparseable private key (want PKCS#1 or PKCS#8 RSA)")
	}
	cb, _ := pem.Decode([]byte(certPEM))
	if cb == nil {
		return nil, errors.New("saml idp: invalid certificate PEM")
	}
	if _, err := x509.ParseCertificate(cb.Bytes); err != nil {
		return nil, fmt.Errorf("saml idp: %w", err)
	}
	return &idpSigner{
		key:     key,
		certDER: cb.Bytes,
		certB64: base64.StdEncoding.EncodeToString(cb.Bytes),
	}, nil
}

// signingContext builds a goxmldsig context: RSA-SHA256 + exclusive c14n, the
// combination SPs expect.
func (s *idpSigner) signingContext() (*dsig.SigningContext, error) {
	ctx, err := dsig.NewSigningContext(s.key, [][]byte{s.certDER})
	if err != nil {
		return nil, err
	}
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	return ctx, nil
}

// GenerateIdPKeyPEM mints a fresh RSA-2048 key and 10-year self-signed
// certificate, for an ephemeral signing identity in development.
func GenerateIdPKeyPEM(commonName string) (keyPEM, certPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return keyPEM, certPEM, nil
}

// =====================================================================
// Service Provider registry + IdP service
// =====================================================================

// ServiceProvider is a downstream app that consumes Qeet ID as its IdP.
// Attributes are what its assertions carry beside the NameID, and with
// AssignmentRequired only the people assigned to it may sign in.
type ServiceProvider struct {
	ID                 uuid.UUID          `json:"id"`
	TenantID           uuid.UUID          `json:"tenant_id"`
	Name               string             `json:"name"`
	EntityID           string             `json:"entity_id"`
	ACSURL             string             `json:"acs_url"`
	NameIDFormat       string             `json:"name_id_format"`
	NameIDAttribute    string             `json:"name_id_attribute"`
	Certificate        string             `json:"certificate"`
	Status             string             `json:"status"`
	Attributes         []AttributeMapping `json:"attributes"`
	AssignmentRequired bool               `json:"assignment_required"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
	LastLoginAt        *time.Time         `json:"last_login_at"`
}

// SessionResolver resolves the hosted-login SSO cookie to a user id. Satisfied
// by *auth.Service (the same dependency the OIDC provider uses).
type SessionResolver interface {
	ResolveLoginSession(ctx context.Context, raw string) (uuid.UUID, error)
}

// IdP issues SAML assertions and manages the SP registry. A nil gate leaves SP
// creation ungated.
type IdP struct {
	pool         *pgxpool.Pool
	q            *dbgen.Queries
	signer       *idpSigner
	sessions     SessionResolver
	loginBaseURL string
	gate         PlanGate
}

// PlanGate reports whether a plan-gated boolean feature is included in the
// tenant's plan. Satisfied by *entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (i *IdP) SetPlanGate(g PlanGate) { i.gate = g }

// NewIdP returns the SAML identity provider, signing with the key and
// certificate given.
func NewIdP(pool *pgxpool.Pool, keyPEM, certPEM, loginBaseURL string, sessions SessionResolver) (*IdP, error) {
	signer, err := newIdPSigner(keyPEM, certPEM)
	if err != nil {
		return nil, err
	}
	return &IdP{
		pool:         pool,
		q:            dbgen.New(pool),
		signer:       signer,
		sessions:     sessions,
		loginBaseURL: strings.TrimRight(loginBaseURL, "/"),
	}, nil
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (i *IdP) Pool() *pgxpool.Pool { return i.pool }

// toSP maps a sqlc-generated row to the API-facing ServiceProvider type.
func toSP(r dbgen.TenantSamlServiceProvider) *ServiceProvider {
	var lastLogin *time.Time
	if r.LastLoginAt.Valid {
		v := r.LastLoginAt.Time
		lastLogin = &v
	}
	return &ServiceProvider{
		ID:                 r.ID,
		TenantID:           r.TenantID,
		Name:               r.Name,
		EntityID:           r.EntityID,
		ACSURL:             r.AcsUrl,
		NameIDFormat:       r.NameIDFormat,
		NameIDAttribute:    r.NameIDAttribute,
		Certificate:        r.Certificate,
		Status:             r.Status,
		Attributes:         decodeAttributes(r.Attributes),
		AssignmentRequired: r.AssignmentRequired,
		CreatedAt:          r.CreatedAt,
		UpdatedAt:          r.UpdatedAt,
		LastLoginAt:        lastLogin,
	}
}

// CreateSPInput is what CreateSP takes. Attributes nil sends the default
// attributes; an empty list sends none.
type CreateSPInput struct {
	Name               string              `json:"name"`
	EntityID           string              `json:"entity_id"`
	ACSURL             string              `json:"acs_url"`
	NameIDFormat       string              `json:"name_id_format"`
	NameIDAttribute    string              `json:"name_id_attribute"`
	Certificate        string              `json:"certificate"`
	Status             string              `json:"status"`
	Attributes         *[]AttributeMapping `json:"attributes"`
	AssignmentRequired bool                `json:"assignment_required"`
}

// check requires the ACS URL to pass validACSURL, a certificate, if given, to
// parse, and the NameID settings and attributes to pass checkNameID and
// checkAttributes.
func (in *CreateSPInput) check() error {
	if in.Status != "" && !validStatus(in.Status) {
		return errs.ErrSAMLStatusInvalid
	}
	in.ACSURL = strings.TrimSpace(in.ACSURL)
	if !validACSURL(in.ACSURL) {
		return errs.ErrSAMLACSURLInvalid
	}
	if in.Certificate != "" {
		if _, err := parseCertificate(in.Certificate); err != nil {
			return errs.ErrSAMLCertificateInvalid
		}
	}
	in.NameIDFormat, in.NameIDAttribute = strings.TrimSpace(in.NameIDFormat), strings.TrimSpace(in.NameIDAttribute)
	if err := checkNameID(&in.NameIDFormat, &in.NameIDAttribute); err != nil {
		return err
	}
	if in.Attributes != nil {
		return checkAttributes(*in.Attributes)
	}
	return nil
}

// validACSURL reports whether raw is an absolute https URL with a host and no
// user information, or plain http to a loopback host, where a signed assertion
// may be posted.
func validACSURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return false
	}
	switch h := u.Hostname(); u.Scheme {
	case "https":
		return true
	case "http":
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// requireSSO refuses with ErrUpgradeRequired when the tenant's plan doesn't
// include enterprise SSO (SAML), a paid feature. It reads on the pool, so the
// handler runs it before it opens the transaction CreateSP joins.
func (i *IdP) requireSSO(ctx context.Context, tenantID uuid.UUID) error {
	if i.gate == nil {
		return nil
	}
	ok, err := i.gate.FeatureAllowed(ctx, tenantID, "sso")
	if err != nil {
		return err
	}
	if !ok {
		return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "sso"})
	}
	return nil
}

// CreateSP registers a service provider in tenantID within tx, refusing input
// that fails check. Callers check the plan first, with requireSSO.
func (i *IdP) CreateSP(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, in CreateSPInput) (*ServiceProvider, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	status := in.Status
	if status == "" {
		status = "draft"
	}
	attributes, err := encodeAttributes(in.Attributes)
	if err != nil {
		return nil, err
	}
	r, err := i.q.WithTx(tx).InsertSamlSP(ctx, dbgen.InsertSamlSPParams{
		TenantID:           tenantID,
		Name:               in.Name,
		EntityID:           in.EntityID,
		AcsUrl:             in.ACSURL,
		NameIDFormat:       in.NameIDFormat,
		NameIDAttribute:    in.NameIDAttribute,
		Certificate:        in.Certificate,
		Status:             status,
		Attributes:         attributes,
		AssignmentRequired: in.AssignmentRequired,
	})
	if pgxerr.IsUnique(err) {
		return nil, errs.ErrSAMLSPEntityIDTaken
	}
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

// ListSP returns the tenant's service providers.
func (i *IdP) ListSP(ctx context.Context, tenantID uuid.UUID) ([]ServiceProvider, error) {
	rows, err := i.q.ListSamlSPs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]ServiceProvider, len(rows))
	for j, r := range rows {
		out[j] = *toSP(r)
	}
	return out, nil
}

// GetSP returns one of the tenant's service providers.
func (i *IdP) GetSP(ctx context.Context, id, tenantID uuid.UUID) (*ServiceProvider, error) {
	r, err := i.q.GetSamlSP(ctx, dbgen.GetSamlSPParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

// UpdateSPInput is what UpdateSP takes. Attributes replaces the whole list.
type UpdateSPInput struct {
	Name               *string             `json:"name"`
	EntityID           *string             `json:"entity_id"`
	ACSURL             *string             `json:"acs_url"`
	NameIDFormat       *string             `json:"name_id_format"`
	NameIDAttribute    *string             `json:"name_id_attribute"`
	Certificate        *string             `json:"certificate"`
	Status             *string             `json:"status"`
	Attributes         *[]AttributeMapping `json:"attributes"`
	AssignmentRequired *bool               `json:"assignment_required"`
}

// check applies CreateSPInput's checks to the fields being changed; UpdateSP
// checks the NameID settings against the ones they change.
func (in *UpdateSPInput) check() error {
	if in.ACSURL != nil {
		acs := strings.TrimSpace(*in.ACSURL)
		if !validACSURL(acs) {
			return errs.ErrSAMLACSURLInvalid
		}
		in.ACSURL = &acs
	}
	if in.Certificate != nil && *in.Certificate != "" {
		if _, err := parseCertificate(*in.Certificate); err != nil {
			return errs.ErrSAMLCertificateInvalid
		}
	}
	if in.NameIDFormat != nil {
		f := strings.TrimSpace(*in.NameIDFormat)
		if f != "" && !knownNameIDFormat(f) {
			return errs.ErrSAMLNameIDFormatInvalid
		}
		in.NameIDFormat = &f
	}
	if in.NameIDAttribute != nil {
		a := strings.TrimSpace(*in.NameIDAttribute)
		if a != "" && !validNameIDAttribute(a) {
			return errs.ErrSAMLNameIDAttributeInvalid
		}
		in.NameIDAttribute = &a
	}
	if in.Attributes != nil {
		return checkAttributes(*in.Attributes)
	}
	return nil
}

// UpdateSP changes the given fields of a service provider in tenantID within
// tx, refusing input that fails check or NameID settings mergeNameID refuses.
func (i *IdP) UpdateSP(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID, in UpdateSPInput) (*ServiceProvider, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	q := i.q.WithTx(tx)
	if in.NameIDFormat != nil || in.NameIDAttribute != nil {
		cur, err := q.GetSamlSPForUpdate(ctx, dbgen.GetSamlSPForUpdateParams{ID: id, TenantID: tenantID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		format, attribute, err := mergeNameID(cur.NameIDFormat, cur.NameIDAttribute, in.NameIDFormat, in.NameIDAttribute)
		if err != nil {
			return nil, err
		}
		in.NameIDFormat, in.NameIDAttribute = &format, &attribute
	}
	var attributes []byte
	if in.Attributes != nil {
		var err error
		if attributes, err = encodeAttributes(in.Attributes); err != nil {
			return nil, err
		}
	}
	r, err := q.UpdateSamlSP(ctx, dbgen.UpdateSamlSPParams{
		ID:                 id,
		TenantID:           tenantID,
		Name:               in.Name,
		EntityID:           in.EntityID,
		AcsUrl:             in.ACSURL,
		NameIDFormat:       in.NameIDFormat,
		NameIDAttribute:    in.NameIDAttribute,
		Certificate:        in.Certificate,
		Status:             in.Status,
		Attributes:         attributes,
		AssignmentRequired: in.AssignmentRequired,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

// DeleteSP removes one of the tenant's service providers.
func (i *IdP) DeleteSP(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) error {
	n, err := i.q.WithTx(tx).DeleteSamlSP(ctx, dbgen.DeleteSamlSPParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// activeTenant reports whether tenantID names an active, undeleted tenant.
func (i *IdP) activeTenant(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	return i.q.IsTenantActive(ctx, tenantID)
}

// lookupSPByEntityID resolves the tenant's (non-disabled) SP by its EntityID,
// which is unique only within a tenant.
func (i *IdP) lookupSPByEntityID(ctx context.Context, tenantID uuid.UUID, entityID string) (*ServiceProvider, error) {
	r, err := i.q.GetSamlSPByEntityID(ctx, dbgen.GetSamlSPByEntityIDParams{TenantID: tenantID, EntityID: entityID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

// lookupSP resolves the tenant's SP by provider UUID (IdP-initiated
// ?sp=<uuid>) or EntityID.
func (i *IdP) lookupSP(ctx context.Context, tenantID uuid.UUID, key string) (*ServiceProvider, error) {
	if id, err := uuid.Parse(key); err == nil {
		return i.GetSP(ctx, id, tenantID)
	}
	return i.lookupSPByEntityID(ctx, tenantID, key)
}

// loadUser returns the account an assertion about userID describes, with its
// home tenant, or ErrAuthAccountInactive for an account that isn't active.
func (i *IdP) loadUser(ctx context.Context, userID uuid.UUID) (*person, error) {
	row, err := i.q.GetUserForIdP(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrAuthAccountInactive
	}
	if err != nil {
		return nil, err
	}
	// A suspended account gets no assertion, whatever its open sign-in session.
	if row.Status != "active" {
		return nil, errs.ErrAuthAccountInactive
	}
	p := &person{id: userID, email: row.Email, metadata: decodeMetadata(row.Metadata)}
	if row.DisplayName != nil {
		p.displayName = *row.DisplayName
	}
	if row.TenantID.Valid {
		p.tenantID = uuid.UUID(row.TenantID.Bytes)
	}
	return p, nil
}

func (i *IdP) recordIssued(ctx context.Context, r *http.Request, sp *ServiceProvider, userID uuid.UUID) error {
	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := i.q.WithTx(tx).TouchSamlSPLastLogin(ctx, sp.ID); err != nil {
		return err
	}
	tid, rid, uid := sp.TenantID, sp.ID, userID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  &uid,
		ActorType:    "user",
		Action:       "saml.idp_assertion_issued",
		ResourceType: "saml_service_provider",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"sp_entity_id": sp.EntityID},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// recordRefused audits that the IdP refused userID an assertion for sp, and why.
func (i *IdP) recordRefused(ctx context.Context, r *http.Request, sp *ServiceProvider, userID uuid.UUID, reason string) error {
	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tid, rid, uid := sp.TenantID, sp.ID, userID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  &uid,
		ActorType:    "user",
		Action:       "saml.idp_assertion_refused",
		ResourceType: "saml_service_provider",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"sp_entity_id": sp.EntityID, "reason": reason},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// =====================================================================
// Assertion construction + signing
// =====================================================================

// buildSignedResponse constructs a SAML Response wrapping a signed Assertion
// about s. inResponseTo is empty for IdP-initiated SSO.
func (i *IdP) buildSignedResponse(idpEntity string, sp *ServiceProvider, acs string, s assertionSubject, inResponseTo string) ([]byte, error) {
	now := time.Now().UTC()
	respID := "_" + uuid.NewString()
	assertID := "_" + uuid.NewString()
	notBefore := now.Add(-clockSkew).Format(time.RFC3339)
	notAfter := now.Add(assertionTTL).Format(time.RFC3339)
	nidFormat := s.nameIDFormat
	if nidFormat == "" {
		nidFormat = nameIDEmail
	}

	// --- Assertion (signed below, once inside the Response) ---
	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", nsAssertion)
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("ID", assertID)
	assertion.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	assertion.CreateElement("saml:Issuer").SetText(idpEntity)

	subject := assertion.CreateElement("saml:Subject")
	nid := subject.CreateElement("saml:NameID")
	nid.CreateAttr("Format", nidFormat)
	nid.SetText(s.nameID)
	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", confirmationBearer)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("NotOnOrAfter", notAfter)
	scd.CreateAttr("Recipient", acs)
	if inResponseTo != "" {
		scd.CreateAttr("InResponseTo", inResponseTo)
	}

	cond := assertion.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", notBefore)
	cond.CreateAttr("NotOnOrAfter", notAfter)
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(sp.EntityID)

	authn := assertion.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", now.Format(time.RFC3339))
	authn.CreateAttr("SessionIndex", assertID)
	authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(authnCtxPassword)

	// The schema wants an AttributeStatement to hold an attribute, so one with
	// none is left out.
	var attrStmt *etree.Element
	if len(s.attributes) > 0 {
		attrStmt = assertion.CreateElement("saml:AttributeStatement")
	}
	for _, attr := range s.attributes {
		a := attrStmt.CreateElement("saml:Attribute")
		a.CreateAttr("Name", attr.name)
		a.CreateAttr("NameFormat", attr.nameFormat)
		for _, v := range attr.values {
			a.CreateElement("saml:AttributeValue").SetText(v)
		}
	}

	// --- Response wrapping the assertion ---
	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("ID", respID)
	resp.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	resp.CreateAttr("Destination", acs)
	if inResponseTo != "" {
		resp.CreateAttr("InResponseTo", inResponseTo)
	}
	resp.CreateElement("saml:Issuer").SetText(idpEntity)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", statusSuccess)
	resp.AddChild(assertion)

	// Sign the assertion in place inside the Response, so the canonical form the SP
	// checks matches what was signed, then move ds:Signature after saml:Issuer.
	ctx, err := i.signer.signingContext()
	if err != nil {
		return nil, err
	}
	signed, err := ctx.SignEnveloped(assertion)
	if err != nil {
		return nil, err
	}
	moveSignatureAfterIssuer(signed)
	resp.RemoveChild(assertion)
	resp.AddChild(signed)

	doc := etree.NewDocument()
	doc.SetRoot(resp)
	return doc.WriteToBytes()
}

// moveSignatureAfterIssuer moves ds:Signature to just after saml:Issuer, where
// the schema puts it and strict SPs such as ADFS require it. It edits el.Child
// directly because goxmldsig leaves etree's child indexes stale. An enveloped
// signature doesn't cover itself, so moving it keeps it valid.
func moveSignatureAfterIssuer(el *etree.Element) {
	sigIdx, issuerIdx := -1, -1
	for i, tok := range el.Child {
		e, ok := tok.(*etree.Element)
		if !ok {
			continue
		}
		switch e.Tag {
		case "Signature":
			if sigIdx < 0 {
				sigIdx = i
			}
		case "Issuer":
			if issuerIdx < 0 {
				issuerIdx = i
			}
		}
	}
	if sigIdx < 0 || issuerIdx < 0 {
		return
	}
	target := issuerIdx + 1
	if sigIdx == target {
		return
	}
	sig := el.Child[sigIdx]
	el.Child = append(el.Child[:sigIdx], el.Child[sigIdx+1:]...)
	if target > sigIdx {
		target--
	}
	tail := append([]etree.Token{sig}, el.Child[target:]...)
	el.Child = append(el.Child[:target], tail...)
}

// authnRequest is the minimal subset of <AuthnRequest> we read.
type authnRequest struct {
	XMLName                     xml.Name
	ID                          string `xml:"ID,attr"`
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
	Issuer                      string `xml:"Issuer"`
}

// maxInflatedAuthnRequest caps a redirect-binding SAMLRequest after inflation.
const maxInflatedAuthnRequest = 256 << 10

// decodeAuthnRequest base64-decodes (and, for the redirect binding, inflates)
// a SAMLRequest. An inflated request over maxInflatedAuthnRequest is refused
// with ErrSAMLAuthnRequestInvalid.
func decodeAuthnRequest(encoded, method string) (*authnRequest, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if method == http.MethodGet {
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		inflated, err := io.ReadAll(io.LimitReader(fr, maxInflatedAuthnRequest+1))
		if err != nil {
			return nil, err
		}
		if len(inflated) > maxInflatedAuthnRequest {
			return nil, errs.ErrSAMLAuthnRequestInvalid
		}
		raw = inflated
	}
	var ar authnRequest
	if err := xml.Unmarshal(raw, &ar); err != nil { // #nosec G709 -- decodes into a typed struct
		return nil, err
	}
	return &ar, nil
}

// redirectEncoded re-encodes an HTTP-POST binding SAMLRequest (base64) for the
// HTTP-Redirect binding (DEFLATE, then base64), leaving the request's XML as it
// was. A request too large for decodeAuthnRequest to inflate is refused.
func redirectEncoded(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", err
	}
	if len(raw) > maxInflatedAuthnRequest {
		return "", errs.ErrSAMLAuthnRequestInvalid
	}
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(raw); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// ssoReturnURL is where the hosted login sends the browser once the person has
// signed in: this endpoint, by GET. A POST's parameters move into the query,
// its SAMLRequest re-encoded for the Redirect binding that the GET decodes.
func ssoReturnURL(base string, r *http.Request) (string, error) {
	if r.Method != http.MethodPost {
		return base + r.URL.RequestURI(), nil
	}
	q := url.Values{}
	if samlReq := r.FormValue("SAMLRequest"); samlReq != "" {
		enc, err := redirectEncoded(samlReq)
		if err != nil {
			return "", err
		}
		q.Set("SAMLRequest", enc)
	} else if spKey := strings.TrimSpace(r.FormValue("sp")); spKey != "" {
		q.Set("sp", spKey)
	}
	if relayState := r.FormValue("RelayState"); relayState != "" {
		q.Set("RelayState", relayState)
	}
	return base + r.URL.EscapedPath() + "?" + q.Encode(), nil
}

// idpEntityID is the tenant's IdP entity ID.
func idpEntityID(base string, tenantID uuid.UUID) string {
	return base + "/saml/idp/" + tenantID.String()
}

// idpSSOURL is the tenant's IdP SingleSignOnService URL.
func idpSSOURL(base string, tenantID uuid.UUID) string {
	return idpEntityID(base, tenantID) + "/sso"
}

// autoSubmit posts the page's form to the service provider once it loads.
const autoSubmit = `document.forms[0].submit()`

// postFormCSP is the API's script-free policy, letting exactly autoSubmit run.
var postFormCSP = func() string {
	sum := sha256.Sum256([]byte(autoSubmit))
	return "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; frame-ancestors 'none'"
}()

// writePostForm answers with the HTTP-POST binding page: a form carrying the
// signed response to acs, submitted by autoSubmit or, without script, a button.
func writePostForm(w http.ResponseWriter, acs, samlResponse, relayState string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", postFormCSP)
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Signing in…</title></head><body>`)
	b.WriteString(`<form method="POST" action="` + html.EscapeString(acs) + `">`)
	b.WriteString(`<input type="hidden" name="SAMLResponse" value="` + html.EscapeString(samlResponse) + `"/>`)
	if relayState != "" {
		b.WriteString(`<input type="hidden" name="RelayState" value="` + html.EscapeString(relayState) + `"/>`)
	}
	b.WriteString(`<noscript><button type="submit">Continue</button></noscript></form>`)
	b.WriteString(`<script>` + autoSubmit + `</script></body></html>`)
	_, _ = w.Write([]byte(b.String()))
}

// errorPageCSP lets the SSO error page show its text and nothing else.
const errorPageCSP = "default-src 'none'; frame-ancestors 'none'"

// writeSSOError answers the SSO endpoint's browser, which asks for HTML, with a
// page saying why it can't sign in and the error's code; anything else, or an
// error outside the catalogue, gets the JSON error.
func writeSSOError(w http.ResponseWriter, r *http.Request, err error) {
	e := errs.As(err)
	if e == nil || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		httpx.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", errorPageCSP)
	w.WriteHeader(httpx.StatusForCode(e.Code))
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Can't sign you in</title></head><body>`)
	b.WriteString(`<h1>Can't sign you in</h1><p>` + html.EscapeString(e.Message) + `</p>`)
	b.WriteString(`<p>Error code: <code>` + html.EscapeString(e.Code) + `</code>`)
	if id := httpx.RequestID(r); id != "" {
		b.WriteString(` · Request ID: <code>` + html.EscapeString(id) + `</code>`)
	}
	b.WriteString(`</p></body></html>`)
	_, _ = w.Write([]byte(b.String())) // #nosec G705 -- every value on the page is HTML-escaped
}

// refuse answers a signed-in person sp won't sign in with err, and audits the
// refusal with reason.
func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, sp *ServiceProvider, userID uuid.UUID, err error, reason string) {
	if auditErr := h.IdP.recordRefused(r.Context(), r, sp, userID, reason); auditErr != nil {
		slog.Warn("saml idp sso: record refused assertion", "err", auditErr, "sp", sp.ID)
	}
	writeSSOError(w, r, err)
}

// =====================================================================
// IdP HTTP handlers (methods on the shared saml.Handler)
// =====================================================================

func (h *Handler) idpSessionUser(r *http.Request) (uuid.UUID, bool) {
	c, err := r.Cookie(auth.LoginSessionCookie)
	if err != nil {
		return uuid.Nil, false
	}
	uid, err := h.IdP.sessions.ResolveLoginSession(r.Context(), c.Value)
	if err != nil {
		return uuid.Nil, false
	}
	return uid, true
}

// idpTenant returns the path's tenant for the IdP endpoints. A malformed,
// unknown or inactive one is ErrNotFound, the same answer as an unknown SP.
func (h *Handler) idpTenant(r *http.Request) (uuid.UUID, error) {
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrNotFound
	}
	active, err := h.IdP.activeTenant(r.Context(), tenantID)
	if err != nil {
		return uuid.Nil, err
	}
	if !active {
		return uuid.Nil, errs.ErrNotFound
	}
	return tenantID, nil
}

// idpMetadata serves the tenant's IdP SAML metadata (EntityDescriptor) for SPs
// to import: the signing cert + SSO endpoints.
func (h *Handler) idpMetadata(w http.ResponseWriter, r *http.Request) {
	if h.IdP == nil {
		httpx.WriteError(w, r, errs.ErrSAMLIdPNotConfigured)
		return
	}
	tenantID, err := h.idpTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	base := h.publicBase(r)
	entity := idpEntityID(base, tenantID)
	sso := idpSSOURL(base, tenantID)
	doc := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>%s</NameIDFormat>
    <NameIDFormat>%s</NameIDFormat>
    <NameIDFormat>%s</NameIDFormat>
    <SingleSignOnService Binding="%s" Location="%s"/>
    <SingleSignOnService Binding="%s" Location="%s"/>
  </IDPSSODescriptor>
</EntityDescriptor>`,
		html.EscapeString(entity), h.IdP.signer.certB64, nameIDEmail, nameIDPersistent, nameIDUnspecified,
		bindingRedirect, html.EscapeString(sso), bindingPOST, html.EscapeString(sso))
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Disposition", `attachment; filename="qeet-idp-metadata.xml"`)
	_, _ = w.Write([]byte(doc))
}

// idpSSO is the tenant's SingleSignOnService. It handles SP-initiated SSO (a
// SAMLRequest via HTTP-Redirect GET or HTTP-POST) and IdP-initiated SSO
// (?sp=<id|entityID>), for SPs of the path's tenant only. Without a hosted-login
// SSO cookie, the browser is bounced to the hosted login and returns here. An
// SP set to assigned people only refuses, and audits refusing, anyone else.
func (h *Handler) idpSSO(w http.ResponseWriter, r *http.Request) {
	if h.IdP == nil {
		writeSSOError(w, r, errs.ErrSAMLIdPNotConfigured)
		return
	}
	tenantID, err := h.idpTenant(r)
	if err != nil {
		writeSSOError(w, r, err)
		return
	}
	if err := httpx.ParseForm(r, httpx.MaxSAMLBodyBytes); err != nil {
		writeSSOError(w, r, err)
		return
	}
	relayState := r.FormValue("RelayState")

	var (
		sp           *ServiceProvider
		inResponseTo string
		acsOverride  string
		lookupErr    error
	)
	if samlReq := r.FormValue("SAMLRequest"); samlReq != "" {
		ar, err := decodeAuthnRequest(samlReq, r.Method)
		if err != nil {
			writeSSOError(w, r, errs.ErrSAMLAuthnRequestInvalid)
			return
		}
		inResponseTo = ar.ID
		acsOverride = strings.TrimSpace(ar.AssertionConsumerServiceURL)
		sp, lookupErr = h.IdP.lookupSPByEntityID(r.Context(), tenantID, strings.TrimSpace(ar.Issuer))
	} else if spKey := strings.TrimSpace(r.FormValue("sp")); spKey != "" {
		sp, lookupErr = h.IdP.lookupSP(r.Context(), tenantID, spKey)
	} else {
		writeSSOError(w, r, errs.ErrSAMLRequestParamMissing)
		return
	}
	if lookupErr != nil || sp == nil {
		// lookupErr is errs.ErrNotFound (no rows) or a real DB error → 404/500.
		err := lookupErr
		if err == nil {
			err = errs.ErrNotFound
		}
		writeSSOError(w, r, err)
		return
	}
	if sp.Status == "disabled" {
		writeSSOError(w, r, errs.ErrSAMLServiceProviderDisabled)
		return
	}
	// A supplied ACS URL must match the registered one (prevents redirecting a
	// signed assertion to an attacker-chosen endpoint).
	if acsOverride != "" && acsOverride != sp.ACSURL {
		writeSSOError(w, r, errs.ErrSAMLACSMismatch)
		return
	}

	base := h.publicBase(r)
	userID, ok := h.idpSessionUser(r)
	if !ok {
		ret, err := ssoReturnURL(base, r)
		if err != nil {
			writeSSOError(w, r, errs.ErrSAMLAuthnRequestInvalid)
			return
		}
		http.Redirect(w, r, h.IdP.loginBaseURL+"/sign-in?return_to="+url.QueryEscape(ret), http.StatusFound)
		return
	}

	ctx := r.Context()
	who, err := h.IdP.loadUser(ctx, userID)
	if errors.Is(err, errs.ErrAuthAccountInactive) {
		writeSSOError(w, r, err)
		return
	}
	if err != nil {
		slog.Error("saml idp sso: user lookup", "err", err, "user", userID)
		writeSSOError(w, r, errs.ErrInternalServer)
		return
	}
	if who.tenantID != sp.TenantID {
		writeSSOError(w, r, errs.ErrSAMLUserTenantMismatch)
		return
	}
	if sp.AssignmentRequired {
		assigned, err := h.IdP.assigned(ctx, sp, userID)
		if err != nil {
			slog.Error("saml idp sso: assignment lookup", "err", err, "sp", sp.ID)
			writeSSOError(w, r, errs.ErrInternalServer)
			return
		}
		if !assigned {
			h.refuse(w, r, sp, userID, errs.ErrSAMLSPNotAssigned, "not_assigned")
			return
		}
	}
	subj, err := h.IdP.subjectFor(ctx, sp, who)
	if errors.Is(err, errs.ErrSAMLNameIDUnavailable) {
		h.refuse(w, r, sp, userID, err, "name_id_unavailable")
		return
	}
	if err != nil {
		slog.Error("saml idp sso: assertion subject", "err", err, "sp", sp.ID)
		writeSSOError(w, r, errs.ErrInternalServer)
		return
	}

	respXML, err := h.IdP.buildSignedResponse(idpEntityID(base, tenantID), sp, sp.ACSURL, subj, inResponseTo)
	if err != nil {
		slog.Error("saml idp sso: build assertion", "err", err, "sp", sp.ID)
		writeSSOError(w, r, errs.ErrInternalServer)
		return
	}
	if err := h.IdP.recordIssued(r.Context(), r, sp, userID); err != nil {
		// Audit/bookkeeping failure shouldn't block the user's SSO — log only.
		slog.Warn("saml idp sso: record issued assertion", "err", err, "sp", sp.ID)
	}
	writePostForm(w, sp.ACSURL, base64.StdEncoding.EncodeToString(respXML), relayState)
}

// =====================================================================
// SP-registry admin handlers (user-JWT, tenant-scoped)
// =====================================================================

func (h *Handler) listSP(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.IdP.ListSP(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) createSP(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateSPInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.EntityID = strings.TrimSpace(in.EntityID)
	in.ACSURL = strings.TrimSpace(in.ACSURL)
	if in.Name == "" || in.EntityID == "" || in.ACSURL == "" {
		httpx.WriteError(w, r, errs.ErrSAMLSPFieldsRequired)
		return
	}
	if err := in.check(); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	if err := h.IdP.requireSSO(ctx, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.IdP.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	sp, err := h.IdP.CreateSP(ctx, tx, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordSPAudit(ctx, tx, r, tenantID, sp.ID, "saml.sp_created", map[string]any{
		"name": sp.Name, "entity_id": sp.EntityID, "name_id_format": sp.NameIDFormat, "name_id_attribute": sp.NameIDAttribute,
		"attributes": sp.Attributes, "assignment_required": sp.AssignmentRequired,
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, sp)
}

func (h *Handler) getSP(w http.ResponseWriter, r *http.Request) {
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
	sp, err := h.IdP.GetSP(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sp)
}

func (h *Handler) updateSP(w http.ResponseWriter, r *http.Request) {
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
	var in UpdateSPInput
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
	tx, err := h.IdP.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	sp, err := h.IdP.UpdateSP(ctx, tx, id, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordSPAudit(ctx, tx, r, tenantID, sp.ID, "saml.sp_updated", spUpdateAudit(in, sp)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sp)
}

func (h *Handler) delSP(w http.ResponseWriter, r *http.Request) {
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
	tx, err := h.IdP.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.IdP.DeleteSP(ctx, tx, id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordSPAudit(ctx, tx, r, tenantID, id, "saml.sp_deleted", nil); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// spUpdateAudit is what the audit records of a change to a service provider:
// the fields it named, and the new values of those deciding where assertions
// go, who gets them and what they say.
func spUpdateAudit(in UpdateSPInput, sp *ServiceProvider) map[string]any {
	meta := map[string]any{"status": sp.Status}
	changed := []string{}
	for _, f := range []struct {
		name  string
		set   bool
		value any
	}{
		{"name", in.Name != nil, nil},
		{"entity_id", in.EntityID != nil, sp.EntityID},
		{"acs_url", in.ACSURL != nil, sp.ACSURL},
		{"name_id_format", in.NameIDFormat != nil || in.NameIDAttribute != nil, sp.NameIDFormat},
		{"name_id_attribute", in.NameIDFormat != nil || in.NameIDAttribute != nil, sp.NameIDAttribute},
		{"certificate", in.Certificate != nil, nil},
		{"status", in.Status != nil, nil},
		{"attributes", in.Attributes != nil, sp.Attributes},
		{"assignment_required", in.AssignmentRequired != nil, sp.AssignmentRequired},
	} {
		if !f.set {
			continue
		}
		changed = append(changed, f.name)
		if f.value != nil {
			meta[f.name] = f.value
		}
	}
	meta["changed"] = changed
	return meta
}

func (h *Handler) recordSPAudit(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID, resourceID uuid.UUID, action string, meta map[string]any) error {
	actorID, actorType := audit.ActorOf(r).Identity()
	tid, rid := tenantID, resourceID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: "saml_service_provider",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
	})
}
