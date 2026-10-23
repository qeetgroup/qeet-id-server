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
type ServiceProvider struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	Name            string     `json:"name"`
	EntityID        string     `json:"entity_id"`
	ACSURL          string     `json:"acs_url"`
	NameIDFormat    string     `json:"name_id_format"`
	NameIDAttribute string     `json:"name_id_attribute"`
	Certificate     string     `json:"certificate"`
	Status          string     `json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastLoginAt     *time.Time `json:"last_login_at"`
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

func (i *IdP) Pool() *pgxpool.Pool { return i.pool }

// toSP maps a sqlc-generated row to the API-facing ServiceProvider type.
func toSP(r dbgen.TenantSamlServiceProvider) *ServiceProvider {
	var lastLogin *time.Time
	if r.LastLoginAt.Valid {
		v := r.LastLoginAt.Time
		lastLogin = &v
	}
	return &ServiceProvider{
		ID:              r.ID,
		TenantID:        r.TenantID,
		Name:            r.Name,
		EntityID:        r.EntityID,
		ACSURL:          r.AcsUrl,
		NameIDFormat:    r.NameIDFormat,
		NameIDAttribute: r.NameIDAttribute,
		Certificate:     r.Certificate,
		Status:          r.Status,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
		LastLoginAt:     lastLogin,
	}
}

type CreateSPInput struct {
	Name            string `json:"name"`
	EntityID        string `json:"entity_id"`
	ACSURL          string `json:"acs_url"`
	NameIDFormat    string `json:"name_id_format"`
	NameIDAttribute string `json:"name_id_attribute"`
	Certificate     string `json:"certificate"`
	Status          string `json:"status"`
}

// check requires the ACS URL to pass validACSURL and a certificate, if given,
// to parse.
func (in *CreateSPInput) check() error {
	in.ACSURL = strings.TrimSpace(in.ACSURL)
	if !validACSURL(in.ACSURL) {
		return errs.ErrSAMLACSURLInvalid
	}
	if in.Certificate != "" {
		if _, err := parseCertificate(in.Certificate); err != nil {
			return errs.ErrSAMLCertificateInvalid
		}
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
	nidFmt := in.NameIDFormat
	if nidFmt == "" {
		nidFmt = nameIDEmail
	}
	nidAttr := in.NameIDAttribute
	if nidAttr == "" {
		nidAttr = "email"
	}
	r, err := i.q.WithTx(tx).InsertSamlSP(ctx, dbgen.InsertSamlSPParams{
		TenantID:        tenantID,
		Name:            in.Name,
		EntityID:        in.EntityID,
		AcsUrl:          in.ACSURL,
		NameIDFormat:    nidFmt,
		NameIDAttribute: nidAttr,
		Certificate:     in.Certificate,
		Status:          status,
	})
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

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

type UpdateSPInput struct {
	Name            *string `json:"name"`
	EntityID        *string `json:"entity_id"`
	ACSURL          *string `json:"acs_url"`
	NameIDFormat    *string `json:"name_id_format"`
	NameIDAttribute *string `json:"name_id_attribute"`
	Certificate     *string `json:"certificate"`
	Status          *string `json:"status"`
}

// check applies CreateSPInput's checks to the fields being changed.
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
	return nil
}

// UpdateSP changes the given fields of a service provider in tenantID within
// tx, refusing input that fails check.
func (i *IdP) UpdateSP(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID, in UpdateSPInput) (*ServiceProvider, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	r, err := i.q.WithTx(tx).UpdateSamlSP(ctx, dbgen.UpdateSamlSPParams{
		ID:              id,
		TenantID:        tenantID,
		Name:            in.Name,
		EntityID:        in.EntityID,
		AcsUrl:          in.ACSURL,
		NameIDFormat:    in.NameIDFormat,
		NameIDAttribute: in.NameIDAttribute,
		Certificate:     in.Certificate,
		Status:          in.Status,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

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

func (i *IdP) loadUser(ctx context.Context, userID uuid.UUID) (email, name string, tenantID uuid.UUID, err error) {
	row, err := i.q.GetUserForIdP(ctx, userID)
	if err != nil {
		return "", "", uuid.Nil, err
	}
	if row.DisplayName != nil {
		name = *row.DisplayName
	}
	if row.TenantID.Valid {
		tenantID = uuid.UUID(row.TenantID.Bytes)
	}
	return row.Email, name, tenantID, nil
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

// =====================================================================
// Assertion construction + signing
// =====================================================================

// buildSignedResponse constructs a SAML Response wrapping a signed Assertion.
// inResponseTo is empty for IdP-initiated SSO.
func (i *IdP) buildSignedResponse(idpEntity string, sp *ServiceProvider, acs, email, name, inResponseTo string) ([]byte, error) {
	now := time.Now().UTC()
	respID := "_" + uuid.NewString()
	assertID := "_" + uuid.NewString()
	notBefore := now.Add(-clockSkew).Format(time.RFC3339)
	notAfter := now.Add(assertionTTL).Format(time.RFC3339)
	nidFormat := sp.NameIDFormat
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
	nid.SetText(email)
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

	attrStmt := assertion.CreateElement("saml:AttributeStatement")
	addAttr := func(attrName, v string) {
		if v == "" {
			return
		}
		a := attrStmt.CreateElement("saml:Attribute")
		a.CreateAttr("Name", attrName)
		a.CreateAttr("NameFormat", attrNameFormatBasic)
		a.CreateElement("saml:AttributeValue").SetText(v)
	}
	addAttr("email", email)
	addAttr("name", name)

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
    <SingleSignOnService Binding="%s" Location="%s"/>
    <SingleSignOnService Binding="%s" Location="%s"/>
  </IDPSSODescriptor>
</EntityDescriptor>`,
		html.EscapeString(entity), h.IdP.signer.certB64, nameIDEmail,
		bindingRedirect, html.EscapeString(sso), bindingPOST, html.EscapeString(sso))
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Disposition", `attachment; filename="qeet-idp-metadata.xml"`)
	_, _ = w.Write([]byte(doc))
}

// idpSSO is the tenant's SingleSignOnService. It handles SP-initiated SSO (a
// SAMLRequest via HTTP-Redirect GET or HTTP-POST) and IdP-initiated SSO
// (?sp=<id|entityID>), for SPs of the path's tenant only. Without a hosted-login
// SSO cookie, the browser is bounced to the hosted login and returns here.
func (h *Handler) idpSSO(w http.ResponseWriter, r *http.Request) {
	if h.IdP == nil {
		httpx.WriteError(w, r, errs.ErrSAMLIdPNotConfigured)
		return
	}
	tenantID, err := h.idpTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := httpx.ParseForm(r, httpx.MaxSAMLBodyBytes); err != nil {
		httpx.WriteError(w, r, err)
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
			httpx.WriteError(w, r, errs.ErrSAMLAuthnRequestInvalid)
			return
		}
		inResponseTo = ar.ID
		acsOverride = strings.TrimSpace(ar.AssertionConsumerServiceURL)
		sp, lookupErr = h.IdP.lookupSPByEntityID(r.Context(), tenantID, strings.TrimSpace(ar.Issuer))
	} else if spKey := strings.TrimSpace(r.FormValue("sp")); spKey != "" {
		sp, lookupErr = h.IdP.lookupSP(r.Context(), tenantID, spKey)
	} else {
		httpx.WriteError(w, r, errs.ErrSAMLRequestParamMissing)
		return
	}
	if lookupErr != nil || sp == nil {
		// lookupErr is errs.ErrNotFound (no rows) or a real DB error → 404/500.
		err := lookupErr
		if err == nil {
			err = errs.ErrNotFound
		}
		httpx.WriteError(w, r, err)
		return
	}
	if sp.Status == "disabled" {
		httpx.WriteError(w, r, errs.ErrSAMLServiceProviderDisabled)
		return
	}
	// A supplied ACS URL must match the registered one (prevents redirecting a
	// signed assertion to an attacker-chosen endpoint).
	if acsOverride != "" && acsOverride != sp.ACSURL {
		httpx.WriteError(w, r, errs.ErrSAMLACSMismatch)
		return
	}

	base := h.publicBase(r)
	userID, ok := h.idpSessionUser(r)
	if !ok {
		ret, err := ssoReturnURL(base, r)
		if err != nil {
			httpx.WriteError(w, r, errs.ErrSAMLAuthnRequestInvalid)
			return
		}
		http.Redirect(w, r, h.IdP.loginBaseURL+"/login?return_to="+url.QueryEscape(ret), http.StatusFound)
		return
	}

	email, name, userTenant, err := h.IdP.loadUser(r.Context(), userID)
	if err != nil {
		slog.Error("saml idp sso: user lookup", "err", err, "user", userID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	if userTenant != sp.TenantID {
		httpx.WriteError(w, r, errs.ErrSAMLUserTenantMismatch)
		return
	}

	respXML, err := h.IdP.buildSignedResponse(idpEntityID(base, tenantID), sp, sp.ACSURL, email, name, inResponseTo)
	if err != nil {
		slog.Error("saml idp sso: build assertion", "err", err, "sp", sp.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
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
	if err := h.recordSPAudit(ctx, tx, r, tenantID, sp.ID, "saml.sp_created", map[string]any{"name": sp.Name, "entity_id": sp.EntityID}); err != nil {
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
	if err := h.recordSPAudit(ctx, tx, r, tenantID, sp.ID, "saml.sp_updated", map[string]any{"status": sp.Status}); err != nil {
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

func (h *Handler) recordSPAudit(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID, resourceID uuid.UUID, action string, meta map[string]any) error {
	actorID, actorType := auditActor(r)
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
