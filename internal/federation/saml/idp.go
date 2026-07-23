// IdP side of SAML 2.0: Qeet ID acting as an identity provider (SSO source) for
// downstream Service Providers — the inverse of saml.go. A tenant registers an SP
// (EntityID + ACS URL); the SP sends users to /saml/idp/sso, we authenticate them
// via the same hosted-login SSO cookie the OIDC provider uses, then sign a SAML
// assertion and POST it to the SP's ACS. Assertions are signed RSA-SHA256 +
// exclusive c14n via goxmldsig (broadest SP compatibility) — we never hand-roll XML-DSig.
package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
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

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
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
	confirmationBearer  = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	authnCtxPassword    = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
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
	certB64 string // base64 DER, for metadata <X509Certificate>
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

// GenerateIdPKeyPEM mints a fresh RSA-2048 key + 10-year self-signed cert. Used
// to bootstrap an ephemeral signing identity in dev when SAML_IDP_KEY is unset.
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

// IdP issues SAML assertions and manages the SP registry.
type IdP struct {
	pool         *pgxpool.Pool
	q            *dbgen.Queries
	signer       *idpSigner
	sessions     SessionResolver
	loginBaseURL string
}

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

func (i *IdP) CreateSP(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, in CreateSPInput) (*ServiceProvider, error) {
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

func (i *IdP) UpdateSP(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID, in UpdateSPInput) (*ServiceProvider, error) {
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

// lookupSPByEntityID resolves a (non-disabled) SP by its EntityID for the SSO
// endpoint, which isn't tenant-scoped in the URL.
func (i *IdP) lookupSPByEntityID(ctx context.Context, entityID string) (*ServiceProvider, error) {
	r, err := i.q.GetSamlSPByEntityID(ctx, entityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

// lookupSP resolves by provider UUID (IdP-initiated ?sp=<uuid>) or EntityID.
func (i *IdP) lookupSP(ctx context.Context, key string) (*ServiceProvider, error) {
	if id, err := uuid.Parse(key); err == nil {
		r, err := i.q.GetSamlSPByUUID(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		return toSP(r), nil
	}
	return i.lookupSPByEntityID(ctx, key)
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

	// --- Assertion (signed standalone, then embedded) ---
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

	// Sign the assertion in its FINAL position inside the Response, so the
	// canonical form the SP validates matches exactly what we signed (signing a
	// detached element then embedding it changes the namespace context and
	// breaks verification). Then swap in the signed copy and move ds:Signature
	// to immediately follow saml:Issuer (SAML schema order; the enveloped
	// transform excludes the signature from its own digest, so this is safe).
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

// moveSignatureAfterIssuer reorders the assertion's children so ds:Signature
// immediately follows saml:Issuer (the SAML/XSD-mandated position that strict
// SPs like ADFS require). It manipulates the exported Child token slice
// directly: goxmldsig appends the signature with a raw slice append that leaves
// etree's index bookkeeping stale, so RemoveChild/InsertChildAt would duplicate
// it. The enveloped-signature transform excludes the signature from its own
// digest, so moving it doesn't invalidate the signature.
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

// decodeAuthnRequest base64-decodes (and, for the redirect binding, inflates)
// a SAMLRequest.
func decodeAuthnRequest(encoded, method string) (*authnRequest, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if method == http.MethodGet {
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(fr); err != nil {
			return nil, err
		}
		raw = buf.Bytes()
	}
	var ar authnRequest
	if err := xml.Unmarshal(raw, &ar); err != nil {
		return nil, err
	}
	return &ar, nil
}

func idpEntityID(r *http.Request) string { return publicBase(r) + "/saml/idp" }
func idpSSOURL(r *http.Request) string   { return publicBase(r) + "/saml/idp/sso" }
func currentURL(r *http.Request) string  { return publicBase(r) + r.URL.RequestURI() }

func writePostForm(w http.ResponseWriter, acs, samlResponse, relayState string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Signing in…</title></head>`)
	b.WriteString(`<body onload="document.forms[0].submit()">`)
	b.WriteString(`<form method="POST" action="` + html.EscapeString(acs) + `">`)
	b.WriteString(`<input type="hidden" name="SAMLResponse" value="` + html.EscapeString(samlResponse) + `"/>`)
	if relayState != "" {
		b.WriteString(`<input type="hidden" name="RelayState" value="` + html.EscapeString(relayState) + `"/>`)
	}
	b.WriteString(`<noscript><button type="submit">Continue</button></noscript></form></body></html>`)
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

// idpMetadata serves this IdP's SAML metadata (EntityDescriptor) for SPs to
// import: the signing cert + SSO endpoints.
func (h *Handler) idpMetadata(w http.ResponseWriter, r *http.Request) {
	if h.IdP == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented.WithDetail("saml idp not configured"))
		return
	}
	entity := idpEntityID(r)
	sso := idpSSOURL(r)
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

// idpSSO is the SingleSignOnService. It handles SP-initiated SSO (a SAMLRequest
// via HTTP-Redirect GET or HTTP-POST) and IdP-initiated SSO (?sp=<id|entityID>).
// The user is authenticated by the hosted-login SSO cookie; if absent, the
// browser is bounced to the hosted login and returns here afterward.
func (h *Handler) idpSSO(w http.ResponseWriter, r *http.Request) {
	if h.IdP == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented.WithDetail("saml idp not configured"))
		return
	}
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid request"))
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
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid SAMLRequest"))
			return
		}
		inResponseTo = ar.ID
		acsOverride = strings.TrimSpace(ar.AssertionConsumerServiceURL)
		sp, lookupErr = h.IdP.lookupSPByEntityID(r.Context(), strings.TrimSpace(ar.Issuer))
	} else if spKey := strings.TrimSpace(r.FormValue("sp")); spKey != "" {
		sp, lookupErr = h.IdP.lookupSP(r.Context(), spKey)
	} else {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("missing SAMLRequest or sp parameter"))
		return
	}
	if lookupErr != nil || sp == nil {
		// lookupErr is errs.ErrNotFound (no rows) or a real DB error → 404/500.
		err := lookupErr
		if err == nil {
			err = errs.ErrNotFound.WithDetail("unknown service provider")
		}
		httpx.WriteError(w, r, err)
		return
	}
	if sp.Status == "disabled" {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("service provider disabled"))
		return
	}
	// A supplied ACS URL must match the registered one (prevents redirecting a
	// signed assertion to an attacker-chosen endpoint).
	if acsOverride != "" && acsOverride != sp.ACSURL {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("AssertionConsumerServiceURL does not match registration"))
		return
	}

	userID, ok := h.idpSessionUser(r)
	if !ok {
		ret := url.QueryEscape(currentURL(r))
		http.Redirect(w, r, h.IdP.loginBaseURL+"/login?return_to="+ret, http.StatusFound)
		return
	}

	email, name, tenantID, err := h.IdP.loadUser(r.Context(), userID)
	if err != nil {
		slog.Error("saml idp sso: user lookup", "err", err, "user", userID)
		httpx.WriteError(w, r, errs.ErrInternal)
		return
	}
	if tenantID != sp.TenantID {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("user is not a member of this service provider's tenant"))
		return
	}

	respXML, err := h.IdP.buildSignedResponse(idpEntityID(r), sp, sp.ACSURL, email, name, inResponseTo)
	if err != nil {
		slog.Error("saml idp sso: build assertion", "err", err, "sp", sp.ID)
		httpx.WriteError(w, r, errs.ErrInternal)
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
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("name, entity_id and acs_url are required"))
		return
	}
	if in.Certificate != "" {
		if _, err := parseCertificate(in.Certificate); err != nil {
			httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("certificate is not a valid X.509 certificate"))
			return
		}
	}
	ctx := r.Context()
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
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
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
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in UpdateSPInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Status != nil && *in.Status != "draft" && *in.Status != "active" && *in.Status != "disabled" {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("status must be draft, active or disabled"))
		return
	}
	if in.Certificate != nil && *in.Certificate != "" {
		if _, err := parseCertificate(*in.Certificate); err != nil {
			httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("certificate is not a valid X.509 certificate"))
			return
		}
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
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
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
