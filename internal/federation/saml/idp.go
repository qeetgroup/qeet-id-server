package saml

// Qeet ID as a SAML identity provider: an organization's registered SP sends the user to
// /saml/idp/{organizationID}/sso, the hosted-login SSO cookie authenticates them, and an
// assertion signed with goxmldsig (RSA-SHA256, exclusive c14n) is POSTed to the
// SP's ACS. Each organization is its own IdP entity; one signing key serves them all.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
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

// ServiceProvider is a downstream app that consumes Qeet ID as its IdP.
// Attributes are what its assertions carry beside the NameID, and with
// AssignmentRequired only the people assigned to it may sign in.
type ServiceProvider struct {
	ID                 uuid.UUID          `json:"id"`
	OrganizationID     uuid.UUID          `json:"organization_id"`
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

	// What Certificate is used for, and what it says about itself.
	RequireSignedRequests bool                `json:"require_signed_requests"`
	EncryptAssertions     bool                `json:"encrypt_assertions"`
	CertificateDetails    *CertificateDetails `json:"certificate_details"`
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
	gate         entitlements.PlanGate
	addresses    ipallow.AddressPolicy
	factors      FactorPolicy
}

// FactorPolicy reads a hosted-login session's sign-in and what second factor
// an organization still requires of it. Satisfied by *auth.Service.
type FactorPolicy interface {
	ResolveLoginSessionAt(ctx context.Context, raw string) (sessionID, userID uuid.UUID, signedInAt time.Time, err error)
	LoginSessionFactorShortfall(ctx context.Context, loginSessionID, userID, organizationID uuid.UUID) error
}

// SetSignInRules sets the organization rules an assertion is signed under, as
// OIDC authorize applies them: its address rules and its second-factor
// requirement. A nil one checks nothing.
func (i *IdP) SetSignInRules(addresses ipallow.AddressPolicy, factors FactorPolicy) {
	i.addresses, i.factors = addresses, factors
}

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (i *IdP) SetPlanGate(g entitlements.PlanGate) { i.gate = g }

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

// toSP maps a sqlc-generated row to the API-facing ServiceProvider type.
func toSP(r dbgen.OrganizationSamlServiceProvider) *ServiceProvider {
	return &ServiceProvider{
		ID:                 r.ID,
		OrganizationID:     r.OrganizationID,
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
		LastLoginAt:        r.LastLoginAt,

		RequireSignedRequests: r.RequireSignedRequests,
		EncryptAssertions:     r.EncryptAssertions,
		CertificateDetails:    certificateDetails(r.Certificate),
	}
}
