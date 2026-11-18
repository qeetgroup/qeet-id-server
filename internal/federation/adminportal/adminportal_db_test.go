//go:build integration

package adminportal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/auth/authtest"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/federation/directory"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// branded is an organization's login branding with only a primary colour.
type branded struct{}

func (branded) LoginBranding(context.Context, uuid.UUID) (string, string, string, string) {
	return "", "#123456", "", ""
}

// idpCertificate returns a throwaway PEM certificate for an identity provider.
func idpCertificate(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// portal sends a request to the public portal with the given bearer token or
// session cookie.
func portal(t *testing.T, h http.Handler, method, path, bearer, session string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequestWithContext(dbtest.Context(t), method, "/v1"+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: portalSessionCookie, Value: session})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// everyPlan includes every feature.
type everyPlan struct{}

func (everyPlan) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return true, nil }

// noSeatLimit leaves group membership uncapped.
type noSeatLimit struct{}

func (noSeatLimit) SeatLimit(context.Context, uuid.UUID) (int, error) { return -1, nil }

func (noSeatLimit) WithinSeats(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ int, change func() error) error {
	return change()
}

// newSAML is the SAML service the portal sets connections up through, on a
// plan gate says the features of.
func newSAML(t *testing.T, gate entitlements.PlanGate) *saml.Service {
	t.Helper()
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := saml.NewService(saml.Deps{
		Pool: pool, Auth: newAuthService(t), Cipher: box, Gate: gate,
		Egress: egress.PublicPolicy(), AppBaseURL: "https://id.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// newSCIM is the SCIM service whose tokens the portal manages.
func newSCIM(t *testing.T) *scim.Service {
	t.Helper()
	pool := dbtest.Pool(t)
	store, err := directory.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := scim.NewService(scim.Deps{
		Pool: pool, Users: user.NewRepository(pool), Signals: sessionsignal.New(nil),
		Gate: everyPlan{}, Seats: noSeatLimit{}, Mapper: store, Observer: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// newAuthService is the sign-in service SAML sign-ins go through.
func newAuthService(t *testing.T) *auth.Service {
	t.Helper()
	return authtest.New(t, dbtest.Pool(t))
}

// newDomains is the domain service on a plan with custom domains, with the
// platform's owner check and member permissions.
func newDomains(t *testing.T) *domainverify.Service {
	t.Helper()
	pool := dbtest.Pool(t)
	domains, err := domainverify.NewService(pool, domainverify.Deps{
		Gate: everyPlan{}, Owners: rbac.NewRepository(pool), MemberPermissions: identitylink.MemberPermissions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return domains
}
