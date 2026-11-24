package saml

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// allPlans includes single sign-on in every plan.
type allPlans struct{}

func (allPlans) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return true, nil }

// openAddresses lets every address sign in.
type openAddresses struct{}

func (openAddresses) CheckSignIn(context.Context, uuid.UUID, uuid.UUID, string, string) error {
	return nil
}

func (openAddresses) CheckSignInTx(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, string, string) error {
	return nil
}

// factorsMet finds every session sessions resolves to have met each second
// factor an organization requires.
type factorsMet struct{ sessions SessionResolver }

func (f factorsMet) ResolveLoginSessionAt(ctx context.Context, raw string) (uuid.UUID, uuid.UUID, time.Time, error) {
	userID, err := f.sessions.ResolveLoginSession(ctx, raw)
	return uuid.New(), userID, time.Now(), err
}

func (factorsMet) LoginSessionFactorShortfall(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error {
	return nil
}

// testCipher seals what the tests store.
func testCipher(t testing.TB) *envelope.Cipher {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

// testDeps are the service's dependencies on pool, signing people in through
// authSvc, on a plan with single sign-on and no hosted login.
func testDeps(t testing.TB, pool *pgxpool.Pool, authSvc *authentication.Service) Deps {
	return Deps{
		Pool: pool, Auth: authSvc, Cipher: testCipher(t), Gate: allPlans{},
		Egress: egress.PublicPolicy(), AppBaseURL: "https://console.example.test",
	}
}

// newTestService is the service on pool signing people in through authSvc,
// its dependencies changed by each of with.
func newTestService(t testing.TB, pool *pgxpool.Pool, authSvc *authentication.Service, with ...func(*Deps)) *Service {
	t.Helper()
	d := testDeps(t, pool, authSvc)
	for _, change := range with {
		change(&d)
	}
	service, err := NewService(d)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// testIdPDeps are the identity provider's dependencies on pool, resolving
// hosted-login sessions with sessions: every address allowed, every factor met
// and single sign-on in every plan.
func testIdPDeps(t testing.TB, pool *pgxpool.Pool, sessions SessionResolver) IdPDeps {
	t.Helper()
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatal(err)
	}
	return IdPDeps{
		Pool: pool, KeyPEM: keyPEM, CertPEM: certPEM, LoginBaseURL: "https://login.id.qeet.in",
		Sessions: sessions, Addresses: openAddresses{}, Factors: factorsMet{sessions}, Gate: allPlans{},
	}
}

// newTestIdP is the identity provider on pool resolving sessions with
// sessions, its dependencies changed by each of with.
func newTestIdP(t testing.TB, pool *pgxpool.Pool, sessions SessionResolver, with ...func(*IdPDeps)) *IdP {
	t.Helper()
	d := testIdPDeps(t, pool, sessions)
	for _, change := range with {
		change(&d)
	}
	idp, err := NewIdP(d)
	if err != nil {
		t.Fatal(err)
	}
	return idp
}

// TestConstructorsRefuseMissingDependencies checks that neither the service
// nor the identity provider is built without any one of its required
// dependencies, and that the error names it.
func TestConstructorsRefuseMissingDependencies(t *testing.T) {
	for _, name := range []string{"Pool", "Auth", "Cipher", "Gate", "Egress", "AppBaseURL"} {
		d := testDeps(t, new(pgxpool.Pool), new(authentication.Service))
		reflect.ValueOf(&d).Elem().FieldByName(name).SetZero()
		if _, err := NewService(d); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("service built without %s: %v", name, err)
		}
	}
	newTestService(t, new(pgxpool.Pool), new(authentication.Service))
	idp := testIdPDeps(t, new(pgxpool.Pool), new(authentication.Service))
	for _, name := range []string{"Pool", "LoginBaseURL", "Sessions", "Addresses", "Factors", "Gate"} {
		d := idp
		reflect.ValueOf(&d).Elem().FieldByName(name).SetZero()
		if _, err := NewIdP(d); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("identity provider built without %s: %v", name, err)
		}
	}
	d := idp
	d.KeyPEM = ""
	if _, err := NewIdP(d); err == nil {
		t.Error("identity provider built without a signing key")
	}
	if _, err := NewIdP(idp); err != nil {
		t.Errorf("identity provider with every dependency: %v", err)
	}
}
