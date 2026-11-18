//go:build integration

package social

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/auth/authtest"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// browse sends a request as a browser holding cookies.
func browse(t *testing.T, h http.Handler, method, target string, cookies []*http.Cookie, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequestWithContext(dbtest.Context(t), method, target, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// socialFixture is a social sign-in service with a fake provider, its public
// and authenticated routes.
type socialFixture struct {
	svc    *Service
	idp    *identityProvider
	public http.Handler
	mount  func(chi.Router)
}

// fixtureChange changes the fixture's service dependencies, given its fake
// provider.
type fixtureChange func(d *Deps, idp *identityProvider)

// newSocialFixture returns the fixture, allowing return to app.example.test,
// its service's dependencies changed by each of with.
func newSocialFixture(t *testing.T, with ...fixtureChange) *socialFixture {
	t.Helper()
	pool := dbtest.Pool(t)
	idp := newIdentityProvider(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, pool, newAuthService(t, registrationPolicies(t)), func(d *Deps) {
		d.Cipher, d.AppBaseURL, d.Egress = box, "https://console.example.test", egress.DevelopmentPolicy()
		d.ReturnOrigins = []string{"https://app.example.test"}
		for _, change := range with {
			change(d, idp)
		}
	})
	h := &Handler{Service: svc, LoginBaseURL: "https://login.example.test", PublicBaseURL: "https://id.example.test",
		ActOnCheck: rbac.NewRepository(pool).CheckActOn}
	public := chi.NewRouter()
	h.MountPublic(public)
	return &socialFixture{svc: svc, idp: idp, public: public, mount: h.Mount}
}

// newAuthService is the sign-in service social sign-in goes through,
// following registration when it isn't nil (else nobody registers).
func newAuthService(t *testing.T, registration auth.RegistrationPolicy) *auth.Service {
	t.Helper()
	return authtest.New(t, dbtest.Pool(t), func(d *auth.Deps) {
		if registration != nil {
			d.Registration = registration
		}
	})
}

// registrationPolicies are the organizations' own registration policies.
func registrationPolicies(t *testing.T) *authpolicy.Service {
	t.Helper()
	policies, err := authpolicy.NewService(dbtest.Pool(t), authpolicy.NoBreachCheck{})
	if err != nil {
		t.Fatal(err)
	}
	return policies
}

// domainCapture is the domain capture bootstrap wires.
func domainCapture(t *testing.T) *domainverify.Service {
	t.Helper()
	pool := dbtest.Pool(t)
	capture, err := domainverify.NewService(pool, domainverify.Deps{
		Gate: allDomains{}, Owners: rbac.NewRepository(pool), MemberPermissions: identitylink.MemberPermissions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return capture
}

// allDomains includes custom domains in every plan.
type allDomains struct{}

func (allDomains) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return true, nil }

// platform gives the fixture's service the console provider name, signing in
// at its fake provider.
func platform(name string) fixtureChange {
	return func(d *Deps, idp *identityProvider) {
		d.Platform = append(d.Platform, PlatformOIDC(name, "qeet", "idp-client-secret", idp.URL+"/.well-known/openid-configuration"))
	}
}

// signIn runs a browser through a sign-in begun at start, the provider
// answering as person, and returns the callback's response.
func (f *socialFixture) signIn(t *testing.T, provider, start string, person userInfo) *httptest.ResponseRecorder {
	t.Helper()
	begun := browse(t, f.public, http.MethodGet, start, nil, nil)
	if begun.Code != http.StatusFound {
		t.Fatalf("start %s: %d %s", start, begun.Code, begun.Header().Get("Location"))
	}
	authURL := begun.Header().Get("Location")
	code := uuid.NewString()
	f.idp.expect(t, authURL, code, person)
	return browse(t, f.public, http.MethodGet, "/social/"+provider+"/callback?state="+url.QueryEscape(stateOf(authURL))+"&code="+code, begun.Result().Cookies(), nil)
}

// redirectQuery returns a redirect's target and query.
func redirectQuery(t *testing.T, rec *httptest.ResponseRecorder) (string, url.Values) {
	t.Helper()
	u, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil {
		t.Fatalf("want a redirect, got %d %s", rec.Code, rec.Body.String())
	}
	return u.Scheme + "://" + u.Host + u.Path, u.Query()
}

// verified marks a's address verified and returns the provider's claims for a.
func verified(t *testing.T, a dbtest.Account) userInfo {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	return userInfo{Subject: "sub-" + a.ID.String(), Email: a.Email, EmailVerified: true, Name: "Asha"}
}

// openOrganization creates an organization that lets people register themselves.
func openOrganization(t *testing.T) uuid.UUID {
	t.Helper()
	organization := dbtest.Organization(t)
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `INSERT INTO organization.auth_policy (organization_id, self_registration_enabled) VALUES ($1, TRUE)`, organization); err != nil {
		t.Fatalf("policy: %v", err)
	}
	return organization
}

// provisioningService returns the service reading each organization's registration
// policy and domain capture, as bootstrap wires it.
func provisioningService(t *testing.T) *Service {
	t.Helper()
	pool := dbtest.Pool(t)
	capture := domainCapture(t)
	return newTestService(t, pool, newAuthService(t, registrationPolicies(t)), func(d *Deps) { d.Capture = capture })
}

// addProvider gives organization the fixture's identity provider under name, an
// OpenID Connect provider found by its discovery URL, through the admin route.
func addProvider(t *testing.T, f *socialFixture, organization uuid.UUID, name string) {
	t.Helper()
	admin := dbtest.User(t, organization, organization)
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(admin.ID, organization), f.mount), http.MethodPost, "/social/providers", map[string]string{
		"provider": name, "client_id": "qeet", "client_secret": "idp-client-secret",
		"discovery_url": f.idp.URL + "/.well-known/openid-configuration",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("add provider %s: %d %s", name, rec.Code, rec.Body.String())
	}
}

// requireSSO makes organization require single sign-on on its verified domains,
// through an active SAML connection.
func requireSSO(t *testing.T, organization uuid.UUID) {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	if _, err := pool.Exec(ctx, `UPDATE organization.domains SET sso_enabled = TRUE WHERE organization_id = $1`, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO organization.saml_connections (organization_id, name, idp_entity_id, idp_sso_url, idp_certificate, status)
		VALUES ($1, 'Okta', 'https://idp.example.test', 'https://idp.example.test/sso', 'cert', 'active')`, organization); err != nil {
		t.Fatal(err)
	}
}

// capturing gives the fixture's service the domain capture bootstrap wires.
func capturing(t *testing.T) fixtureChange {
	t.Helper()
	capture := domainCapture(t)
	return func(d *Deps, _ *identityProvider) { d.Capture = capture }
}

// breakGlass names a as a member of organization who keeps their own sign-in methods.
func breakGlass(t *testing.T, organization uuid.UUID, a dbtest.Account) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `INSERT INTO organization.break_glass_members (organization_id, user_id) VALUES ($1, $2)`, organization, a.ID); err != nil {
		t.Fatal(err)
	}
}

// claims is what a provider asserts for a new subject at email, as verified.
func claims(email string) userInfo {
	return userInfo{Subject: uuid.NewString(), Email: email, EmailVerified: true}
}

// proved reports whether the account's address is marked verified.
func proved(t *testing.T, id uuid.UUID) bool {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND email_verified_at IS NOT NULL`, id) == 1
}
