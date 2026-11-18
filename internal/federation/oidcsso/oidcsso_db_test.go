//go:build integration

package oidcsso

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/auth/authtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// rp is the relying party: the service, its routes and the cookies of the one
// browser signing in.
type rp struct {
	svc     *Service
	plan    *plan
	handler *Handler
	public  chi.Router
	browser []*http.Cookie
}

// newRP returns the relying party, its service's dependencies changed by
// each of with.
func newRP(t *testing.T, with ...func(*Deps)) *rp {
	t.Helper()
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	plans := &plan{}
	svc := newTestService(t, pool, newAuthService(t), func(d *Deps) {
		d.Cipher, d.Gate, d.Egress = box, plans, egress.DevelopmentPolicy()
		for _, change := range with {
			change(d)
		}
	})
	h := &Handler{Service: svc, PublicBaseURL: testPublicBase}
	public := chi.NewRouter()
	h.MountPublic(public)
	return &rp{svc: svc, plan: plans, handler: h, public: public}
}

// newAuthService is the sign-in service connection sign-ins go through.
func newAuthService(t *testing.T) *auth.Service {
	t.Helper()
	return authtest.New(t, dbtest.Pool(t))
}

// send serves req from the browser, keeping the cookies it is given.
func (s *rp) send(req *http.Request) *httptest.ResponseRecorder {
	for _, c := range s.browser {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.public.ServeHTTP(rec, req)
	for _, set := range rec.Result().Cookies() {
		kept := s.browser[:0]
		for _, c := range s.browser {
			if c.Name != set.Name {
				kept = append(kept, c)
			}
		}
		s.browser = kept
		if set.MaxAge >= 0 {
			s.browser = append(s.browser, set)
		}
	}
	return rec
}

// admin returns organization's administration routes as a new admin of it.
func (s *rp) admin(t *testing.T, organization uuid.UUID) http.Handler {
	t.Helper()
	return dbtest.Serve(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization), s.handler.Mount)
}

// connect has organization's admin create an active connection to idp, with change
// applied to the request.
func (s *rp) connect(t *testing.T, organization uuid.UUID, idp *fakeIdP, change map[string]any) Connection {
	t.Helper()
	body := map[string]any{
		"name": "Entra", "issuer": idp.URL, "client_id": testClientID, "client_secret": testClientSecret,
		"status": "active", "claim_mapping": map[string]any{"groups": "groups"},
	}
	for k, v := range change {
		body[k] = v
	}
	rec := dbtest.Do(t, s.admin(t, organization), http.MethodPost, "/organizations/"+organization.String()+"/oidc-connections", body)
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create the connection: %d %s", rec.Code, rec.Body.String())
	}
	return conn
}

// begin starts a sign-in through connID as the browser and returns the
// provider URL it is sent to.
func (s *rp) begin(t *testing.T, connID uuid.UUID) string {
	t.Helper()
	rec := s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+connID.String()+"/login", nil))
	location := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(location, testAuthorizeBase+"?") {
		t.Fatalf("login: %d %s %s; want a redirect to the provider", rec.Code, location, rec.Body.String())
	}
	u, _ := url.Parse(location)
	if got := u.Query().Get("redirect_uri"); got != testPublicBase+"/v1/oidc-connections/"+connID.String()+"/callback" {
		t.Fatalf("redirect_uri %q; want this connection's callback", got)
	}
	return location
}

// callback brings the provider's answer to the sign-in authURL began back to
// connID's callback as the browser, with extra query parameters.
func (s *rp) callback(t *testing.T, connID uuid.UUID, authURL, code string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	u, _ := url.Parse(authURL)
	q := url.Values{"state": {u.Query().Get("state")}, "code": {code}}
	for k, v := range extra {
		q[k] = v
	}
	return s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+connID.String()+"/callback?"+q.Encode(), nil))
}

// answer runs a sign-in through conn, the provider issuing the token claims
// returns, and returns the callback's response.
func (s *rp) answer(t *testing.T, idp *fakeIdP, connID uuid.UUID, claims func(nonce string) jwt.MapClaims) *httptest.ResponseRecorder {
	t.Helper()
	authURL := s.begin(t, connID)
	code := "code-" + uuid.NewString()
	idp.expect(t, authURL, code, claims, nil, "")
	return s.callback(t, connID, authURL, code, nil)
}

// exchange trades a one-time login code.
func (s *rp) exchange(t *testing.T, code string) *httptest.ResponseRecorder {
	t.Helper()
	return dbtest.Do(t, s.public, http.MethodPost, "/oidc-connections/exchange", map[string]string{"code": code})
}

// signIn runs a whole sign-in and returns the token pair it buys.
func (s *rp) signIn(t *testing.T, idp *fakeIdP, connID uuid.UUID, claims func(nonce string) jwt.MapClaims) auth.TokenPair {
	t.Helper()
	rec := s.exchange(t, loginCode(t, s.answer(t, idp, connID, claims)))
	var pair auth.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.AccessToken == "" {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
	}
	return pair
}

// loginCode returns the one-time code a completed sign-in hands the console.
func loginCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	location := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(location, callbackStart) || len(location) == len(callbackStart) {
		t.Fatalf("callback: %d %s %s; want the console's callback with a code", rec.Code, location, rec.Body.String())
	}
	return strings.TrimPrefix(location, callbackStart)
}

// refused fails unless rec answers with code.
func refused(t *testing.T, what string, rec *httptest.ResponseRecorder, code string) {
	t.Helper()
	if rec.Code/100 != 4 && rec.Code/100 != 5 || !strings.Contains(rec.Body.String(), code) {
		t.Errorf("%s: %d %s %s, want %s", what, rec.Code, rec.Header().Get("Location"), rec.Body.String(), code)
	}
}

// as returns claims for the provider's correct token, changed by change.
func as(idp *fakeIdP, sub, email string, change func(jwt.MapClaims)) func(string) jwt.MapClaims {
	return func(nonce string) jwt.MapClaims {
		claims := idp.claimsFor(nonce, sub, email)
		if change != nil {
			change(claims)
		}
		return claims
	}
}

func verify(t *testing.T, userID uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
}

// failures counts the failed sign-ins recorded in organization for reason.
func failures(t *testing.T, organization uuid.UUID, reason string) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.sign_in_failed'
		AND metadata->>'method' = 'oidc' AND metadata->>'reason' = $2`, organization, reason)
}

// expect makes the token endpoint redeem code, for the sign-in authURL began,
// with an ID token: the one claims returns for the nonce authURL carries,
// signed as sign would.
func (p *fakeIdP) expect(t *testing.T, authURL, code string, claims func(nonce string) jwt.MapClaims, signer crypto.Signer, kid string) {
	t.Helper()
	u, err := url.Parse(authURL)
	q := u.Query()
	if err != nil || !strings.HasPrefix(authURL, testAuthorizeBase+"?") || q.Get("code_challenge_method") != "S256" ||
		q.Get("client_id") != testClientID || q.Get("response_type") != "code" || q.Get("nonce") == "" || q.Get("state") == "" ||
		!strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		t.Fatalf("authorization URL %q; want the provider's, with PKCE, a state, a nonce and openid", authURL)
	}
	token := p.sign(t, claims(q.Get("nonce")), signer, kid)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending[code] = pendingCode{challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri"), token: token}
}

const (
	testAppBase    = "https://console.example.test"           // where a sign-in hands its code
	testPublicBase = "https://id.example.test"                // this API's public origin
	callbackStart  = testAppBase + "/sso/callback#oidc_code=" // a completed sign-in's redirect, before the code
)
