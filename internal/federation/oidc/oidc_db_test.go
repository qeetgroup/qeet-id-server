//go:build integration

package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

const testRedirect = "https://app.example.test/callback"

// registerClient registers a confidential client in organization and returns it with
// its secret.
func registerClient(t *testing.T, svc *Service, organization uuid.UUID) (*Client, string) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	client, secret, err := svc.RegisterClient(ctx, tx, CreateClientInput{
		OrganizationID: organization, Name: "App", RedirectURIs: []string{testRedirect},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return client, secret
}

const (
	resourceA = "https://api-a.example.test"
	resourceB = "https://api-b.example.test"
	deviceIP  = "192.0.2.10"
)

// registerClientWith registers a client from in and returns it with its secret
// ("" for a public client).
func registerClientWith(t *testing.T, svc *Service, in CreateClientInput) (*Client, string) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if in.Name == "" {
		in.Name = "App"
	}
	if in.RedirectURIs == nil {
		in.RedirectURIs = []string{testRedirect}
	}
	client, secret, err := svc.RegisterClient(ctx, tx, in)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return client, secret
}

// redeemCode runs an authorization and code exchange for user, naming resource
// at the token endpoint ("" for none), and returns the tokens.
func redeemCode(t *testing.T, svc *Service, client *Client, secret string, userID uuid.UUID, resource string) *TokenResponse {
	t.Helper()
	ctx := dbtest.Context(t)
	verifier, challenge, err := codes.URLToken()
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	code, _, err := svc.Authorize(ctx, userID, client.ClientID, testRedirect, []string{"openid"}, "n-1", challenge, "S256")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, resource)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return issued
}

func wantOAuthError(t *testing.T, what string, err error, code string) {
	t.Helper()
	var oe *oauthError
	if !errors.As(err, &oe) || oe.Code != code {
		t.Errorf("%s: %v, want %s", what, err, code)
	}
}

const (
	loginBase  = "https://login.example.test"
	publicBase = "https://id.example.test"
)

// provider is the OpenID provider as browsers and applications reach it: the
// service, a real hosted-login session service, the public routes and the
// authenticated ones.
type provider struct {
	svc      *Service
	sessions *auth.Service
	public   http.Handler
	mount    func(chi.Router)
}

// newProvider returns the provider wired as production wires it, sign-out
// notices included.
func newProvider(t *testing.T) *provider {
	t.Helper()
	pool := dbtest.Pool(t)
	issuer := dbtest.Issuer(t)
	svc := NewService(pool, issuer)
	sessions := auth.NewService(pool, user.NewRepository(pool), issuer)
	sessions.SetSignOutNotifier(svc)
	h := &Handler{Service: svc, Sessions: sessions, LoginBaseURL: loginBase, PublicBaseURL: publicBase}
	public := chi.NewRouter()
	h.MountPublic(public)
	h.MountBrowser(public)
	h.MountToken(public)
	return &provider{svc: svc, sessions: sessions, public: public, mount: h.Mount}
}

// signIn opens a hosted-login session for userID and returns the browser's
// cookie and the session's id.
func (p *provider) signIn(t *testing.T, userID uuid.UUID) (*http.Cookie, uuid.UUID) {
	t.Helper()
	ctx := dbtest.Context(t)
	raw, err := p.sessions.CreateLoginSession(ctx, userID, "192.0.2.1", "test")
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	sessionID, _, err := p.sessions.ResolveLoginSessionWithID(ctx, raw)
	if err != nil {
		t.Fatalf("resolve the session: %v", err)
	}
	return &http.Cookie{Name: auth.LoginSessionCookie, Value: raw}, sessionID
}

// asApplication serves the authenticated routes to the bearer of an access
// token issued to an application, as the API's token middleware would.
func (p *provider) asApplication(t *testing.T, accessToken string) http.Handler {
	t.Helper()
	claims, err := p.svc.issuer.VerifyAccessAnyAudience(accessToken)
	if err != nil {
		t.Fatalf("verify the access token: %v", err)
	}
	principal := dbtest.Principal(claims.UserID, claims.OrganizationID)
	principal.Scopes = strings.Fields(claims.Scope)
	return dbtest.Serve(principal, p.mount)
}

// browse sends a request as a browser holding cookie (nil for none), with
// body (when not nil) as JSON.
func browse(t *testing.T, h http.Handler, method, target string, cookie *http.Cookie, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatalf("encode the body: %v", err)
		}
	}
	req := httptest.NewRequestWithContext(dbtest.Context(t), method, target, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// postForm posts form to path, with Basic credentials when user is not
// empty.
func postForm(t *testing.T, h http.Handler, path string, form url.Values, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(dbtest.Context(t), http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// redirected returns where a 302 sends the browser, without the query, and
// the query; any other answer fails t.
func redirected(t *testing.T, rec *httptest.ResponseRecorder) (string, url.Values) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("want a redirect, got %d %s", rec.Code, rec.Body.String())
	}
	return splitURL(t, rec.Header().Get("Location"))
}

// verifyDomain records domain as verified by organization.
func verifyDomain(t *testing.T, organization uuid.UUID, domain string) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(context.Background(), `
		INSERT INTO organization.domains (organization_id, domain, verification_token, verified_at) VALUES ($1, $2, 'token', NOW())`, organization, domain); err != nil {
		t.Fatal(err)
	}
}

// pendingBackchannel starts a backchannel request of client for a and returns
// its auth_req_id and the id a's approval names.
func pendingBackchannel(t *testing.T, svc *Service, client *Client, secret string, a dbtest.Account) (string, uuid.UUID) {
	t.Helper()
	ctx := dbtest.Context(t)
	started, err := svc.BackchannelAuthorize(ctx, client.ClientID, secret, a.Email, "openid", "")
	if err != nil {
		t.Fatalf("backchannel authorize: %v", err)
	}
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `SELECT id FROM auth.oidc_ciba_requests WHERE auth_req_id_hash = $1`,
		codes.Hash(started.AuthReqID)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return started.AuthReqID, id
}

// refuseAudit makes recording action in organization fail until t ends, so a
// test can check that the change the row describes rolls back with it.
func refuseAudit(t *testing.T, organization uuid.UUID, action string) {
	t.Helper()
	owner, ctx := dbtest.Owner(t), dbtest.Context(t)
	name := "refuse_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	for _, ddl := range []string{
		`CREATE FUNCTION public.` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit refused'; END $$`,
		`CREATE TRIGGER ` + name + ` BEFORE INSERT ON audit.events FOR EACH ROW
		 WHEN (NEW.organization_id = '` + organization.String() + `' AND NEW.action = '` + action + `')
		 EXECUTE FUNCTION public.` + name + `()`,
	} {
		if _, err := owner.Exec(ctx, ddl); err != nil {
			t.Fatalf("refuse %s: %v", action, err)
		}
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), `DROP TRIGGER `+name+` ON audit.events`)
		_, _ = owner.Exec(context.Background(), `DROP FUNCTION public.`+name+`()`)
	})
}

// recordedBy counts organization's audit rows of action about resource by
// actor, from its address.
func recordedBy(t *testing.T, organization uuid.UUID, action string, resource uuid.UUID, actor audit.Actor) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND resource_id = $3
		AND actor_user_id = $4 AND actor_type = $5 AND host(ip) = $6 AND request_id = $7`,
		organization, action, resource, actor.UserID, actor.Type, actor.IP, actor.RequestID)
}
