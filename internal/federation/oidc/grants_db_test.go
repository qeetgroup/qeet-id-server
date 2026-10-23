//go:build integration

package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/risk/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

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

func registerResources(t *testing.T, svc *Service, tenant uuid.UUID, identifiers ...string) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	for _, id := range identifiers {
		if _, err := svc.CreateResource(ctx, tx, tenant, CreateResourceInput{Identifier: id, Name: id}); err != nil {
			t.Fatalf("create resource %s: %v", id, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
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

// TestRefreshKeepsTheGrantsResource checks that a refresh can carry forward or
// repeat the resource its grant is bound to while it is registered, and can't
// name another.
func TestRefreshKeepsTheGrantsResource(t *testing.T) {
	ctx := dbtest.Context(t)
	issuer := dbtest.Issuer(t)
	svc := NewService(dbtest.Pool(t), issuer)
	tenant := dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	client, secret := registerClient(t, svc, tenant)
	registerResources(t, svc, tenant, resourceA, resourceB)

	bound := redeemCode(t, svc, client, secret, user.ID, resourceA)
	_, err := svc.RefreshToken(ctx, client.ClientID, secret, bound.RefreshToken, resourceB)
	wantOAuthError(t, "refresh naming another resource", err, "invalid_target")

	// The refused request spent nothing; the bound resource carries forward.
	carried, err := svc.RefreshToken(ctx, client.ClientID, secret, bound.RefreshToken, "")
	if err != nil {
		t.Fatalf("refresh carrying the resource forward: %v", err)
	}
	if _, err := issuer.VerifyAccessFor(carried.AccessToken, resourceA); err != nil {
		t.Errorf("carried-forward access token is not for %s: %v", resourceA, err)
	}
	repeated, err := svc.RefreshToken(ctx, client.ClientID, secret, carried.RefreshToken, resourceA)
	if err != nil {
		t.Fatalf("refresh repeating the bound resource: %v", err)
	}
	if _, err := issuer.VerifyAccessFor(repeated.AccessToken, resourceA); err != nil {
		t.Errorf("repeated-resource access token is not for %s: %v", resourceA, err)
	}

	// A grant bound to no resource can't gain one on refresh.
	unbound := redeemCode(t, svc, client, secret, user.ID, "")
	_, err = svc.RefreshToken(ctx, client.ClientID, secret, unbound.RefreshToken, resourceA)
	wantOAuthError(t, "refresh of an unbound grant naming a resource", err, "invalid_target")
	plain, err := svc.RefreshToken(ctx, client.ClientID, secret, unbound.RefreshToken, "")
	if err != nil {
		t.Fatalf("refresh of an unbound grant: %v", err)
	}
	if _, err := issuer.VerifyAccess(plain.AccessToken); err != nil {
		t.Errorf("unbound grant's access token is not for the platform: %v", err)
	}

	// Once the bound resource is removed, a refresh carrying it forward is
	// refused like one naming it.
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM auth.oidc_resources WHERE tenant_id = $1 AND identifier = $2`, tenant, resourceA); err != nil {
		t.Fatal(err)
	}
	_, err = svc.RefreshToken(ctx, client.ClientID, secret, repeated.RefreshToken, "")
	wantOAuthError(t, "refresh carrying a removed resource forward", err, "invalid_target")
}

// TestDevicePollingAuthenticatesConfidentialClients checks that collecting a
// device grant's tokens needs a confidential client's secret, and a public
// client's device_code alone.
func TestDevicePollingAuthenticatesConfidentialClients(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	grants := []string{"urn:ietf:params:oauth:grant-type:device_code"}

	approved := func(clientID string) string {
		t.Helper()
		raw, userCode, _, err := svc.DeviceAuthorize(ctx, clientID, nil)
		if err != nil {
			t.Fatalf("device authorize: %v", err)
		}
		if err := svc.DecideDevice(ctx, user.ID, userCode, true, deviceIP); err != nil {
			t.Fatalf("approve device: %v", err)
		}
		return raw
	}

	confidential, secret := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, GrantTypes: grants})
	deviceCode := approved(confidential.ClientID)
	for name, presented := range map[string]string{"no secret": "", "a wrong secret": "wrong-secret"} {
		if _, err := svc.DeviceToken(ctx, confidential.ClientID, presented, deviceCode, deviceIP); !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Errorf("confidential client polling with %s: %v, want %v", name, err, errs.ErrOIDCClientAuthFailed)
		}
	}
	if issued, err := svc.DeviceToken(ctx, confidential.ClientID, secret, deviceCode, deviceIP); err != nil || issued.AccessToken == "" {
		t.Fatalf("confidential client polling with its secret: %+v, %v", issued, err)
	}

	public, _ := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, Type: "public", GrantTypes: grants})
	if issued, err := svc.DeviceToken(ctx, public.ClientID, "", approved(public.ClientID), deviceIP); err != nil || issued.AccessToken == "" {
		t.Fatalf("public client polling: %+v, %v", issued, err)
	}
}

// TestBackchannelPollingAuthenticatesTheClient checks that collecting a CIBA
// grant's tokens needs the client's secret.
func TestBackchannelPollingAuthenticatesTheClient(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	client, secret := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, GrantTypes: []string{grantTypeCIBA}})

	started, err := svc.BackchannelAuthorize(ctx, client.ClientID, secret, user.Email, "openid", "")
	if err != nil {
		t.Fatalf("backchannel authorize: %v", err)
	}
	pending, err := svc.ListPendingCIBA(ctx, user.ID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending requests: %+v, %v", pending, err)
	}
	if err := svc.DecideBackchannel(ctx, user.ID, pending[0].ID, true); err != nil {
		t.Fatalf("approve: %v", err)
	}
	for name, presented := range map[string]string{"no secret": "", "a wrong secret": "wrong-secret"} {
		if _, err := svc.BackchannelToken(ctx, client.ClientID, presented, started.AuthReqID); !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
			t.Errorf("polling with %s: %v, want %v", name, err, errs.ErrOIDCClientAuthFailed)
		}
	}
	if issued, err := svc.BackchannelToken(ctx, client.ClientID, secret, started.AuthReqID); err != nil || issued.AccessToken == "" {
		t.Fatalf("polling with the secret: %+v, %v", issued, err)
	}
}

// TestGrantsRunOnTheirTransaction checks that registering a resource served by
// an application, redeeming a code and refreshing for that resource, and
// approving a device run every query on the transaction they hold.
func TestGrantsRunOnTheirTransaction(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	dbtest.LeaveOneConnection(t)
	svc := NewService(pool, dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	server, _ := registerClient(t, svc, tenant)
	client, secret := registerClientWith(t, svc, CreateClientInput{
		TenantID: tenant, GrantTypes: []string{"authorization_code", "refresh_token", grantTypeDeviceCode},
	})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := svc.CreateResource(ctx, tx, tenant, CreateResourceInput{Identifier: resourceA, Name: "A", ServerClientID: server.ClientID}); err != nil {
		t.Fatalf("create resource: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	issued := redeemCode(t, svc, client, secret, user.ID, resourceA)
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	_, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, nil)
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	if err := svc.DecideDevice(ctx, user.ID, userCode, true, deviceIP); err != nil {
		t.Fatalf("approve device: %v", err)
	}
}

// postToken posts form to the token endpoint, with Basic credentials when
// user is not empty.
func postToken(t *testing.T, h http.Handler, form url.Values, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(dbtest.Context(t), http.MethodPost, "/oauth/token-code", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestTokenEndpointAnswersGrantErrorsInOAuthShape checks the token endpoint's
// answers to refused client authentication and grants.
func TestTokenEndpointAnswersGrantErrorsInOAuthShape(t *testing.T) {
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	client, secret := registerClient(t, svc, tenant)
	issued := redeemCode(t, svc, client, secret, user.ID, "")
	router := chi.NewRouter()
	(&Handler{Service: svc}).MountToken(router)

	form := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	code := form("grant_type", "authorization_code", "code", "not-a-code", "redirect_uri", testRedirect)
	for _, tc := range []struct {
		name             string
		form             url.Values
		user, pass       string
		status           int
		error, challenge string
	}{
		{"a wrong Basic secret", code, client.ClientID, "wrong-secret", http.StatusUnauthorized, "invalid_client", `Basic realm="qeet"`},
		{"a wrong form secret", form("grant_type", "refresh_token", "client_id", client.ClientID, "client_secret", "wrong-secret", "refresh_token", issued.RefreshToken), "", "", http.StatusUnauthorized, "invalid_client", ""},
		{"an unknown client", code, "qci_unknown", secret, http.StatusUnauthorized, "invalid_client", `Basic realm="qeet"`},
		{"an unknown code", code, client.ClientID, secret, http.StatusBadRequest, "invalid_grant", ""},
		{"an unknown refresh token", form("grant_type", "refresh_token", "refresh_token", "not-a-token"), client.ClientID, secret, http.StatusBadRequest, "invalid_grant", ""},
		{"no refresh token", form("grant_type", "refresh_token"), client.ClientID, secret, http.StatusBadRequest, "invalid_request", ""},
		{"a resource other than the one the grant is bound to", form("grant_type", "refresh_token", "refresh_token", issued.RefreshToken, "resource", resourceB), client.ClientID, secret, http.StatusBadRequest, "invalid_target", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postToken(t, router, tc.form, tc.user, tc.pass)
			if rec.Code != tc.status {
				t.Errorf("status %d, want %d", rec.Code, tc.status)
			}
			if got, _ := decodeTokenError(t, rec); got != tc.error {
				t.Errorf("error %q, want %q", got, tc.error)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tc.challenge {
				t.Errorf("WWW-Authenticate %q, want %q", got, tc.challenge)
			}
		})
	}

	// A locked-out application is answered as a wrong secret, its right one too.
	svc.SetClientLockout(ClientLockout{Threshold: 1, Window: time.Minute, Duration: time.Minute})
	refresh := form("grant_type", "refresh_token", "refresh_token", issued.RefreshToken)
	postToken(t, router, refresh, client.ClientID, "wrong-secret")
	rec := postToken(t, router, refresh, client.ClientID, secret)
	if got, _ := decodeTokenError(t, rec); rec.Code != http.StatusUnauthorized || got != "invalid_client" {
		t.Errorf("locked-out application = %d %q, want 401 invalid_client", rec.Code, got)
	}
}

// TestDeviceFlowAddressRulesWithOneConnection checks, with only one connection
// free, that the organisation's address rules decide device approval and token
// collection: a refusal is recorded, leaves the device pending when approving,
// and spends the device code when collecting.
func TestDeviceFlowAddressRulesWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	svc.SetAddressPolicy(ipallow.NewService(pool))
	tenant := dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	if _, err := pool.Exec(ctx, `
		WITH rule AS (INSERT INTO tenant.ip_rules (tenant_id, cidr, label, action) VALUES ($1, '192.0.2.0/24', 'office', 'allow'))
		INSERT INTO tenant.ip_rules_config (tenant_id, enabled) VALUES ($1, TRUE)
	`, tenant); err != nil {
		t.Fatalf("address rules: %v", err)
	}
	client, secret := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, GrantTypes: []string{grantTypeDeviceCode}})
	deviceCode, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, nil)
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	const refusedIP = "198.51.100.7"
	refusals := func(path string) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.address_refused' AND tenant_id = $1
			AND metadata->>'path' = $2 AND metadata->>'address' = $3`, tenant, path, refusedIP)
	}

	dbtest.LeaveOneConnection(t)
	if err := svc.DecideDevice(ctx, user.ID, userCode, true, refusedIP); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Fatalf("approve from a refused address: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if n := refusals("device_approval"); n != 1 {
		t.Errorf("the refused approval was recorded %d times, want 1", n)
	}
	if err := svc.DecideDevice(ctx, user.ID, userCode, true, deviceIP); err != nil {
		t.Fatalf("approve from an allowed address after a refused one: %v", err)
	}
	_, err = svc.DeviceToken(ctx, client.ClientID, secret, deviceCode, refusedIP)
	wantOAuthError(t, "collect from a refused address", err, "access_denied")
	if n := refusals("device"); n != 1 {
		t.Errorf("the refused collection was recorded %d times, want 1", n)
	}
	_, err = svc.DeviceToken(ctx, client.ClientID, secret, deviceCode, deviceIP)
	wantOAuthError(t, "collect again after a refused collection", err, "invalid_grant")
}

// poolLimiter caps applications at limit, reading on the pool as the plan
// service does.
type poolLimiter struct {
	pool  *pgxpool.Pool
	limit int
}

func (l poolLimiter) Limit(ctx context.Context, _ uuid.UUID, _ string) (int, error) {
	var one int
	return l.limit, l.pool.QueryRow(ctx, `SELECT 1`).Scan(&one)
}

// TestClientRegistrationPlanCapWithOneConnection checks, with only one
// connection free, that both registration routes apply the plan's cap on
// applications: under it they register, at it they refuse, before any
// validation of the request.
func TestClientRegistrationPlanCapWithOneConnection(t *testing.T) {
	pool := dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	svc.SetPlanLimiter(poolLimiter{pool: pool, limit: 2})
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	inTenant := "/tenants/" + tenant.String() + "/oidc/clients"
	app := map[string]any{"name": "App", "redirect_uris": []string{testRedirect}}

	dbtest.LeaveOneConnection(t)
	for _, path := range []string{inTenant, "/oidc/clients"} {
		if rec := dbtest.Do(t, h, http.MethodPost, path, app); rec.Code != http.StatusCreated {
			t.Errorf("POST %s under the cap = %d %s, want 201", path, rec.Code, rec.Body.String())
		}
	}
	invalid := map[string]any{"name": "App", "type": "neither"}
	for _, path := range []string{inTenant, "/oidc/clients"} {
		for _, body := range []map[string]any{app, invalid} {
			if rec := dbtest.Do(t, h, http.MethodPost, path, body); rec.Code != http.StatusPaymentRequired {
				t.Errorf("POST %s %v at the cap = %d %s, want 402", path, body, rec.Code, rec.Body.String())
			}
		}
	}
}
