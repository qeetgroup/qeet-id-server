//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/domains/access/authentication"
	"github.com/qeetgroup/qeet-id/domains/federation/oidc"
	"github.com/qeetgroup/qeet-id/platform/codes"
)

// =====================================================================
// OAuth 2.0 Device Authorization Grant (RFC 8628)
// =====================================================================

// approveDevice flips a device row to authorized + binds the user directly,
// standing in for the SSO-cookie decision path when a test only needs the
// post-approval token behaviour. (The full cookie-driven path is covered by
// TestDeviceGrantHTTPHappyPath.)
func approveDevice(t *testing.T, ctx context.Context, userCode string, userID uuid.UUID) {
	t.Helper()
	ct, err := testPool.Exec(ctx, `
		UPDATE auth.oidc_device_codes
		SET status = 'authorized', user_id = $1, approved_at = NOW()
		WHERE user_code = $2 AND status = 'pending'
	`, userID, userCode)
	if err != nil {
		t.Fatalf("approve device: %v", err)
	}
	if ct.RowsAffected() != 1 {
		t.Fatalf("approve device affected %d rows, want 1", ct.RowsAffected())
	}
}

// TestDeviceGrantHappyPath drives the service layer end to end: device
// authorization mints a (device_code, user_code) pair scoped to the client's
// tenant; polling before approval is authorization_pending; after the user
// approves, a poll issues the same token pair as the auth-code flow; and the
// device_code is single-use.
func TestDeviceGrantHappyPath(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("dev"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	client, _ := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")

	deviceCode, userCode, gotTenant, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device authorize returned empty codes: %q / %q", deviceCode, userCode)
	}
	if gotTenant != tenantID {
		t.Fatalf("device row tenant = %v, want %v", gotTenant, tenantID)
	}
	// user_code is the unambiguous XXXX-XXXX shape.
	if len(userCode) != 9 || userCode[4] != '-' {
		t.Errorf("user_code = %q, want XXXX-XXXX", userCode)
	}
	if strings.ContainsAny(userCode, "0O1I") {
		t.Errorf("user_code %q contains ambiguous characters", userCode)
	}
	// The device_code is stored hashed, never in the clear.
	var rawCount int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM auth.oidc_device_codes WHERE device_code_hash = $1`,
		codes.Hash(deviceCode)).Scan(&rawCount); err != nil || rawCount != 1 {
		t.Fatalf("device_code should be stored hashed: count=%d err=%v", rawCount, err)
	}

	// Poll before approval → authorization_pending.
	if _, err := svc.DeviceToken(ctx, client.ClientID, deviceCode); err == nil ||
		!strings.Contains(err.Error(), "authorization_pending") {
		t.Fatalf("pre-approval poll = %v, want authorization_pending", err)
	}

	// Approve and poll → tokens. (Bypass the interval throttle: the prior poll
	// just set last_polled_at, so push it back.)
	approveDevice(t, ctx, userCode, userID)
	resetPollClock(t, ctx, userCode)

	issued, err := svc.DeviceToken(ctx, client.ClientID, deviceCode)
	if err != nil {
		t.Fatalf("post-approval poll: %v", err)
	}
	if issued.AccessToken == "" {
		t.Fatal("device grant yielded no access token")
	}
	if issued.IDToken == "" {
		t.Fatal("openid scope should yield an id_token")
	}
	if issued.RefreshToken == "" {
		t.Fatal("device grant should mint a refresh token (client allows refresh_token)")
	}

	// Single-use: a second poll with the consumed device_code is rejected.
	resetPollClock(t, ctx, userCode)
	if _, err := svc.DeviceToken(ctx, client.ClientID, deviceCode); err == nil ||
		!strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("reused device_code = %v, want invalid_grant", err)
	}
}

// resetPollClock pushes last_polled_at into the past so the next poll isn't
// throttled by the interval check (lets tests poll back-to-back).
func resetPollClock(t *testing.T, ctx context.Context, userCode string) {
	t.Helper()
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.oidc_device_codes SET last_polled_at = NOW() - INTERVAL '1 hour' WHERE user_code = $1`,
		userCode); err != nil {
		t.Fatalf("reset poll clock: %v", err)
	}
}

// TestDeviceGrantSlowDown proves the interval throttle: a poll arriving sooner
// than `interval` seconds after the previous one returns slow_down.
func TestDeviceGrantSlowDown(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("dev"))
	svc := oidc.NewService(testPool, mustIssuer())
	client, _ := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")

	deviceCode, _, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}

	// First poll establishes last_polled_at (pending).
	if _, err := svc.DeviceToken(ctx, client.ClientID, deviceCode); err == nil ||
		!strings.Contains(err.Error(), "authorization_pending") {
		t.Fatalf("first poll = %v, want authorization_pending", err)
	}
	// Immediate second poll is faster than the interval → slow_down.
	if _, err := svc.DeviceToken(ctx, client.ClientID, deviceCode); err == nil ||
		!strings.Contains(err.Error(), "slow_down") {
		t.Fatalf("rapid second poll = %v, want slow_down", err)
	}
}

// TestDeviceGrantDenied proves a user denial surfaces as access_denied on poll.
func TestDeviceGrantDenied(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("dev"))
	userID := createUserInTenant(t, ctx, tenantID)
	svc := oidc.NewService(testPool, mustIssuer())
	client, _ := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")

	deviceCode, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	if err := svc.DecideDevice(ctx, userID, userCode, false); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if _, err := svc.DeviceToken(ctx, client.ClientID, deviceCode); err == nil ||
		!strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("poll after denial = %v, want access_denied", err)
	}
}

// TestDeviceGrantExpired forces a device row past expiry and proves the poll
// returns expired_token.
func TestDeviceGrantExpired(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("dev"))
	svc := oidc.NewService(testPool, mustIssuer())
	client, _ := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")

	deviceCode, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.oidc_device_codes SET expires_at = NOW() - INTERVAL '1 minute' WHERE user_code = $1`,
		userCode); err != nil {
		t.Fatalf("expire device: %v", err)
	}
	if _, err := svc.DeviceToken(ctx, client.ClientID, deviceCode); err == nil ||
		!strings.Contains(err.Error(), "expired_token") {
		t.Fatalf("poll after expiry = %v, want expired_token", err)
	}
}

// TestDeviceGrantClientMismatch proves a device_code is bound to its issuing
// client: another client (even valid) can't poll with it.
func TestDeviceGrantClientMismatch(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("dev"))
	svc := oidc.NewService(testPool, mustIssuer())
	clientA, _ := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")
	clientB, _ := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")

	deviceCode, _, _, err := svc.DeviceAuthorize(ctx, clientA.ClientID, []string{"openid"})
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	if _, err := svc.DeviceToken(ctx, clientB.ClientID, deviceCode); err == nil ||
		!strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("cross-client poll = %v, want invalid_grant", err)
	}
}

// TestDeviceGrantUnknownDeviceCode proves a wholly unknown device_code is
// rejected with invalid_grant.
func TestDeviceGrantUnknownDeviceCode(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("dev"))
	svc := oidc.NewService(testPool, mustIssuer())
	client, _ := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")

	if _, err := svc.DeviceToken(ctx, client.ClientID, "not-a-real-device-code"); err == nil ||
		!strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("unknown device_code = %v, want invalid_grant", err)
	}
}

// TestDeviceUserCodeLookupAndExpiry covers the verification-screen lookup:
// the requesting client name + scopes resolve for a pending code, an unknown
// user_code 404s, and an expired user_code is rejected.
func TestDeviceUserCodeLookupAndExpiry(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("dev"))
	svc := oidc.NewService(testPool, mustIssuer())
	client, _ := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")

	_, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}

	vc, err := svc.LookupDeviceByUserCode(ctx, userCode)
	if err != nil {
		t.Fatalf("lookup user_code: %v", err)
	}
	if vc.ClientName != "RP" {
		t.Errorf("client_name = %q, want RP", vc.ClientName)
	}
	if len(vc.Scopes) != 2 {
		t.Errorf("scopes = %v, want [openid profile]", vc.Scopes)
	}
	// Lower-case input is normalized to the stored upper-case value.
	if _, err := svc.LookupDeviceByUserCode(ctx, strings.ToLower(userCode)); err != nil {
		t.Errorf("lower-case user_code should normalize and resolve: %v", err)
	}
	// Unknown user_code is a clean not-found.
	if _, err := svc.LookupDeviceByUserCode(ctx, "ZZZZ-ZZZZ"); err == nil {
		t.Error("unknown user_code must fail")
	}
	// Expired user_code is rejected at lookup.
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.oidc_device_codes SET expires_at = NOW() - INTERVAL '1 minute' WHERE user_code = $1`,
		userCode); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if _, err := svc.LookupDeviceByUserCode(ctx, userCode); err == nil {
		t.Error("expired user_code lookup must fail")
	}
}

// TestDeviceDecisionForeignTenantUser proves a user who does not belong to the
// client's tenant cannot approve the device request (multi-tenant isolation).
func TestDeviceDecisionForeignTenantUser(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantA := createTenant(t, ctx, uniqueSlug("devA"))
	tenantB := createTenant(t, ctx, uniqueSlug("devB"))
	foreignUser := createUserInTenant(t, ctx, tenantB)

	svc := oidc.NewService(testPool, mustIssuer())
	client, _ := registerOIDCClient(t, ctx, svc, tenantA, "https://app.example/cb")

	_, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	if err := svc.DecideDevice(ctx, foreignUser, userCode, true); err == nil {
		t.Fatal("a user outside the client's tenant must not approve the device request")
	}
	// The row stays pending after the rejected approval.
	var status string
	if err := testPool.QueryRow(ctx,
		`SELECT status FROM auth.oidc_device_codes WHERE user_code = $1`, userCode).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "pending" {
		t.Errorf("status = %q after rejected approval, want pending", status)
	}
}

// TestDeviceGrantHTTPHappyPath drives the full grant over real HTTP: the device
// calls device_authorization (client auth), the user establishes an SSO session
// and approves via the cookie-gated decision endpoint, and the device polls the
// token endpoint for tokens — exercising the RFC 6749 §5.2 flat error shape for
// the pending poll and the JSON token body on success.
func TestDeviceGrantHTTPHappyPath(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	// A user with a password, made a member of the client's tenant.
	authSvc, _ := newAuth()
	email := uniqueSlug("dev") + "@example.com"
	_, u, _, err := authSvc.Signup(ctx, auth.SignupInput{Email: email, Password: "password123"})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}

	oidcSvc := oidc.NewService(testPool, mustIssuer())
	tenantID := createTenant(t, ctx, uniqueSlug("dev"))
	// Bind the user to the client's tenant so approval is permitted.
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET tenant_id = $1 WHERE id = $2`, tenantID, u.ID); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	client, secret := registerOIDCClient(t, ctx, oidcSvc, tenantID, "https://app.example/cb")

	authH := &auth.Handler{Service: authSvc, Validate: validator.New(validator.WithRequiredStructEnabled())}
	oidcH := &oidc.Handler{Service: oidcSvc, Sessions: authSvc, LoginBaseURL: "http://login.test"}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		authH.Mount(r)
		oidcH.MountBrowser(r)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 1) Device authorization (client-authenticated form POST).
	form := url.Values{"client_id": {client.ClientID}, "client_secret": {secret}, "scope": {"openid"}}
	resp, err := hc.PostForm(srv.URL+"/v1/oauth/device_authorization", form)
	if err != nil {
		t.Fatalf("device_authorization: %v", err)
	}
	var da struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&da)
	resp.Body.Close()
	if da.DeviceCode == "" || da.UserCode == "" {
		t.Fatalf("device_authorization response missing codes: %+v", da)
	}
	if da.VerificationURI != "http://login.test/device" {
		t.Errorf("verification_uri = %q", da.VerificationURI)
	}
	if !strings.Contains(da.VerificationURIComplete, "user_code="+da.UserCode) {
		t.Errorf("verification_uri_complete = %q", da.VerificationURIComplete)
	}
	if da.Interval != 5 {
		t.Errorf("interval = %d, want 5", da.Interval)
	}

	pollForm := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {da.DeviceCode},
		"client_id":   {client.ClientID},
	}
	poll := func() (int, map[string]any) {
		resetPollClock(t, ctx, da.UserCode)
		resp, err := hc.PostForm(srv.URL+"/v1/oauth/token-code", pollForm)
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}

	// 2) Poll before approval → 400 with flat {"error":"authorization_pending"}.
	status, body := poll()
	if status != http.StatusBadRequest || body["error"] != "authorization_pending" {
		t.Fatalf("pre-approval poll = %d %v, want 400 authorization_pending", status, body)
	}

	// 3) Establish the SSO session, then approve via the cookie-gated decision.
	sb, _ := json.Marshal(map[string]string{"email": email, "password": "password123"})
	sresp, err := hc.Post(srv.URL+"/v1/auth/session", "application/json", bytes.NewReader(sb))
	if err != nil || sresp.StatusCode != http.StatusOK {
		t.Fatalf("session: %v (status %v)", err, sresp.StatusCode)
	}
	sresp.Body.Close()

	db, _ := json.Marshal(map[string]any{"user_code": da.UserCode, "approve": true})
	dresp, err := hc.Post(srv.URL+"/v1/oauth/device/decision", "application/json", bytes.NewReader(db))
	if err != nil {
		t.Fatalf("decision: %v", err)
	}
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("decision status %d", dresp.StatusCode)
	}
	dresp.Body.Close()

	// 4) Poll after approval → 200 with a token body.
	status, body = poll()
	if status != http.StatusOK {
		t.Fatalf("post-approval poll = %d %v, want 200", status, body)
	}
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Fatalf("post-approval poll missing access_token: %v", body)
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", body["token_type"])
	}

	// 5) Single-use: another poll with the consumed device_code → invalid_grant.
	status, body = poll()
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("reused device_code poll = %d %v, want 400 invalid_grant", status, body)
	}
}

// TestDeviceAuthorizationUnknownClient proves an unauthenticated/unknown client
// can't obtain a device_code.
func TestDeviceAuthorizationUnknownClient(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("dev"))
	svc := oidc.NewService(testPool, mustIssuer())
	_, _ = registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")

	if _, _, _, err := svc.DeviceAuthorize(ctx, "qci_does-not-exist", []string{"openid"}); err == nil {
		t.Fatal("device authorize with an unknown client must fail")
	}

	// And a scope outside the client's set is rejected.
	client, _ := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")
	if _, _, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"admin:super"}); err == nil {
		t.Fatal("device authorize with a non-permitted scope must fail")
	}
}
