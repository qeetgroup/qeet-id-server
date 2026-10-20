//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Signing out everywhere also closes the ways back in that are not sessions:
// devices remembered so they skip the second factor, authorisation codes no
// application has redeemed yet, and device or back-channel sign-in requests
// that are pending or approved but not yet collected. The administrator's
// force sign-out does the same. Other people are not touched.

// leftovers is one person's ways back in that are not sessions.
type leftovers struct {
	device     string // remembered-device token
	code       string // unredeemed authorisation code
	deviceCode string // device sign-in, approved, not collected
	cibaReq    string // back-channel sign-in request, pending
}

func (f *signOutEverywhereFixture) leaveWaysBackIn(t *testing.T, ctx context.Context, userID uuid.UUID, cibaClient, cibaSecret string) leftovers {
	t.Helper()
	var l leftovers
	var err error
	if l.device, err = f.svc.CreateTrustedDevice(ctx, userID, f.tenantID, "laptop", 30*24*time.Hour); err != nil {
		t.Fatalf("remember device: %v", err)
	}
	if l.code, _, err = f.oidc.Authorize(ctx, userID, f.clientID, f.redirectURI, []string{"openid"}, testNonce, testChallenge, "S256"); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	deviceCode, userCode, _, err := f.oidc.DeviceAuthorize(ctx, f.clientID, []string{"openid"})
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	if err := f.oidc.DecideDevice(ctx, userID, userCode, true, ""); err != nil {
		t.Fatalf("approve device: %v", err)
	}
	l.deviceCode = deviceCode
	var email string
	if err := testPool.QueryRow(ctx, `SELECT email FROM "user".users WHERE id = $1`, userID).Scan(&email); err != nil {
		t.Fatalf("read email: %v", err)
	}
	ciba, err := f.oidc.BackchannelAuthorize(ctx, cibaClient, cibaSecret, email, "", "Approve")
	if err != nil {
		t.Fatalf("back-channel authorize: %v", err)
	}
	l.cibaReq = ciba.AuthReqID
	return l
}

// stillOpen reports which of the ways back in still work.
func (f *signOutEverywhereFixture) stillOpen(t *testing.T, ctx context.Context, userID uuid.UUID, l leftovers, cibaClient string) map[string]bool {
	t.Helper()
	open := map[string]bool{}
	open["remembered device"] = f.svc.IsTrustedDevice(ctx, userID, f.tenantID, l.device)
	_, err := f.oidc.ExchangeCode(ctx, f.clientID, f.secret, l.code, f.redirectURI, testVerifier, "")
	open["authorisation code"] = err == nil
	if err != nil && !errors.Is(err, errs.ErrOIDCAuthCodeUsed) {
		t.Errorf("redeeming the code failed with %v, want it refused as already used", err)
	}
	_, err = f.oidc.DeviceToken(ctx, f.clientID, l.deviceCode, "")
	open["device sign-in"] = err == nil
	pending, err := f.oidc.ListPendingCIBA(ctx, userID)
	if err != nil {
		t.Fatalf("list back-channel requests: %v", err)
	}
	open["back-channel request"] = len(pending) > 0
	for _, p := range pending {
		_ = f.oidc.DecideBackchannel(ctx, userID, p.ID, true)
	}
	if _, err := f.oidc.BackchannelToken(ctx, cibaClient, l.cibaReq); err == nil {
		open["back-channel request"] = true
	}
	return open
}

func cibaClientIn(t *testing.T, ctx context.Context, svc *oidc.Service, tenantID uuid.UUID) (string, string) {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	c, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "CIBA", RedirectURIs: []string{"https://app.example/cb"},
		GrantTypes: []string{"refresh_token", "urn:openid:params:grant-type:ciba"},
	})
	if err != nil {
		t.Fatalf("register CIBA client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return c.ClientID, secret
}

func endedCounts(t *testing.T, rr *httptest.ResponseRecorder) (devices, pending float64) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	d, _ := body["trusted_devices"].(float64)
	p, _ := body["pending_authorizations"].(float64)
	return d, p
}

// TestSignOutEverywhereAlsoClosesTheOtherWaysBackIn: the person's remembered
// device, unredeemed code, approved device sign-in and pending back-channel
// request all stop working; the response and the audit record say so; another
// person's are untouched.
func TestSignOutEverywhereAlsoClosesTheOtherWaysBackIn(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignOutEverywhereFixture(t, ctx)
	cibaClient, cibaSecret := cibaClientIn(t, ctx, f.oidc, f.tenantID)
	me := f.newPerson(t, ctx, 1, 0, 0)
	bystander := f.newPerson(t, ctx, 0, 0, 0)
	mine := f.leaveWaysBackIn(t, ctx, me.userID, cibaClient, cibaSecret)
	theirs := f.leaveWaysBackIn(t, ctx, bystander.userID, cibaClient, cibaSecret)

	req := httptest.NewRequest(http.MethodPost, signOutEverywherePath, nil)
	req.Header.Set("Authorization", "Bearer "+me.sessions[0].AccessToken)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign out everywhere = %d %s", rr.Code, rr.Body.String())
	}
	if d, p := endedCounts(t, rr); d != 1 || p != 3 {
		t.Errorf("response trusted_devices = %v, pending_authorizations = %v; want 1 and 3", d, p)
	}
	for what, open := range f.stillOpen(t, ctx, me.userID, mine, cibaClient) {
		if open {
			t.Errorf("%s still works after signing out everywhere", what)
		}
	}
	for what, open := range f.stillOpen(t, ctx, bystander.userID, theirs, cibaClient) {
		if !open {
			t.Errorf("another person's %s was closed", what)
		}
	}
	var devices, pending int64
	if err := testPool.QueryRow(ctx, `
		SELECT (metadata->>'revoked_trusted_devices')::bigint, (metadata->>'ended_pending_authorizations')::bigint
		FROM audit.events WHERE resource_id = $1 AND action = 'auth.all_sessions_revoked'`, me.userID).Scan(&devices, &pending); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if devices != 1 || pending != 3 {
		t.Fatalf("audit records %d devices and %d pending authorisations, want 1 and 3", devices, pending)
	}
}

// TestAdminForceSignOutAlsoClosesTheOtherWaysBackIn: an administrator's force
// sign-out does the same.
func TestAdminForceSignOutAlsoClosesTheOtherWaysBackIn(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignOutEverywhereFixture(t, ctx)
	cibaClient, cibaSecret := cibaClientIn(t, ctx, f.oidc, f.tenantID)
	target := f.newPerson(t, ctx, 1, 0, 0)
	left := f.leaveWaysBackIn(t, ctx, target.userID, cibaClient, cibaSecret)
	adminID := createUserInTenant(t, ctx, f.tenantID)

	handler := &user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New(), SignIns: f.svc}
	router := chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Use(withPrincipal(adminID, f.tenantID))
	handler.Mount(router)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/users/"+target.userID.String()+"/sessions/revoke-all", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("force sign-out = %d %s", rr.Code, rr.Body.String())
	}
	if d, p := endedCounts(t, rr); d != 1 || p != 3 {
		t.Errorf("response trusted_devices = %v, pending_authorizations = %v; want 1 and 3", d, p)
	}
	for what, open := range f.stillOpen(t, ctx, target.userID, left, cibaClient) {
		if open {
			t.Errorf("%s still works after a force sign-out", what)
		}
	}
}
