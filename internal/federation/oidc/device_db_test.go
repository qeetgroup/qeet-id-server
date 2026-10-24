//go:build integration

package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// userCodeShape is a device user code as RFC 8628 §6.1 suggests: two groups
// of four from an alphabet without ambiguous characters.
var userCodeShape = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)

// TestDeviceFlow checks that a device polls as pending and is slowed when too
// quick, that only a member of the application's organisation approves it,
// once, and its code buys tokens once for the application that asked, and that
// a denial, an expiry and an admin's revocation each end it.
func TestDeviceFlow(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	p := newProvider(t)
	tenant, otherTenant := dbtest.Tenant(t), dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	outsider := dbtest.User(t, otherTenant, otherTenant)
	grants := []string{grantTypeDeviceCode, "refresh_token"}
	device, _ := registerClientWith(t, p.svc, CreateClientInput{TenantID: tenant, Name: "TV", Type: "public", GrantTypes: grants})
	other, _ := registerClientWith(t, p.svc, CreateClientInput{TenantID: tenant, Type: "public", GrantTypes: grants})
	cookie, _ := p.signIn(t, person.ID)
	outsiderCookie, _ := p.signIn(t, outsider.ID)

	start := func() DeviceAuthResponse {
		t.Helper()
		rec := postForm(t, p.public, "/oauth/device_authorization", url.Values{"client_id": {device.ClientID}, "scope": {"openid email"}}, "", "")
		var out DeviceAuthResponse
		dbtest.Decode(t, rec, &out)
		if rec.Code != http.StatusOK || out.DeviceCode == "" || !userCodeShape.MatchString(out.UserCode) {
			t.Fatalf("device authorization: %d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	collect := func(clientID, deviceCode string) *httptest.ResponseRecorder {
		t.Helper()
		return postForm(t, p.public, "/oauth/token-code", url.Values{"grant_type": {grantTypeDeviceCode}, "client_id": {clientID}, "device_code": {deviceCode}}, "", "")
	}
	// poll collects as a device that waited out the interval since its last poll.
	poll := func(clientID, deviceCode string) *httptest.ResponseRecorder {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE auth.oidc_device_codes SET last_polled_at = last_polled_at - INTERVAL '1 minute'
			WHERE tenant_id = $1 AND device_code_hash = $2`, tenant, codes.Hash(deviceCode)); err != nil {
			t.Fatal(err)
		}
		return collect(clientID, deviceCode)
	}
	pollError := func(clientID, deviceCode string) string {
		t.Helper()
		code, _ := decodeTokenError(t, poll(clientID, deviceCode))
		return code
	}
	decide := func(c *http.Cookie, userCode string, approve bool) *httptest.ResponseRecorder {
		t.Helper()
		return browse(t, p.public, http.MethodPost, "/oauth/device/decision", c, map[string]any{"user_code": userCode, "approve": approve})
	}

	started := start()
	if started.VerificationURI != loginBase+"/device" || started.VerificationURIComplete != loginBase+"/device?user_code="+started.UserCode ||
		started.Interval != devicePollInterval || started.ExpiresIn != int(deviceCodeTTL.Seconds()) {
		t.Errorf("device authorization %+v, want the hosted /device page and the RFC 8628 timings", started)
	}
	tooWide := url.Values{"client_id": {device.ClientID}, "scope": {"openid admin"}}
	if rec := postForm(t, p.public, "/oauth/device_authorization", tooWide, "", ""); !strings.Contains(rec.Body.String(), errs.CodeOIDCScopeNotPermitted) {
		t.Errorf("device authorization for a scope the application may not have: %d %s", rec.Code, rec.Body.String())
	}
	if got := pollError(device.ClientID, started.DeviceCode); got != "authorization_pending" {
		t.Errorf("poll before approval: %s, want authorization_pending", got)
	}
	if got, _ := decodeTokenError(t, collect(device.ClientID, started.DeviceCode)); got != "slow_down" {
		t.Errorf("poll again at once: %s, want slow_down", got)
	}
	if got := pollError(other.ClientID, started.DeviceCode); got != "invalid_grant" {
		t.Errorf("another application collecting the device code: %s, want invalid_grant", got)
	}

	page := "/oauth/device?user_code=" + url.QueryEscape(" "+strings.ToLower(started.UserCode)+" ")
	if rec := browse(t, p.public, http.MethodGet, page, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the verification page signed out: %d, want 401", rec.Code)
	}
	var shown DeviceVerificationContext
	dbtest.Decode(t, browse(t, p.public, http.MethodGet, page, cookie, nil), &shown)
	if shown.ClientName != "TV" || !slices.Equal(shown.Scopes, []string{"openid", "email"}) {
		t.Errorf("the verification page shows %+v, want the application and its scopes", shown)
	}
	if rec := decide(outsiderCookie, started.UserCode, true); !strings.Contains(rec.Body.String(), errs.CodeOIDCUserTenantMismatch) {
		t.Errorf("approval by another organisation's person: %d %s", rec.Code, rec.Body.String())
	}
	if got := pollError(device.ClientID, started.DeviceCode); got != "authorization_pending" {
		t.Errorf("poll after the outsider's approval: %s, want authorization_pending", got)
	}
	if rec := decide(cookie, started.UserCode, true); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if rec := decide(cookie, started.UserCode, false); !strings.Contains(rec.Body.String(), errs.CodeOIDCDeviceAlreadyDecided) {
		t.Errorf("decide again: %d %s", rec.Code, rec.Body.String())
	}

	rec := poll(device.ClientID, started.DeviceCode)
	var issued TokenResponse
	dbtest.Decode(t, rec, &issued)
	claims, err := p.svc.issuer.VerifyAccessAnyAudience(issued.AccessToken)
	if rec.Code != http.StatusOK || err != nil || claims.UserID != person.ID || claims.TenantID != tenant || claims.ClientID != device.ClientID ||
		issued.IDToken == "" || issued.RefreshToken == "" || issued.Scope != "openid email" {
		t.Fatalf("collect: %d %s, %v", rec.Code, rec.Body.String(), err)
	}
	if got := pollError(device.ClientID, started.DeviceCode); got != "invalid_grant" {
		t.Errorf("collect twice: %s, want invalid_grant", got)
	}

	denied := start()
	if rec := decide(cookie, denied.UserCode, false); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"denied"`) {
		t.Errorf("deny: %d %s", rec.Code, rec.Body.String())
	}
	if got := pollError(device.ClientID, denied.DeviceCode); got != "access_denied" {
		t.Errorf("poll after denial: %s, want access_denied", got)
	}

	expired := start()
	if _, err := pool.Exec(ctx, `UPDATE auth.oidc_device_codes SET expires_at = NOW() - INTERVAL '1 second'
		WHERE tenant_id = $1 AND device_code_hash = $2`, tenant, codes.Hash(expired.DeviceCode)); err != nil {
		t.Fatal(err)
	}
	if rec := decide(cookie, expired.UserCode, true); !strings.Contains(rec.Body.String(), errs.CodeOIDCUserCodeExpired) {
		t.Errorf("approve an expired code: %d %s", rec.Code, rec.Body.String())
	}
	if got := pollError(device.ClientID, expired.DeviceCode); got != "expired_token" {
		t.Errorf("poll after expiry: %s, want expired_token", got)
	}

	revoked := start()
	asAdmin := dbtest.Serve(dbtest.Principal(person.ID, tenant), p.mount)
	asOutsider := dbtest.Serve(dbtest.Principal(outsider.ID, otherTenant), p.mount)
	rec = dbtest.Do(t, asAdmin, http.MethodGet, "/tenants/"+tenant.String()+"/oauth/devices", nil)
	var list struct {
		Items []DeviceAuthorization `json:"items"`
	}
	dbtest.Decode(t, rec, &list)
	at := slices.IndexFunc(list.Items, func(d DeviceAuthorization) bool { return d.UserCode == revoked.UserCode })
	if len(list.Items) != 4 || at < 0 {
		t.Fatalf("devices %+v, want the four started", list.Items)
	}
	for _, d := range []DeviceAuthResponse{started, denied, expired, revoked} {
		if strings.Contains(rec.Body.String(), d.DeviceCode) || strings.Contains(rec.Body.String(), codes.Hash(d.DeviceCode)) {
			t.Error("the device list shows a device code")
		}
	}
	id := list.Items[at].ID.String()
	if rec := dbtest.Do(t, asOutsider, http.MethodGet, "/tenants/"+tenant.String()+"/oauth/devices", nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organisation listing the devices: %d, want 403", rec.Code)
	}
	inOther := "/tenants/" + otherTenant.String() + "/oauth/devices/" + id
	if rec := dbtest.Do(t, asOutsider, http.MethodDelete, inOther, nil); !strings.Contains(rec.Body.String(), errs.CodeOIDCDeviceNotFound) {
		t.Errorf("another organisation revoking the device: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/tenants/"+tenant.String()+"/oauth/devices/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke the device: %d %s", rec.Code, rec.Body.String())
	}
	if got := pollError(device.ClientID, revoked.DeviceCode); got != "access_denied" {
		t.Errorf("poll after revocation: %s, want access_denied", got)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'oauth.device_revoked'`, tenant); n != 1 {
		t.Errorf("the revocation was audited %d times, want once", n)
	}
}

// TestDeviceAuthorizationNeedsTheDeviceGrant checks that only an application
// registered for the device grant can start a device sign-in: a browser-only
// public client's id, shown in every sign-in link, must not let anyone run a
// device sign-in in its name.
func TestDeviceAuthorizationNeedsTheDeviceGrant(t *testing.T) {
	p := newProvider(t)
	tenant := dbtest.Tenant(t)
	spa, _ := registerClientWith(t, p.svc, CreateClientInput{TenantID: tenant, Type: "public"})

	rec := postForm(t, p.public, "/oauth/device_authorization", url.Values{"client_id": {spa.ClientID}, "scope": {"openid"}}, "", "")
	if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "unauthorized_client") {
		t.Errorf("device authorization for a client without the grant: %d %s, want unauthorized_client", rec.Code, rec.Body.String())
	}
}

// TestDeviceAndBackchannelJudgeMembershipLikeSignIn checks that device
// approval and backchannel sign-in admit whom the browser sign-in admits: a
// member of the application's organisation whose account lives in another,
// and not an account of the organisation holding no role there.
func TestDeviceAndBackchannelJudgeMembershipLikeSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant, home := dbtest.Tenant(t), dbtest.Tenant(t)
	web, _ := registerClient(t, svc, tenant)
	device, _ := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, Type: "public", GrantTypes: []string{grantTypeDeviceCode}})
	ciba, cibaSecret := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, GrantTypes: []string{grantTypeCIBA}})
	_, challenge, _ := codes.URLToken()

	for _, tc := range []struct {
		name    string
		account dbtest.Account
		member  bool
	}{
		{"a member whose account lives elsewhere", dbtest.User(t, home, home, tenant), true},
		{"an account of the organisation without a role", dbtest.User(t, tenant), false},
	} {
		if _, _, err := svc.Authorize(ctx, tc.account.ID, web.ClientID, testRedirect, []string{"openid"}, "n-1", challenge, "S256"); (err == nil) != tc.member {
			t.Fatalf("%s signing in: %v, want admitted %t", tc.name, err, tc.member)
		}
		_, userCode, _, err := svc.DeviceAuthorize(ctx, device.ClientID, nil)
		if err != nil {
			t.Fatalf("device authorize: %v", err)
		}
		if err := svc.DecideDevice(ctx, tc.account.ID, userCode, true, deviceIP); (err == nil) != tc.member {
			t.Errorf("%s approving a device: %v, want admitted %t", tc.name, err, tc.member)
		}
		if _, err := svc.BackchannelAuthorize(ctx, ciba.ClientID, cibaSecret, tc.account.Email, "openid", ""); (err == nil) != tc.member {
			t.Errorf("%s as a backchannel login_hint: %v, want admitted %t", tc.name, err, tc.member)
		}
	}
}
