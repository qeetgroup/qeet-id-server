//go:build integration

package oidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// userCodeShape is a device user code as RFC 8628 §6.1 suggests: two groups
// of four from an alphabet without ambiguous characters.
var userCodeShape = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)

// TestDeviceFlow checks that a device polls as pending and is slowed when too
// quick, that only a member of the application's organization approves it,
// once, and its code buys tokens once for the application that asked, and that
// a denial, an expiry and an admin's revocation each end it.
func TestDeviceFlow(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	p := newProvider(t)
	organization, otherOrganization := dbtest.Organization(t), dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	outsider := dbtest.User(t, otherOrganization, otherOrganization)
	grants := []string{grantTypeDeviceCode, "refresh_token"}
	device, _ := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organization, Name: "TV", Type: "public", GrantTypes: grants})
	other, _ := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organization, Type: "public", GrantTypes: grants})
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
		return postForm(t, p.public, "/oauth/token", url.Values{"grant_type": {grantTypeDeviceCode}, "client_id": {clientID}, "device_code": {deviceCode}}, "", "")
	}
	// poll collects as a device that waited out the interval since its last poll.
	poll := func(clientID, deviceCode string) *httptest.ResponseRecorder {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE auth.oidc_device_codes SET last_polled_at = last_polled_at - INTERVAL '1 minute'
			WHERE organization_id = $1 AND device_code_hash = $2`, organization, codes.Hash(deviceCode)); err != nil {
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
	if rec := postForm(t, p.public, "/oauth/device_authorization", tooWide, "", ""); !strings.Contains(rec.Body.String(), CodeScopeNotPermitted) {
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
	if rec := decide(outsiderCookie, started.UserCode, true); !strings.Contains(rec.Body.String(), CodeUserOrganizationMismatch) {
		t.Errorf("approval by another organization's person: %d %s", rec.Code, rec.Body.String())
	}
	if got := pollError(device.ClientID, started.DeviceCode); got != "authorization_pending" {
		t.Errorf("poll after the outsider's approval: %s, want authorization_pending", got)
	}
	if rec := decide(cookie, started.UserCode, true); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if rec := decide(cookie, started.UserCode, false); !strings.Contains(rec.Body.String(), CodeDeviceAlreadyDecided) {
		t.Errorf("decide again: %d %s", rec.Code, rec.Body.String())
	}

	rec := poll(device.ClientID, started.DeviceCode)
	var issued TokenResponse
	dbtest.Decode(t, rec, &issued)
	claims, err := p.svc.issuer.VerifyAccessAnyAudience(issued.AccessToken)
	if rec.Code != http.StatusOK || err != nil || claims.UserID != person.ID || claims.OrganizationID != organization || claims.ClientID != device.ClientID ||
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
		WHERE organization_id = $1 AND device_code_hash = $2`, organization, codes.Hash(expired.DeviceCode)); err != nil {
		t.Fatal(err)
	}
	if rec := decide(cookie, expired.UserCode, true); !strings.Contains(rec.Body.String(), CodeUserCodeExpired) {
		t.Errorf("approve an expired code: %d %s", rec.Code, rec.Body.String())
	}
	if got := pollError(device.ClientID, expired.DeviceCode); got != "expired_token" {
		t.Errorf("poll after expiry: %s, want expired_token", got)
	}

	revoked := start()
	asAdmin := dbtest.Serve(dbtest.Principal(person.ID, organization), p.mount)
	asOutsider := dbtest.Serve(dbtest.Principal(outsider.ID, otherOrganization), p.mount)
	rec = dbtest.Do(t, asAdmin, http.MethodGet, "/organizations/"+organization.String()+"/oauth/devices", nil)
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
	if rec := dbtest.Do(t, asOutsider, http.MethodGet, "/organizations/"+organization.String()+"/oauth/devices", nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organization listing the devices: %d, want 403", rec.Code)
	}
	inOther := "/organizations/" + otherOrganization.String() + "/oauth/devices/" + id
	if rec := dbtest.Do(t, asOutsider, http.MethodDelete, inOther, nil); !strings.Contains(rec.Body.String(), CodeDeviceNotFound) {
		t.Errorf("another organization revoking the device: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/organizations/"+organization.String()+"/oauth/devices/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke the device: %d %s", rec.Code, rec.Body.String())
	}
	if got := pollError(device.ClientID, revoked.DeviceCode); got != "access_denied" {
		t.Errorf("poll after revocation: %s, want access_denied", got)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'oauth.device_revoked'`, organization); n != 1 {
		t.Errorf("the revocation was audited %d times, want once", n)
	}

	// The approved code that bought tokens names its application and when it
	// was spent, and revoking it ends the grant it bought.
	approved := list.Items[slices.IndexFunc(list.Items, func(d DeviceAuthorization) bool { return d.UserCode == started.UserCode })]
	if approved.ClientName != "TV" || approved.ConsumedAt == nil || list.Items[at].ConsumedAt != nil {
		t.Errorf("devices %+v, want the application's name and when an approval was spent", list.Items)
	}
	renew := url.Values{"grant_type": {"refresh_token"}, "client_id": {device.ClientID}, "refresh_token": {issued.RefreshToken}}
	if rec := postForm(t, p.public, "/oauth/token", renew, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("renew the device's tokens: %d %s", rec.Code, rec.Body.String())
	} else {
		dbtest.Decode(t, rec, &issued)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/organizations/"+organization.String()+"/oauth/devices/"+approved.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke the approved device: %d %s", rec.Code, rec.Body.String())
	}
	renew.Set("refresh_token", issued.RefreshToken)
	if code, _ := decodeTokenError(t, postForm(t, p.public, "/oauth/token", renew, "", "")); code != "invalid_grant" {
		t.Errorf("renew after the device was revoked: %s, want invalid_grant", code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'oauth.device_revoked'
		AND (metadata->>'grant_ended')::boolean`, organization); n != 1 {
		t.Errorf("%d revocations recorded ending a grant, want one", n)
	}
}

// TestDeviceAuthorizationNeedsTheDeviceGrant checks that only an application
// registered for the device grant can start a device sign-in: a browser-only
// public client's id, shown in every sign-in link, must not let anyone run a
// device sign-in in its name.
func TestDeviceAuthorizationNeedsTheDeviceGrant(t *testing.T) {
	p := newProvider(t)
	organization := dbtest.Organization(t)
	spa, _ := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organization, Type: "public"})

	rec := postForm(t, p.public, "/oauth/device_authorization", url.Values{"client_id": {spa.ClientID}, "scope": {"openid"}}, "", "")
	if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "unauthorized_client") {
		t.Errorf("device authorization for a client without the grant: %d %s, want unauthorized_client", rec.Code, rec.Body.String())
	}
}

// TestDeviceAndBackchannelJudgeMembershipLikeSignIn checks that device
// approval and backchannel sign-in admit whom the browser sign-in admits: a
// member of the application's organization whose account lives in another,
// and an account of the organization holding no role there; not a guest whose
// roles were removed, nor a suspended account of the organization.
func TestDeviceAndBackchannelJudgeMembershipLikeSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newTestService(t, pool, dbtest.Issuer(t))
	organization, home := dbtest.Organization(t), dbtest.Organization(t)
	web, _ := registerClient(t, svc, organization)
	device, _ := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Type: "public", GrantTypes: []string{grantTypeDeviceCode}})
	ciba, cibaSecret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: []string{grantTypeCIBA}})
	_, challenge, _ := codes.URLToken()
	formerGuest, suspended := dbtest.User(t, home, organization), dbtest.User(t, organization)
	if _, err := pool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, formerGuest.ID, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, suspended.ID); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		account dbtest.Account
		member  bool
	}{
		{"a member whose account lives elsewhere", dbtest.User(t, home, home, organization), true},
		{"an account of the organization without a role", dbtest.User(t, organization), true},
		{"a guest whose roles were removed", formerGuest, false},
		{"a suspended account of the organization", suspended, false},
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
		want := 0
		if tc.member {
			want = 1
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'oauth.device_approved'
			AND actor_user_id = $2 AND resource_type = 'oidc_device_code' AND host(ip) = $3 AND metadata->>'client_id' = $4`,
			organization, tc.account.ID, deviceIP, device.ClientID); n != want {
			t.Errorf("%s: %d approval records, want %d", tc.name, n, want)
		}
		if _, err := svc.BackchannelAuthorize(ctx, ciba.ClientID, cibaSecret, tc.account.Email, "openid", ""); (err == nil) != tc.member {
			t.Errorf("%s as a backchannel login_hint: %v, want admitted %t", tc.name, err, tc.member)
		}
	}
}

// TestDeviceDenialIsAudited checks that denying a device code is recorded in
// the code's organization, naming the person, the code and the client.
func TestDeviceDenialIsAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t, dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	device, _ := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Type: "public", GrantTypes: []string{grantTypeDeviceCode}})
	person := dbtest.User(t, organization, organization)
	_, userCode, _, err := svc.DeviceAuthorize(ctx, device.ClientID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DecideDevice(ctx, person.ID, userCode, false, deviceIP); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events e JOIN auth.oidc_device_codes d ON d.id = e.resource_id
		WHERE e.organization_id = $1 AND e.action = 'oauth.device_denied' AND e.actor_user_id = $2 AND d.status = 'denied'
		AND e.metadata->>'client_id' = $3 AND host(e.ip) = $4`, organization, person.ID, device.ClientID, deviceIP); n != 1 {
		t.Errorf("%d denial records, want 1", n)
	}
}

// TestSigningKeysAreDated checks that the signing-key list dates a key the
// registry holds, and leaves a key it doesn't hold undated.
func TestSigningKeysAreDated(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newTestService(t, pool, dbtest.Issuer(t))
	keys, err := svc.SigningKeys(ctx)
	if err != nil || len(keys) == 0 {
		t.Fatalf("signing keys: %v, %v", keys, err)
	}
	if keys[0].CreatedAt != nil {
		t.Errorf("a key the registry doesn't hold is dated %v", keys[0].CreatedAt)
	}
	activated := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `
		INSERT INTO platform.jwt_signing_keys (kid, algorithm, state, public_key_pem, activated_at, retire_at)
		VALUES ($1, 'ES256', 'retired', 'pem', $2, NOW() + INTERVAL '1 day')`, keys[0].Kid, activated); err != nil {
		t.Fatal(err)
	}
	keys, err = svc.SigningKeys(ctx)
	if err != nil || keys[0].CreatedAt == nil || keys[0].ActivatedAt == nil || !keys[0].ActivatedAt.Equal(activated) {
		t.Errorf("signing key %+v (%v), want it dated from the registry", keys[0], err)
	}
}

// TestDeviceFlowAddressRulesWithOneConnection checks, with only one connection
// free, that the organization's address rules decide device approval and token
// collection: a refusal is recorded, leaves the device pending when approving,
// and spends the device code when collecting.
func TestDeviceFlowAddressRulesWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newTestService(t, pool, dbtest.Issuer(t), func(d *Deps) { d.Addresses = ipallow.NewService(pool) })
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	if _, err := pool.Exec(ctx, `
		WITH rule AS (INSERT INTO organization.ip_rules (organization_id, cidr, label, action) VALUES ($1, '192.0.2.0/24', 'office', 'allow'))
		INSERT INTO organization.ip_rules_config (organization_id, enabled) VALUES ($1, TRUE)
	`, organization); err != nil {
		t.Fatalf("address rules: %v", err)
	}
	client, secret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: []string{grantTypeDeviceCode}})
	deviceCode, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, nil)
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	const refusedIP = "198.51.100.7"
	refusals := func(path string) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.address_refused' AND organization_id = $1
			AND metadata->>'path' = $2 AND metadata->>'address' = $3`, organization, path, refusedIP)
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
