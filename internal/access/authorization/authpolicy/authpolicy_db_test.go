//go:build integration

package authpolicy

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// updates counts the organisation's auth_policy.updated audit events.
func updates(t *testing.T, tenantID uuid.UUID) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'auth_policy.updated'`, tenantID)
}

// TestPolicyIsSavedAndAppliedToSignIn checks that an organisation that never
// saved a policy gets the defaults; that a policy saved over HTTP is returned,
// audited and read by the sign-in checks; and that a save replaces the whole
// policy, clamping the password length and magic-link lifetime.
func TestPolicyIsSavedAndAppliedToSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	path := "/tenants/" + tenant.String() + "/auth-policy"

	rec := dbtest.Do(t, h, http.MethodGet, path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	var def Policy
	dbtest.Decode(t, rec, &def)
	limits := def.LockoutLimits
	def.LockoutLimits = nil
	if def != DefaultPolicy() {
		t.Errorf("policy never saved: %+v, want the defaults", def)
	}
	wantLimits := LockoutLimitsView{
		Defaults: LockoutSettingsView{Threshold: 5, WindowMinutes: 15, DurationMinutes: 15},
		Min:      LockoutSettingsView{Threshold: 3, WindowMinutes: 1, DurationMinutes: 1},
		Max:      LockoutSettingsView{Threshold: 20, WindowMinutes: 1440, DurationMinutes: 1440},
	}
	if limits == nil || *limits != wantLimits {
		t.Errorf("lockout limits %+v, want %+v", limits, wantLimits)
	}
	if on, err := svc.SelfRegistrationEnabled(ctx, tenant); err != nil || on {
		t.Errorf("self-registration by default: %v, %v; want off", on, err)
	}
	if m, err := svc.SignInMethodsFor(ctx, tenant); err != nil || m != (SignInMethods{Password: true, Passkey: true, MagicLink: true}) {
		t.Errorf("sign-in methods by default: %+v, %v; want all three", m, err)
	}
	if on, d, err := svc.RememberDevicePolicy(ctx, tenant); err != nil || on || d != 30*24*time.Hour {
		t.Errorf("remembered devices by default: %v for %s, %v; want off, 30 days", on, d, err)
	}
	if l, err := svc.SignInLockout(ctx, tenant); err != nil || l != DefaultLockoutLimits().Defaults {
		t.Errorf("lockout by default: %+v, %v; want the platform defaults", l, err)
	}

	ptr := func(v int) *int { return &v }
	want := Policy{
		PasswordEnabled: true, PasswordMinLength: 12,
		PasswordRequireUppercase: true, PasswordRequireNumber: true, PasswordRequireSymbol: true,
		MagicLinkTTLMinutes: 30, PasskeyEnabled: true, SelfRegistrationEnabled: true,
		RememberDeviceEnabled: true, RememberDeviceDays: 14,
		LockoutThreshold: ptr(3), LockoutWindowMinutes: ptr(10), LockoutDurationMinutes: ptr(60),
		LockoutLimits: limits, // read-only: sent back as GET returned it, and ignored
	}
	rec = dbtest.Do(t, h, http.MethodPut, path, want)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	var saved, got Policy
	dbtest.Decode(t, rec, &saved)
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, path, nil), &got)
	if !reflect.DeepEqual(saved, want) || !reflect.DeepEqual(got, want) {
		t.Errorf("policy after saving: %+v, read back %+v; want %+v", saved, got, want)
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM audit.events
		WHERE tenant_id = $1 AND action = 'auth_policy.updated' AND actor_user_id = $2
		  AND (metadata->>'password_min_length')::int = 12 AND (metadata->>'lockout_threshold')::int = 3
	`, tenant, admin.ID); n != 1 {
		t.Errorf("%d auth_policy.updated events by the admin naming the new settings, want 1", n)
	}

	if on, err := svc.SelfRegistrationEnabled(ctx, tenant); err != nil || !on {
		t.Errorf("self-registration after saving: %v, %v; want on", on, err)
	}
	if pw, pk, ml, err := svc.AllowedSignInMethods(ctx, tenant); err != nil || !pw || !pk || ml {
		t.Errorf("sign-in methods after saving: password %v, passkey %v, magic link %v, %v; want magic link off", pw, pk, ml, err)
	}
	if on, err := svc.PasswordEnabled(ctx, tenant); err != nil || !on {
		t.Errorf("password sign-in after saving: %v, %v; want on", on, err)
	}
	if on, err := svc.PasskeyEnabled(ctx, tenant); err != nil || !on {
		t.Errorf("passkeys after saving: %v, %v; want on", on, err)
	}
	if on, ttl, err := svc.MagicLinkPolicy(ctx, tenant); err != nil || on || ttl != 30*time.Minute {
		t.Errorf("magic links after saving: %v for %s, %v; want off, 30 minutes", on, ttl, err)
	}
	if on, err := svc.RememberDeviceEnabled(ctx, tenant); err != nil || !on {
		t.Errorf("remembered devices after saving: %v, %v; want on", on, err)
	}
	if on, d, err := svc.RememberDevicePolicy(ctx, tenant); err != nil || !on || d != 14*24*time.Hour {
		t.Errorf("remembered devices after saving: %v for %s, %v; want on, 14 days", on, d, err)
	}
	if l, err := svc.SignInLockout(ctx, tenant); err != nil || l != (Lockout{Threshold: 3, Window: 10 * time.Minute, Duration: time.Hour}) {
		t.Errorf("lockout after saving: %+v, %v; want 3 failures in 10 minutes locking for an hour", l, err)
	}
	for pw, wantCode := range map[string]string{
		"Zq7#xLm2-Wv":   errs.CodeAuthPolicyPasswordTooShort,
		"zq7#xlm2-wvbt": errs.CodeAuthPolicyPasswordNoUppercase,
		"Zqh#xLmk-Wvbt": errs.CodeAuthPolicyPasswordNoNumber,
		"Zq7kxLm2eWvbt": errs.CodeAuthPolicyPasswordNoSymbol,
		"Zq7#xLm2-Wvbt": "",
	} {
		err := svc.ValidateForTenant(ctx, tenant, admin.Email, pw)
		code := ""
		if e := errs.As(err); e != nil {
			code = e.Code
		} else if err != nil {
			t.Fatalf("%q: unexpected error %v", pw, err)
		}
		if code != wantCode {
			t.Errorf("password %q under the saved rules: %q, want %q", pw, code, wantCode)
		}
	}

	rec = dbtest.Do(t, h, http.MethodPut, path, map[string]any{"passkey_enabled": true, "password_min_length": 4, "magic_link_ttl_minutes": 5000})
	var replaced Policy
	dbtest.Decode(t, rec, &replaced)
	if rec.Code != http.StatusOK || replaced.PasswordEnabled || replaced.SelfRegistrationEnabled || replaced.RememberDeviceEnabled ||
		replaced.RememberDeviceDays != 30 || replaced.LockoutThreshold != nil || replaced.LockoutDurationMinutes != nil {
		t.Errorf("policy after saving only passkeys: %d %+v; want everything else off or back to the default", rec.Code, replaced)
	}
	if replaced.PasswordMinLength != 8 || replaced.MagicLinkTTLMinutes != 1440 {
		t.Errorf("policy after saving 4 characters and 5000 minutes: %d, %d; want clamped to 8 and 1440",
			replaced.PasswordMinLength, replaced.MagicLinkTTLMinutes)
	}
	if m, err := svc.SignInMethodsFor(ctx, tenant); err != nil || m != (SignInMethods{Passkey: true}) {
		t.Errorf("sign-in methods after saving only passkeys: %+v, %v; want passkeys alone", m, err)
	}
	if l, err := svc.SignInLockout(ctx, tenant); err != nil || l != DefaultLockoutLimits().Defaults {
		t.Errorf("lockout after clearing it: %+v, %v; want the platform defaults", l, err)
	}
}

// TestPolicyRefusalsStoreNothing checks that each invalid setting is refused,
// named in the error, with nothing stored or audited, and that another
// organisation can neither read nor change the policy, which stays separate
// from its own.
func TestPolicyRefusalsStoreNothing(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	path := "/tenants/" + tenant.String() + "/auth-policy"
	stored := DefaultPolicy()
	stored.PasswordMinLength, stored.SelfRegistrationEnabled = 10, true
	if rec := dbtest.Do(t, h, http.MethodPut, path, stored); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}

	for _, c := range []struct {
		name, field, code string
		body              map[string]any
	}{
		{"a threshold under the minimum", "lockout_threshold", "out_of_range", map[string]any{"passkey_enabled": true, "lockout_threshold": 2}},
		{"a window over a day", "lockout_window_minutes", "out_of_range", map[string]any{"passkey_enabled": true, "lockout_window_minutes": 1441}},
		{"a lock lasting no time", "lockout_duration_minutes", "out_of_range", map[string]any{"passkey_enabled": true, "lockout_duration_minutes": 0}},
		{"a device remembered for 91 days", "remember_device_days", "out_of_range", map[string]any{"passkey_enabled": true, "remember_device_days": 91}},
		{"every sign-in method off", "password_enabled", "no_sign_in_method", map[string]any{"password_enabled": false}},
		{"email one-time codes", "otp_email_enabled", "not_available", map[string]any{"passkey_enabled": true, "otp_email_enabled": true}},
		{"SMS one-time codes", "otp_sms_enabled", "not_available", map[string]any{"passkey_enabled": true, "otp_sms_enabled": true}},
	} {
		rec := dbtest.Do(t, h, http.MethodPut, path, c.body)
		body := rec.Body.String()
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(body, errs.CodeValidation) ||
			!strings.Contains(body, `"field":"`+c.field+`","code":"`+c.code+`"`) {
			t.Errorf("%s: %d %s, want 422 naming %s %s", c.name, rec.Code, body, c.field, c.code)
		}
	}
	if rec := dbtest.Do(t, h, http.MethodPut, path, map[string]any{"passkey_enabled": true, "mfa_required": true}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), errs.CodeBadRequest) {
		t.Errorf("an unknown setting: %d %s, want 400", rec.Code, rec.Body.String())
	}
	if got, err := svc.Get(ctx, tenant); err != nil || got.PasswordMinLength != 10 || !got.SelfRegistrationEnabled || !got.PasswordEnabled {
		t.Errorf("policy after the refusals: %+v, %v; want it unchanged", got, err)
	}
	if n := updates(t, tenant); n != 1 {
		t.Errorf("%d auth_policy.updated events after the refusals, want only the first save", n)
	}

	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), (&Handler{Service: svc}).Mount)
	own := DefaultPolicy()
	own.PasswordMinLength = 14
	if rec := dbtest.Do(t, asOther, http.MethodPut, "/tenants/"+other.String()+"/auth-policy", own); rec.Code != http.StatusOK {
		t.Fatalf("the other organisation saving its own policy: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asOther, http.MethodGet, path, nil); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), errs.CodeForbidden) || strings.Contains(rec.Body.String(), "password_min_length") {
		t.Errorf("another organisation reading the policy: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asOther, http.MethodPut, path, DefaultPolicy()); rec.Code != http.StatusForbidden {
		t.Errorf("another organisation changing the policy: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if got, err := svc.Get(ctx, tenant); err != nil || got.PasswordMinLength != 10 || !got.SelfRegistrationEnabled {
		t.Errorf("policy after another organisation's attempts: %+v, %v; want it unchanged", got, err)
	}
	if got, err := svc.Get(ctx, other); err != nil || got.PasswordMinLength != 14 || got.SelfRegistrationEnabled {
		t.Errorf("the other organisation's own policy: %+v, %v; want its 14-character minimum", got, err)
	}
	if a, b := updates(t, tenant), updates(t, other); a != 1 || b != 1 {
		t.Errorf("auth_policy.updated events: %d here, %d for the other organisation; want one each", a, b)
	}
}

// TestUsageCountsHowPeopleSignIn checks that the usage counts the
// organisation's live people by way of signing in, and those each way alone
// lets in, and leaves out other organisations' people.
func TestUsageCountsHowPeopleSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	passwordOnly, both, passkeyOnly, googleOnly := dbtest.User(t, tenant, tenant), dbtest.User(t, tenant, tenant), dbtest.User(t, tenant, tenant), dbtest.User(t, tenant, tenant)
	elsewhere := dbtest.User(t, other, other)
	for _, u := range []uuid.UUID{passwordOnly.ID, both.ID, elsewhere.ID} {
		dbtest.SetPassword(t, u, "Kx7mQ2vLp9Wz")
	}
	for _, u := range []uuid.UUID{both.ID, passkeyOnly.ID} {
		if _, err := pool.Exec(ctx, `INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, sign_count) VALUES ($1, $2, $3, 0)`,
			u, []byte(uuid.NewString()), []byte("key")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, encryption_version) VALUES ($1, 'google', 'cid', 'legacy-secret', 0)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO "user".external_identities (user_id, tenant_id, provider, subject) VALUES ($1, $2, 'google', $3), ($4, $2, 'google', $5)`,
		googleOnly.ID, tenant, uuid.NewString(), both.ID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: NewService(pool)}).Mount)
	var got MethodUsage
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/tenants/"+tenant.String()+"/auth-policy/usage", nil), &got)
	if got.People != 5 || got.Password != (MethodCount{People: 2, Only: 1}) || got.Passkey != (MethodCount{People: 2, Only: 1}) {
		t.Errorf("usage %+v; want 5 people, 2 with a password (1 only), 2 with a passkey (1 only)", got)
	}
	if len(got.Social) != 1 || got.Social[0] != (SocialCount{Provider: "google", Linked: 2, Only: 1}) || !got.MagicLinkEnabled {
		t.Errorf("social %+v, magic link %v; want google with 2 linked, 1 only, and magic links on", got.Social, got.MagicLinkEnabled)
	}
}

// TestEveryMethodOffNeedsSingleSignOn checks that an organisation may switch
// every first-factor method off only while it has an active SAML or LDAP
// connection of its own: a draft or disabled one, or another organisation's
// active one, doesn't count.
func TestEveryMethodOffNeedsSingleSignOn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	path := "/tenants/" + tenant.String() + "/auth-policy"
	ssoOnly := map[string]any{"password_enabled": false, "passkey_enabled": false, "magic_link_enabled": false}
	refused := func(when string) {
		t.Helper()
		if rec := dbtest.Do(t, h, http.MethodPut, path, ssoOnly); rec.Code != http.StatusUnprocessableEntity ||
			!strings.Contains(rec.Body.String(), `"code":"no_sign_in_method"`) {
			t.Errorf("every method off %s: %d %s, want 422 no_sign_in_method", when, rec.Code, rec.Body.String())
		}
	}
	saml := func(tenant uuid.UUID, status string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO tenant.saml_connections (tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate, status)
			VALUES ($1, 'Okta', 'https://idp.example.test', 'https://idp.example.test/sso', 'cert', $2)
		`, tenant, status); err != nil {
			t.Fatal(err)
		}
	}

	refused("with no connection")
	saml(tenant, "draft")
	saml(tenant, "disabled")
	saml(other, "active")
	refused("with a draft and a disabled connection, and another organisation's active one")

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant.ldap_connections (tenant_id, name, server_url, bind_dn, bind_password, base_dn, status)
		VALUES ($1, 'Directory', 'ldaps://ldap.example.test', 'cn=service', 'secret', 'dc=example', 'active')
	`, tenant); err != nil {
		t.Fatal(err)
	}
	if rec := dbtest.Do(t, h, http.MethodPut, path, ssoOnly); rec.Code != http.StatusOK {
		t.Fatalf("every method off with an active LDAP connection: %d %s", rec.Code, rec.Body.String())
	}
	if m, err := svc.SignInMethodsFor(ctx, tenant); err != nil || m != (SignInMethods{}) {
		t.Errorf("sign-in methods of a single-sign-on-only organisation: %+v, %v; want none", m, err)
	}
}
