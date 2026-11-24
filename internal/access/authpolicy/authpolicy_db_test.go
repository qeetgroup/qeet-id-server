//go:build integration

package authpolicy

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// newService returns the policy service with the breach check off.
func newService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(dbtest.Pool(t), NoBreachCheck{})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// updates counts the organization's auth_policy.updated audit events.
func updates(t *testing.T, organizationID uuid.UUID) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth_policy.updated'`, organizationID)
}

// TestPolicyIsSavedAndAppliedToSignIn checks that an organization that never
// saved a policy gets the defaults; that a policy saved over HTTP is returned,
// audited and read by the sign-in checks; and that a save replaces the whole
// policy, clamping the password length and magic-link lifetime.
func TestPolicyIsSavedAndAppliedToSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	path := "/organizations/" + organization.String() + "/auth-policy"

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
		Min:      LockoutSettingsView{Threshold: 3, WindowMinutes: 15, DurationMinutes: 15},
		Max:      LockoutSettingsView{Threshold: 5, WindowMinutes: 1440, DurationMinutes: 1440},
	}
	if limits == nil || *limits != wantLimits {
		t.Errorf("lockout limits %+v, want %+v", limits, wantLimits)
	}
	if on, err := svc.SelfRegistrationEnabled(ctx, organization); err != nil || on {
		t.Errorf("self-registration by default: %v, %v; want off", on, err)
	}
	if m, err := svc.SignInMethodsFor(ctx, organization); err != nil || m != (SignInMethods{Password: true, Passkey: true, MagicLink: true}) {
		t.Errorf("sign-in methods by default: %+v, %v; want all three", m, err)
	}
	if on, d, err := svc.RememberDevicePolicy(ctx, organization); err != nil || on || d != 30*24*time.Hour {
		t.Errorf("remembered devices by default: %v for %s, %v; want off, 30 days", on, d, err)
	}
	if l, err := svc.SignInLockout(ctx, organization); err != nil || l != DefaultLockoutLimits().Defaults {
		t.Errorf("lockout by default: %+v, %v; want the platform defaults", l, err)
	}

	want := Policy{
		PasswordEnabled: true, PasswordMinLength: 12,
		PasswordRequireUppercase: true, PasswordRequireNumber: true, PasswordRequireSymbol: true,
		MagicLinkTTLMinutes: 30, PasskeyEnabled: true, SelfRegistrationEnabled: true,
		RememberDeviceEnabled: true, RememberDeviceDays: 14,
		LockoutThreshold: new(3), LockoutWindowMinutes: new(30), LockoutDurationMinutes: new(60),
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
		WHERE organization_id = $1 AND action = 'auth_policy.updated' AND actor_user_id = $2
		  AND (metadata->>'password_min_length')::int = 12 AND (metadata->>'lockout_threshold')::int = 3
	`, organization, admin.ID); n != 1 {
		t.Errorf("%d auth_policy.updated events by the admin naming the new settings, want 1", n)
	}

	if on, err := svc.SelfRegistrationEnabled(ctx, organization); err != nil || !on {
		t.Errorf("self-registration after saving: %v, %v; want on", on, err)
	}
	if pw, pk, ml, err := svc.AllowedSignInMethods(ctx, organization); err != nil || !pw || !pk || ml {
		t.Errorf("sign-in methods after saving: password %v, passkey %v, magic link %v, %v; want magic link off", pw, pk, ml, err)
	}
	if on, err := svc.PasswordEnabled(ctx, organization); err != nil || !on {
		t.Errorf("password sign-in after saving: %v, %v; want on", on, err)
	}
	if on, err := svc.PasskeyEnabled(ctx, organization); err != nil || !on {
		t.Errorf("passkeys after saving: %v, %v; want on", on, err)
	}
	if on, ttl, err := svc.MagicLinkPolicy(ctx, organization); err != nil || on || ttl != 30*time.Minute {
		t.Errorf("magic links after saving: %v for %s, %v; want off, 30 minutes", on, ttl, err)
	}
	if on, err := svc.RememberDeviceEnabled(ctx, organization); err != nil || !on {
		t.Errorf("remembered devices after saving: %v, %v; want on", on, err)
	}
	if on, d, err := svc.RememberDevicePolicy(ctx, organization); err != nil || !on || d != 14*24*time.Hour {
		t.Errorf("remembered devices after saving: %v for %s, %v; want on, 14 days", on, d, err)
	}
	if l, err := svc.SignInLockout(ctx, organization); err != nil || l != (Lockout{Threshold: 3, Window: 30 * time.Minute, Duration: time.Hour}) {
		t.Errorf("lockout after saving: %+v, %v; want 3 failures in 30 minutes locking for an hour", l, err)
	}
	for pw, wantCode := range map[string]string{
		"Zq7#xLm2-Wv":   errs.CodeAuthPolicyPasswordTooShort,
		"zq7#xlm2-wvbt": errs.CodeAuthPolicyPasswordNoUppercase,
		"Zqh#xLmk-Wvbt": errs.CodeAuthPolicyPasswordNoNumber,
		"Zq7kxLm2eWvbt": errs.CodeAuthPolicyPasswordNoSymbol,
		"Zq7#xLm2-Wvbt": "",
	} {
		err := svc.ValidateForOrganization(ctx, organization, admin.Email, pw)
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
	if m, err := svc.SignInMethodsFor(ctx, organization); err != nil || m != (SignInMethods{Passkey: true}) {
		t.Errorf("sign-in methods after saving only passkeys: %+v, %v; want passkeys alone", m, err)
	}
	if l, err := svc.SignInLockout(ctx, organization); err != nil || l != DefaultLockoutLimits().Defaults {
		t.Errorf("lockout after clearing it: %+v, %v; want the platform defaults", l, err)
	}
}

// TestPolicyRefusalsStoreNothing checks that each invalid setting is refused,
// named in the error, with nothing stored or audited, and that another
// organization can neither read nor change the policy, which stays separate
// from its own.
func TestPolicyRefusalsStoreNothing(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	path := "/organizations/" + organization.String() + "/auth-policy"
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
		{"a threshold looser than the platform's", "lockout_threshold", "out_of_range", map[string]any{"passkey_enabled": true, "lockout_threshold": 6}},
		{"a window shorter than the platform's", "lockout_window_minutes", "out_of_range", map[string]any{"passkey_enabled": true, "lockout_window_minutes": 14}},
		{"a lock shorter than the platform's", "lockout_duration_minutes", "out_of_range", map[string]any{"passkey_enabled": true, "lockout_duration_minutes": 14}},
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
	if got, err := svc.Get(ctx, organization); err != nil || got.PasswordMinLength != 10 || !got.SelfRegistrationEnabled || !got.PasswordEnabled {
		t.Errorf("policy after the refusals: %+v, %v; want it unchanged", got, err)
	}
	if n := updates(t, organization); n != 1 {
		t.Errorf("%d auth_policy.updated events after the refusals, want only the first save", n)
	}

	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), (&Handler{Service: svc}).Mount)
	own := DefaultPolicy()
	own.PasswordMinLength = 14
	if rec := dbtest.Do(t, asOther, http.MethodPut, "/organizations/"+other.String()+"/auth-policy", own); rec.Code != http.StatusOK {
		t.Fatalf("the other organization saving its own policy: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asOther, http.MethodGet, path, nil); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), errs.CodeForbidden) || strings.Contains(rec.Body.String(), "password_min_length") {
		t.Errorf("another organization reading the policy: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asOther, http.MethodPut, path, DefaultPolicy()); rec.Code != http.StatusForbidden {
		t.Errorf("another organization changing the policy: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if got, err := svc.Get(ctx, organization); err != nil || got.PasswordMinLength != 10 || !got.SelfRegistrationEnabled {
		t.Errorf("policy after another organization's attempts: %+v, %v; want it unchanged", got, err)
	}
	if got, err := svc.Get(ctx, other); err != nil || got.PasswordMinLength != 14 || got.SelfRegistrationEnabled {
		t.Errorf("the other organization's own policy: %+v, %v; want its 14-character minimum", got, err)
	}
	if a, b := updates(t, organization), updates(t, other); a != 1 || b != 1 {
		t.Errorf("auth_policy.updated events: %d here, %d for the other organization; want one each", a, b)
	}
}

// TestUpdateCommitsWithItsAudit checks that a policy save and its audit row
// commit together: a save whose audit row can't be written is not stored.
func TestUpdateCommitsWithItsAudit(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	svc := newService(t)
	p := DefaultPolicy()
	p.PasswordMinLength = 12
	unrecordable := audit.Actor{UserID: &admin.ID, Type: "user", IP: "not an address"}
	if _, err := svc.Update(ctx, organization, p, unrecordable); err == nil {
		t.Fatal("a save whose audit row failed was accepted")
	}
	if got, err := svc.Get(ctx, organization); err != nil || got.PasswordMinLength == 12 {
		t.Errorf("after a save that couldn't be audited the policy is %+v (%v); want it unchanged", got, err)
	}
	if n := updates(t, organization); n != 0 {
		t.Errorf("%d saves audited, want none", n)
	}
}
