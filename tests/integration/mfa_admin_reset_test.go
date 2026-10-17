//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
)

// An administrator resetting a person's MFA removes every second factor they
// hold — push devices included — and what those factors earned, and withdraws
// an unused code for linking a phone, so the person shows as having none and
// can set one up afresh; the audit record names what was removed.
func TestAdminMFAResetRemovesEveryFactor(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	devices := newDeviceAuth()
	tenantID := createTenant(t, ctx, uniqueSlug("reset"))
	admin, member := createUserInTenant(t, ctx, tenantID), createUserInTenant(t, ctx, tenantID)

	holdApp(t, ctx, svc, member)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.mfa_otp_factors (user_id, channel, destination, verified_at)
		VALUES ($1, 'email', $2, NOW())`, member, uniqueSlug("reset")+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RegisterPushDevice(ctx, member, "Phone", "ExponentPushToken["+uniqueSlug("tok")+"]", "ios"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePushChallenge(ctx, member, "sign_in", mfa.PushChallengeContext{}); err != nil {
		t.Fatal(err)
	}
	rememberDevice(t, ctx, devices, member, tenantID, uaChromeMac)
	_, pairingCode, err := svc.CreatePushPairing(ctx, member, &tenantID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	recordStepUp(t, ctx, svc, member, openSession(t, ctx, member, tenantID), "totp")

	r := chi.NewRouter()
	r.Use(withPrincipal(admin, tenantID))
	(&user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New(), MFA: svc}).Mount(r)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/users/"+member.String()+"/mfa", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rr.Code, rr.Body.String())
	}

	var left int
	if err := testPool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM auth.mfa_totp WHERE user_id = $1)
		     + (SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id = $1)
		     + (SELECT count(*) FROM auth.mfa_otp_factors WHERE user_id = $1)
		     + (SELECT count(*) FROM auth.mfa_push_devices WHERE user_id = $1)
		     + (SELECT count(*) FROM auth.mfa_push_challenges WHERE user_id = $1 AND status = 'pending')
		     + (SELECT count(*) FROM auth.mfa_push_pairings WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW())
		     + (SELECT count(*) FROM auth.trusted_devices WHERE user_id = $1)
		     + (SELECT count(*) FROM auth.mfa_verifications WHERE user_id = $1)`, member).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("a reset must remove every factor and what it earned, %d rows left", left)
	}
	if factors, err := svc.LoginFactors(ctx, member); err != nil || len(factors) != 0 {
		t.Fatalf("after a reset the person must hold no second factor: %+v (%v)", factors, err)
	}

	var raw []byte
	if err := testPool.QueryRow(ctx, `
		SELECT metadata->'removed' FROM audit.events WHERE action = 'mfa.admin_reset' AND resource_id = $1`, member).
		Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var removed map[string]int
	_ = json.Unmarshal(raw, &removed)
	for _, kind := range []string{"totp", "otp_factors", "push_devices", "push_challenges", "push_pairings", "trusted_devices", "step_ups"} {
		if removed[kind] != 1 {
			t.Errorf("audit: removed[%s] = %d, want 1 (%s)", kind, removed[kind], raw)
		}
	}
	if removed["recovery_codes"] != 10 {
		t.Errorf("audit: removed[recovery_codes] = %d, want 10", removed["recovery_codes"])
	}

	if _, err := svc.ClaimPushPairing(ctx, pairingCode, "Phone", "ExponentPushToken["+uniqueSlug("tok")+"]", "ios", "", ""); err == nil {
		t.Fatal("a pairing code asked for before the reset must not link a phone after it")
	}

	// Setting up again works as for someone new.
	if e := startApp(t, ctx, svc, member); e.Replacing {
		t.Fatal("after a reset a new authenticator app is a first setup, not a replacement")
	}
}
