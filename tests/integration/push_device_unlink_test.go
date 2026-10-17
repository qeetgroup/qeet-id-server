//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
)

// A linked phone can remove itself with its own credential, that credential
// ages out, and an administrator can disconnect a member's lost phone; a phone
// removed or expired by any route gets no requests and cannot answer one.

func linkPhone(t *testing.T, ctx context.Context, svc *mfa.Service, userID uuid.UUID) (mfa.PushDevice, string) {
	t.Helper()
	d, token, err := svc.RegisterPushDevice(ctx, userID, "Phone", "ExponentPushToken["+uniqueSlug("tok")+"]", "ios")
	if err != nil {
		t.Fatal(err)
	}
	return d, token
}

func pushDevicesLeft(t *testing.T, ctx context.Context, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_push_devices WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestPhoneUnlinksItself: the app unlinks with its device credential; the
// wrong credential is refused; an unlinked phone cannot answer a request.
func TestPhoneUnlinksItself(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("unlink")))
	device, token := linkPhone(t, ctx, svc, userID)
	challenge, err := svc.CreatePushChallenge(ctx, userID, "sign_in", mfa.PushChallengeContext{})
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	(&mfa.Handler{Service: svc}).MountPublic(r)
	unlink := func(credential string) int {
		body, _ := json.Marshal(map[string]any{"user_id": userID, "device_token": credential})
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mfa/push/devices/"+device.ID.String()+"/unlink", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := unlink("not-the-credential"); code != http.StatusUnauthorized {
		t.Fatalf("unlink with the wrong credential = %d, want 401", code)
	}
	if code := unlink(token); code != http.StatusNoContent {
		t.Fatalf("unlink with the device's credential = %d, want 204", code)
	}
	if n := pushDevicesLeft(t, ctx, userID); n != 0 {
		t.Fatalf("the phone must be removed from the account, %d left", n)
	}
	if err := svc.RespondToPushChallenge(ctx, challenge, userID, token, true); err == nil {
		t.Fatal("an unlinked phone must not answer a request delivered earlier")
	}
	if deviceAuditCount(t, ctx, userID, "mfa.push_device_unlinked") != 1 {
		t.Error("the unlink must be audited")
	}
}

// TestPhoneCredentialExpires: past its expiry a phone is not offered at
// sign-in and cannot answer a request.
func TestPhoneCredentialExpires(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("expire-phone")))
	_, token := linkPhone(t, ctx, svc, userID)
	challenge, err := svc.CreatePushChallenge(ctx, userID, "sign_in", mfa.PushChallengeContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.mfa_push_devices SET device_token_expires_at = NOW() - INTERVAL '1 minute' WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RespondToPushChallenge(ctx, challenge, userID, token, true); err == nil {
		t.Fatal("a phone past its expiry must not answer a request")
	}
	factors, err := svc.LoginFactors(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range factors {
		if f.Type == "push" {
			t.Fatal("a phone past its expiry must not be offered as a second factor")
		}
	}
}

// TestAdministratorDisconnectsAPhone: an administrator lists and disconnects a
// member's phone, audited with them as the actor; someone who is not a member
// is not found.
func TestAdministratorDisconnectsAPhone(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	org, elsewhere := createTenant(t, ctx, uniqueSlug("phones")), createTenant(t, ctx, uniqueSlug("phones-elsewhere"))
	admin, member, outsider := createUserInTenant(t, ctx, org), createUserInTenant(t, ctx, org), createUserInTenant(t, ctx, elsewhere)
	device, _ := linkPhone(t, ctx, svc, member)

	r := chi.NewRouter()
	r.Use(withPrincipal(admin, org))
	(&mfa.Handler{Service: svc}).MountAdmin(r)
	call := func(method, path string) (int, []byte) {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
		return rr.Code, rr.Body.Bytes()
	}
	if code, body := call(http.MethodGet, "/users/"+member.String()+"/push-devices"); code != http.StatusOK || !bytes.Contains(body, []byte(device.ID.String())) {
		t.Fatalf("list a member's phones: %d %s", code, body)
	}
	if code, _ := call(http.MethodGet, "/users/"+outsider.String()+"/push-devices"); code != http.StatusNotFound {
		t.Fatalf("someone who is not a member = %d, want 404", code)
	}
	if code, body := call(http.MethodDelete, "/users/"+member.String()+"/push-devices/"+device.ID.String()); code != http.StatusNoContent {
		t.Fatalf("disconnect: %d %s", code, body)
	}
	if n := pushDevicesLeft(t, ctx, member); n != 0 {
		t.Fatalf("the phone must be disconnected, %d left", n)
	}
	if deviceAuditCount(t, ctx, admin, "mfa.push_device_revoked") != 1 {
		t.Error("the disconnect must be audited with the administrator as the actor")
	}
}
