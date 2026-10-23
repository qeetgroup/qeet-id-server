//go:build integration

package mfa

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// api calls the MFA routes as one signed-in session.
type api struct {
	t *testing.T
	h http.Handler
}

func (a api) call(method, path string, body any, want int) map[string]any {
	a.t.Helper()
	rec := dbtest.Do(a.t, a.h, method, path, body)
	if rec.Code != want {
		a.t.Fatalf("%s %s: %d %s, want %d", method, path, rec.Code, rec.Body.String(), want)
	}
	return decodeMap(a.t, rec)
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s: %v", rec.Body.String(), err)
		}
	}
	return out
}

// TestFactorsOverHTTP walks a person's second factors through the API: an
// authenticator app with recovery codes and the step-up it gives, an email
// factor, a phone linked by device and by pairing code, and turning the app
// off again.
func TestFactorsOverHTTP(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc, authSvc := services(t, mail)
	a, tenant := member(t)
	pair, err := authSvc.IssuePair(ctx, a.ID, tenant, "192.0.2.1", "test", "password")
	if err != nil {
		t.Fatal(err)
	}
	p := dbtest.Principal(a.ID, tenant)
	p.SessionID = &pair.SessionID
	c := api{t, dbtest.Serve(p, (&Handler{Service: svc}).Mount)}

	if got := c.call(http.MethodGet, "/mfa/totp", nil, http.StatusOK); got["enrolled"] != false {
		t.Fatalf("status before enrolment: %v", got)
	}
	enrollment := c.call(http.MethodPost, "/mfa/totp/enroll/start", map[string]string{"account": a.Email}, http.StatusOK)
	secret, _ := enrollment["secret"].(string)
	confirmed := c.call(http.MethodPost, "/mfa/totp/enroll/confirm", map[string]string{"code": codeAt(t, secret, 0)}, http.StatusOK)
	if codes, _ := confirmed["recovery_codes"].([]any); len(codes) != recoveryCodeCount {
		t.Fatalf("confirm gave %d recovery codes, want %d", len(codes), recoveryCodeCount)
	}
	if got := c.call(http.MethodGet, "/mfa/recovery-codes", nil, http.StatusOK); got["remaining"] != float64(recoveryCodeCount) {
		t.Errorf("recovery codes: %v", got)
	}

	// Regenerating recovery codes needs a step-up of the calling session:
	// refused to another session until it meets the authenticator app.
	second, err := authSvc.IssuePair(ctx, a.ID, tenant, "192.0.2.1", "test", "password")
	if err != nil {
		t.Fatal(err)
	}
	p2 := dbtest.Principal(a.ID, tenant)
	p2.SessionID = &second.SessionID
	c = api{t, dbtest.Serve(p2, (&Handler{Service: svc}).Mount)}
	c.call(http.MethodPost, "/mfa/recovery-codes/regenerate", nil, http.StatusForbidden)
	c.call(http.MethodPost, "/mfa/totp/verify", map[string]string{"code": codeAt(t, secret, 1)}, http.StatusOK)
	if got := c.call(http.MethodGet, "/mfa/step-up/status", nil, http.StatusOK); got["recently_verified"] != true {
		t.Errorf("step-up after verifying: %v, want recently verified", got)
	}
	if regenerated := c.call(http.MethodPost, "/mfa/recovery-codes/regenerate", nil, http.StatusOK); regenerated["recovery_codes"] == nil {
		t.Errorf("regenerate: %v", regenerated)
	}

	// An email factor: added, confirmed with the code sent, used, removed.
	added := c.call(http.MethodPost, "/mfa/otp/factors", map[string]string{"channel": "email", "destination": a.Email}, http.StatusCreated)
	factor, _ := added["factor_id"].(string)
	c.call(http.MethodPost, "/mfa/otp/factors/"+factor+"/confirm", map[string]string{"code": sixDigits.FindString(mail.Last(t).Body)}, http.StatusOK)
	if items, _ := c.call(http.MethodGet, "/mfa/otp/factors", nil, http.StatusOK)["items"].([]any); len(items) != 1 {
		t.Errorf("email factors: %v, want one", items)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.mfa_otp_codes SET created_at = created_at - interval '1 minute' WHERE factor_id = $1`, factor); err != nil {
		t.Fatal(err)
	}
	c.call(http.MethodPost, "/mfa/otp/factors/"+factor+"/challenge", nil, http.StatusAccepted)
	c.call(http.MethodPost, "/mfa/otp/verify", map[string]string{"code": sixDigits.FindString(mail.Last(t).Body)}, http.StatusOK)
	c.call(http.MethodDelete, "/mfa/otp/factors/"+factor, nil, http.StatusNoContent)

	// A phone: linked directly, listed, revoked; a pairing code made and withdrawn.
	device := c.call(http.MethodPost, "/mfa/push/devices", map[string]string{"name": "Phone", "push_token": "ExponentPushToken[x]", "platform": "ios"}, http.StatusCreated)
	if device["device_token"] == "" {
		t.Errorf("register device: %v", device)
	}
	devices, _ := c.call(http.MethodGet, "/mfa/push/devices", nil, http.StatusOK)["items"].([]any)
	if len(devices) != 1 {
		t.Fatalf("devices %v, want one", devices)
	}
	deviceID, _ := devices[0].(map[string]any)["id"].(string)
	c.call(http.MethodDelete, "/mfa/push/devices/"+deviceID, nil, http.StatusNoContent)
	pairing := c.call(http.MethodPost, "/mfa/push/pairing", nil, http.StatusCreated)
	pairingID, _ := pairing["id"].(string)
	if got := c.call(http.MethodGet, "/mfa/push/pairing/"+pairingID, nil, http.StatusOK); got["status"] != "pending" {
		t.Errorf("pairing %v, want pending", got)
	}
	c.call(http.MethodDelete, "/mfa/push/pairing/"+pairingID, nil, http.StatusNoContent)

	// Turning the app off, with the step-up still fresh.
	c.call(http.MethodDelete, "/mfa/totp", nil, http.StatusNoContent)
	if got := c.call(http.MethodGet, "/mfa/totp", nil, http.StatusOK); got["enrolled"] != false {
		t.Errorf("status after turning the app off: %v", got)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action LIKE 'mfa.%'`, a.ID); n < 5 {
		t.Errorf("%d MFA changes audited, want each one", n)
	}
}
