//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Every sign-in is assessed for risk and leaves its country and device for the
// next one to be compared against. A risky sign-in by someone holding a second
// factor is asked for it; one by someone holding none is confirmed with a code
// sent to their verified email address, and refused when there is none.

const uaScript = "curl/8.4.0"

// newRiskFixture is the factor fixture with risk assessed and the
// confirmation email sent through its capture sender.
func newRiskFixture(t *testing.T, ctx context.Context) *factorFixture {
	t.Helper()
	f := newFactorFixture(t, ctx)
	f.auth.SetRiskAssessor(risk.NewService(testPool))
	f.auth.SetSender(f.sender)
	return f
}

// postFrom posts as a client with the given user agent and country.
func (f *factorFixture) postFrom(path string, body any, ua, country string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ua)
	if country != "" {
		req = req.WithContext(httpx.WithGeoCountry(req.Context(), country))
	}
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

func (f *factorFixture) signInFrom(t *testing.T, email, ua, country string) (*httptest.ResponseRecorder, challenge) {
	t.Helper()
	rr := f.postFrom("/v1/auth/login", map[string]string{"email": email, "password": factorPassword}, ua, country)
	var c challenge
	_ = json.Unmarshal(rr.Body.Bytes(), &c)
	return rr, c
}

func verifyEmail(t *testing.T, ctx context.Context, userID uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
}

func riskSettings(t *testing.T, ctx context.Context, tenantID uuid.UUID, travel, device bool) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.risk_settings (tenant_id, medium_threshold, force_mfa_at_level, impossible_travel_enabled,
		                                device_reputation_enabled)
		VALUES ($1, 0.2, 'medium', $2, $3)`, tenantID, travel, device); err != nil {
		t.Fatal(err)
	}
}

// confirmByEmail completes a risk challenge with the code sent to the
// verified address and returns the response.
func (f *factorFixture) confirmByEmail(t *testing.T, c challenge, address string) *httptest.ResponseRecorder {
	t.Helper()
	if rr := f.post("/v1/auth/mfa/send", map[string]any{"mfa_token": c.MFAToken, "factor_id": c.Factors[0].ID}); rr.Code != http.StatusOK {
		t.Fatalf("send the confirmation code: %d %s", rr.Code, rr.Body.String())
	}
	m, _ := f.sender.last()
	if m.To != address || sixDigits.FindString(m.Body) == "" {
		t.Fatalf("the confirmation code must go to the verified address: %+v", m)
	}
	rr, _ := f.complete(map[string]any{"mfa_token": c.MFAToken, "code": sixDigits.FindString(m.Body)})
	return rr
}

// TestRiskySignInWithoutAFactorIsConfirmedByEmail: a risky sign-in by someone
// with no second factor gets a challenge whose one factor is their verified
// email; the code sent there confirms it, a wrong one does not, and the
// session it opens is not stepped up.
func TestRiskySignInWithoutAFactorIsConfirmedByEmail(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRiskFixture(t, ctx)
	me, email := f.member(t, ctx)
	verifyEmail(t, ctx, me)

	rr, c := f.signInFrom(t, email, uaScript, "")
	if rr.Code != http.StatusOK || !c.MFARequired || c.AccessToken != "" {
		t.Fatalf("a risky sign-in with no factor must be challenged: %d %s", rr.Code, rr.Body.String())
	}
	if len(c.Factors) != 1 || c.Factors[0].Type != "email" || c.Factors[0].ID == nil ||
		c.Factors[0].ID.String() != c.MFAToken || c.Factors[0].Destination == email {
		t.Fatalf("the challenge must offer the masked verified email, named by the challenge: %+v", c.Factors)
	}
	if rr, _ := f.complete(map[string]any{"mfa_token": c.MFAToken, "code": "000000"}); errorCode(t, rr) != errs.CodeMFACodeInvalid {
		t.Fatalf("a wrong code: %d %s", rr.Code, rr.Body.String())
	}
	done := f.confirmByEmail(t, c, email)
	var pair struct {
		AccessToken string    `json:"access_token"`
		SessionID   uuid.UUID `json:"session_id"`
	}
	_ = json.Unmarshal(done.Body.Bytes(), &pair)
	if done.Code != http.StatusOK || pair.AccessToken == "" {
		t.Fatalf("the emailed code must confirm the sign-in: %d %s", done.Code, done.Body.String())
	}
	if stepUpMet(t, ctx, f.mfa, me, pair.SessionID) {
		t.Fatal("a confirmed sign-in met no second factor, so its session must not be stepped up")
	}
	var confirmed int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.sign_in_confirmed'`, me).Scan(&confirmed); err != nil || confirmed != 1 {
		t.Fatalf("the confirmation must be audited: %d %v", confirmed, err)
	}
}

// TestRiskySignInWithNothingToConfirmIsRefused: with no second factor and no
// verified email address, a risky sign-in is refused.
func TestRiskySignInWithNothingToConfirmIsRefused(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRiskFixture(t, ctx)
	_, email := f.member(t, ctx)
	if rr, _ := f.signInFrom(t, email, uaScript, ""); errorCode(t, rr) != errs.CodeAuthRiskVerificationUnavailable {
		t.Fatalf("a risky sign-in with nothing to confirm it: %d %s", rr.Code, rr.Body.String())
	}
}

// TestRiskySignInWithAFactorAsksForIt: someone holding a second factor is
// asked for it, not for an email code.
func TestRiskySignInWithAFactorAsksForIt(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRiskFixture(t, ctx)
	me, email := f.member(t, ctx)
	verifyEmail(t, ctx, me)
	f.holdTOTP(t, ctx, me)
	_, c := f.signInFrom(t, email, uaScript, "")
	if !c.MFARequired || len(c.Methods) == 0 || c.Methods[0] != "totp" {
		t.Fatalf("a risky sign-in by a factor holder must ask for the factor: %+v", c)
	}
}

// TestEverySignInIsRecorded: an ordinary sign-in with no risk signal turned on
// goes straight in and still leaves its device for the next one.
func TestEverySignInIsRecorded(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRiskFixture(t, ctx)
	me, email := f.member(t, ctx)
	if rr, c := f.signInFrom(t, email, uaChromeMac, "IN"); rr.Code != http.StatusOK || c.AccessToken == "" {
		t.Fatalf("an ordinary sign-in: %d %s", rr.Code, rr.Body.String())
	}
	var recorded int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM auth.login_context_history WHERE user_id = $1 AND country = 'IN'`, me).Scan(&recorded); err != nil || recorded != 1 {
		t.Fatalf("the sign-in must be recorded for later ones: %d %v", recorded, err)
	}
}

// TestUsualDeviceIsRecognised: with device reputation on, a first sign-in from
// a device is confirmed, and the next one from it is recognised.
func TestUsualDeviceIsRecognised(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRiskFixture(t, ctx)
	riskSettings(t, ctx, f.tenantID, false, true)
	me, email := f.member(t, ctx)
	verifyEmail(t, ctx, me)

	_, first := f.signInFrom(t, email, uaChromeMac, "")
	if !first.MFARequired || len(first.Methods) != 1 || first.Methods[0] != "email" {
		t.Fatalf("a new device must be confirmed: %+v", first)
	}
	if rr := f.confirmByEmail(t, first, email); rr.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", rr.Code, rr.Body.String())
	}
	if rr, again := f.signInFrom(t, email, uaChromeMac, ""); rr.Code != http.StatusOK || again.AccessToken == "" {
		t.Fatalf("the usual device must be recognised: %d %s", rr.Code, rr.Body.String())
	}
}

// TestImpossibleTravelIsRecognised: with impossible travel on, two sign-ins
// from countries that cannot be travelled between in the time are caught.
func TestImpossibleTravelIsRecognised(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRiskFixture(t, ctx)
	riskSettings(t, ctx, f.tenantID, true, false)
	me, email := f.member(t, ctx)
	verifyEmail(t, ctx, me)
	if rr, c := f.signInFrom(t, email, uaChromeMac, "IN"); rr.Code != http.StatusOK || c.AccessToken == "" {
		t.Fatalf("the first sign-in: %d %s", rr.Code, rr.Body.String())
	}
	if _, c := f.signInFrom(t, email, uaChromeMac, "US"); !c.MFARequired || c.Methods[0] != "email" {
		t.Fatalf("a sign-in from another continent minutes later must be confirmed: %+v", c)
	}
}

// TestHostedAndMagicLinkSignInsAreAssessed: the hosted password sign-in is
// held to the same terms; a magic link, which proved the mailbox already, goes
// in.
func TestHostedAndMagicLinkSignInsAreAssessed(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRiskFixture(t, ctx)
	me, email := f.member(t, ctx)
	verifyEmail(t, ctx, me)

	res, err := f.auth.BeginLoginSession(ctx, auth.SignInAttempt{Email: email, Password: factorPassword, IP: "198.51.100.7"},
		uaScript, "", "")
	if err != nil || !res.MFARequired || len(res.Methods) != 1 || res.Methods[0] != "email" {
		t.Fatalf("a risky hosted sign-in with no factor must be confirmed: %+v %v", res, err)
	}
	ml, err := f.auth.BeginMagicLinkSignIn(ctx, me, f.tenantID, "198.51.100.7", uaScript)
	if err != nil || ml.Pair == nil {
		t.Fatalf("a magic link proved the mailbox, so it must go in: %+v %v", ml, err)
	}
}
