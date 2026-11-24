//go:build integration

package mfa

import (
	"errors"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestEmailCodes checks that an email factor is confirmed only by the code
// sent to it, shown masked, completes a sign-in with a code sent then, and
// can be removed; and that a step-up code never completes a sign-in, nor a
// sign-in code a step-up.
func TestEmailCodes(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	mfaSvc, authSvc := services(t, mail)
	a, organization := member(t)

	factor, err := mfaSvc.EnrollOTPStart(ctx, a.ID, &organization, "email", a.Email)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	sent := mail.Last(t)
	code := sixDigits.FindString(sent.Body)
	if sent.To != a.Email || code == "" {
		t.Fatalf("sent %q to %s; want a code to %s", sent.Body, sent.To, a.Email)
	}
	if sent.TemplateKey != "" {
		t.Errorf("an enrollment code sent as the %q template; want the platform's wording", sent.TemplateKey)
	}
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	confirm := func(c string) error {
		t.Helper()
		return mfaSvc.EnrollOTPConfirm(ctx, a.ID, factor, c, self(a.ID))
	}
	if err := confirm(wrong); !errors.Is(err, ErrOTPCodeInvalid) {
		t.Errorf("confirm with a wrong code: %v; want %v", err, ErrOTPCodeInvalid)
	}
	if err := confirm(code); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	factors, err := mfaSvc.ListOTPFactors(ctx, a.ID)
	if err != nil || len(factors) != 1 || !factors[0].Verified || factors[0].Destination == a.Email {
		t.Fatalf("factors %+v, %v; want one confirmed, its address masked", factors, err)
	}

	// The resend wait is per factor: let it pass.
	pastWait := func() {
		t.Helper()
		if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.mfa_otp_codes SET created_at = created_at - interval '1 minute' WHERE factor_id = $1`, factor); err != nil {
			t.Fatal(err)
		}
	}
	pastWait()
	token := challenge(t, authSvc, a)
	if err := mfaSvc.ChallengeOTP(ctx, a.ID, &organization, factor); err != nil {
		t.Fatalf("send step-up code: %v", err)
	}
	stepUp := mail.Last(t)
	if !strings.Contains(stepUp.Body, "confirm a change") || stepUp.TemplateKey != "" {
		t.Errorf("step-up mail %q as template %q; want the platform's wording, saying what the code is for", stepUp.Body, stepUp.TemplateKey)
	}
	if _, err := authSvc.CompleteMFALogin(ctx, token, sixDigits.FindString(stepUp.Body), "", ""); err == nil {
		t.Error("a step-up code completed a sign-in")
	}
	pastWait()
	if err := authSvc.SendMFACode(ctx, token, factor); err != nil {
		t.Fatalf("send sign-in code: %v", err)
	}
	signInMail := mail.Last(t)
	signInCode := sixDigits.FindString(signInMail.Body)
	if signInMail.TemplateKey != "mfa_otp" || signInMail.OrganizationID != organization.String() ||
		signInMail.TemplateVariables["code"] != signInCode || signInMail.TemplateVariables["ttl"] == "" {
		t.Errorf("sign-in code sent as template %q of organization %q with %v; want mfa_otp of %s with the code %s",
			signInMail.TemplateKey, signInMail.OrganizationID, signInMail.TemplateVariables, organization, signInCode)
	}
	if err := mfaSvc.VerifyOTP(ctx, a.ID, signInCode, self(a.ID)); !errors.Is(err, errs.ErrMFACodeInvalid) {
		t.Errorf("a sign-in code as a step-up: %v, want %v", err, errs.ErrMFACodeInvalid)
	}
	if pair, err := authSvc.CompleteMFALogin(ctx, token, signInCode, "", ""); err != nil || pair.UserID != a.ID {
		t.Fatalf("sign in with the emailed code: %+v, %v", pair, err)
	}

	if err := mfaSvc.DeleteOTPFactor(ctx, a.ID, factor, self(a.ID)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if factors, err := mfaSvc.ListOTPFactors(ctx, a.ID); err != nil || len(factors) != 0 {
		t.Errorf("factors after removal: %+v, %v; want none", factors, err)
	}
}
