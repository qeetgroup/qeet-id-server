package auth

import "testing"

// TestRiskConfirmationIsNotMFA: a sign-in confirmed by an emailed code is
// recorded as confirmed, never as having met a second factor.
func TestRiskConfirmationIsNotMFA(t *testing.T) {
	m := metChallenge{firstFactor: firstFactorPassword, riskVerified: true}
	if m.method() != "password_email_confirmed" {
		t.Errorf("method = %q", m.method())
	}
	if metAction(true) != "auth.sign_in_confirmed" || metProofKind(MFAProof{Code: "1"}, false, true) != "email_confirmation" {
		t.Error("a risk confirmation must not be audited as MFA")
	}
}
