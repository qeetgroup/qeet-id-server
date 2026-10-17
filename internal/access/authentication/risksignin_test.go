package auth

import "testing"

// TestMaskEmail: a confirmation code's destination is shown with the local
// part hidden but for its first character.
func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"jane@example.com": "j***@example.com",
		"j@example.com":    "j@example.com",
		"no-at-sign":       "no-at-sign",
	} {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

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
