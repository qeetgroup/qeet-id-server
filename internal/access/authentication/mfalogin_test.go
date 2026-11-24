package authentication

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestChallengeWithoutFactorsListsThemEmpty checks that an enrolment challenge, which has no
// factors yet, answers "factors": [] and "methods": [] as the API document's arrays, not null.
func TestChallengeWithoutFactorsListsThemEmpty(t *testing.T) {
	b, err := json.Marshal(MFAChallenge{MFAToken: "mfa_test", EnrollmentRequired: true}.Body())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"factors":[]`, `"methods":[]`, `"mfa_token":"mfa_test"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("challenge %s, want %s", b, want)
		}
	}
}
