package mfa

import (
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-identity/internal/platform/password"
)

func TestMaskDestination(t *testing.T) {
	cases := []struct {
		name    string
		channel string
		dest    string
		want    string
	}{
		// Email: keep first char + domain, star out the local part's tail.
		{"email typical", "email", "alice@example.com", "a****@example.com"},
		{"email short local", "email", "ab@x.io", "a*@x.io"},
		// at <= 1: a single-char local part (or leading '@') is returned as-is,
		// since masking it would reveal nothing useful and risk index issues.
		{"email single-char local", "email", "a@x.io", "a@x.io"},
		{"email leading at", "email", "@nolocal.io", "@nolocal.io"},
		// Phone: keep the last three digits.
		{"phone typical", "sms", "+15555550123", "*********123"},
		{"phone short", "sms", "12", "12"},
		{"phone exactly three", "sms", "123", "123"},
		{"phone four", "sms", "1234", "*234"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := maskDestination(c.channel, c.dest); got != c.want {
				t.Errorf("maskDestination(%q, %q) = %q, want %q", c.channel, c.dest, got, c.want)
			}
		})
	}
}

func TestMaskDestination_EmailHidesLocalLength(t *testing.T) {
	// The star count equals (at-1); the masked output's local part length must
	// match the original so the UI hint stays stable, but the chars are hidden.
	masked := maskDestination("email", "verylongname@corp.example")
	if !strings.HasPrefix(masked, "v") || !strings.HasSuffix(masked, "@corp.example") {
		t.Fatalf("unexpected mask: %q", masked)
	}
	stars := strings.Count(masked, "*")
	if stars != len("verylongname")-1 {
		t.Errorf("masked %d chars, want %d", stars, len("verylongname")-1)
	}
}

// TestRecoveryCodeCount documents the batch size minted on enrollment.
func TestRecoveryCodeCount(t *testing.T) {
	if recoveryCodeCount != 10 {
		t.Errorf("recoveryCodeCount = %d, want 10", recoveryCodeCount)
	}
}

// TestRecoveryCodeHashing exercises the security contract the recovery-code
// store relies on: codes are stored as one-way hashes (never plaintext),
// the right code verifies, a wrong one does not, and two equal plaintexts
// still produce distinct (salted) hashes — so the DB column can't be matched
// by a rainbow table.
func TestRecoveryCodeHashing(t *testing.T) {
	const code = "0123456789"
	h1, err := password.Hash(code)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if h1 == code {
		t.Fatal("recovery code must not be stored in plaintext")
	}
	if !password.Verify(h1, code) {
		t.Error("the correct recovery code must verify against its hash")
	}
	if password.Verify(h1, "9999999999") {
		t.Error("a wrong recovery code must not verify")
	}
	h2, _ := password.Hash(code)
	if h1 == h2 {
		t.Error("identical recovery codes must hash to distinct (salted) values")
	}
	// Each independently-salted hash still verifies its own plaintext.
	if !password.Verify(h2, code) {
		t.Error("second salted hash must still verify the same code")
	}
}
