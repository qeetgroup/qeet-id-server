package mfa

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
)

// TestRecoveryCodeCount checks that a batch holds 10 recovery codes.
func TestRecoveryCodeCount(t *testing.T) {
	if recoveryCodeCount != 10 {
		t.Errorf("recoveryCodeCount = %d, want 10", recoveryCodeCount)
	}
}

// TestRecoveryCodeHashing checks that recovery codes are stored as salted
// one-way hashes: the right code verifies, a wrong one doesn't, and equal
// codes hash differently.
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
