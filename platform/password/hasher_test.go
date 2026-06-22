package password

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHash_IsArgon2idAndVerifies(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Errorf("new hashes must be argon2id, got %q", h)
	}
	if !Verify(h, "correct horse battery staple") {
		t.Error("Verify must accept the correct password")
	}
	if Verify(h, "wrong password") {
		t.Error("Verify must reject a wrong password")
	}
}

func TestHash_SaltedPerCall(t *testing.T) {
	a, _ := Hash("same")
	b, _ := Hash("same")
	if a == b {
		t.Error("each Hash must use a fresh salt")
	}
}

func TestVerify_AcceptsLegacyBcrypt(t *testing.T) {
	// A pre-existing bcrypt hash must keep verifying after the switch.
	b, err := bcrypt.GenerateFromPassword([]byte("legacy-secret"), 10)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if !Verify(string(b), "legacy-secret") {
		t.Error("Verify must accept a legacy bcrypt hash")
	}
	if Verify(string(b), "nope") {
		t.Error("Verify must reject a wrong password against a bcrypt hash")
	}
}

func TestNeedsRehash(t *testing.T) {
	// Legacy bcrypt → needs rehash.
	b, _ := bcrypt.GenerateFromPassword([]byte("x"), 10)
	if !NeedsRehash(string(b)) {
		t.Error("bcrypt hash must be flagged for rehash")
	}
	// Fresh argon2id at current params → does not.
	h, _ := Hash("x")
	if NeedsRehash(h) {
		t.Error("current-param argon2id must not need rehash")
	}
	// Weaker-param argon2id → needs rehash.
	weak := "$argon2id$v=19$m=1024,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$3Iaa2pYsFvU0bYV0u0sJ8w"
	if !NeedsRehash(weak) {
		t.Error("weaker-param argon2id must be flagged for rehash")
	}
}

func TestVerify_RejectsGarbage(t *testing.T) {
	if Verify("not-a-hash", "x") {
		t.Error("unknown hash format must not verify")
	}
	if Verify("", "x") {
		t.Error("empty hash must not verify")
	}
}
