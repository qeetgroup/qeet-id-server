package password

import (
	"testing"
)

// TestVerifySecret checks that a machine secret verifies against its SHA-256
// hash and not another's, and that an Argon2id hash, which nothing writes for
// a machine secret, matches nothing.
func TestVerifySecret(t *testing.T) {
	hash := HashSecret("qk_secret")
	if !VerifySecret(hash, "qk_secret") {
		t.Error("the secret did not verify against its hash")
	}
	if VerifySecret(hash, "qk_other") {
		t.Error("another secret verified")
	}
	argon, err := Hash("qk_secret")
	if err != nil {
		t.Fatal(err)
	}
	if VerifySecret(argon, "qk_secret") {
		t.Error("the secret verified against an Argon2id hash")
	}
	if VerifySecret("", "") || VerifySecret(secretPrefix, "") {
		t.Error("an empty or truncated hash verified")
	}
}

// TestVerifySecretNeedsNoHasherSlot checks that verifying a machine secret
// never waits for the bounded password hasher, so a flood of password sign-ins
// can't hold up API keys and client secrets.
func TestVerifySecretNeedsNoHasherSlot(t *testing.T) {
	release := FillForTest()
	defer release()
	if !VerifySecret(HashSecret("qk_secret"), "qk_secret") {
		t.Error("a SHA-256 secret with the hasher full did not verify")
	}
}

// TestHashSecretIsStable pins a machine secret's stored form, so every stored
// secret still verifies.
func TestHashSecretIsStable(t *testing.T) {
	if got, want := HashSecret("abc"), "sha256$ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"; got != want {
		t.Errorf(`HashSecret("abc") = %q, want %q`, got, want)
	}
}
