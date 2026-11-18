package mfa

import (
	"testing"
)

// TestSecretHashIsStable pins the stored form of push tokens, device tokens
// and pairing codes, so the devices and pairings already stored still match.
func TestSecretHashIsStable(t *testing.T) {
	if got, want := secretHash("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Errorf(`secretHash("abc") = %q, want %q`, got, want)
	}
}
