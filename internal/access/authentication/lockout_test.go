package authentication

import (
	"context"
	"errors"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestVerifyPassword_NoStoredPasswordNeverMatches(t *testing.T) {
	for _, plain := range []string{"", "anything"} {
		if ok, err := verifyPassword(context.Background(), "", plain); ok || err != nil {
			t.Errorf("verifyPassword with no stored hash = %v, %v for %q; want false, nil", ok, err, plain)
		}
	}
	if h, err := timingHash(); h == "" || err != nil {
		t.Errorf("timing hash %q, %v: an address with no account would answer faster than a wrong password", h, err)
	}
}

// TestVerifyPasswordWhenTheHasherIsFull checks that a full hasher answers
// server.overloaded, for an account and for an address with none alike,
// never a wrong password.
func TestVerifyPasswordWhenTheHasherIsFull(t *testing.T) {
	stored, err := password.Hash("right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := timingHash(); err != nil {
		t.Fatal(err)
	}
	release := password.FillForTest()
	defer release()
	for _, hash := range []string{stored, ""} {
		if ok, err := verifyPassword(context.Background(), hash, "right"); ok || !errors.Is(err, errs.ErrServerOverloaded) {
			t.Errorf("verifyPassword(%.10q) with the hasher full = %v, %v; want false, server.overloaded", hash, ok, err)
		}
	}
}
