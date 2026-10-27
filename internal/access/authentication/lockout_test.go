package auth

import (
	"context"
	"testing"
)

func TestVerifyPassword_NoStoredPasswordNeverMatches(t *testing.T) {
	for _, plain := range []string{"", "anything"} {
		if ok, err := verifyPassword(context.Background(), "", plain); ok || err != nil {
			t.Errorf("verifyPassword with no stored hash = %v, %v for %q; want false, nil", ok, err, plain)
		}
	}
	if timingHash() == "" {
		t.Error("no timing hash: an address with no account would answer faster than a wrong password")
	}
}
