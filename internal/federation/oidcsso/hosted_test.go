package oidcsso

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestBeginSignInRefusesAReturnAddressItDoesntAllow checks that a sign-in started on the hosted
// login can only be sent back to a path or an allowed origin, and to none at all while the hosted
// login isn't configured, before the connection is read.
func TestBeginSignInRefusesAReturnAddressItDoesntAllow(t *testing.T) {
	configured := &Service{}
	configured.SetHostedLogin("https://accounts.example.test", "https://api.example.test")
	for _, tc := range []struct {
		name     string
		service  *Service
		returnTo string
	}{
		{"another site", configured, "https://evil.example.test/oauth/authorize"},
		{"no hosted login configured", &Service{}, "/device"},
	} {
		_, _, err := tc.service.BeginSignIn(context.Background(), uuid.New(), "https://api.example.test/cb", tc.returnTo)
		if !errors.Is(err, errs.ErrOIDCSSOReturnToInvalid) {
			t.Errorf("%s: %v, want %v", tc.name, err, errs.ErrOIDCSSOReturnToInvalid)
		}
	}
}
