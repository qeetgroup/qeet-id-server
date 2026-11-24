package oidcsso

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
)

// TestBeginSignInRefusesAReturnAddressItDoesntAllow checks that a sign-in started on the hosted
// login can only be sent back to a path or an allowed origin, and to none at all while the hosted
// login isn't configured, before the connection is read.
func TestBeginSignInRefusesAReturnAddressItDoesntAllow(t *testing.T) {
	configured := newTestService(t, new(pgxpool.Pool), new(authentication.Service), func(d *Deps) {
		d.LoginBaseURL, d.ReturnOrigins = "https://accounts.example.test", []string{"https://api.example.test"}
	})
	for _, tc := range []struct {
		name     string
		service  *Service
		returnTo string
	}{
		{"another site", configured, "https://evil.example.test/oauth/authorize"},
		{"no hosted login configured", newTestService(t, new(pgxpool.Pool), new(authentication.Service)), "/device"},
	} {
		_, _, err := tc.service.BeginSignIn(context.Background(), uuid.New(), "https://api.example.test/cb", tc.returnTo)
		if !errors.Is(err, ErrReturnToInvalid) {
			t.Errorf("%s: %v, want %v", tc.name, err, ErrReturnToInvalid)
		}
	}
}
