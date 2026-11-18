package servicehealth

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNewServiceNeedsTheSignInCheck checks that the service is not built
// without the check that reports whether tokens can be signed, which would
// show sign-in as up with no signing key.
func TestNewServiceNeedsTheSignInCheck(t *testing.T) {
	if _, err := NewService(new(pgxpool.Pool), nil); err == nil {
		t.Error("built without a sign-in readiness check")
	}
}
