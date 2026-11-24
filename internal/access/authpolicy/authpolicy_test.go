package authpolicy

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNewServiceNeedsABreachChecker checks that the policy service can't be
// built without a breach checker, so turning the check off is a choice
// (NoBreachCheck) rather than a missing call.
func TestNewServiceNeedsABreachChecker(t *testing.T) {
	if svc, err := NewService(&pgxpool.Pool{}, nil); err == nil {
		t.Fatalf("NewService without a breach checker: %v, nil; want an error", svc)
	}
	if _, err := NewService(&pgxpool.Pool{}, NoBreachCheck{}); err != nil {
		t.Fatalf("NewService with NoBreachCheck: %v", err)
	}
}
