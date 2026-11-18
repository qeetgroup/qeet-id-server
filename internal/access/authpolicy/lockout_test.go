package authpolicy

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCheckLockout_BoundsAreInclusiveAndUnsetIsTheDefault(t *testing.T) {
	limits := DefaultLockoutLimits()
	n := func(v int) *int { return &v }
	if got := limits.CheckLockout(Policy{}); len(got) != 0 {
		t.Errorf("unset settings take the platform default, got %v", got)
	}
	ok := Policy{LockoutThreshold: n(3), LockoutWindowMinutes: n(1440), LockoutDurationMinutes: n(15)}
	if got := limits.CheckLockout(ok); len(got) != 0 {
		t.Errorf("settings on the bounds must be accepted, got %v", got)
	}
	// Looser than the platform default is out of range, as is past 24 hours.
	bad := Policy{LockoutThreshold: n(6), LockoutWindowMinutes: n(14), LockoutDurationMinutes: n(1441)}
	got := limits.CheckLockout(bad)
	if len(got) != 3 {
		t.Fatalf("want all three settings refused, got %v", got)
	}
	for i, field := range []string{"lockout_threshold", "lockout_window_minutes", "lockout_duration_minutes"} {
		if got[i].Field != field || got[i].Code != "out_of_range" || !strings.Contains(got[i].Message, "between") {
			t.Errorf("refusal %d = %+v, want %s out_of_range naming the bounds", i, got[i], field)
		}
	}
}

func TestSignInLockout_NoOrganizationGetsThePlatformDefaults(t *testing.T) {
	s := &Service{lockout: DefaultLockoutLimits()} // no database: uuid.Nil must not read one
	got, err := s.SignInLockout(context.Background(), uuid.Nil)
	if err != nil || got != DefaultLockoutLimits().Defaults {
		t.Errorf("SignInLockout(no organization) = %+v, %v; want the platform defaults", got, err)
	}
}
