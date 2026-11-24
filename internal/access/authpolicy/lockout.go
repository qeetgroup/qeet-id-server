package authpolicy

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Lockout is the sign-in lockout an organization applies: after Threshold failed
// password sign-ins to one account from one network, each within Window of the
// last, the account is locked for that network for Duration.
type Lockout struct {
	Threshold int
	Window    time.Duration
	Duration  time.Duration
}

// LockoutLimits are the platform defaults for the lockout settings and the
// documented bounds an organization may choose within; windows and durations
// are whole minutes.
type LockoutLimits struct {
	Defaults Lockout
	Min      Lockout
	Max      Lockout
}

// DefaultLockoutLimits are the built-in limits: five failures within fifteen
// minutes lock for fifteen minutes. An organization may only be stricter: a threshold
// of 3 to 5, and a window and a duration of 15 minutes to 24 hours.
func DefaultLockoutLimits() LockoutLimits {
	return LockoutLimits{
		Defaults: Lockout{Threshold: 5, Window: 15 * time.Minute, Duration: 15 * time.Minute},
		Min:      Lockout{Threshold: 3, Window: 15 * time.Minute, Duration: 15 * time.Minute},
		Max:      Lockout{Threshold: 5, Window: 24 * time.Hour, Duration: 24 * time.Hour},
	}
}

// LockoutSettingsView is a lockout in API units (minutes).
type LockoutSettingsView struct {
	Threshold       int `json:"threshold"`
	WindowMinutes   int `json:"window_minutes"`
	DurationMinutes int `json:"duration_minutes"`
}

// LockoutLimitsView is LockoutLimits in API units.
type LockoutLimitsView struct {
	Defaults LockoutSettingsView `json:"defaults"`
	Min      LockoutSettingsView `json:"min"`
	Max      LockoutSettingsView `json:"max"`
}

func lockoutView(l Lockout) LockoutSettingsView {
	return LockoutSettingsView{
		Threshold:       l.Threshold,
		WindowMinutes:   int(l.Window / time.Minute),
		DurationMinutes: int(l.Duration / time.Minute),
	}
}

func (l LockoutLimits) view() *LockoutLimitsView {
	return &LockoutLimitsView{Defaults: lockoutView(l.Defaults), Min: lockoutView(l.Min), Max: lockoutView(l.Max)}
}

// CheckLockout reports each lockout setting in p that lies outside the
// bounds. Unset (nil) settings take the platform default and are not checked.
// Pure, so it is unit-tested without a database.
func (l LockoutLimits) CheckLockout(p Policy) []errs.FieldError {
	lo, hi := lockoutView(l.Min), lockoutView(l.Max)
	var out []errs.FieldError
	for _, f := range []struct {
		field  string
		value  *int
		lo, hi int
		unit   string
	}{
		{"lockout_threshold", p.LockoutThreshold, lo.Threshold, hi.Threshold, "failed attempts"},
		{"lockout_window_minutes", p.LockoutWindowMinutes, lo.WindowMinutes, hi.WindowMinutes, "minutes"},
		{"lockout_duration_minutes", p.LockoutDurationMinutes, lo.DurationMinutes, hi.DurationMinutes, "minutes"},
	} {
		if f.value != nil && (*f.value < f.lo || *f.value > f.hi) {
			out = append(out, errs.FieldError{
				Field:   f.field,
				Code:    "out_of_range",
				Message: fmt.Sprintf("Must be between %d and %d %s.", f.lo, f.hi, f.unit),
			})
		}
	}
	return out
}

// SignInLockout returns the lockout a password sign-in for organizationID is held
// to: each setting the organization chose, the platform default for the rest.
// uuid.Nil (a sign-in with no organization) gets the platform defaults without a
// read. Which organization a sign-in belongs to is the caller's decision.
func (s *Service) SignInLockout(ctx context.Context, organizationID uuid.UUID) (Lockout, error) {
	l := s.lockout.Defaults
	if organizationID == uuid.Nil {
		return l, nil
	}
	p, err := s.Get(ctx, organizationID)
	if err != nil {
		return Lockout{}, err
	}
	if p.LockoutThreshold != nil {
		l.Threshold = *p.LockoutThreshold
	}
	if p.LockoutWindowMinutes != nil {
		l.Window = time.Duration(*p.LockoutWindowMinutes) * time.Minute
	}
	if p.LockoutDurationMinutes != nil {
		l.Duration = time.Duration(*p.LockoutDurationMinutes) * time.Minute
	}
	return l, nil
}
