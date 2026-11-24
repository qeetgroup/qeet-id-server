package rbac

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

// TestNewServiceNeedsItsDependencies checks that the role service can't be
// built without its webhook events, plan limit, seat guard or session
// announcements.
func TestNewServiceNeedsItsDependencies(t *testing.T) {
	full := ServiceDeps{
		Emitter: func(context.Context, uuid.UUID, string, any) error { return nil },
		Limits:  stubLimits{}, Seats: stubSeats{}, Signals: sessionsignal.New(nil),
	}
	for name, drop := range map[string]func(*ServiceDeps){
		"Emitter": func(d *ServiceDeps) { d.Emitter = nil },
		"Limits":  func(d *ServiceDeps) { d.Limits = nil },
		"Seats":   func(d *ServiceDeps) { d.Seats = nil },
		"Signals": func(d *ServiceDeps) { d.Signals = nil },
	} {
		d := full
		drop(&d)
		if svc, err := NewService(&Repository{}, d); err == nil {
			t.Errorf("NewService without %s: %v, nil; want an error", name, svc)
		}
	}
	if _, err := NewService(&Repository{}, full); err != nil {
		t.Errorf("NewService with every dependency: %v", err)
	}
}

type (
	stubLimits struct{ entitlements.PlanLimiter }
	stubSeats  struct{ entitlements.SeatGuard }
)
