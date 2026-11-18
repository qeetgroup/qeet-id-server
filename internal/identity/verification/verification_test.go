package verification

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestNewServiceNeedsItsDependencies checks that the verification service
// can't be built without its sender, the plan gate for SMS codes or the check
// that a channel can deliver.
func TestNewServiceNeedsItsDependencies(t *testing.T) {
	deliverable := func(string) bool { return true }
	for name, build := range map[string]func() (*Service, error){
		"sender":      func() (*Service, error) { return NewService(&pgxpool.Pool{}, nil, 0, stubGate{}, deliverable) },
		"plan gate":   func() (*Service, error) { return NewService(&pgxpool.Pool{}, stubSender{}, 0, nil, deliverable) },
		"deliverable": func() (*Service, error) { return NewService(&pgxpool.Pool{}, stubSender{}, 0, stubGate{}, nil) },
	} {
		if svc, err := build(); err == nil {
			t.Errorf("NewService without its %s: %v, nil; want an error", name, svc)
		}
	}
}

type (
	stubSender struct{ notifier.Sender }
	stubGate   struct{ entitlements.PlanGate }
)
