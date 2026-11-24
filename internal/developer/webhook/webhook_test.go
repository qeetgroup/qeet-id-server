package webhook

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
)

type everyPlan struct{}

func (everyPlan) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return true, nil }

type noAlerts struct{}

func (noAlerts) Notify(context.Context, uuid.UUID, uuid.UUID, string, string, string, string) error {
	return nil
}

// TestNewServiceNeedsEachDependency checks that the webhook service is not
// built without the cipher for its secrets, the plan gate webhooks are sold
// behind, or the notifier that tells managers a subscription was turned off.
func TestNewServiceNeedsEachDependency(t *testing.T) {
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	full := Deps{Cipher: box, PlanGate: everyPlan{}, Notifier: noAlerts{}}
	if _, err := NewService(new(pgxpool.Pool), full); err != nil {
		t.Fatalf("built with every dependency: %v", err)
	}
	for name, without := range map[string]func(*Deps){
		"cipher":    func(d *Deps) { d.Cipher = nil },
		"plan gate": func(d *Deps) { d.PlanGate = nil },
		"notifier":  func(d *Deps) { d.Notifier = nil },
	} {
		d := full
		without(&d)
		if _, err := NewService(new(pgxpool.Pool), d); err == nil {
			t.Errorf("built without a %s", name)
		}
	}
}
