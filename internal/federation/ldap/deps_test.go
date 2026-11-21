package ldap

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// allPlans includes LDAP in every plan.
type allPlans struct{}

func (allPlans) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return true, nil }

// noMappings reads no extra attribute, maps none and stores no profile.
type noMappings struct{}

func (noMappings) SourceAttributes(context.Context, uuid.UUID, string) ([]string, error) {
	return nil, nil
}

func (noMappings) MapProfile(context.Context, uuid.UUID, string, map[string]any, bool) (map[string]any, error) {
	return map[string]any{}, nil
}

func (noMappings) StoreProfile(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, string, map[string]any) error {
	return nil
}

// notices keeps the in-app notices it is asked to send.
type notices struct {
	mu   sync.Mutex
	sent []notice
}

type notice struct {
	userID             uuid.UUID
	kind, title, about string
}

func (n *notices) Notify(_ context.Context, _, userID uuid.UUID, kind, title, description, _ string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, notice{userID: userID, kind: kind, title: title, about: description})
	return nil
}

func (n *notices) of(userID uuid.UUID) []notice {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []notice
	for _, sent := range n.sent {
		if sent.userID == userID {
			out = append(out, sent)
		}
	}
	return out
}

// unrecorded drops every operation.
type unrecorded struct{}

func (unrecorded) RecordLDAPOperation(context.Context, Operation) error { return nil }

// testDeps are the service's dependencies on pool, signing people in through
// authSvc and sealing with box, as on a developer workstation, since the tests'
// directory speaks plain LDAP.
func testDeps(pool *pgxpool.Pool, authSvc *authentication.Service, box *envelope.Cipher) Deps {
	return Deps{
		Pool: pool, Auth: authSvc, Cipher: box, Gate: allPlans{}, Mapper: noMappings{},
		Observer: unrecorded{}, Egress: egress.DevelopmentPolicy(), AllowInsecureTLS: true,
		Signals: sessionsignal.New(nil), Notifier: &notices{},
	}
}

// production is every environment but a developer workstation.
func production(d *Deps) { d.AllowInsecureTLS = false }

// unitService is a service with no database behind it, for checks that end
// before one is reached.
func unitService(t *testing.T, with ...func(*Deps)) *Service {
	t.Helper()
	d := testDeps(new(pgxpool.Pool), new(authentication.Service), new(envelope.Cipher))
	for _, change := range with {
		change(&d)
	}
	service, err := NewService(d)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// TestNewServiceRefusesMissingDependencies checks that the service is not
// built without any one of its required dependencies, and that the error
// names it.
func TestNewServiceRefusesMissingDependencies(t *testing.T) {
	for _, name := range []string{"Pool", "Auth", "Cipher", "Gate", "Mapper", "Observer", "Egress", "Signals", "Notifier"} {
		d := testDeps(new(pgxpool.Pool), new(authentication.Service), new(envelope.Cipher))
		reflect.ValueOf(&d).Elem().FieldByName(name).SetZero()
		if _, err := NewService(d); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("built without %s: %v", name, err)
		}
	}
	unitService(t)
}
