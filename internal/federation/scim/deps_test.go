package scim

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

// allPlans includes SCIM in every plan.
type allPlans struct{}

func (allPlans) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return true, nil }

// noSeatLimit leaves group membership uncapped.
type noSeatLimit struct{}

func (noSeatLimit) SeatLimit(context.Context, uuid.UUID) (int, error) { return -1, nil }

func (noSeatLimit) WithinSeats(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ int, change func() error) error {
	return change()
}

// noMappings maps no attribute and stores no profile.
type noMappings struct{}

func (noMappings) MapProfile(context.Context, uuid.UUID, string, map[string]any, bool) (map[string]any, error) {
	return map[string]any{}, nil
}

func (noMappings) StoreProfile(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, string, map[string]any) error {
	return nil
}

// unrecorded drops every operation.
type unrecorded struct{}

func (unrecorded) RecordSCIMOperation(context.Context, Operation) error { return nil }

// testDeps are the service's dependencies on pool, with the fakes above.
func testDeps(pool *pgxpool.Pool) Deps {
	return Deps{
		Pool: pool, Users: user.NewRepository(pool), Signals: sessionsignal.New(nil),
		Gate: allPlans{}, Seats: noSeatLimit{}, Mapper: noMappings{}, Observer: unrecorded{},
	}
}

// newTestService is the service on pool, its dependencies changed by each of
// with.
func newTestService(t *testing.T, pool *pgxpool.Pool, with ...func(*Deps)) *Service {
	t.Helper()
	d := testDeps(pool)
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
// built without any one of its dependencies, and that the error names it.
func TestNewServiceRefusesMissingDependencies(t *testing.T) {
	for _, name := range []string{"Pool", "Users", "Signals", "Gate", "Seats", "Mapper", "Observer"} {
		d := testDeps(new(pgxpool.Pool))
		reflect.ValueOf(&d).Elem().FieldByName(name).SetZero()
		if _, err := NewService(d); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("built without %s: %v", name, err)
		}
	}
	if _, err := NewService(testDeps(new(pgxpool.Pool))); err != nil {
		t.Errorf("built with every dependency: %v", err)
	}
}
