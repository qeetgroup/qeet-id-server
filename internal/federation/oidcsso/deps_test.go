package oidcsso

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// plan includes single sign-on until it lapses.
type plan struct{ lapsed bool }

func (p *plan) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) {
	return !p.lapsed, nil
}

// testDeps are the service's dependencies on pool, signing people in through
// authSvc, on a plan with single sign-on and no hosted login.
func testDeps(pool *pgxpool.Pool, authSvc *auth.Service) Deps {
	return Deps{
		Pool: pool, Auth: authSvc, Cipher: new(envelope.Cipher), Gate: &plan{},
		Egress: egress.PublicPolicy(), AppBaseURL: "https://console.example.test",
	}
}

// newTestService is the service on pool signing people in through authSvc,
// its dependencies changed by each of with.
func newTestService(t testing.TB, pool *pgxpool.Pool, authSvc *auth.Service, with ...func(*Deps)) *Service {
	t.Helper()
	d := testDeps(pool, authSvc)
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
	for _, name := range []string{"Pool", "Auth", "Cipher", "Gate", "Egress", "AppBaseURL"} {
		d := testDeps(new(pgxpool.Pool), new(auth.Service))
		reflect.ValueOf(&d).Elem().FieldByName(name).SetZero()
		if _, err := NewService(d); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("built without %s: %v", name, err)
		}
	}
	newTestService(t, new(pgxpool.Pool), new(auth.Service))
}
