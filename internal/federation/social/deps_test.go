package social

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// noCapture captures no address.
type noCapture struct{}

func (noCapture) RefuseCaptured(context.Context, string) error { return nil }

// testDeps are the service's dependencies on pool, signing people in through
// authSvc, with no domain captured.
func testDeps(pool *pgxpool.Pool, authSvc *authentication.Service) Deps {
	return Deps{
		Pool: pool, Auth: authSvc, Cipher: new(envelope.Cipher), Capture: noCapture{},
		Egress: egress.PublicPolicy(), AppBaseURL: "https://api.id.qeet.in",
	}
}

// newTestService is the service on pool signing people in through authSvc,
// its dependencies changed by each of with.
func newTestService(t testing.TB, pool *pgxpool.Pool, authSvc *authentication.Service, with ...func(*Deps)) *Service {
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
	for _, name := range []string{"Pool", "Auth", "Cipher", "Capture", "Egress", "AppBaseURL"} {
		d := testDeps(new(pgxpool.Pool), new(authentication.Service))
		reflect.ValueOf(&d).Elem().FieldByName(name).SetZero()
		if _, err := NewService(d); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("built without %s: %v", name, err)
		}
	}
	s := newTestService(t, new(pgxpool.Pool), new(authentication.Service), func(d *Deps) {
		d.Platform = []PlatformProvider{PlatformGitHub("id", "secret")}
	})
	if !s.PlatformProviderEnabled(kindGitHub) || s.PlatformProviderEnabled("google") {
		t.Errorf("platform providers %v, want GitHub alone", s.PlatformProviderNames())
	}
}
