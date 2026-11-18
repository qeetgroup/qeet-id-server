package oidc

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// openAddresses lets every address sign in.
type openAddresses struct{}

func (openAddresses) CheckSignIn(context.Context, uuid.UUID, uuid.UUID, string, string) error {
	return nil
}

func (openAddresses) CheckSignInTx(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, string, string) error {
	return nil
}

// unnotified drops every notification.
type unnotified struct{}

func (unnotified) Notify(context.Context, uuid.UUID, uuid.UUID, string, string, string, string) error {
	return nil
}

// noLimits caps nothing.
type noLimits struct{}

func (noLimits) Limit(context.Context, uuid.UUID, string) (int, error) { return -1, nil }

// testDeps are the provider's dependencies on pool, signing with issuer: every
// address allowed, every agent, session and principal live, no second factor
// still owed and no plan cap.
func testDeps(pool *pgxpool.Pool, issuer *tokens.Issuer) Deps {
	return Deps{
		Pool: pool, Issuer: issuer, Addresses: openAddresses{}, Egress: egress.PublicPolicy(),
		Notifier: unnotified{}, Limits: noLimits{},
		AgentStatus:    func(context.Context, uuid.UUID) (string, error) { return "active", nil },
		SessionLive:    func(context.Context, uuid.UUID, uuid.UUID) (bool, error) { return true, nil },
		PrincipalLive:  func(context.Context, uuid.UUID) (bool, error) { return true, nil },
		SessionFactors: func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error { return nil },
		GrantMaxAge:    30 * 24 * time.Hour,
	}
}

// newTestService is the provider on pool signing with issuer, its
// dependencies changed by each of with.
func newTestService(t testing.TB, pool *pgxpool.Pool, issuer *tokens.Issuer, with ...func(*Deps)) *Service {
	t.Helper()
	d := testDeps(pool, issuer)
	for _, change := range with {
		change(&d)
	}
	service, err := NewService(d)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// TestNewServiceRefusesMissingDependencies checks that the provider is not
// built without any one of its required dependencies, and that the error
// names it.
func TestNewServiceRefusesMissingDependencies(t *testing.T) {
	issuer := testIssuer(t)
	required := []string{"Pool", "Issuer", "Addresses", "Egress", "Notifier", "Limits",
		"AgentStatus", "SessionLive", "PrincipalLive", "SessionFactors", "GrantMaxAge"}
	for _, name := range required {
		d := testDeps(new(pgxpool.Pool), issuer)
		reflect.ValueOf(&d).Elem().FieldByName(name).SetZero()
		if _, err := NewService(d); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("built without %s: %v", name, err)
		}
	}
	service := newTestService(t, new(pgxpool.Pool), issuer)
	if service.lockout != DefaultClientLockout() || service.logoutClient == nil {
		t.Errorf("built with the defaults: lockout %+v, logout client %v", service.lockout, service.logoutClient)
	}
	if _, err := NewLogoutNotices(nil, issuer); err == nil || !strings.Contains(err.Error(), "pool") {
		t.Errorf("logout notices without a pool: %v", err)
	}
	if _, err := NewLogoutNotices(new(pgxpool.Pool), nil); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Errorf("logout notices without an issuer: %v", err)
	}
}
