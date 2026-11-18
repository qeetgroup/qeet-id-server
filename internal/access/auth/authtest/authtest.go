//go:build integration

// Package authtest builds the sign-in service for other packages' database
// tests, with dependencies that decide nothing. Only tests import it.
package authtest

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// New returns a sign-in service over pool where no account holds a second factor, no sign-in is
// risky, every method is allowed, no new password is accepted, no device is remembered, no address is
// captured or refused and no hook runs. Each change edits its Deps first, so a test replaces just the
// dependency it is about.
func New(t testing.TB, pool *pgxpool.Pool, change ...func(*auth.Deps)) *auth.Service {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	d := auth.Deps{
		Pool: pool, Users: user.NewRepository(pool), Tokens: dbtest.Issuer(t), Cipher: box,
		MFA: NoFactors{}, Risk: nothing{}, Registration: nothing{}, Methods: nothing{}, Devices: nothing{},
		Lockout: func(context.Context, uuid.UUID) (auth.Lockout, error) {
			return auth.DefaultLockoutConfig().Defaults, nil
		},
		Capture: nothing{}, Addresses: nothing{}, Anomalies: nothing{}, Sender: &dbtest.Mailbox{},
		LoginHook: nothing{}, SignOut: nothing{}, Signals: sessionsignal.New(nil),
	}
	for _, c := range change {
		c(&d)
	}
	svc, err := auth.New(d)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// NoFactors is an MFA service whose accounts hold no second factor; a sign-in
// never reaches its other methods.
type NoFactors struct{ auth.MFAEnroller }

// LoginFactors lists no factor.
func (NoFactors) LoginFactors(context.Context, uuid.UUID) ([]auth.LoginFactor, error) {
	return nil, nil
}

// LoginFactorsTx lists no factor.
func (NoFactors) LoginFactorsTx(context.Context, pgx.Tx, uuid.UUID) ([]auth.LoginFactor, error) {
	return nil, nil
}

// nothing is every other dependency, answering so that it changes no sign-in.
type nothing struct{}

func (nothing) ShouldForceMFA(context.Context, uuid.UUID, uuid.UUID, string, string, string) bool {
	return false
}
func (nothing) RecordSignIn(context.Context, uuid.UUID, uuid.UUID, string, string) {}
func (nothing) SelfRegistrationEnabled(context.Context, uuid.UUID) (bool, error)   { return false, nil }
func (nothing) ValidateForOrganization(context.Context, uuid.UUID, string, string) error {
	return errs.ErrNotImplemented
}
func (nothing) PasswordEnabled(context.Context, uuid.UUID) (bool, error)       { return true, nil }
func (nothing) RememberDeviceEnabled(context.Context, uuid.UUID) (bool, error) { return false, nil }
func (nothing) RememberDevicePolicy(context.Context, uuid.UUID) (bool, time.Duration, error) {
	return false, 0, nil
}
func (nothing) RefuseCaptured(context.Context, string) error { return nil }
func (nothing) CheckSignIn(context.Context, uuid.UUID, uuid.UUID, string, string) error {
	return nil
}
func (nothing) CheckSignInTx(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, string, string) error {
	return nil
}
func (nothing) OnAccountLocked(context.Context, auth.AccountLock)      {}
func (nothing) OnSourceThrottled(context.Context, auth.SourceThrottle) {}
func (nothing) Run(context.Context, uuid.UUID, uuid.UUID, string) (map[string]any, error) {
	return nil, nil
}
func (nothing) NotifySignOut(context.Context, uuid.UUID, uuid.UUID, string) ([]string, error) {
	return nil, nil
}
