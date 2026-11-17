//go:build integration

package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAnotherOrganisationsClientCannotLoosenLockout checks that naming the
// application of an organisation with a lenient lockout doesn't loosen the
// lockout another organisation's member is held to: the platform's threshold
// still locks, for the platform's window and lock time.
func TestAnotherOrganisationsClientCannotLoosenLockout(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, seen := newService(t), &anomalies{}
	svc.SetAnomalyRecorder(seen)
	platform := DefaultLockoutConfig().Defaults
	lenient := dbtest.Tenant(t)
	svc.SetLockoutSource(func(_ context.Context, tenantID uuid.UUID) (Lockout, error) {
		if tenantID == lenient {
			return Lockout{Threshold: 20, Window: time.Minute, Duration: time.Minute}, nil
		}
		return platform, nil
	})
	client := dbtest.Unique("app")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (tenant_id, client_id, name) VALUES ($1, $2, $2)`, lenient, client); err != nil {
		t.Fatal(err)
	}
	victim, _ := member(t)
	ip := freshIP()
	guess := func(password string) error {
		_, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: victim.Email, Password: password, IP: ip, ClientID: client}, testUserAgent, "", "")
		return err
	}

	for i := range platform.Threshold {
		if err := guess("Wrong-password-1"); !errors.Is(err, errs.ErrAuthInvalidCredentials) {
			t.Fatalf("guess %d through the lenient organisation's application: %v, want %v", i+1, err, errs.ErrAuthInvalidCredentials)
		}
	}
	if err := guess(testPassword); !errors.Is(err, errs.ErrAuthAccountLocked) {
		t.Errorf("the right password after the platform's threshold of guesses: %v, want %v", err, errs.ErrAuthAccountLocked)
	}
	if len(seen.locks) != 1 || seen.locks[0].Threshold != platform.Threshold || seen.locks[0].Window != platform.Window ||
		time.Until(seen.locks[0].LockedUntil) < platform.Duration-time.Minute {
		t.Errorf("locks set %+v, want one at the platform's %+v", seen.locks, platform)
	}
}

// TestStricterLockoutCannotLockAnAccountEverywhere checks that an organisation
// with a strict lockout can't use its application to lock another
// organisation's member out on every network: the account-wide lock counts to
// the platform's threshold and lasts the platform's time, while the strict
// lock still holds the networks it was guessed from.
func TestStricterLockoutCannotLockAnAccountEverywhere(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, seen := newService(t), &anomalies{}
	svc.SetAnomalyRecorder(seen)
	platform := DefaultLockoutConfig().Defaults
	strict := dbtest.Tenant(t)
	svc.SetLockoutSource(func(_ context.Context, tenantID uuid.UUID) (Lockout, error) {
		if tenantID == strict {
			return Lockout{Threshold: 3, Window: 24 * time.Hour, Duration: 24 * time.Hour}, nil
		}
		return platform, nil
	})
	client := dbtest.Unique("app")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (tenant_id, client_id, name) VALUES ($1, $2, $2)`, strict, client); err != nil {
		t.Fatal(err)
	}
	victim, _ := member(t)
	guess := func(password, ip, clientID string) error {
		_, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: victim.Email, Password: password, IP: ip, ClientID: clientID}, testUserAgent, "", "")
		return err
	}

	// The strict organisation's own cap would have been 3 × 4 = 12 failures.
	accountCap := platform.Threshold * DefaultLockoutConfig().AccountMultiplier
	for i := range 12 {
		if err := guess("Wrong-password-1", freshIP(), client); !errors.Is(err, errs.ErrAuthInvalidCredentials) {
			t.Fatalf("guess %d from a new network: %v, want %v", i+1, err, errs.ErrAuthInvalidCredentials)
		}
	}
	if err := guess(testPassword, freshIP(), ""); err != nil {
		t.Errorf("the member's own sign-in from another network after 12 guesses: %v, want it to work", err)
	}
	// That sign-in cleared the count, so the platform's cap counts from zero.
	for range accountCap {
		_ = guess("Wrong-password-1", freshIP(), client)
	}
	var everywhere []AccountLock
	for _, lock := range seen.locks {
		if lock.Counter == CounterAccount {
			everywhere = append(everywhere, lock)
		}
	}
	if len(everywhere) != 1 || everywhere[0].Threshold != accountCap || everywhere[0].Window != platform.Window ||
		time.Until(everywhere[0].LockedUntil) > platform.Duration {
		t.Errorf("account-wide locks %+v; want one at the platform's %d failures in %s, for %s", everywhere, accountCap, platform.Window, platform.Duration)
	}

	network := freshIP()
	for range 3 {
		_ = guess("Wrong-password-1", network, client)
	}
	if err := guess(testPassword, network, client); !errors.Is(err, errs.ErrAuthAccountLocked) {
		t.Errorf("the right password from a network the strict lockout locked: %v, want %v", err, errs.ErrAuthAccountLocked)
	}
}

// TestLockoutKeyMatchesAccountLookupForNonASCII checks that a sign-in is
// counted under the address as the account lookup folds it, PostgreSQL's
// LOWER, so the case variants of one account share one counter and no fold
// the lookup doesn't make (Go's lowercasing of Ⓐ, which LOWER keeps) gives an
// account a second one.
func TestLockoutKeyMatchesAccountLookupForNonASCII(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	for _, account := range []string{"Asha@Example.TEST", "  ÉVA@example.test ", "İPEK@example.test", "ⒶNNA@example.test", "STRAẞE@example.test"} {
		var lookup string
		if err := dbtest.Pool(t).QueryRow(ctx, `SELECT LOWER(TRIM($1::text))`, account).Scan(&lookup); err != nil {
			t.Fatal(err)
		}
		a, err := svc.signInAttemptIn(ctx, uuid.Nil, account, "192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		if a.email != lookup {
			t.Errorf("%q is counted as %q, but the account lookup reads it as %q", account, a.email, lookup)
		}
	}
}
