//go:build integration

package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAnotherOrganizationsClientCannotLoosenLockout checks that naming the
// application of an organization with a lenient lockout doesn't loosen the
// lockout another organization's member is held to: the platform's threshold
// still locks, for the platform's window and lock time.
func TestAnotherOrganizationsClientCannotLoosenLockout(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, seen := newService(t), &anomalies{}
	svc.SetAnomalyRecorder(seen)
	platform := DefaultLockoutConfig().Defaults
	lenient := dbtest.Organization(t)
	svc.SetLockoutSource(func(_ context.Context, organizationID uuid.UUID) (Lockout, error) {
		if organizationID == lenient {
			return Lockout{Threshold: 20, Window: time.Minute, Duration: time.Minute}, nil
		}
		return platform, nil
	})
	client := dbtest.Unique("app")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, $2, $2)`, lenient, client); err != nil {
		t.Fatal(err)
	}
	victim, _ := member(t)
	ip := freshIP()
	guess := func(password string) error {
		_, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: victim.Email, Password: password, IP: ip, ClientID: client}, testUserAgent, "", "")
		return err
	}

	for i := range platform.Threshold {
		if err := guess("Wrong-password-1"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("guess %d through the lenient organization's application: %v, want %v", i+1, err, ErrInvalidCredentials)
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

// TestStricterLockoutCannotLockAnAccountEverywhere checks that an organization
// with a strict lockout can't use its application to lock another
// organization's member out on every network: the account-wide lock counts to
// the platform's threshold and lasts the platform's time, while the strict
// lock still holds the networks it was guessed from.
func TestStricterLockoutCannotLockAnAccountEverywhere(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, seen := newService(t), &anomalies{}
	svc.SetAnomalyRecorder(seen)
	platform := DefaultLockoutConfig().Defaults
	strict := dbtest.Organization(t)
	svc.SetLockoutSource(func(_ context.Context, organizationID uuid.UUID) (Lockout, error) {
		if organizationID == strict {
			return Lockout{Threshold: 3, Window: 24 * time.Hour, Duration: 24 * time.Hour}, nil
		}
		return platform, nil
	})
	client := dbtest.Unique("app")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, $2, $2)`, strict, client); err != nil {
		t.Fatal(err)
	}
	victim, _ := member(t)
	guess := func(password, ip, clientID string) error {
		_, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: victim.Email, Password: password, IP: ip, ClientID: clientID}, testUserAgent, "", "")
		return err
	}

	// The strict organization's own cap would have been 3 × 4 = 12 failures.
	accountCap := platform.Threshold * DefaultLockoutConfig().AccountMultiplier
	for i := range 12 {
		if err := guess("Wrong-password-1", freshIP(), client); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("guess %d from a new network: %v, want %v", i+1, err, ErrInvalidCredentials)
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

// TestSignInLockout checks that a success clears earlier failures, that five
// failures in a row lock the account so even the right password is refused,
// and that the lock holds only that account.
func TestSignInLockout(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, _ := member(t)
	other, _ := member(t)
	fail := func(n int) {
		t.Helper()
		for range n {
			if _, err := svc.Login(ctx, LoginInput{Email: a.Email, Password: "wrong-password"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("wrong password: %v, want %v", err, ErrInvalidCredentials)
			}
		}
	}

	fail(4)
	signIn(t, svc, a)
	fail(5)
	if _, err := svc.Login(ctx, LoginInput{Email: a.Email, Password: testPassword}); !errors.Is(err, errs.ErrAuthAccountLocked) {
		t.Fatalf("right password on a locked account: %v, want %v", err, errs.ErrAuthAccountLocked)
	}
	signIn(t, svc, other)
}

// TestSignInLockoutOverHTTP checks that five failures from one network lock
// the account there whatever the password, answered exactly as an address
// with no account is once it has as many failures, while its owner still
// signs in from another network; and that the lock lifts when its time is up.
func TestSignInLockoutOverHTTP(t *testing.T) {
	ctx := dbtest.Context(t)
	h := publicRoutes(newHandler(newService(t)))
	a, _ := member(t)
	attacker, owner := newBrowser(t, h), newBrowser(t, h)
	nobody := dbtest.Unique("nobody") + "@example.test"

	for _, email := range []string{a.Email, nobody} {
		for i := range 5 {
			if rec := attacker.do(http.MethodPost, "/auth/login", loginBody(email, "Wrong-password-1")); !answered(rec, http.StatusUnauthorized, CodeInvalidCredentials) {
				t.Fatalf("failure %d for %s: %d %s, want 401", i+1, email, rec.Code, rec.Body.String())
			}
		}
	}
	locked := attacker.do(http.MethodPost, "/auth/login", loginBody(a.Email, testPassword))
	if !answered(locked, http.StatusTooManyRequests, errs.CodeAuthAccountLocked) {
		t.Fatalf("right password on a locked account: %d %s, want 429 %s", locked.Code, locked.Body.String(), errs.CodeAuthAccountLocked)
	}
	if rec := attacker.do(http.MethodPost, "/auth/login", loginBody(nobody, testPassword)); rec.Code != locked.Code || rec.Body.String() != locked.Body.String() {
		t.Errorf("an address with no account after five failures: %d %s, want the locked account's %d %s", rec.Code, rec.Body.String(), locked.Code, locked.Body.String())
	}
	if rec := owner.do(http.MethodPost, "/auth/login", loginBody(a.Email, testPassword)); rec.Code != http.StatusOK {
		t.Errorf("the owner signing in from another network: %d %s, want 200", rec.Code, rec.Body.String())
	}
	if rec := attacker.do(http.MethodPost, "/auth/login", loginBody(a.Email, testPassword)); !answered(rec, http.StatusTooManyRequests, errs.CodeAuthAccountLocked) {
		t.Errorf("the owner's sign-in elsewhere lifted the lock on the attacker's network: %d", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.account_locked' AND resource_id = $1
		AND metadata->>'counter' = 'account_network' AND metadata->>'network' = $2`, a.ID, attacker.ip); n != 1 {
		t.Errorf("the lock was recorded %d times, want 1", n)
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.login_attempts_by_network SET locked_until = NOW() - INTERVAL '1 second'
		WHERE email = lower($1) AND network = $2`, a.Email, attacker.ip); err != nil {
		t.Fatal(err)
	}
	if rec := attacker.do(http.MethodPost, "/auth/login", loginBody(a.Email, testPassword)); rec.Code != http.StatusOK {
		t.Errorf("right password once the lock has lifted: %d %s, want 200", rec.Code, rec.Body.String())
	}
}

// TestLockoutCounters checks the wider counters: failures from many networks
// lock the account everywhere at the account-wide cap, a network failing
// against many accounts is refused for any account, each reported once; an
// organization's own lockout applies to its application's hosted sign-in;
// and lockout settings that can't be read refuse the sign-in.
func TestLockoutCounters(t *testing.T) {
	ctx := dbtest.Context(t)
	small := Lockout{Threshold: 2, Window: time.Minute, Duration: time.Minute}
	config := LockoutConfig{Defaults: small, AccountMultiplier: 2, SourceAccounts: 3, SourceWindow: time.Minute, SourceBlock: time.Minute}
	login := func(svc *Service, email, password, ip string) error {
		_, err := svc.Login(ctx, LoginInput{Email: email, Password: password, IP: ip})
		return err
	}

	t.Run("account-wide cap", func(t *testing.T) {
		svc, seen := newService(t), &anomalies{}
		svc.lockout = config
		svc.SetAnomalyRecorder(seen)
		a, _ := member(t)
		for i := range 4 {
			if err := login(svc, a.Email, "Wrong-password-1", freshIP()); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("failure %d: %v, want %v", i+1, err, ErrInvalidCredentials)
			}
		}
		if err := login(svc, a.Email, testPassword, freshIP()); !errors.Is(err, errs.ErrAuthAccountLocked) {
			t.Errorf("right password from a new network past the account-wide cap: %v, want %v", err, errs.ErrAuthAccountLocked)
		}
		if len(seen.locks) != 1 || seen.locks[0].Counter != CounterAccount || seen.locks[0].Threshold != 4 {
			t.Errorf("locks reported %+v, want one account-wide lock at 4 failures", seen.locks)
		}
	})

	t.Run("spraying source", func(t *testing.T) {
		svc, seen := newService(t), &anomalies{}
		svc.lockout = config
		svc.SetAnomalyRecorder(seen)
		a, _ := member(t)
		source := freshIP()
		for i := range 3 {
			if err := login(svc, dbtest.Unique("sprayed")+"@example.test", "Wrong-password-1", source); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("failure %d: %v", i+1, err)
			}
		}
		if err := login(svc, a.Email, testPassword, source); !errors.Is(err, errs.ErrTooManyRequests) {
			t.Errorf("right password from a throttled network: %v, want %v", err, errs.ErrTooManyRequests)
		}
		if err := login(svc, a.Email, testPassword, freshIP()); err != nil {
			t.Errorf("right password from another network: %v", err)
		}
		if len(seen.throttles) != 1 || len(seen.throttles[0].Accounts) != 3 || seen.throttles[0].Network != source {
			t.Errorf("throttles reported %+v, want one of %s for 3 accounts", seen.throttles, source)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.source_throttled' AND metadata->>'network' = $1`, source); n != 1 {
			t.Errorf("the throttle was recorded %d times, want 1", n)
		}
	})

	t.Run("organization's own lockout", func(t *testing.T) {
		svc := newService(t)
		strict := dbtest.Organization(t)
		svc.SetLockoutSource(func(_ context.Context, organizationID uuid.UUID) (Lockout, error) {
			if organizationID == strict {
				return Lockout{Threshold: 1, Window: time.Minute, Duration: time.Minute}, nil
			}
			return DefaultLockoutConfig().Defaults, nil
		})
		client := dbtest.Unique("app")
		if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, $2, $2)`, strict, client); err != nil {
			t.Fatal(err)
		}
		a, _ := member(t)
		ip := freshIP()
		hosted := func(password, clientID string) error {
			_, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: a.Email, Password: password, IP: ip, ClientID: clientID}, testUserAgent, "", "")
			return err
		}
		if err := hosted("Wrong-password-1", ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("one failure under the platform lockout: %v", err)
		}
		if err := hosted(testPassword, ""); err != nil {
			t.Fatalf("right password after one failure under the platform lockout: %v", err)
		}
		if err := hosted("Wrong-password-1", client); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("one failure under the organization's lockout: %v", err)
		}
		if err := hosted(testPassword, client); !errors.Is(err, errs.ErrAuthAccountLocked) {
			t.Errorf("right password after one failure under a lockout of one: %v, want %v", err, errs.ErrAuthAccountLocked)
		}
	})

	t.Run("settings unavailable", func(t *testing.T) {
		svc := newService(t)
		svc.SetLockoutSource(func(context.Context, uuid.UUID) (Lockout, error) { return Lockout{}, errors.New("store down") })
		a, _ := member(t)
		if err := login(svc, a.Email, testPassword, freshIP()); !errors.Is(err, errs.ErrAuthSignInUnavailable) {
			t.Errorf("sign in while the lockout settings can't be read: %v, want %v", err, errs.ErrAuthSignInUnavailable)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, a.ID); n != 0 {
			t.Errorf("a sign-in the lockout couldn't judge opened %d sessions", n)
		}
	})
}
