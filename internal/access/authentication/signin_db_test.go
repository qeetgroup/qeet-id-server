//go:build integration

package auth

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

const testPassword = "Kx7mQ2vLp9Wz"

// newService returns the authentication service with no optional policies.
func newService(t *testing.T) *Service {
	t.Helper()
	pool := dbtest.Pool(t)
	return NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
}

// member creates a tenant and an active member of it who signs in with
// testPassword.
func member(t *testing.T) (dbtest.Account, uuid.UUID) {
	t.Helper()
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	dbtest.SetPassword(t, a.ID, testPassword)
	return a, tenant
}

// signIn signs a in with testPassword, failing t unless tokens are issued.
func signIn(t *testing.T, svc *Service, a dbtest.Account) *TokenPair {
	t.Helper()
	res, err := svc.Login(dbtest.Context(t), LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || res.Pair == nil {
		t.Fatalf("sign in: %+v, %v", res, err)
	}
	return res.Pair
}

// TestPasswordSignIn checks that the right password signs a user in to their
// tenant with a live session, an access token naming it, and an audit record.
func TestPasswordSignIn(t *testing.T) {
	svc := newService(t)
	a, tenant := member(t)

	pair := signIn(t, svc, a)
	if pair.UserID != a.ID || pair.TenantID == nil || *pair.TenantID != tenant || pair.RefreshToken == "" {
		t.Fatalf("token pair %+v; want user %s in tenant %s with a refresh token", pair, a.ID, tenant)
	}
	claims, err := svc.tokens.VerifyAccess(pair.AccessToken)
	if err != nil || claims.UserID != a.ID || claims.TenantID != tenant || claims.SessionID != pair.SessionID {
		t.Fatalf("access token claims %+v, %v", claims, err)
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM auth.sessions WHERE id = $1 AND user_id = $2 AND tenant_id = $3 AND revoked_at IS NULL
	`, pair.SessionID, a.ID, tenant); n != 1 {
		t.Error("no live session for the sign-in")
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM audit.events WHERE action = 'auth.login_succeeded' AND resource_id = $1 AND tenant_id = $2
	`, pair.SessionID, tenant); n != 1 {
		t.Error("the sign-in was not audited")
	}
}

// TestPasswordSignInRefused checks that a wrong password, an unknown address
// and a suspended account are refused, and open no session.
func TestPasswordSignInRefused(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, _ := member(t)
	suspended, _ := member(t)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, suspended.ID); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	for _, tc := range []struct {
		name, email, password string
		want                  error
	}{
		{"wrong password", a.Email, "Kx7mQ2vLp9Wy", errs.ErrAuthInvalidCredentials},
		{"unknown address", dbtest.Unique("nobody") + "@example.test", testPassword, errs.ErrAuthInvalidCredentials},
		{"suspended account", suspended.Email, testPassword, errs.ErrAuthAccountInactive},
		{"suspended account, wrong password", suspended.Email, "Kx7mQ2vLp9Wy", errs.ErrAuthInvalidCredentials},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := svc.Login(ctx, LoginInput{Email: tc.email, Password: tc.password})
			if !errors.Is(err, tc.want) || res != nil {
				t.Errorf("sign in: %+v, %v; want %v", res, err, tc.want)
			}
		})
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = ANY($1)`, []uuid.UUID{a.ID, suspended.ID}); n != 0 {
		t.Errorf("refused sign-ins opened %d sessions", n)
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
			if _, err := svc.Login(ctx, LoginInput{Email: a.Email, Password: "wrong-password"}); !errors.Is(err, errs.ErrAuthInvalidCredentials) {
				t.Fatalf("wrong password: %v, want %v", err, errs.ErrAuthInvalidCredentials)
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

// TestRefreshRotation checks that a refresh token renews its session once, and
// that presenting a spent one ends the session, so its replacement stops
// working too.
func TestRefreshRotation(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, _ := member(t)
	first := signIn(t, svc, a)

	second, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken || second.SessionID != first.SessionID {
		t.Fatalf("refresh returned %+v; want a new token for session %s", second, first.SessionID)
	}

	// The spent token first: presenting it is what ends the session.
	for _, tc := range []struct{ name, token string }{{"spent", first.RefreshToken}, {"replacement", second.RefreshToken}} {
		if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: tc.token}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
			t.Errorf("refresh with the %s token: %v, want %v", tc.name, err, errs.ErrAuthSessionRevoked)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NOT NULL`, first.SessionID); n != 1 {
		t.Error("reusing a spent refresh token left the session live")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.token_reuse_detected' AND resource_id = $1`, first.SessionID); n != 1 {
		t.Error("the reuse was not audited")
	}
}

// TestSignOut checks that signing out ends only that session, and that no one
// else can end it.
func TestSignOut(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, _ := member(t)
	stranger, _ := member(t)
	ended, kept := signIn(t, svc, a), signIn(t, svc, a)

	if err := svc.Logout(ctx, ended.SessionID, stranger.ID); err != nil {
		t.Fatalf("sign out as someone else: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NULL`, ended.SessionID); n != 1 {
		t.Fatal("another user ended the session")
	}
	if err := svc.Logout(ctx, ended.SessionID, a.ID); err != nil {
		t.Fatalf("sign out: %v", err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: ended.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
		t.Errorf("refresh after sign-out: %v, want %v", err, errs.ErrAuthSessionRevoked)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: kept.RefreshToken}); err != nil {
		t.Errorf("the other session stopped renewing: %v", err)
	}
	sessions, err := svc.ListSessions(ctx, a.ID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	status := map[uuid.UUID]string{}
	for _, s := range sessions {
		status[s.ID] = s.Status
	}
	if want := map[uuid.UUID]string{ended.SessionID: "revoked", kept.SessionID: "active"}; !maps.Equal(status, want) {
		t.Errorf("sessions %v, want %v", status, want)
	}
}

// noFactors is an MFA service whose accounts hold no second factor.
type noFactors struct{ MFAEnroller }

func (noFactors) LoginFactors(context.Context, uuid.UUID) ([]LoginFactor, error) { return nil, nil }

func (noFactors) LoginFactorsTx(context.Context, pgx.Tx, uuid.UUID) ([]LoginFactor, error) {
	return nil, nil
}

// hookFunc is a LoginHook.
type hookFunc func(ctx context.Context, tenantID, userID uuid.UUID, email string) (map[string]any, error)

func (f hookFunc) Run(ctx context.Context, tenantID, userID uuid.UUID, email string) (map[string]any, error) {
	return f(ctx, tenantID, userID, email)
}

// riskStub assesses every sign-in as risky or not, and counts the sign-ins
// recorded.
type riskStub struct {
	risky    bool
	recorded int
}

func (r *riskStub) ShouldForceMFA(context.Context, uuid.UUID, uuid.UUID, string, string, string) bool {
	return r.risky
}

func (r *riskStub) RecordSignIn(context.Context, uuid.UUID, uuid.UUID, string, string) { r.recorded++ }

// addressFunc is an AddressPolicy.
type addressFunc func(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error

func (f addressFunc) CheckSignIn(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error {
	return f(ctx, tenantID, userID, ip, path)
}

func (f addressFunc) CheckSignInTx(ctx context.Context, _ pgx.Tx, tenantID, userID uuid.UUID, ip, path string) error {
	return f(ctx, tenantID, userID, ip, path)
}

// anyPassword accepts every new password.
type anyPassword struct{}

func (anyPassword) SelfRegistrationEnabled(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}
func (anyPassword) ValidateForTenant(context.Context, uuid.UUID, string, string) error { return nil }

// TestExternalSignIn checks that a sign-in whose first factor is checked
// elsewhere gets the lockout, hook, second-factor and risk decisions of a
// password sign-in, answering with the challenge where it needs another step.
func TestExternalSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	a, tenant := member(t)
	in := ExternalSignIn{TenantID: tenant, Account: "test:" + a.Email, Method: "ldap", IP: "192.0.2.10"}
	proved := func(context.Context) (uuid.UUID, bool, error) { return a.ID, false, nil }

	t.Run("signs in", func(t *testing.T) {
		svc := newService(t)
		svc.SetMFA(noFactors{})
		risk := &riskStub{}
		svc.SetRiskAssessor(risk)
		res, err := svc.SignInExternal(ctx, in, proved)
		if err != nil || res.Pair == nil {
			t.Fatalf("sign in: %+v, %v", res, err)
		}
		pair := res.Pair
		if pair.UserID != a.ID || pair.TenantID == nil || *pair.TenantID != tenant {
			t.Fatalf("signed in as %s to %v, want %s to %s", pair.UserID, pair.TenantID, a.ID, tenant)
		}
		if risk.recorded != 1 {
			t.Errorf("a completed sign-in was recorded for risk %d times, want 1", risk.recorded)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.login_succeeded'
			AND resource_id = $1 AND metadata->>'method' = 'ldap'`, pair.SessionID); n != 1 {
			t.Error("the sign-in was not audited with its method")
		}
	})

	t.Run("lockout", func(t *testing.T) {
		svc := newService(t)
		locked := in
		locked.Account = dbtest.Unique("test:locked")
		refused := errors.New("refused")
		for range 5 {
			_, err := svc.SignInExternal(ctx, locked, func(context.Context) (uuid.UUID, bool, error) { return uuid.Nil, true, refused })
			if !errors.Is(err, refused) {
				t.Fatalf("refused credential: %v, want %v", err, refused)
			}
		}
		checked := false
		_, err := svc.SignInExternal(ctx, locked, func(context.Context) (uuid.UUID, bool, error) {
			checked = true
			return a.ID, false, nil
		})
		if !errors.Is(err, errs.ErrAuthAccountLocked) || checked {
			t.Errorf("locked account: %v (checked %v), want %v before any check", err, checked, errs.ErrAuthAccountLocked)
		}
	})

	t.Run("address rules", func(t *testing.T) {
		svc := newService(t)
		svc.SetAddressPolicy(addressFunc(func(context.Context, uuid.UUID, uuid.UUID, string, string) error {
			return errs.ErrAuthAddressNotAllowed
		}))
		checked := false
		_, err := svc.SignInExternal(ctx, in, func(context.Context) (uuid.UUID, bool, error) {
			checked = true
			return a.ID, false, nil
		})
		if !errors.Is(err, errs.ErrAuthAddressNotAllowed) || checked {
			t.Errorf("refused network: %v (checked %v), want %v before any check", err, checked, errs.ErrAuthAddressNotAllowed)
		}
	})

	t.Run("hook", func(t *testing.T) {
		svc := newService(t)
		denied := errs.ErrForbidden.WithDetail("denied by hook")
		var hookTenant uuid.UUID
		svc.SetLoginHook(hookFunc(func(_ context.Context, tenantID, _ uuid.UUID, _ string) (map[string]any, error) {
			hookTenant = tenantID
			return nil, denied
		}))
		if _, err := svc.SignInExternal(ctx, in, proved); !errors.Is(err, errs.ErrForbidden) || hookTenant != tenant {
			t.Errorf("hook denies: %v for tenant %s, want %v for %s", err, hookTenant, errs.ErrForbidden, tenant)
		}
	})

	t.Run("second factor required", func(t *testing.T) {
		svc := newService(t)
		svc.SetMFA(noFactors{})
		required, _ := member(t)
		if _, err := pool.Exec(ctx, `UPDATE "user".users SET mfa_required = TRUE WHERE id = $1`, required.ID); err != nil {
			t.Fatalf("require MFA: %v", err)
		}
		res, err := svc.SignInExternal(ctx, in, func(context.Context) (uuid.UUID, bool, error) { return required.ID, false, nil })
		if err != nil || res.Pair != nil || !res.MFARequired || !res.EnrollmentRequired || res.MFAToken == "" {
			t.Fatalf("sign in: %+v, %v; want an enrolment challenge", res, err)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_login_challenges WHERE id = $1 AND first_factor = 'ldap'`, res.MFAToken); n != 1 {
			t.Error("the challenge does not record its first factor")
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, required.ID); n != 0 {
			t.Errorf("a challenged sign-in opened %d sessions", n)
		}
	})

	t.Run("risky", func(t *testing.T) {
		svc := newService(t)
		svc.SetMFA(noFactors{})
		svc.SetSender(&dbtest.Mailbox{})
		risk := &riskStub{risky: true}
		svc.SetRiskAssessor(risk)
		if _, err := pool.Exec(ctx, `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
			t.Fatal(err)
		}
		for attempt := range 2 {
			res, err := svc.SignInExternal(ctx, in, proved)
			if err != nil || res.Pair != nil || !res.MFARequired || len(res.Methods) != 1 || res.Methods[0] != "email" {
				t.Fatalf("risky sign-in %d: %+v, %v; want an emailed-code challenge", attempt+1, res, err)
			}
		}
		if risk.recorded != 0 {
			t.Errorf("challenged sign-ins were recorded for risk %d times, so asking again could pass", risk.recorded)
		}
	})
}

// TestChangePasswordEndsSignIns checks that changing the password keeps the
// current session and ends every other way in: sessions, remembered devices
// and application grants.
func TestChangePasswordEndsSignIns(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.SetRegistrationPolicy(anyPassword{})
	a, tenant := member(t)
	current, other := signIn(t, svc, a), signIn(t, svc, a)
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.trusted_devices (user_id, tenant_id, token_hash, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 day')
	`, a.ID, tenant, dbtest.Unique("device")); err != nil {
		t.Fatalf("trusted device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, expires_at)
		VALUES ($1, 'app', $2, $3, NOW() + INTERVAL '1 day')
	`, dbtest.Unique("grant"), a.ID, tenant); err != nil {
		t.Fatalf("application grant: %v", err)
	}

	if err := svc.ChangePassword(ctx, ChangePasswordInput{
		UserID: a.ID, KeepSessionID: current.SessionID, Current: testPassword, Next: "Pw4!nKx7mQ2v-new",
	}); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NULL`, current.SessionID); n != 1 {
		t.Error("the current session ended")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NULL`, other.SessionID); n != 0 {
		t.Error("another session survived")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE user_id = $1`, a.ID); n != 0 {
		t.Errorf("%d remembered devices survived", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, a.ID); n != 0 {
		t.Errorf("%d application grants survived", n)
	}
}

// TestSignupAnswersAlike checks that signing up with an email that already
// has an account gets the neutral answer, not one naming the email.
func TestSignupAnswersAlike(t *testing.T) {
	svc := newService(t)
	svc.SetRegistrationPolicy(anyPassword{})
	h := &Handler{Service: svc, Validate: validator.New()}
	a, tenant := member(t)
	srv := chi.NewRouter()
	h.Mount(srv)

	for path, body := range map[string]map[string]any{
		"/auth/signup":   {"email": a.Email, "password": testPassword},
		"/auth/register": {"tenant_id": tenant, "email": a.Email, "password": testPassword},
	} {
		rec := dbtest.Do(t, srv, http.MethodPost, path, body)
		var got struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		dbtest.Decode(t, rec, &got)
		if rec.Code != http.StatusUnprocessableEntity || got.Error.Code != errs.CodeUnprocessable {
			t.Errorf("%s with a registered email: %d %s, want %d %s", path, rec.Code, rec.Body.String(),
				http.StatusUnprocessableEntity, errs.CodeUnprocessable)
		}
	}
}
