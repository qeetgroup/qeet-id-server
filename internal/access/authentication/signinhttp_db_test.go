//go:build integration

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// testUserAgent is the browser every request of a browser names.
const testUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

// browser is one client calling h from an address of its own, so its failed
// sign-ins count against no other test's network, and sending back the
// cookies it has been set.
type browser struct {
	t       *testing.T
	h       http.Handler
	ip      string
	cookies map[string]*http.Cookie
}

// newBrowser returns a browser calling h from a fresh address.
func newBrowser(t *testing.T, h http.Handler) *browser {
	return &browser{t: t, h: h, ip: freshIP(), cookies: map[string]*http.Cookie{}}
}

// freshIP returns an IPv4 address no other test is likely to sign in from.
func freshIP() string {
	b := uuid.New()
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

// do sends a request with body (when not nil) as JSON, keeping the cookies
// the answer sets and forgetting those it clears.
func (b *browser) do(method, path string, body any) *httptest.ResponseRecorder {
	b.t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			b.t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequestWithContext(dbtest.Context(b.t), method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", testUserAgent)
	req.RemoteAddr = b.ip + ":4000"
	for _, c := range b.cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return rec
}

// setCookie returns the cookie named name that rec sets, or nil.
func setCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// answered reports whether rec has status and, unless code is "", carries
// that error code.
func answered(rec *httptest.ResponseRecorder, status int, code string) bool {
	return rec.Code == status && (code == "" || strings.Contains(rec.Body.String(), code))
}

// newHandler returns the HTTP handler of svc, with its cookies marked Secure.
func newHandler(svc *Service) *Handler {
	return &Handler{Service: svc, Validate: validator.New(validator.WithRequiredStructEnabled()), CookieSecure: true}
}

// publicRoutes serves h's sign-in routes and its authenticated ones, of which
// those in cookieRoutes accept the hosted login's cookie in place of a token,
// as in production; the others find no one signed in.
func publicRoutes(h *Handler, cookieRoutes ...string) http.Handler {
	r := chi.NewRouter()
	h.Mount(r)
	r.Group(func(r chi.Router) {
		r.Use(h.Service.LoginSessionAuth(cookieRoutes))
		h.MountAuthed(r)
	})
	return r
}

// heldFactor is an MFA service whose accounts each hold an authenticator app
// that accepts only code.
type heldFactor struct {
	MFAEnroller
	code string
}

func (heldFactor) LoginFactors(context.Context, uuid.UUID) ([]LoginFactor, error) {
	return []LoginFactor{{Type: "totp"}}, nil
}

func (heldFactor) LoginFactorsTx(context.Context, pgx.Tx, uuid.UUID) ([]LoginFactor, error) {
	return []LoginFactor{{Type: "totp"}}, nil
}

func (f heldFactor) VerifyForLoginTx(_ context.Context, _ pgx.Tx, _ uuid.UUID, code string) (string, error) {
	if code != f.code {
		return "", nil
	}
	return "totp", nil
}

func (heldFactor) RecordVerification(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, string) error {
	return nil
}

// anomalies keeps the locks and throttles sign-in reports.
type anomalies struct {
	locks     []AccountLock
	throttles []SourceThrottle
}

func (a *anomalies) OnAccountLocked(_ context.Context, lock AccountLock) {
	a.locks = append(a.locks, lock)
}

func (a *anomalies) OnSourceThrottled(_ context.Context, throttle SourceThrottle) {
	a.throttles = append(a.throttles, throttle)
}

// loginBody is a POST /auth/login body.
func loginBody(email, password string) map[string]string {
	return map[string]string{"email": email, "password": password}
}

// TestPasswordSignInOverHTTP checks that the right password, whatever the
// case of the address, answers a token pair for a live session recorded with
// the client's address and browser, and that a body missing the password is
// refused before any account is looked at.
func TestPasswordSignInOverHTTP(t *testing.T) {
	svc := newService(t)
	b := newBrowser(t, publicRoutes(newHandler(svc)))
	a, tenant := member(t)

	for _, email := range []string{a.Email, strings.ToUpper(a.Email)} {
		rec := b.do(http.MethodPost, "/auth/login", loginBody(email, testPassword))
		if rec.Code != http.StatusOK {
			t.Fatalf("sign in as %s: %d %s, want 200", email, rec.Code, rec.Body.String())
		}
		var pair TokenPair
		dbtest.Decode(t, rec, &pair)
		if pair.UserID != a.ID || pair.TenantID == nil || *pair.TenantID != tenant || pair.RefreshToken == "" || pair.TokenType != "Bearer" {
			t.Fatalf("token pair %+v; want a Bearer pair for %s in %s", pair, a.ID, tenant)
		}
		if claims, err := svc.tokens.VerifyAccess(pair.AccessToken); err != nil || claims.SessionID != pair.SessionID {
			t.Errorf("access token claims %+v, %v; want session %s", claims, err, pair.SessionID)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND user_id = $2 AND host(ip) = $3
			AND user_agent = $4 AND revoked_at IS NULL`, pair.SessionID, a.ID, b.ip, testUserAgent); n != 1 {
			t.Errorf("no live session recorded with the client's address and browser")
		}
	}
	if rec := b.do(http.MethodPost, "/auth/login", map[string]string{"email": a.Email}); !answered(rec, http.StatusUnprocessableEntity, errs.CodeValidation) {
		t.Errorf("sign in without a password: %d %s, want 422 %s", rec.Code, rec.Body.String(), errs.CodeValidation)
	}
	if rec := b.do(http.MethodPost, "/auth/login", loginBody("not-an-address", testPassword)); !answered(rec, http.StatusUnprocessableEntity, errs.CodeValidation) {
		t.Errorf("sign in with a malformed address: %d %s, want 422 %s", rec.Code, rec.Body.String(), errs.CodeValidation)
	}
}

// TestSignInAnswersAlikeOverHTTP checks that a wrong password, an address with
// no account, a deleted account and a wrong password for a suspended account
// all get the very same answer, that only the right password learns an
// account is suspended, and that no record keeps what was submitted.
func TestSignInAnswersAlikeOverHTTP(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	h := publicRoutes(newHandler(newService(t)))
	a, _ := member(t)
	suspended, _ := member(t)
	deleted, _ := member(t)
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, suspended.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET status = 'deleted', deleted_at = NOW() WHERE id = $1`, deleted.ID); err != nil {
		t.Fatal(err)
	}
	wrong := dbtest.Unique("Wr0ng-Secret")
	login := func(email, password string) *httptest.ResponseRecorder {
		t.Helper()
		return newBrowser(t, h).do(http.MethodPost, "/auth/login", loginBody(email, password))
	}

	want := login(a.Email, wrong)
	if !answered(want, http.StatusUnauthorized, errs.CodeAuthInvalidCredentials) {
		t.Fatalf("sign in with the wrong password: %d %s, want 401 %s", want.Code, want.Body.String(), errs.CodeAuthInvalidCredentials)
	}
	for _, tc := range []struct{ name, email, password string }{
		{"an address with no account", dbtest.Unique("nobody") + "@example.test", wrong},
		{"a suspended account's wrong password", suspended.Email, wrong},
		{"a deleted account's wrong password", deleted.Email, wrong},
		{"a deleted account's right password", deleted.Email, testPassword},
	} {
		if rec := login(tc.email, tc.password); rec.Code != want.Code || rec.Body.String() != want.Body.String() {
			t.Errorf("sign in with %s: %d %s, want the wrong password's %d %s", tc.name, rec.Code, rec.Body.String(), want.Code, want.Body.String())
		}
	}
	if rec := login(suspended.Email, testPassword); !answered(rec, http.StatusForbidden, errs.CodeAuthAccountInactive) {
		t.Errorf("sign in to a suspended account with the right password: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeAuthAccountInactive)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = ANY($1)`, []uuid.UUID{a.ID, suspended.ID, deleted.ID}); n != 0 {
		t.Errorf("refused sign-ins opened %d sessions", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.sign_in_failed' AND resource_id = $1
		AND metadata->>'reason' = 'wrong_password'`, a.ID); n != 1 {
		t.Errorf("the wrong password was recorded %d times, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.sign_in_failed' AND actor_user_id IS NULL
		AND metadata->>'reason' = 'unknown_account' AND metadata->>'method' = 'password' AND created_at > NOW() - INTERVAL '1 minute'`); n < 2 {
		t.Errorf("%d sign-ins to no account recorded, want the unknown and the deleted address", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE metadata::text LIKE '%' || $1 || '%'`, wrong); n != 0 {
		t.Errorf("%d audit records keep the submitted password", n)
	}
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
			if rec := attacker.do(http.MethodPost, "/auth/login", loginBody(email, "Wrong-password-1")); !answered(rec, http.StatusUnauthorized, errs.CodeAuthInvalidCredentials) {
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
// organisation's own lockout applies to its application's hosted sign-in;
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
		svc.SetLockoutConfig(config)
		svc.SetAnomalyRecorder(seen)
		a, _ := member(t)
		for i := range 4 {
			if err := login(svc, a.Email, "Wrong-password-1", freshIP()); !errors.Is(err, errs.ErrAuthInvalidCredentials) {
				t.Fatalf("failure %d: %v, want %v", i+1, err, errs.ErrAuthInvalidCredentials)
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
		svc.SetLockoutConfig(config)
		svc.SetAnomalyRecorder(seen)
		a, _ := member(t)
		source := freshIP()
		for i := range 3 {
			if err := login(svc, dbtest.Unique("sprayed")+"@example.test", "Wrong-password-1", source); !errors.Is(err, errs.ErrAuthInvalidCredentials) {
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

	t.Run("organisation's own lockout", func(t *testing.T) {
		svc := newService(t)
		strict := dbtest.Tenant(t)
		svc.SetLockoutSource(func(_ context.Context, tenantID uuid.UUID) (Lockout, error) {
			if tenantID == strict {
				return Lockout{Threshold: 1, Window: time.Minute, Duration: time.Minute}, nil
			}
			return DefaultLockoutConfig().Defaults, nil
		})
		client := dbtest.Unique("app")
		if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (tenant_id, client_id, name) VALUES ($1, $2, $2)`, strict, client); err != nil {
			t.Fatal(err)
		}
		a, _ := member(t)
		ip := freshIP()
		hosted := func(password, clientID string) error {
			_, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: a.Email, Password: password, IP: ip, ClientID: clientID}, testUserAgent, "", "")
			return err
		}
		if err := hosted("Wrong-password-1", ""); !errors.Is(err, errs.ErrAuthInvalidCredentials) {
			t.Fatalf("one failure under the platform lockout: %v", err)
		}
		if err := hosted(testPassword, ""); err != nil {
			t.Fatalf("right password after one failure under the platform lockout: %v", err)
		}
		if err := hosted("Wrong-password-1", client); !errors.Is(err, errs.ErrAuthInvalidCredentials) {
			t.Fatalf("one failure under the organisation's lockout: %v", err)
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

// TestMFAChallengeOverHTTP checks the two-step sign-in through the API: the
// password alone issues no tokens, a wrong code is counted and leaves the
// challenge, the right code opens a session recorded as password_mfa, a
// challenge is spent by its first success, and five wrong codes refuse even a
// fresh challenge met with the right code.
func TestMFAChallengeOverHTTP(t *testing.T) {
	svc := newService(t)
	svc.SetMFA(heldFactor{code: "246810"})
	b := newBrowser(t, publicRoutes(newHandler(svc)))
	a, _ := member(t)
	challenge := func() string {
		t.Helper()
		rec := b.do(http.MethodPost, "/auth/login", loginBody(a.Email, testPassword))
		var body struct {
			MFARequired bool     `json:"mfa_required"`
			MFAToken    string   `json:"mfa_token"`
			Methods     []string `json:"methods"`
			AccessToken string   `json:"access_token"`
		}
		dbtest.Decode(t, rec, &body)
		if rec.Code != http.StatusOK || !body.MFARequired || body.MFAToken == "" || body.AccessToken != "" ||
			len(body.Methods) != 1 || body.Methods[0] != "totp" {
			t.Fatalf("sign in holding a second factor: %d %s, want a totp challenge and no token", rec.Code, rec.Body.String())
		}
		return body.MFAToken
	}
	mfa := func(body map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		return b.do(http.MethodPost, "/auth/mfa", body)
	}

	token := challenge()
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, a.ID); n != 0 {
		t.Fatalf("the password alone opened %d sessions", n)
	}
	for _, tc := range []struct {
		name   string
		body   map[string]any
		status int
		code   string
	}{
		{"no proof", map[string]any{"mfa_token": token}, http.StatusUnprocessableEntity, errs.CodeValidation},
		{"two proofs", map[string]any{"mfa_token": token, "code": "246810", "push": true}, http.StatusUnprocessableEntity, errs.CodeValidation},
		{"a malformed token", map[string]any{"mfa_token": "not-a-token", "code": "246810"}, http.StatusBadRequest, errs.CodeAuthSessionInvalid},
		{"an unknown token", map[string]any{"mfa_token": uuid.NewString(), "code": "246810"}, http.StatusUnauthorized, errs.CodeAuthMFAChallengeExpired},
		{"a wrong code", map[string]any{"mfa_token": token, "code": "000000"}, http.StatusUnauthorized, errs.CodeMFACodeInvalid},
	} {
		if rec := mfa(tc.body); !answered(rec, tc.status, tc.code) {
			t.Errorf("complete with %s: %d %s, want %d %s", tc.name, rec.Code, rec.Body.String(), tc.status, tc.code)
		}
	}
	for _, path := range []string{"/auth/mfa/send", "/auth/mfa/passkey/begin", "/auth/mfa/push", "/auth/mfa/enroll"} {
		if rec := b.do(http.MethodPost, path, map[string]any{"mfa_token": uuid.NewString()}); !answered(rec, http.StatusUnauthorized, errs.CodeAuthMFAChallengeExpired) {
			t.Errorf("%s for an unknown challenge: %d %s, want 401 %s", path, rec.Code, rec.Body.String(), errs.CodeAuthMFAChallengeExpired)
		}
	}
	if rec := b.do(http.MethodPost, "/auth/mfa/enroll", map[string]any{"mfa_token": token}); !answered(rec, http.StatusBadRequest, errs.CodeBadRequest) {
		t.Errorf("start an enrolment for a challenge that is not one: %d %s, want 400", rec.Code, rec.Body.String())
	}

	rec := mfa(map[string]any{"mfa_token": token, "code": "246810"})
	if rec.Code != http.StatusOK {
		t.Fatalf("complete with the right code: %d %s", rec.Code, rec.Body.String())
	}
	var pair TokenPair
	dbtest.Decode(t, rec, &pair)
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND user_id = $2 AND second_factor = 'mfa'`, pair.SessionID, a.ID); n != 1 {
		t.Error("the session does not record its second factor")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.login_succeeded' AND resource_id = $1
		AND metadata->>'method' = 'password_mfa'`, pair.SessionID); n != 1 {
		t.Error("the sign-in was not audited as password_mfa")
	}
	if rec := mfa(map[string]any{"mfa_token": token, "code": "246810"}); !answered(rec, http.StatusUnauthorized, errs.CodeAuthMFAChallengeExpired) {
		t.Errorf("complete a spent challenge again: %d %s, want 401 %s", rec.Code, rec.Body.String(), errs.CodeAuthMFAChallengeExpired)
	}

	token = challenge()
	for i := range maxMFALoginAttempts {
		rec := mfa(map[string]any{"mfa_token": token, "code": "000000"})
		if i < maxMFALoginAttempts-1 && !answered(rec, http.StatusUnauthorized, errs.CodeMFACodeInvalid) {
			t.Fatalf("wrong code %d: %d %s, want 401", i+1, rec.Code, rec.Body.String())
		}
		if i == maxMFALoginAttempts-1 && !answered(rec, http.StatusTooManyRequests, errs.CodeMFAAttemptsExceeded) {
			t.Fatalf("wrong code %d: %d %s, want 429 %s", i+1, rec.Code, rec.Body.String(), errs.CodeMFAAttemptsExceeded)
		}
	}
	if rec := mfa(map[string]any{"mfa_token": challenge(), "code": "246810"}); !answered(rec, http.StatusTooManyRequests, errs.CodeMFAAttemptsExceeded) {
		t.Errorf("the right code on a fresh challenge after five wrong ones: %d %s, want 429 %s", rec.Code, rec.Body.String(), errs.CodeMFAAttemptsExceeded)
	}
}
