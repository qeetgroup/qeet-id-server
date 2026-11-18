//go:build integration

package authentication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

const testPassword = "Kx7mQ2vLp9Wz"

// newService returns the authentication service with dependencies that
// decide nothing: no account holds a second factor, no sign-in is risky,
// every method is allowed, no new password is accepted, no device is
// remembered and no address is captured or refused. A test changes the
// dependency it is about.
func newService(t *testing.T) *Service {
	t.Helper()
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Deps{
		Pool: pool, Users: user.NewRepository(pool), Tokens: dbtest.Issuer(t), Cipher: box,
		MFA: noFactors{}, Risk: &riskStub{}, Registration: noRegistration{}, Methods: allMethods{},
		Devices: noRememberedDevices{}, Lockout: platformLockout, Capture: noCapture{},
		Addresses: addressFunc(func(context.Context, uuid.UUID, uuid.UUID, string, string) error { return nil }),
		Anomalies: &anomalies{}, Sender: &dbtest.Mailbox{},
		LoginHook: hookFunc(func(context.Context, uuid.UUID, uuid.UUID, string) (map[string]any, error) { return nil, nil }),
		SignOut:   noSignOut{}, Signals: sessionsignal.New(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// passThrough is a route throttle that holds nothing back.
func passThrough(h http.Handler) http.Handler { return h }

// noBots scores no attempt as a bot.
type noBots struct{}

func (noBots) Evaluate(context.Context, string, string, string) {}

// noRegistration refuses self-registration and every new password.
type noRegistration struct{}

func (noRegistration) SelfRegistrationEnabled(context.Context, uuid.UUID) (bool, error) {
	return false, nil
}

func (noRegistration) ValidateForOrganization(context.Context, uuid.UUID, string, string) error {
	return errs.ErrNotImplemented
}

// allMethods allows every sign-in method.
type allMethods struct{}

func (allMethods) PasswordEnabled(context.Context, uuid.UUID) (bool, error) { return true, nil }

// noRememberedDevices remembers no device.
type noRememberedDevices struct{}

func (noRememberedDevices) RememberDeviceEnabled(context.Context, uuid.UUID) (bool, error) {
	return false, nil
}

func (noRememberedDevices) RememberDevicePolicy(context.Context, uuid.UUID) (bool, time.Duration, error) {
	return false, 0, nil
}

// platformLockout holds every organization to the platform's lockout.
func platformLockout(context.Context, uuid.UUID) (Lockout, error) {
	return DefaultLockoutConfig().Defaults, nil
}

// noCapture captures no address.
type noCapture struct{}

func (noCapture) RefuseCaptured(context.Context, string) error { return nil }

// noSignOut has no application to tell of a sign-out.
type noSignOut struct{}

func (noSignOut) NotifySignOut(context.Context, uuid.UUID, uuid.UUID, string) ([]string, error) {
	return nil, nil
}

// member creates an organization and an active member of it who signs in with
// testPassword.
func member(t *testing.T) (dbtest.Account, uuid.UUID) {
	t.Helper()
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	dbtest.SetPassword(t, a.ID, testPassword)
	return a, organization
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

// noFactors is an MFA service whose accounts hold no second factor.
type noFactors struct{ MFAEnroller }

// hookFunc is a LoginHook.
type hookFunc func(ctx context.Context, organizationID, userID uuid.UUID, email string) (map[string]any, error)

func (f hookFunc) Run(ctx context.Context, organizationID, userID uuid.UUID, email string) (map[string]any, error) {
	return f(ctx, organizationID, userID, email)
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

// addressFunc is an AddressPolicy.
type addressFunc func(ctx context.Context, organizationID, userID uuid.UUID, ip, path string) error

func (f addressFunc) CheckSignIn(ctx context.Context, organizationID, userID uuid.UUID, ip, path string) error {
	return f(ctx, organizationID, userID, ip, path)
}

func (f addressFunc) CheckSignInTx(ctx context.Context, _ pgx.Tx, organizationID, userID uuid.UUID, ip, path string) error {
	return f(ctx, organizationID, userID, ip, path)
}

// anyPassword accepts every new password.
type anyPassword struct{}

func (anyPassword) SelfRegistrationEnabled(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

func (anyPassword) ValidateForOrganization(context.Context, uuid.UUID, string, string) error {
	return nil
}

func (noFactors) LoginFactors(context.Context, uuid.UUID) ([]LoginFactor, error) { return nil, nil }

func (noFactors) LoginFactorsTx(context.Context, pgx.Tx, uuid.UUID) ([]LoginFactor, error) {
	return nil, nil
}

func (r *riskStub) RecordSignIn(context.Context, uuid.UUID, uuid.UUID, string, string) { r.recorded++ }

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
	return &Handler{Service: svc, Throttle: passThrough, Bot: noBots{}, Validate: validator.New(validator.WithRequiredStructEnabled()), CookieSecure: true,
		ActOnCheck: rbac.NewRepository(svc.pool).CheckActOn}
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

// enforceAddressRules turns organization's address rules on with one allow rule for
// 192.0.2.0/24, so every sign-in to it and renewal in it reads them.
func enforceAddressRules(t *testing.T, organization uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		WITH rule AS (INSERT INTO organization.ip_rules (organization_id, cidr, label, action) VALUES ($1, '192.0.2.0/24', 'office', 'allow'))
		INSERT INTO organization.ip_rules_config (organization_id, enabled) VALUES ($1, TRUE)
	`, organization); err != nil {
		t.Fatalf("address rules: %v", err)
	}
}

// concurrently runs fn n times at once and returns the errors.
func concurrently(n int, fn func(i int) error) []error {
	out := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { out[i] = fn(i) })
	}
	wg.Wait()
	return out
}

// poolFactors is an MFA service whose accounts hold factors. Like the MFA
// service, its methods that take a transaction work through it and the rest
// through the pool; SendLoginCode then fails while failSend is set.
type poolFactors struct {
	MFAEnroller
	pool     *pgxpool.Pool
	factors  []LoginFactor
	failSend bool
	// cancelSend, when set, makes SendLoginCode fail by ending the context.
	cancelSend context.CancelFunc
}

func (f *poolFactors) LoginFactors(ctx context.Context, _ uuid.UUID) ([]LoginFactor, error) {
	return f.factors, f.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (f *poolFactors) LoginFactorsTx(ctx context.Context, tx pgx.Tx, _ uuid.UUID) ([]LoginFactor, error) {
	return f.factors, tx.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (f *poolFactors) StartLoginEnrollment(ctx context.Context, tx pgx.Tx, _ uuid.UUID, _ string) (string, string, error) {
	return "secret", "otpauth://totp/test", tx.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (f *poolFactors) BeginLoginPasskey(ctx context.Context, _ uuid.UUID) (uuid.UUID, any, error) {
	return uuid.New(), "options", f.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (f *poolFactors) StartLoginPush(ctx context.Context, _ uuid.UUID, _, _ string) (LoginPush, error) {
	return LoginPush{ID: uuid.New(), ExpiresAt: time.Now().Add(time.Minute), Number: 42}, f.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (f *poolFactors) SendLoginCode(ctx context.Context, _ uuid.UUID, _ *uuid.UUID, _ uuid.UUID) error {
	if err := f.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int)); err != nil {
		return err
	}
	if f.cancelSend != nil {
		f.cancelSend()
		return ctx.Err()
	}
	if f.failSend {
		return errs.ErrMFADeliveryFailed
	}
	return nil
}

// poolMailbox is a sender that reads through the pool before it sends, as the
// delivery tracker does, and refuses every message while fail is set.
type poolMailbox struct {
	dbtest.Mailbox
	pool *pgxpool.Pool
	fail bool
}

func (m *poolMailbox) Send(ctx context.Context, msg notifier.Message) error {
	if err := m.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int)); err != nil {
		return err
	}
	if m.fail {
		return errors.New("provider unavailable")
	}
	return m.Mailbox.Send(ctx, msg)
}

// cancellingMailbox is a sender whose send fails because it ends the
// request's context.
type cancellingMailbox struct{ cancel context.CancelFunc }

func (m *cancellingMailbox) Send(ctx context.Context, _ notifier.Message) error {
	m.cancel()
	return ctx.Err()
}

// rememberIn is a device policy under which only its organization remembers
// devices, for the default time.
type rememberIn uuid.UUID

func (r rememberIn) RememberDeviceEnabled(_ context.Context, organizationID uuid.UUID) (bool, error) {
	return organizationID == uuid.UUID(r), nil
}

func (r rememberIn) RememberDevicePolicy(_ context.Context, organizationID uuid.UUID) (bool, time.Duration, error) {
	return organizationID == uuid.UUID(r), 0, nil
}

// hostedChallenge starts a hosted sign-in as a from b, failing t unless it
// answers a challenge and sets no session cookie, and returns its token.
func hostedChallenge(t *testing.T, b *browser, a dbtest.Account) string {
	t.Helper()
	rec := b.do(http.MethodPost, "/auth/session", loginBody(a.Email, testPassword))
	var body struct {
		MFARequired bool   `json:"mfa_required"`
		MFAToken    string `json:"mfa_token"`
	}
	dbtest.Decode(t, rec, &body)
	if rec.Code != http.StatusOK || !body.MFARequired || body.MFAToken == "" || setCookie(rec, LoginSessionCookie) != nil {
		t.Fatalf("hosted sign-in holding a second factor: %d %s, want a challenge and no cookie", rec.Code, rec.Body.String())
	}
	return body.MFAToken
}

// sessionIDOf returns the id of the hosted-login session behind cookie raw.
func sessionIDOf(t *testing.T, svc *Service, raw string) uuid.UUID {
	t.Helper()
	id, _, err := svc.ResolveLoginSessionWithID(dbtest.Context(t), raw)
	if err != nil {
		t.Fatalf("resolve the hosted-login session: %v", err)
	}
	return id
}

// requiringOrganization creates an organization that requires a second factor
// at once and makes a a member of it.
func requiringOrganization(t *testing.T, a dbtest.Account) uuid.UUID {
	t.Helper()
	organization := dbtest.Organization(t)
	dbtest.Assign(t, a.ID, organization, dbtest.Role(t, organization))
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO organization.security_policies (organization_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since)
		VALUES ($1, 'required', 0, NOW())
	`, organization); err != nil {
		t.Fatalf("require a second factor: %v", err)
	}
	return organization
}
