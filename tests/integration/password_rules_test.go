//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- the breach provider's range protocol is SHA-1 by definition.
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Every path that sets or replaces a password evaluates the
// organisation's password rules (and the breach check when it is on) the same
// way. The organisation in these tests requires 14 characters with an
// uppercase letter, a number and a symbol.
const (
	pwCompliant   = "Correct-Horse-Battery-9" // meets every rule
	pwTooShort    = "Short-Pass-9!"           // 13 characters, every class
	pwNoUppercase = "correct-horse-battery-9" // long, number, symbol — no uppercase
	pwNoSymbol    = "CorrectHorseBattery99"   // long, uppercase, number — no symbol
	pwOriginal    = "Original-Password-1"     // the credential a user starts with
	pwBaselineBad = "Zq7#x"                   // fails the platform baseline (8 characters)
)

// strictTenant creates an organisation whose password rules are 14 characters
// plus an uppercase letter, a number and a symbol. Self-registration is on so
// the hosted sign-up path can run.
func strictTenant(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()
	tid := createTenant(t, ctx, uniqueSlug("pwrules"))
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.auth_policy (tenant_id, password_min_length, password_require_uppercase,
		                                password_require_number, password_require_symbol, self_registration_enabled)
		VALUES ($1, 14, TRUE, TRUE, TRUE, TRUE)
	`, tid); err != nil {
		t.Fatalf("set password rules: %v", err)
	}
	return tid
}

// userWithPassword creates a user (tenant-less when tenantID is uuid.Nil) who
// already has a password credential.
func userWithPassword(t *testing.T, ctx context.Context, tenantID uuid.UUID, plain string) (uuid.UUID, string) {
	t.Helper()
	email := uniqueSlug("pwrules") + "@example.com"
	var tenant any
	if tenantID != uuid.Nil {
		tenant = tenantID
	}
	var id uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id`, tenant, email).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	hash, err := password.Hash(plain)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, $2)`, id, hash); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	return id, email
}

// storedPasswordIs reports whether the user's stored credential is plain.
func storedPasswordIs(t *testing.T, ctx context.Context, userID uuid.UUID, plain string) bool {
	t.Helper()
	var hash string
	if err := testPool.QueryRow(ctx,
		`SELECT password_hash FROM auth.password_credentials WHERE user_id = $1`, userID).Scan(&hash); err != nil {
		t.Fatalf("read credential: %v", err)
	}
	return password.Verify(hash, plain)
}

func userExists(t *testing.T, ctx context.Context, email string) bool {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM "user".users WHERE LOWER(email) = LOWER($1)`, email).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n > 0
}

// refusal is what a caller is told when a password is not accepted. code is
// empty for a bulk-import row, which reports only a message per row.
type refusal struct{ code, message string }

func refusalOf(t *testing.T, err error) *refusal {
	t.Helper()
	if err == nil {
		return nil
	}
	e := errs.As(err)
	if e == nil {
		t.Fatalf("unexpected non-domain error: %v", err)
	}
	return &refusal{code: e.Code, message: e.Message}
}

func refusalOfResponse(t *testing.T, rec *httptest.ResponseRecorder) *refusal {
	t.Helper()
	if rec.Code < 300 {
		return nil
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error envelope (%d): %v: %s", rec.Code, err, rec.Body.String())
	}
	return &refusal{code: body.Error.Code, message: body.Error.Message}
}

func serveJSON(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func adminRouter(h *user.Handler, actorID, tenantID uuid.UUID) http.Handler {
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(withPrincipal(actorID, tenantID))
	h.Mount(r)
	return r
}

// passwordPaths holds every service that sets a password, wired the way the
// server wires them (see wirePasswordRules).
type passwordPaths struct {
	auth     *auth.Service
	recovery *recovery.Service
	invites  *invite.Service
	users    *user.Handler
}

// passwordPath sets pw through one of the eight paths, for an account in
// tenantID (uuid.Nil = no organisation), and returns the refusal, if any.
type passwordPath struct {
	name string
	set  func(t *testing.T, ctx context.Context, p passwordPaths, tenantID uuid.UUID, pw string) *refusal
}

var (
	hostedSignUp = passwordPath{"hosted sign-up", func(t *testing.T, ctx context.Context, p passwordPaths, tenantID uuid.UUID, pw string) *refusal {
		_, _, err := p.auth.RegisterInTenant(ctx, tenantID, uniqueSlug("pwrules")+"@example.com", pw, "", "203.0.113.9", "test")
		return refusalOf(t, err)
	}}
	consoleSignUp = passwordPath{"console sign-up", func(t *testing.T, ctx context.Context, p passwordPaths, _ uuid.UUID, pw string) *refusal {
		_, _, _, err := p.auth.Signup(ctx, auth.SignupInput{Email: uniqueSlug("pwrules") + "@example.com", Password: pw})
		return refusalOf(t, err)
	}}
	selfServiceChange = passwordPath{"self-service change", func(t *testing.T, ctx context.Context, p passwordPaths, tenantID uuid.UUID, pw string) *refusal {
		userID, _ := userWithPassword(t, ctx, tenantID, pwOriginal)
		err := p.auth.ChangePassword(ctx, auth.ChangePasswordInput{
			UserID: userID, KeepSessionID: uuid.New(), Current: pwOriginal, Next: pw,
		})
		return refusalOf(t, err)
	}}
	passwordReset = passwordPath{"password reset", func(t *testing.T, ctx context.Context, p passwordPaths, tenantID uuid.UUID, pw string) *refusal {
		_, email := userWithPassword(t, ctx, tenantID, pwOriginal)
		token, err := p.recovery.StartPasswordReset(ctx, email)
		if err != nil || token == "" {
			t.Fatalf("start reset: token=%q err=%v", token, err)
		}
		return refusalOf(t, p.recovery.ConfirmPasswordReset(ctx, token, pw, recovery.AuditCtx{}))
	}}
	invitationAccept = passwordPath{"invitation accept", func(t *testing.T, ctx context.Context, p passwordPaths, tenantID uuid.UUID, pw string) *refusal {
		_, raw, err := p.invites.Create(ctx, invite.CreateInput{TenantID: tenantID, Email: uniqueSlug("pwrules") + "@example.com"}, nil)
		if err != nil {
			t.Fatalf("create invite: %v", err)
		}
		_, err = p.invites.Accept(ctx, invite.AcceptInput{Token: raw, Password: pw})
		return refusalOf(t, err)
	}}
	adminSetPassword = passwordPath{"admin set-password", func(t *testing.T, ctx context.Context, p passwordPaths, tenantID uuid.UUID, pw string) *refusal {
		actor := createUserInTenant(t, ctx, tenantID)
		target, _ := userWithPassword(t, ctx, tenantID, pwOriginal)
		rec := serveJSON(t, adminRouter(p.users, actor, tenantID), http.MethodPost,
			"/users/"+target.String()+"/password", map[string]any{"password": pw})
		return refusalOfResponse(t, rec)
	}}
	adminCreate = passwordPath{"admin create", func(t *testing.T, ctx context.Context, p passwordPaths, tenantID uuid.UUID, pw string) *refusal {
		actor := createUserInTenant(t, ctx, tenantID)
		rec := serveJSON(t, adminRouter(p.users, actor, tenantID), http.MethodPost, "/users",
			map[string]any{"email": uniqueSlug("pwrules") + "@example.com", "password": pw})
		return refusalOfResponse(t, rec)
	}}
	bulkImport = passwordPath{"bulk import", func(t *testing.T, ctx context.Context, p passwordPaths, tenantID uuid.UUID, pw string) *refusal {
		actor := createUserInTenant(t, ctx, tenantID)
		rec := serveJSON(t, adminRouter(p.users, actor, tenantID), http.MethodPost, "/users/bulk",
			map[string]any{"users": []map[string]any{{"email": uniqueSlug("pwrules") + "@example.com", "password": pw}}})
		if rec.Code != http.StatusOK {
			t.Fatalf("bulk import status = %d: %s", rec.Code, rec.Body.String())
		}
		var res user.BulkImportResult
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode bulk result: %v", err)
		}
		if res.Failed == 0 {
			return nil
		}
		return &refusal{message: res.Errors[0].Message}
	}}
)

// organisationPaths are the paths that set a password for an account that
// belongs to an organisation; consoleSignUp is the eighth, tenant-less path.
var organisationPaths = []passwordPath{
	hostedSignUp, selfServiceChange, passwordReset, invitationAccept,
	adminSetPassword, adminCreate, bulkImport,
}

// assertRefused checks a refusal names exactly the expected requirement (same
// code and message on every path; bulk rows carry the message only) and never
// echoes the submitted password.
func assertRefused(t *testing.T, got *refusal, want *errs.Error, pw string) {
	t.Helper()
	if got == nil {
		t.Fatalf("password %q was accepted; want refusal %s", pw, want.Code)
	}
	if got.code != "" && got.code != want.Code {
		t.Errorf("code = %q, want %q (message %q)", got.code, want.Code, got.message)
	}
	if got.message != want.Message {
		t.Errorf("message = %q, want %q", got.message, want.Message)
	}
	if strings.Contains(got.message, pw) {
		t.Errorf("refusal echoes the submitted password: %q", got.message)
	}
}

// AC: a password set through any of the eight paths → the organisation's
// configured rules are evaluated identically on each.
func TestPasswordRules_EveryPathEvaluatesTheOrganisationRules(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	paths := wirePasswordRules(t, nil)
	tenantID := strictTenant(t, ctx)

	for _, path := range organisationPaths {
		t.Run(path.name, func(t *testing.T) {
			assertRefused(t, path.set(t, ctx, paths, tenantID, pwNoUppercase), errs.ErrAuthPolicyPasswordNoUppercase, pwNoUppercase)
			assertRefused(t, path.set(t, ctx, paths, tenantID, pwNoSymbol), errs.ErrAuthPolicyPasswordNoSymbol, pwNoSymbol)
			if r := path.set(t, ctx, paths, tenantID, pwCompliant); r != nil {
				t.Fatalf("a compliant password was refused: %+v", r)
			}
		})
	}
}

// A password set without an organisation gets the documented platform
// baseline (8 characters), not nothing: the console sign-up, and a tenant-less
// account changing or resetting its password.
func TestPasswordRules_NoOrganisationGetsThePlatformBaseline(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	paths := wirePasswordRules(t, nil)
	want := errs.ErrAuthPolicyPasswordTooShort.WithMessage("Your password must be at least 8 characters.")

	for _, path := range []passwordPath{consoleSignUp, selfServiceChange, passwordReset} {
		t.Run(path.name, func(t *testing.T) {
			assertRefused(t, path.set(t, ctx, paths, uuid.Nil, pwBaselineBad), want, pwBaselineBad)
			if r := path.set(t, ctx, paths, uuid.Nil, "Zq7#xLm2"); r != nil {
				t.Fatalf("an 8-character password was refused without an organisation: %+v", r)
			}
		})
	}
}

// AC: a reset with a password shorter than the configured minimum is refused
// and the credential is unchanged (and the link still works for a compliant
// password).
func TestPasswordRules_ResetShorterThanTheMinimumIsRefused(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	paths := wirePasswordRules(t, nil)
	tenantID := strictTenant(t, ctx)
	userID, email := userWithPassword(t, ctx, tenantID, pwOriginal)

	token, err := paths.recovery.StartPasswordReset(ctx, email)
	if err != nil || token == "" {
		t.Fatalf("start reset: token=%q err=%v", token, err)
	}
	got := refusalOf(t, paths.recovery.ConfirmPasswordReset(ctx, token, pwTooShort, recovery.AuditCtx{}))
	assertRefused(t, got, errs.ErrAuthPolicyPasswordTooShort.WithMessage("Your password must be at least 14 characters."), pwTooShort)
	if !storedPasswordIs(t, ctx, userID, pwOriginal) {
		t.Fatal("a refused reset changed the stored credential")
	}
	if err := paths.recovery.ConfirmPasswordReset(ctx, token, pwCompliant, recovery.AuditCtx{}); err != nil {
		t.Fatalf("the reset link should still work for a compliant password: %v", err)
	}
	if !storedPasswordIs(t, ctx, userID, pwCompliant) {
		t.Fatal("the compliant reset did not set the password")
	}
}

// AC: a user changing their own password to one missing a required character
// class is refused with the specific unmet requirement — the same answer
// whether or not they typed their current password correctly, so the refusal
// says nothing about the stored credential.
func TestPasswordRules_ChangeMissingAClassNamesTheRequirement(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	paths := wirePasswordRules(t, nil)
	tenantID := strictTenant(t, ctx)
	userID, _ := userWithPassword(t, ctx, tenantID, pwOriginal)

	for _, current := range []string{pwOriginal, "not-the-current-password"} {
		err := paths.auth.ChangePassword(ctx, auth.ChangePasswordInput{
			UserID: userID, KeepSessionID: uuid.New(), Current: current, Next: pwNoSymbol,
		})
		assertRefused(t, refusalOf(t, err), errs.ErrAuthPolicyPasswordNoSymbol, pwNoSymbol)
	}
	if !storedPasswordIs(t, ctx, userID, pwOriginal) {
		t.Fatal("a refused change replaced the stored credential")
	}
}

// AC: an administrator creating a user with a weak password is refused before
// any user row is written.
func TestPasswordRules_AdminCreateIsRefusedBeforeAnyRowIsWritten(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	paths := wirePasswordRules(t, nil)
	tenantID := strictTenant(t, ctx)
	actor := createUserInTenant(t, ctx, tenantID)
	email := uniqueSlug("weak-admin-create") + "@example.com"

	rec := serveJSON(t, adminRouter(paths.users, actor, tenantID), http.MethodPost, "/users",
		map[string]any{"email": email, "password": pwTooShort})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body.String())
	}
	assertRefused(t, refusalOfResponse(t, rec), errs.ErrAuthPolicyPasswordTooShort.WithMessage("Your password must be at least 14 characters."), pwTooShort)
	if userExists(t, ctx, email) {
		t.Fatal("a user row was written for a refused password")
	}
}

// AC: a bulk import with compliant and non-compliant rows creates the
// compliant rows and refuses the others individually, with reasons.
func TestPasswordRules_BulkImportRefusesRowsIndividually(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	paths := wirePasswordRules(t, nil)
	tenantID := strictTenant(t, ctx)
	actor := createUserInTenant(t, ctx, tenantID)

	emails := make([]string, 5)
	for i := range emails {
		emails[i] = uniqueSlug(fmt.Sprintf("bulk%d", i+1)) + "@example.com"
	}
	rows := []map[string]any{
		{"email": emails[0], "password": pwCompliant},
		{"email": emails[1], "password": pwTooShort},
		{"email": emails[2], "password": pwNoSymbol},
		{"email": emails[3]}, // no password: nothing to check
		{"email": emails[4], "password": pwCompliant},
	}
	rec := serveJSON(t, adminRouter(paths.users, actor, tenantID), http.MethodPost, "/users/bulk", map[string]any{"users": rows})
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk status = %d: %s", rec.Code, rec.Body.String())
	}
	var res user.BulkImportResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Succeeded != 3 || res.Failed != 2 || len(res.Errors) != 2 {
		t.Fatalf("result = %+v, want 3 created and 2 refused", res)
	}
	want := map[int]string{
		2: "Your password must be at least 14 characters.",
		3: errs.ErrAuthPolicyPasswordNoSymbol.Message,
	}
	for _, e := range res.Errors {
		if want[e.Line] == "" || e.Message != want[e.Line] || e.Email != emails[e.Line-1] {
			t.Errorf("row error = %+v, want line 2 (too short) and line 3 (no symbol) with their reasons", e)
		}
	}
	for i, email := range emails {
		created := i != 1 && i != 2
		if userExists(t, ctx, email) != created {
			t.Errorf("row %d (%s): created = %v, want %v", i+1, email, !created, created)
		}
	}
}

// fakeBreachProvider is a Pwned Passwords range API that reports breached as
// seen `count` times, or answers every request with status when it is not 200.
func fakeBreachProvider(t *testing.T, breached string, count, status int) *hibp.Checker {
	t.Helper()
	sum := sha1.Sum([]byte(breached)) // #nosec G401 -- protocol requirement, not a security use.
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		body := "0000000000000000000000000000000000A:0\r\n"
		if strings.HasSuffix(r.URL.Path, "/range/"+digest[:5]) {
			body += fmt.Sprintf("%s:%d\r\n", digest[5:], count)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return hibp.New(&http.Client{Timeout: 2 * time.Second}, srv.URL, 1)
}

// AC: with the breach check on, a password known from breach corpora is
// refused on every path with the breach-specific message, which omits the
// sighting count.
func TestPasswordRules_BreachedPasswordIsRefusedOnEveryPath(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	paths := wirePasswordRules(t, fakeBreachProvider(t, pwCompliant, 48213, http.StatusOK))
	tenantID := strictTenant(t, ctx)

	for _, path := range append([]passwordPath{consoleSignUp}, organisationPaths...) {
		t.Run(path.name, func(t *testing.T) {
			got := path.set(t, ctx, paths, tenantID, pwCompliant)
			assertRefused(t, got, errs.ErrAuthPolicyPasswordBreached, pwCompliant)
			if got != nil && strings.ContainsAny(got.message, "0123456789") {
				t.Errorf("breach message reveals a count: %q", got.message)
			}
		})
	}
}

// breachErrorsCounted reads the allowed-on-error counter from the process's
// metrics registry (the one /metrics serves); -1 when it is not registered.
func breachErrorsCounted(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "breached_password_check_allowed_on_error_total" {
			continue
		}
		var total float64
		for _, m := range f.GetMetric() {
			total += m.GetCounter().GetValue()
		}
		return total
	}
	return -1
}

// AC: when the breach provider is unreachable the behaviour matches the
// recorded decision — fail open: the password is accepted — and the event is
// counted in a metric.
func TestPasswordRules_UnreachableBreachProviderFailsOpenAndIsCounted(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	paths := wirePasswordRules(t, fakeBreachProvider(t, pwCompliant, 1, http.StatusServiceUnavailable))
	tenantID := strictTenant(t, ctx)

	before := breachErrorsCounted(t)
	if r := adminCreate.set(t, ctx, paths, tenantID, pwCompliant); r != nil {
		t.Fatalf("the password was refused while the breach provider was down: %+v", r)
	}
	after := breachErrorsCounted(t)
	if after < 0 {
		t.Fatal("no breached_password_check_allowed_on_error_total metric is registered")
	}
	if after < before+1 {
		t.Fatalf("allowed-on-error count went from %v to %v, want an increase", before, after)
	}
}
