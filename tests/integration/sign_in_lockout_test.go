//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/threat"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
)

// Sign-in lockout. Every test signs in through the HTTP handlers the console
// (POST /auth/login) and the hosted login (POST /auth/session) call, from a
// network of its own, so the tests never share a counter.

const lockoutPassword = "Lockout-Correct-Horse-7"

// signInHarness is the auth service wired the way bootstrap wires it, behind
// its public routes, plus the auth-policy API a tenant administrator uses.
type signInHarness struct {
	auth   *auth.Service
	policy *authpolicy.Service
	routes http.Handler
}

func newSignInHarness(t *testing.T, pool *pgxpool.Pool) *signInHarness {
	t.Helper()
	svc := auth.NewService(pool, user.NewRepository(pool), mustIssuer())
	rules := authpolicy.NewService(pool)
	svc.SetRegistrationPolicy(rules)
	svc.SetAnomalyRecorder(threat.NewService(pool))
	wireSignInLockout(svc, rules)
	r := chi.NewRouter()
	(&auth.Handler{Service: svc, Validate: validator.New(validator.WithRequiredStructEnabled())}).Mount(r)
	return &signInHarness{auth: svc, policy: rules, routes: r}
}

type apiReply struct {
	status int
	body   map[string]any
}

// errorCode is the error envelope's code ("" for a success body).
func (r apiReply) errorCode() string {
	e, _ := r.body["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

// comparable drops the per-request id so two replies can be compared whole.
func (r apiReply) comparable() string {
	if e, ok := r.body["error"].(map[string]any); ok {
		delete(e, "req_id")
	}
	raw, _ := json.Marshal(r.body)
	return fmt.Sprintf("%d %s", r.status, raw)
}

func serve(t *testing.T, h http.Handler, method, path, ip string, body any) apiReply {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if ip != "" {
		req.RemoteAddr = net.JoinHostPort(ip, "41000")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := apiReply{status: rec.Code, body: map[string]any{}}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out.body); err != nil {
			t.Fatalf("%s %s: decode %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return out
}

// consoleSignIn is the console's password sign-in (no OAuth client).
func (h *signInHarness) consoleSignIn(t *testing.T, ip, email, pw string) apiReply {
	t.Helper()
	return serve(t, h.routes, http.MethodPost, "/auth/login", ip, map[string]any{"email": email, "password": pw})
}

// hostedSignIn is the hosted login's password sign-in for an OAuth client
// ("" = a hosted sign-in that names no client).
func (h *signInHarness) hostedSignIn(t *testing.T, ip, email, pw, clientID string) apiReply {
	t.Helper()
	body := map[string]any{"email": email, "password": pw}
	if clientID != "" {
		body["client_id"] = clientID
	}
	return serve(t, h.routes, http.MethodPost, "/auth/session", ip, body)
}

// policyAPI is the tenant administrator's view of /tenants/{id}/auth-policy.
func (h *signInHarness) policyAPI(t *testing.T, tenantID uuid.UUID) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	r.Use(withPrincipal(createUserInTenant(t, context.Background(), tenantID), tenantID))
	(&authpolicy.Handler{Service: h.policy}).Mount(r)
	return r
}

func getPolicy(t *testing.T, api http.Handler, tenantID uuid.UUID) map[string]any {
	t.Helper()
	got := serve(t, api, http.MethodGet, "/tenants/"+tenantID.String()+"/auth-policy", "", nil)
	if got.status != http.StatusOK {
		t.Fatalf("GET auth-policy = %d %v", got.status, got.body)
	}
	return got.body
}

// putLockout saves the tenant's policy with the given lockout fields, the way
// the console does: read the whole policy, change a slice, write it back.
func putLockout(t *testing.T, api http.Handler, tenantID uuid.UUID, lockout map[string]any) apiReply {
	t.Helper()
	p := getPolicy(t, api, tenantID)
	for k, v := range lockout {
		p[k] = v
	}
	return serve(t, api, http.MethodPut, "/tenants/"+tenantID.String()+"/auth-policy", "", p)
}

// randomNetwork returns an IPv6 /64 no other test uses, and an address in it.
func randomNetwork() func(host int) string {
	a, b := rand.IntN(0xffff), rand.IntN(0xffff)
	return func(host int) string { return fmt.Sprintf("2001:db8:%x:%x::%x", a, b, host+1) }
}

// randomIPv4 returns a private IPv4 address no other test is likely to use.
func randomIPv4() string {
	return fmt.Sprintf("10.%d.%d.%d", rand.IntN(256), rand.IntN(256), 1+rand.IntN(254))
}

// tenantClient creates an organisation with an OAuth client its hosted login serves.
func tenantClient(t *testing.T, ctx context.Context) (uuid.UUID, string) {
	t.Helper()
	tenantID := createTenant(t, ctx, uniqueSlug("lockout"))
	clientID := uniqueSlug("lockout-client")
	if _, err := testPool.Exec(ctx,
		`INSERT INTO auth.oidc_clients (tenant_id, client_id, name, type) VALUES ($1, $2, 'Lockout app', 'public')`,
		tenantID, clientID); err != nil {
		t.Fatalf("create client: %v", err)
	}
	return tenantID, clientID
}

// ageSignInCounters moves every failure and lock recorded for email d into the
// past, as if d had elapsed.
func ageSignInCounters(t *testing.T, ctx context.Context, email string, d time.Duration) {
	t.Helper()
	for _, table := range []string{"auth.login_attempts", "auth.login_attempts_by_network"} {
		if _, err := testPool.Exec(ctx, `UPDATE `+table+`
			SET first_failed_at = first_failed_at - $2::interval,
			    last_failed_at  = last_failed_at  - $2::interval,
			    locked_until    = locked_until    - $2::interval
			WHERE email = $1`, email, fmt.Sprintf("%d milliseconds", d.Milliseconds())); err != nil {
			t.Fatalf("age %s: %v", table, err)
		}
	}
}

func wantStatus(t *testing.T, step string, got apiReply, status int, code string) {
	t.Helper()
	if got.status != status || got.errorCode() != code {
		t.Fatalf("%s: got %d %q (%v), want %d %q", step, got.status, got.errorCode(), got.body, status, code)
	}
}

// metricValue sums a counter (all label values, or only those matching
// labels) from the registry /metrics serves; -1 when it is not registered.
func metricValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		var total float64
	metrics:
		for _, m := range f.GetMetric() {
			for k, v := range labels {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == k && lp.GetValue() == v {
						found = true
					}
				}
				if !found {
					continue metrics
				}
			}
			total += m.GetCounter().GetValue()
		}
		return total
	}
	return -1
}

// Repeated wrong passwords against one account from one source lock it at the
// threshold the tenant configured, and the lock lifts after the duration the
// tenant configured.
func TestSignInLockout_LocksAtTheTenantThresholdAndReleasesAfterTheTenantDuration(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	h := newSignInHarness(t, testPool)
	tenantID, clientID := tenantClient(t, ctx)
	_, email := userWithPassword(t, ctx, tenantID, lockoutPassword)
	api := h.policyAPI(t, tenantID)

	saved := putLockout(t, api, tenantID, map[string]any{
		"lockout_threshold": 3, "lockout_window_minutes": 10, "lockout_duration_minutes": 2,
	})
	wantStatus(t, "save lockout settings", saved, http.StatusOK, "")

	ip := randomIPv4()
	for i := 1; i <= 3; i++ {
		wantStatus(t, fmt.Sprintf("wrong password %d", i),
			h.hostedSignIn(t, ip, email, "wrong-password", clientID), http.StatusUnauthorized, "auth.invalid_credentials")
	}
	wantStatus(t, "correct password at the threshold",
		h.hostedSignIn(t, ip, email, lockoutPassword, clientID), http.StatusTooManyRequests, "auth.account_locked")

	ageSignInCounters(t, ctx, email, time.Minute)
	wantStatus(t, "correct password one minute into a two-minute lock",
		h.hostedSignIn(t, ip, email, lockoutPassword, clientID), http.StatusTooManyRequests, "auth.account_locked")

	ageSignInCounters(t, ctx, email, time.Minute+time.Second)
	wantStatus(t, "correct password after the two-minute lock",
		h.hostedSignIn(t, ip, email, lockoutPassword, clientID), http.StatusOK, "")
}

// A third party who knows the address cannot lock the owner out: failures from
// the attacker's network lock the account for that network only. Failures from
// many networks together still lock it everywhere, at a looser cap, so a
// distributed attack stays bounded.
func TestSignInLockout_StrangerOnAnotherNetworkCannotLockTheOwnerOut(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	h := newSignInHarness(t, testPool)
	_, email := userWithPassword(t, ctx, uuid.Nil, lockoutPassword)
	attacker, owner := randomNetwork(), randomNetwork()

	for i := 1; i <= 5; i++ {
		wantStatus(t, fmt.Sprintf("attacker wrong password %d", i),
			h.consoleSignIn(t, attacker(0), email, "guess-"+fmt.Sprint(i)), http.StatusUnauthorized, "auth.invalid_credentials")
	}
	wantStatus(t, "attacker after the threshold",
		h.consoleSignIn(t, attacker(0), email, "guess-6"), http.StatusTooManyRequests, "auth.account_locked")
	wantStatus(t, "another address in the attacker's /64 is the same network",
		h.consoleSignIn(t, attacker(7), email, lockoutPassword), http.StatusTooManyRequests, "auth.account_locked")

	wantStatus(t, "owner on an unrelated network",
		h.consoleSignIn(t, owner(0), email, lockoutPassword), http.StatusOK, "")

	t.Run("failures from many networks still lock the account", func(t *testing.T) {
		_, target := userWithPassword(t, ctx, uuid.Nil, lockoutPassword)
		// The account cap is four times the per-network threshold: four
		// networks at the threshold reach it.
		for n := 0; n < 4; n++ {
			network := randomNetwork()
			for i := 1; i <= 5; i++ {
				wantStatus(t, fmt.Sprintf("network %d wrong password %d", n, i),
					h.consoleSignIn(t, network(0), target, "guess"), http.StatusUnauthorized, "auth.invalid_credentials")
			}
		}
		wantStatus(t, "owner once the account cap is reached",
			h.consoleSignIn(t, randomNetwork()(0), target, lockoutPassword), http.StatusTooManyRequests, "auth.account_locked")
	})
}

// A tenant that lowers the threshold and shortens the window sees the new
// values on the very next attempt, with the same running services.
func TestSignInLockout_TenantChangesApplyToTheNextAttempt(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	h := newSignInHarness(t, testPool)
	tenantID, clientID := tenantClient(t, ctx)
	_, email := userWithPassword(t, ctx, tenantID, lockoutPassword)
	api := h.policyAPI(t, tenantID)

	before := randomIPv4()
	for i := 1; i <= 3; i++ {
		wantStatus(t, fmt.Sprintf("default settings, wrong password %d", i),
			h.hostedSignIn(t, before, email, "wrong-password", clientID), http.StatusUnauthorized, "auth.invalid_credentials")
	}
	wantStatus(t, "default settings: three failures do not lock",
		h.hostedSignIn(t, before, email, lockoutPassword, clientID), http.StatusOK, "")

	wantStatus(t, "lower the threshold and shorten the window", putLockout(t, api, tenantID, map[string]any{
		"lockout_threshold": 3, "lockout_window_minutes": 5, "lockout_duration_minutes": 15,
	}), http.StatusOK, "")

	ip := randomIPv4()
	for i := 1; i <= 2; i++ {
		wantStatus(t, fmt.Sprintf("wrong password %d", i),
			h.hostedSignIn(t, ip, email, "wrong-password", clientID), http.StatusUnauthorized, "auth.invalid_credentials")
	}
	// Six minutes later the two failures are outside the five-minute window
	// (they would still count under the default fifteen minutes).
	ageSignInCounters(t, ctx, email, 6*time.Minute)
	for i := 3; i <= 4; i++ {
		wantStatus(t, fmt.Sprintf("wrong password %d", i),
			h.hostedSignIn(t, ip, email, "wrong-password", clientID), http.StatusUnauthorized, "auth.invalid_credentials")
	}
	wantStatus(t, "two failures in the new window do not lock",
		h.hostedSignIn(t, ip, email, lockoutPassword, clientID), http.StatusOK, "")

	for i := 1; i <= 3; i++ {
		wantStatus(t, fmt.Sprintf("again, wrong password %d", i),
			h.hostedSignIn(t, ip, email, "wrong-password", clientID), http.StatusUnauthorized, "auth.invalid_credentials")
	}
	wantStatus(t, "the lowered threshold locks",
		h.hostedSignIn(t, ip, email, lockoutPassword, clientID), http.StatusTooManyRequests, "auth.account_locked")
}

// A threshold, window or duration outside the documented bounds is refused
// with a validation error, and nothing in the stored policy changes.
func TestSignInLockout_OutOfBoundsSettingsAreRefusedAndNothingChanges(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	h := newSignInHarness(t, testPool)
	tenantID := createTenant(t, ctx, uniqueSlug("lockout-bounds"))
	api := h.policyAPI(t, tenantID)

	wantStatus(t, "save valid settings", putLockout(t, api, tenantID, map[string]any{
		"lockout_threshold": 4, "lockout_window_minutes": 20, "lockout_duration_minutes": 30,
	}), http.StatusOK, "")
	stored := getPolicy(t, api, tenantID)

	limits, _ := stored["lockout_limits"].(map[string]any)
	if limits == nil || limits["min"] == nil || limits["max"] == nil || limits["defaults"] == nil {
		t.Fatalf("the policy does not document the bounds: %v", stored)
	}

	for _, tc := range []struct {
		field string
		value any
	}{
		{"lockout_threshold", 2},
		{"lockout_threshold", 1000},
		{"lockout_threshold", -1},
		{"lockout_window_minutes", 0},
		{"lockout_window_minutes", 100000},
		{"lockout_duration_minutes", 0},
		{"lockout_duration_minutes", 100000},
	} {
		t.Run(fmt.Sprintf("%s=%v", tc.field, tc.value), func(t *testing.T) {
			// Change an unrelated setting in the same write: it must not stick either.
			got := putLockout(t, api, tenantID, map[string]any{tc.field: tc.value, "password_min_length": 20})
			wantStatus(t, "out-of-bounds write", got, http.StatusUnprocessableEntity, "validation_failed")
			e, _ := got.body["error"].(map[string]any)
			fields, _ := e["fields"].([]any)
			named := false
			for _, f := range fields {
				if fm, _ := f.(map[string]any); fm["field"] == tc.field {
					named = true
				}
			}
			if !named {
				t.Errorf("the refusal does not name %s: %v", tc.field, got.body)
			}
			after := getPolicy(t, api, tenantID)
			for _, k := range []string{"lockout_threshold", "lockout_window_minutes", "lockout_duration_minutes", "password_min_length"} {
				if fmt.Sprint(after[k]) != fmt.Sprint(stored[k]) {
					t.Errorf("%s changed from %v to %v", k, stored[k], after[k])
				}
			}
		})
	}
}

// One source trying a few passwords against many accounts is throttled once
// it has failed against the configured number of distinct accounts, and the
// throttle reaches security monitoring.
func TestSignInLockout_SprayingSourceIsThrottledAndReported(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	h := newSignInHarness(t, testPool)
	tenantA, clientA := tenantClient(t, ctx)
	tenantB, _ := tenantClient(t, ctx)
	_, realA := userWithPassword(t, ctx, tenantA, lockoutPassword)
	_, realB := userWithPassword(t, ctx, tenantB, lockoutPassword)
	throttlesBefore := metricValue(t, "sign_in_source_throttles_total", nil)

	sprayer := randomNetwork()
	targets := []string{realA, realB}
	for len(targets) < 30 { // the default: 30 distinct accounts
		targets = append(targets, uniqueSlug("nobody")+"@example.com")
	}
	for i, email := range targets {
		// The source rotates addresses inside its /64; it is still one network.
		wantStatus(t, fmt.Sprintf("spray attempt %d", i+1),
			h.hostedSignIn(t, sprayer(i), email, "Summer2026!", clientA), http.StatusUnauthorized, "auth.invalid_credentials")
	}
	wantStatus(t, "the source is throttled, even with a correct password",
		h.hostedSignIn(t, sprayer(99), realA, lockoutPassword, clientA), http.StatusTooManyRequests, "too_many_requests")
	wantStatus(t, "the same account from another network",
		h.hostedSignIn(t, randomNetwork()(0), realA, lockoutPassword, clientA), http.StatusOK, "")

	for _, tenantID := range []uuid.UUID{tenantA, tenantB} {
		var n int
		var counter, distinct string
		if err := testPool.QueryRow(ctx, `
			SELECT COUNT(*), COALESCE(MAX(metadata->>'counter'), ''), COALESCE(MAX(metadata->>'distinct_accounts'), '')
			FROM auth.security_events WHERE tenant_id = $1 AND type = 'password_spraying'`, tenantID).Scan(&n, &counter, &distinct); err != nil {
			t.Fatalf("read security events: %v", err)
		}
		if n != 1 || counter != "source" || distinct != "30" {
			t.Errorf("tenant %s: %d spraying signals (counter %q, distinct accounts %q), want 1 from the source counter with 30",
				tenantID, n, counter, distinct)
		}
	}
	if got := metricValue(t, "sign_in_source_throttles_total", nil); got != throttlesBefore+1 {
		t.Errorf("sign_in_source_throttles_total = %v, want %v", got, throttlesBefore+1)
	}
}

// When the counter store cannot be read or written, sign-in fails closed (the
// recorded decision): the attempt is refused as temporarily unavailable — the
// same answer whatever the password and whether the address has an account —
// and each refusal is counted in a metric.
func TestSignInLockout_CounterStoreUnavailableFailsClosedAndIsCounted(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	// A pool that gives up on a locked table after 100 ms, so a lock held by
	// the test makes the counter store unavailable to the service.
	pool, err := pgxpool.New(ctx, testDSN+"&lock_timeout=100")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	h := newSignInHarness(t, pool)
	_, email := userWithPassword(t, ctx, uuid.Nil, lockoutPassword)
	unknown := uniqueSlug("nobody") + "@example.com"

	unavailable := func(t *testing.T, mode string, stages map[string]float64) {
		t.Helper()
		ip := randomIPv4()
		before := map[string]float64{}
		for stage := range stages {
			before[stage] = metricValue(t, "sign_in_lockout_unavailable_total", map[string]string{"stage": stage})
		}
		hold, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := hold.Exec(ctx, `LOCK TABLE auth.login_attempts IN `+mode+` MODE`); err != nil {
			t.Fatalf("lock counter store: %v", err)
		}
		correct := h.consoleSignIn(t, ip, email, lockoutPassword)
		wrong := h.consoleSignIn(t, ip, email, "wrong-password")
		nobody := h.consoleSignIn(t, ip, unknown, "wrong-password")
		if err := hold.Rollback(ctx); err != nil {
			t.Fatalf("release lock: %v", err)
		}
		wantStatus(t, "correct password", correct, http.StatusServiceUnavailable, "auth.sign_in_unavailable")
		if retry, _ := correct.body["error"].(map[string]any)["retryable"].(bool); !retry {
			t.Errorf("the refusal is not marked retryable: %v", correct.body)
		}
		if wrong.comparable() != correct.comparable() || nobody.comparable() != correct.comparable() {
			t.Errorf("answers differ:\n correct  %s\n wrong    %s\n no account %s",
				correct.comparable(), wrong.comparable(), nobody.comparable())
		}
		for stage, n := range stages {
			if got := metricValue(t, "sign_in_lockout_unavailable_total", map[string]string{"stage": stage}); got != before[stage]+n {
				t.Errorf("sign_in_lockout_unavailable_total{stage=%q} = %v, want %v", stage, got, before[stage]+n)
			}
		}
		wantStatus(t, "once the store is back", h.consoleSignIn(t, ip, email, lockoutPassword), http.StatusOK, "")
	}
	// No read: the lock state cannot be checked (all three attempts).
	t.Run("unreadable", func(t *testing.T) {
		unavailable(t, "ACCESS EXCLUSIVE", map[string]float64{"check": 3})
	})
	// Reads work, writes do not: the two failures cannot be recorded and the
	// success cannot be cleared.
	t.Run("unwritable", func(t *testing.T) {
		unavailable(t, "EXCLUSIVE", map[string]float64{"record": 2, "clear": 1})
	})
}

// An account that crosses the threshold raises exactly one account-locked
// signal, carrying why it locked and what it was counting: the account, the
// source network and which counter tripped. Attempts refused while it is
// locked raise nothing more; the next lock raises the next signal.
func TestSignInLockout_LockRaisesExactlyOneSignalWithItsReason(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	h := newSignInHarness(t, testPool)
	tenantID, clientID := tenantClient(t, ctx)
	userID, email := userWithPassword(t, ctx, tenantID, lockoutPassword)
	ip := randomIPv4()

	for i := 1; i <= 9; i++ {
		h.hostedSignIn(t, ip, email, "wrong-password", clientID)
	}
	type signal struct{ counter, network, reason, ip string }
	read := func() []signal {
		rows, err := testPool.Query(ctx, `
			SELECT COALESCE(metadata->>'counter', ''), COALESCE(metadata->>'network', ''),
			       COALESCE(metadata->>'reason', ''), COALESCE(host(ip), '')
			FROM auth.security_events
			WHERE tenant_id = $1 AND user_id = $2 AND type = 'credential_stuffing'
			ORDER BY created_at`, tenantID, userID)
		if err != nil {
			t.Fatalf("read signals: %v", err)
		}
		defer rows.Close()
		var out []signal
		for rows.Next() {
			var s signal
			if err := rows.Scan(&s.counter, &s.network, &s.reason, &s.ip); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out = append(out, s)
		}
		return out
	}
	got := read()
	if len(got) != 1 {
		t.Fatalf("%d account-locked signals after one lock, want 1: %+v", len(got), got)
	}
	if got[0].counter != "account_network" || got[0].network != ip || got[0].ip != ip || got[0].reason == "" {
		t.Errorf("signal = %+v, want the account+network counter, network %s and a reason", got[0], ip)
	}
	// The administrator's anomaly list carries the same context.
	listed, err := threat.NewService(testPool).List(ctx, tenantID, 50)
	if err != nil {
		t.Fatalf("list anomalies: %v", err)
	}
	if len(listed) != 1 || listed[0].Metadata["counter"] != "account_network" || listed[0].Metadata["reason"] == "" {
		t.Errorf("anomaly list = %+v, want the one lock with its counter and reason", listed)
	}

	ageSignInCounters(t, ctx, email, 16*time.Minute)
	for i := 1; i <= 5; i++ {
		h.hostedSignIn(t, ip, email, "wrong-password", clientID)
	}
	if got := read(); len(got) != 2 {
		t.Errorf("%d account-locked signals after a second lock, want 2", len(got))
	}
}

// Failures against an address with no account answer exactly like a wrong
// password on a real account — the same status and body on every attempt,
// including the one that locks — and take as long.
func TestSignInLockout_UnknownAddressIsIndistinguishableFromWrongPassword(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	h := newSignInHarness(t, testPool)

	for _, route := range []struct {
		name   string
		signIn func(t *testing.T, ip, email, pw string) apiReply
	}{
		{"console", h.consoleSignIn},
		{"hosted", func(t *testing.T, ip, email, pw string) apiReply {
			return h.hostedSignIn(t, ip, email, pw, "")
		}},
	} {
		t.Run(route.name, func(t *testing.T) {
			_, known := userWithPassword(t, ctx, uuid.Nil, lockoutPassword)
			unknown := uniqueSlug("nobody") + "@example.com"
			ip := randomIPv4()
			for i := 1; i <= 7; i++ {
				a := route.signIn(t, ip, known, "wrong-password")
				b := route.signIn(t, ip, unknown, "wrong-password")
				if a.comparable() != b.comparable() {
					t.Fatalf("attempt %d differs:\n real account %s\n no account   %s", i, a.comparable(), b.comparable())
				}
			}
		})
	}

	t.Run("timing", func(t *testing.T) {
		knownAccounts := make([]string, 3)
		for i := range knownAccounts {
			_, knownAccounts[i] = userWithPassword(t, ctx, uuid.Nil, lockoutPassword)
		}
		var known, unknown []time.Duration
		for i := 0; i < 9; i++ { // three below-threshold failures per real account
			ip := randomIPv4()
			start := time.Now()
			h.consoleSignIn(t, ip, knownAccounts[i%3], "wrong-password")
			known = append(known, time.Since(start))
			start = time.Now()
			h.consoleSignIn(t, ip, uniqueSlug("nobody")+"@example.com", "wrong-password")
			unknown = append(unknown, time.Since(start))
		}
		k, u := median(known), median(unknown)
		t.Logf("median time: real account %v, no account %v", k, u)
		if u < k/2 || u > k*2 {
			t.Errorf("median time: no account %v, real account %v — the difference reveals which addresses have an account", u, k)
		}
	})
}

func median(ds []time.Duration) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}
