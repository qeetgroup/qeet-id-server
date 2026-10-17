//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// A step-up proves something about the session that earned it: a second
// factor met in one session never unlocks sensitive actions in another, it
// ends with its session, it lasts as long as the organisation says and counts
// only when met by a factor type the organisation accepts, and a changed
// password or an administrative factor reset clears it.

// openSession inserts a live session of userID's in tenantID.
func openSession(t *testing.T, ctx context.Context, userID, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO auth.sessions (user_id, tenant_id) VALUES ($1, $2) RETURNING id`, userID, tenantID).Scan(&id); err != nil {
		t.Fatalf("open session: %v", err)
	}
	return id
}

// withSessionPrincipal is withPrincipal for a principal signed in through one
// of its own sessions, as the bearer-token middleware builds it.
func withSessionPrincipal(userID, tenantID, sessionID uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uid, tid, sid := userID, tenantID, sessionID
			p := &httpx.Principal{UserID: &uid, TenantID: &tid, SessionID: &sid, ActorType: "user", Subject: uid.String()}
			next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), p)))
		})
	}
}

func newStepUpMFA(t *testing.T) *mfa.Service {
	t.Helper()
	svc := mfa.NewService(testPool, "qeet-test", notifier.LogSender{}, "")
	svc.SetCipher(testEnvelope(t))
	return svc
}

func recordStepUp(t *testing.T, ctx context.Context, svc *mfa.Service, userID, sessionID uuid.UUID, method string) {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := svc.RecordVerification(ctx, tx, userID, sessionID, method); err != nil {
		t.Fatalf("record step-up: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func stepUpMet(t *testing.T, ctx context.Context, svc *mfa.Service, userID, sessionID uuid.UUID) bool {
	t.Helper()
	st, err := svc.StepUpState(ctx, userID, &sessionID)
	if err != nil {
		t.Fatalf("step-up state: %v", err)
	}
	return st.Met
}

func stepUpRows(t *testing.T, ctx context.Context, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_verifications WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestStepUpBelongsToItsSession: a factor met in one session steps that
// session up and no other of the person's; it cannot be recorded against
// someone else's session; and it ends when its session is revoked.
func TestStepUpBelongsToItsSession(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	tenantID := createTenant(t, ctx, uniqueSlug("stepup"))
	userID := createUserInTenant(t, ctx, tenantID)
	laptop := openSession(t, ctx, userID, tenantID)
	sharedPC := openSession(t, ctx, userID, tenantID)

	if stepUpMet(t, ctx, svc, userID, laptop) {
		t.Fatal("a session that met no factor must not read as stepped up")
	}
	recordStepUp(t, ctx, svc, userID, laptop, "totp")
	if !stepUpMet(t, ctx, svc, userID, laptop) {
		t.Fatal("the session that met the factor must be stepped up")
	}
	if stepUpMet(t, ctx, svc, userID, sharedPC) {
		t.Fatal("a step-up in one session must not unlock another session of the same person")
	}

	// Nobody can be stepped up through a session that is not theirs.
	other := createUserInTenant(t, ctx, tenantID)
	recordStepUp(t, ctx, svc, other, sharedPC, "totp")
	if n := stepUpRows(t, ctx, other); n != 0 {
		t.Fatalf("a step-up recorded against someone else's session was written (%d rows)", n)
	}

	if _, err := testPool.Exec(ctx, `UPDATE auth.sessions SET revoked_at = NOW() WHERE id = $1`, laptop); err != nil {
		t.Fatal(err)
	}
	if stepUpMet(t, ctx, svc, userID, laptop) {
		t.Fatal("a revoked session's step-up must no longer count")
	}
	recordStepUp(t, ctx, svc, userID, laptop, "totp")
	if stepUpMet(t, ctx, svc, userID, laptop) {
		t.Fatal("a revoked session must not be stepped up again")
	}
}

// TestStepUpFollowsTheOrganisation: the organisation's window and accepted
// factor types decide whether a session's step-up counts, and a change to them
// applies at once.
func TestStepUpFollowsTheOrganisation(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	tenantID := createTenant(t, ctx, uniqueSlug("stepup-org"))
	userID := createUserInTenant(t, ctx, tenantID)
	sess := openSession(t, ctx, userID, tenantID)

	st, err := svc.StepUpState(ctx, userID, &sess)
	if err != nil {
		t.Fatal(err)
	}
	if st.Window != 5*time.Minute || st.Methods != nil {
		t.Fatalf("an organisation that set nothing: window %v methods %v, want 5m and every factor", st.Window, st.Methods)
	}

	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.security_policies (tenant_id, step_up_window, step_up_methods)
		VALUES ($1, INTERVAL '1 minute', ARRAY['webauthn'])`, tenantID); err != nil {
		t.Fatal(err)
	}
	recordStepUp(t, ctx, svc, userID, sess, "recovery_code")
	st, _ = svc.StepUpState(ctx, userID, &sess)
	if st.Met || st.Method != "recovery_code" {
		t.Fatalf("a step-up by a factor the organisation does not count must not be met: %+v", st)
	}
	if len(st.Methods) != 1 || st.Methods[0] != "webauthn" || st.Window != time.Minute {
		t.Fatalf("the organisation's settings were not reported: %+v", st)
	}
	recordStepUp(t, ctx, svc, userID, sess, "webauthn")
	if !stepUpMet(t, ctx, svc, userID, sess) {
		t.Fatal("a step-up by a counted factor inside the window must be met")
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.mfa_verifications SET verified_at = NOW() - INTERVAL '2 minutes' WHERE session_id = $1`, sess); err != nil {
		t.Fatal(err)
	}
	if stepUpMet(t, ctx, svc, userID, sess) {
		t.Fatal("a step-up older than the organisation's window must not be met")
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE tenant.security_policies SET step_up_window = INTERVAL '10 minutes' WHERE tenant_id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}
	if !stepUpMet(t, ctx, svc, userID, sess) {
		t.Fatal("lengthening the window must apply at once, without a release")
	}
}

// TestStepUpClearedByPasswordAndReset: changing a password or an
// administrator resetting the person's factors clears their step-ups in every
// session.
func TestStepUpClearedByPasswordAndReset(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	tenantID := createTenant(t, ctx, uniqueSlug("stepup-clear"))
	userID := createUserInTenant(t, ctx, tenantID)
	a, b := openSession(t, ctx, userID, tenantID), openSession(t, ctx, userID, tenantID)
	if _, err := testPool.Exec(ctx,
		`INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, 'old-hash')`, userID); err != nil {
		t.Fatal(err)
	}

	recordStepUp(t, ctx, svc, userID, a, "totp")
	recordStepUp(t, ctx, svc, userID, b, "otp")
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.password_credentials SET password_hash = 'new-hash' WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if n := stepUpRows(t, ctx, userID); n != 0 {
		t.Fatalf("a changed password must clear every step-up, %d left", n)
	}

	recordStepUp(t, ctx, svc, userID, a, "totp")
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResetForUser(ctx, tx, userID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if stepUpMet(t, ctx, svc, userID, a) {
		t.Fatal("an administrative factor reset must clear the person's step-ups")
	}
}

// TestStepUpGate: a gated request from a session that has not stepped up is
// refused with step_up_required and the organisation's accepted factors, and
// the refusal is audited; once that session steps up the request passes, and
// another session of the same person is still refused.
func TestStepUpGate(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	tenantID := createTenant(t, ctx, uniqueSlug("stepup-gate"))
	userID := createUserInTenant(t, ctx, tenantID)
	sess, otherSess := openSession(t, ctx, userID, tenantID), openSession(t, ctx, userID, tenantID)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.security_policies (tenant_id, step_up_methods) VALUES ($1, ARRAY['totp', 'webauthn'])`,
		tenantID); err != nil {
		t.Fatal(err)
	}

	hit := false
	gate := mfa.RequireRecentMFA(svc)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	serve := func(s uuid.UUID) *httptest.ResponseRecorder {
		hit = false
		rr := httptest.NewRecorder()
		withSessionPrincipal(userID, tenantID, s)(gate).ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/v1/mfa/totp", nil))
		return rr
	}

	rr := serve(sess)
	if hit || rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "step_up_required") {
		t.Fatalf("no step-up: hit=%v %d %s", hit, rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"allowed_methods":["totp","webauthn"]`) {
		t.Errorf("the refusal should name the factors that count: %s", rr.Body.String())
	}
	var audited int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = 'mfa.step_up_required'`, userID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Errorf("the refusal must be audited once, found %d", audited)
	}

	recordStepUp(t, ctx, svc, userID, sess, "totp")
	if rr := serve(sess); !hit || rr.Code != http.StatusOK {
		t.Fatalf("after its step-up the session must pass: hit=%v %d", hit, rr.Code)
	}
	if rr := serve(otherSess); hit || rr.Code != http.StatusForbidden {
		t.Fatalf("another session of the same person must still be refused: hit=%v %d", hit, rr.Code)
	}
}

// TestStepUpThroughTheRoutes drives the MFA routes: confirming an
// authenticator app steps up the session that did it, so the gated routes work
// there at once; another session is refused until it verifies a code itself,
// and each completed step-up is audited.
func TestStepUpThroughTheRoutes(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	tenantID := createTenant(t, ctx, uniqueSlug("stepup-routes"))
	userID := createUserInTenant(t, ctx, tenantID)
	first, second := openSession(t, ctx, userID, tenantID), openSession(t, ctx, userID, tenantID)

	serverFor := func(sess uuid.UUID) *httptest.Server {
		r := chi.NewRouter()
		r.Group(func(r chi.Router) {
			r.Use(withSessionPrincipal(userID, tenantID, sess))
			(&mfa.Handler{Service: svc}).Mount(r)
		})
		srv := httptest.NewServer(r)
		t.Cleanup(srv.Close)
		return srv
	}
	do := func(srv *httptest.Server, method, path string, body any) (int, []byte) {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}
	one, two := serverFor(first), serverFor(second)

	code, body := do(one, http.MethodPost, "/mfa/totp/enroll/start", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("enroll start: %d %s", code, body)
	}
	var enr mfa.Enrollment
	_ = json.Unmarshal(body, &enr)
	if code, body := do(one, http.MethodPost, "/mfa/totp/enroll/confirm", map[string]string{"code": totpCodeAtStep(t, enr.Secret, 0)}); code != http.StatusOK {
		t.Fatalf("enroll confirm: %d %s", code, body)
	}
	if code, _ := do(one, http.MethodPost, "/mfa/recovery-codes/regenerate", map[string]any{}); code != http.StatusOK {
		t.Fatalf("regenerate in the session that just enrolled = %d, want 200", code)
	}
	if code, _ := do(two, http.MethodPost, "/mfa/recovery-codes/regenerate", map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("regenerate in another session = %d, want 403", code)
	}
	if code, body := do(two, http.MethodPost, "/mfa/totp/verify", map[string]string{"code": totpCodeAtStep(t, enr.Secret, 1)}); code != http.StatusOK {
		t.Fatalf("verify in the second session: %d %s", code, body)
	}
	if code, _ := do(two, http.MethodPost, "/mfa/recovery-codes/regenerate", map[string]any{}); code != http.StatusOK {
		t.Fatalf("regenerate after the second session stepped up = %d, want 200", code)
	}
	var audited int
	if err := testPool.QueryRow(ctx, `
		SELECT count(DISTINCT metadata->>'session_id') FROM audit.events
		WHERE actor_user_id = $1 AND action = 'mfa.step_up_verified'`, userID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 2 {
		t.Errorf("each session's completed step-up must be audited, found %d sessions", audited)
	}
}

// TestSignInStepsUpOnlyItsOwnSession: a sign-in that meets its second factor
// opens a session that is stepped up, and the person's sessions that already
// existed gain nothing from it.
func TestSignInStepsUpOnlyItsOwnSession(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	me, email := f.member(t, ctx)
	secret := f.holdTOTP(t, ctx, me)
	existing := openSession(t, ctx, me, f.tenantID)

	c := f.signIn(t, email)
	if !c.MFARequired {
		t.Fatalf("an account with an authenticator app must be challenged: %+v", c)
	}
	rr, _ := f.complete(map[string]any{"mfa_token": c.MFAToken, "code": totpCodeAtStep(t, secret, 1)})
	if rr.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rr.Code, rr.Body.String())
	}
	var pair struct {
		SessionID uuid.UUID `json:"session_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &pair); err != nil || pair.SessionID == uuid.Nil {
		t.Fatalf("no session in %s", rr.Body.String())
	}
	if !stepUpMet(t, ctx, f.mfa, me, pair.SessionID) {
		t.Fatal("the session a sign-in with a second factor opens must start stepped up")
	}
	if stepUpMet(t, ctx, f.mfa, me, existing) {
		t.Fatal("signing in with a factor must not step up the person's other sessions")
	}
}
