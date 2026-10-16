//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/policy"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// A session ends by itself: at its maximum age however active it is, and once
// it goes longer than its idle timeout without being renewed. The bounds come
// from the organisation's security policy when the session opens. The server
// refuses a renewal past either bound whatever the client was told, records
// the ending as an expiry, and stops listing the session as active.

type lifetimeFixture struct {
	*signalFixture
	router http.Handler
	admin  uuid.UUID
	issuer *tokens.Issuer
}

func newLifetimeFixture(t *testing.T, ctx context.Context) *lifetimeFixture {
	t.Helper()
	f := &lifetimeFixture{signalFixture: newSignalFixture(t, ctx)}
	issuer := mustIssuer() // the same keys as the router verifies with
	f.issuer = issuer
	f.auth = auth.NewService(testPool, user.NewRepository(testPool), issuer)
	f.auth.SetSessionSignals(f.sig)
	f.admin = createUserInTenant(t, ctx, f.tenantID)
	authH := &auth.Handler{Service: f.auth, Validate: validator.New()}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		authH.Mount(r)
		r.Group(func(r chi.Router) {
			r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: issuer}))
			authH.MountAuthed(r)
		})
		r.Group(func(r chi.Router) {
			r.Use(withPrincipal(f.admin, f.tenantID))
			(&policy.Handler{Repo: policy.NewRepository(testPool)}).Mount(r)
		})
	})
	f.router = r
	return f
}

func (f *lifetimeFixture) do(method, path, token string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

func (f *lifetimeFixture) refresh(refreshToken string) *httptest.ResponseRecorder {
	return f.do(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refresh_token": refreshToken})
}

// setPolicy saves the organisation's session bounds through the policy API.
func (f *lifetimeFixture) setPolicy(t *testing.T, maxAge, idle string) {
	t.Helper()
	rr := f.do(http.MethodPut, "/v1/tenants/"+f.tenantID.String()+"/policy", "", map[string]any{
		"password_min_length": 8, "password_complexity": "standard", "mfa_enforcement": "optional",
		"session_max_age": maxAge, "session_idle_timeout": idle,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("save policy: %d %s", rr.Code, rr.Body.String())
	}
}

func (f *lifetimeFixture) signIn(t *testing.T, ctx context.Context, userID uuid.UUID) *auth.TokenPair {
	t.Helper()
	pair, err := f.auth.IssuePair(ctx, userID, f.tenantID, "198.51.100.7", "device", "password")
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	return pair
}

type sessionBounds struct {
	expiresAt time.Time
	idle      time.Duration
	lastSeen  time.Time
	revoked   bool
}

func boundsOf(t *testing.T, ctx context.Context, sessionID uuid.UUID) sessionBounds {
	t.Helper()
	var b sessionBounds
	var idleSeconds int64
	if err := testPool.QueryRow(ctx, `
		SELECT expires_at, EXTRACT(EPOCH FROM idle_timeout)::bigint, last_seen_at, revoked_at IS NOT NULL
		FROM auth.sessions WHERE id = $1`, sessionID).Scan(&b.expiresAt, &idleSeconds, &b.lastSeen, &b.revoked); err != nil {
		t.Fatalf("read session %s: %v", sessionID, err)
	}
	b.idle = time.Duration(idleSeconds) * time.Second
	return b
}

func ageSession(t *testing.T, ctx context.Context, sessionID uuid.UUID, set string, args ...any) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `UPDATE auth.sessions SET `+set+` WHERE id = $1`, append([]any{sessionID}, args...)...); err != nil {
		t.Fatalf("age session: %v", err)
	}
}

func near(got, want time.Time) bool {
	d := got.Sub(want)
	return d > -time.Minute && d < time.Minute
}

func expiryAudits(t *testing.T, ctx context.Context, sessionID uuid.UUID) []string {
	t.Helper()
	rows, err := testPool.Query(ctx, `
		SELECT metadata->>'reason' FROM audit.events
		WHERE action = 'auth.session_expired' AND resource_id = $1`, sessionID)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var reason string
		if err := rows.Scan(&reason); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		out = append(out, reason)
	}
	return out
}

func listedStatus(t *testing.T, f *lifetimeFixture, token string) map[string]string {
	t.Helper()
	rr := f.do(http.MethodGet, "/v1/auth/sessions", token, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list sessions: %d %s", rr.Code, rr.Body.String())
	}
	var page struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	out := map[string]string{}
	for _, it := range page.Items {
		out[it.ID] = it.Status
	}
	return out
}

// TestSessionIdleTimeout covers: a session idle beyond its idle timeout is
// refused and must sign in again, however often the client tries; the ending
// is recorded once, as an idle expiry, and announced as expired; it is listed
// as expired, not active; and a renewal inside the timeout counts the timeout
// from that renewal.
func TestSessionIdleTimeout(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newLifetimeFixture(t, ctx)
	f.setPolicy(t, "720h", "1h")
	me := createUserInTenant(t, ctx, f.tenantID)

	t.Run("renewing inside the timeout counts it from the renewal", func(t *testing.T) {
		pair := f.signIn(t, ctx, me)
		if !near(pair.IdleExpiresAt, time.Now().Add(time.Hour)) || !near(pair.SessionExpiresAt, time.Now().Add(720*time.Hour)) {
			t.Fatalf("sign-in reports idle end %v and session end %v, want about 1h and 720h from now", pair.IdleExpiresAt, pair.SessionExpiresAt)
		}
		ageSession(t, ctx, pair.SessionID, "last_seen_at = NOW() - INTERVAL '50 minutes'")
		rr := f.refresh(pair.RefreshToken)
		if rr.Code != http.StatusOK {
			t.Fatalf("renewal inside the idle timeout refused: %d %s", rr.Code, rr.Body.String())
		}
		var renewed auth.TokenPair
		_ = json.Unmarshal(rr.Body.Bytes(), &renewed)
		if !near(renewed.IdleExpiresAt, time.Now().Add(time.Hour)) {
			t.Errorf("renewal reports idle end %v, want about 1h from now", renewed.IdleExpiresAt)
		}
		if b := boundsOf(t, ctx, pair.SessionID); !near(b.lastSeen, time.Now()) {
			t.Errorf("last use %v was not moved to the renewal", b.lastSeen)
		}
	})

	t.Run("idle beyond the timeout ends the session", func(t *testing.T) {
		keep := f.signIn(t, ctx, me)
		pair := f.signIn(t, ctx, me)
		ageSession(t, ctx, pair.SessionID, "last_seen_at = NOW() - INTERVAL '61 minutes'")
		for i := 0; i < 2; i++ {
			rr := f.refresh(pair.RefreshToken)
			if rr.Code != http.StatusUnauthorized || errorCode(t, rr) != errs.CodeAuthSessionTimedOut {
				t.Fatalf("renewal %d of an idle session: %d %s, want 401 %s", i+1, rr.Code, rr.Body.String(), errs.CodeAuthSessionTimedOut)
			}
		}
		if got := expiryAudits(t, ctx, pair.SessionID); len(got) != 1 || got[0] != "idle" {
			t.Errorf("expiry audit reasons = %v, want one \"idle\"", got)
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonExpired, []*auth.TokenPair{pair})
		status := listedStatus(t, f, keep.AccessToken)
		if status[pair.SessionID.String()] != "expired" || status[keep.SessionID.String()] != "active" {
			t.Errorf("listed statuses = %v, want the idle session expired and the other active", status)
		}
	})
}

// TestSessionMaximumAge covers: a session at its maximum age ends however
// recently it was used, recorded as a max-age expiry; and a renewal's refresh
// token never outlives the session.
func TestSessionMaximumAge(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newLifetimeFixture(t, ctx)
	f.setPolicy(t, "2h", "1h")
	me := createUserInTenant(t, ctx, f.tenantID)

	pair := f.signIn(t, ctx, me)
	var refreshExp time.Time
	if err := testPool.QueryRow(ctx, `SELECT max(expires_at) FROM auth.refresh_tokens WHERE session_id = $1`, pair.SessionID).Scan(&refreshExp); err != nil {
		t.Fatalf("read refresh token: %v", err)
	}
	if refreshExp.After(pair.SessionExpiresAt) {
		t.Errorf("refresh token expires %v, after the session ends %v", refreshExp, pair.SessionExpiresAt)
	}

	// A renewal shortly before the end: the access token ends with the session.
	ageSession(t, ctx, pair.SessionID, "expires_at = NOW() + INTERVAL '3 minutes'")
	near := f.refresh(pair.RefreshToken)
	if near.Code != http.StatusOK {
		t.Fatalf("renewal before the end: %d %s", near.Code, near.Body.String())
	}
	var renewed auth.TokenPair
	_ = json.Unmarshal(near.Body.Bytes(), &renewed)
	ends := boundsOf(t, ctx, pair.SessionID).expiresAt
	if renewed.ExpiresAt.After(ends) || !renewed.SessionExpiresAt.Equal(ends) {
		t.Errorf("access token expires %v, after its session ends %v", renewed.ExpiresAt, ends)
	}
	if claims, err := f.issuer.VerifyAccess(renewed.AccessToken); err != nil || claims.ExpiresAt.Time.After(ends.Add(time.Second)) {
		t.Errorf("access token exp claim outlives the session (%v): %v", ends, err)
	}
	pair.RefreshToken = renewed.RefreshToken

	ageSession(t, ctx, pair.SessionID, "expires_at = NOW() - INTERVAL '1 second', last_seen_at = NOW()")
	rr := f.refresh(pair.RefreshToken)
	if rr.Code != http.StatusUnauthorized || errorCode(t, rr) != errs.CodeAuthSessionTimedOut {
		t.Fatalf("renewal at the maximum age: %d %s, want 401 %s", rr.Code, rr.Body.String(), errs.CodeAuthSessionTimedOut)
	}
	if got := expiryAudits(t, ctx, pair.SessionID); len(got) != 1 || got[0] != "max_age" {
		t.Errorf("expiry audit reasons = %v, want one \"max_age\"", got)
	}
}

// TestSessionBoundsFollowThePolicyForNewSessions covers: the organisation's
// saved bounds apply to sessions opened afterwards and not to ones already
// open; the policy reads back as duration strings; out-of-range values are
// refused field by field.
func TestSessionBoundsFollowThePolicyForNewSessions(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newLifetimeFixture(t, ctx)
	me := createUserInTenant(t, ctx, f.tenantID)

	before := f.signIn(t, ctx, me)
	f.setPolicy(t, "2h", "30m")
	after := f.signIn(t, ctx, me)

	if b := boundsOf(t, ctx, before.SessionID); !near(b.expiresAt, time.Now().Add(30*24*time.Hour)) || b.idle != 24*time.Hour {
		t.Errorf("session opened before the change: ends %v idle %v, want the platform defaults kept", b.expiresAt, b.idle)
	}
	if b := boundsOf(t, ctx, after.SessionID); !near(b.expiresAt, time.Now().Add(2*time.Hour)) || b.idle != 30*time.Minute {
		t.Errorf("session opened after the change: ends %v idle %v, want 2h and 30m", b.expiresAt, b.idle)
	}

	rr := f.do(http.MethodGet, "/v1/tenants/"+f.tenantID.String()+"/policy", "", nil)
	var got map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["session_max_age"] != "2h" || got["session_idle_timeout"] != "30m" {
		t.Errorf("policy reads back %v / %v, want \"2h\" / \"30m\"", got["session_max_age"], got["session_idle_timeout"])
	}

	for name, body := range map[string]map[string]any{
		"session_idle_timeout": {"session_max_age": "2h", "session_idle_timeout": "3h", "password_min_length": 8, "password_complexity": "standard", "mfa_enforcement": "optional"},
		"session_max_age":      {"session_max_age": "30m", "password_min_length": 8, "password_complexity": "standard", "mfa_enforcement": "optional"},
		"password_complexity":  {"password_min_length": 8, "password_complexity": "basic", "mfa_enforcement": "optional"},
		"mfa_enforcement":      {"password_min_length": 8, "password_complexity": "standard", "mfa_enforcement": "disabled"},
	} {
		rr := f.do(http.MethodPut, "/v1/tenants/"+f.tenantID.String()+"/policy", "", body)
		var e struct {
			Error struct {
				Code   string `json:"code"`
				Fields []struct {
					Field string `json:"field"`
				} `json:"fields"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &e)
		if rr.Code < 400 || rr.Code >= 500 || len(e.Error.Fields) != 1 || e.Error.Fields[0].Field != name {
			t.Errorf("invalid %s: %d %s, want a refusal naming that field", name, rr.Code, rr.Body.String())
		}
	}
}

// TestSwitchingOrganisationKeepsTheSessionEnd covers: the session a switch
// opens ends no later than the sign-in it continues; and a session past its
// bounds cannot be switched from.
func TestSwitchingOrganisationKeepsTheSessionEnd(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newLifetimeFixture(t, ctx)
	me := createUserInTenant(t, ctx, f.tenantID)
	addTenantMembership(t, ctx, me, f.tenantID)
	other := createTenant(t, ctx, uniqueSlug("lifetime-other"))
	addTenantMembership(t, ctx, me, other)

	pair := f.signIn(t, ctx, me)
	ends := time.Now().Add(90 * time.Minute).UTC().Truncate(time.Second)
	ageSession(t, ctx, pair.SessionID, "expires_at = $2", ends)
	switched, err := f.auth.SwitchTenant(ctx, auth.SwitchTenantInput{UserID: me, FromSessionID: pair.SessionID, TenantID: other})
	if err != nil {
		t.Fatalf("switch: %v", err)
	}
	if b := boundsOf(t, ctx, switched.SessionID); b.expiresAt.After(ends) || !switched.SessionExpiresAt.Equal(b.expiresAt) {
		t.Errorf("switched session ends %v (reported %v), want no later than %v", b.expiresAt, switched.SessionExpiresAt, ends)
	}

	idle := f.signIn(t, ctx, me)
	ageSession(t, ctx, idle.SessionID, "last_seen_at = NOW() - INTERVAL '25 hours'")
	if _, err := f.auth.SwitchTenant(ctx, auth.SwitchTenantInput{UserID: me, FromSessionID: idle.SessionID, TenantID: other}); !errors.Is(err, errs.ErrUnauthorized) {
		t.Fatalf("switch from an idle session: %v, want refused", err)
	}
}

// TestExpiredSessionsAreNotEndedAgain: signing out everywhere ends the live
// sessions only; one already past its idle timeout stays an expired session
// and is not counted or announced as revoked.
func TestExpiredSessionsAreNotEndedAgain(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newLifetimeFixture(t, ctx)
	me := createUserInTenant(t, ctx, f.tenantID)
	live := f.signIn(t, ctx, me)
	idle := f.signIn(t, ctx, me)
	ageSession(t, ctx, idle.SessionID, "last_seen_at = NOW() - INTERVAL '25 hours'")

	ended, err := f.auth.RevokeAllSessions(ctx, auth.RevokeAllSessionsInput{UserID: me, SessionID: live.SessionID})
	if err != nil {
		t.Fatalf("sign out everywhere: %v", err)
	}
	if ended.Sessions != 1 {
		t.Errorf("signed out %d sessions, want only the live one", ended.Sessions)
	}
	if boundsOf(t, ctx, idle.SessionID).revoked {
		t.Error("the expired session was revoked again")
	}
	got := f.announced(t, ctx, f.tenantID, me)
	if _, ok := got[idle.SessionID.String()]; ok {
		t.Errorf("the expired session was announced: %v", got)
	}
}

// TestApplicationGrantEndsAtTheMaximumAge covers: an application's grant ends
// at the organisation's maximum session age however often it is renewed —
// each renewal keeps that end and no token outlives it.
func TestApplicationGrantEndsAtTheMaximumAge(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newAppTokenFixture(t, ctx)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.security_policies (tenant_id, session_max_age) VALUES ($1, INTERVAL '2 hours')`, f.tenantID); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	me := createUserInTenant(t, ctx, f.tenantID)
	addTenantMembership(t, ctx, me, f.tenantID)

	issued := f.appToken(t, ctx, me, "openid", "email")
	var grantEnds, tokenEnds time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT grant_expires_at, expires_at FROM auth.oidc_refresh_tokens
		WHERE client_id = $1 AND user_id = $2`, f.clientID, me).Scan(&grantEnds, &tokenEnds); err != nil {
		t.Fatalf("read grant: %v", err)
	}
	if !near(grantEnds, time.Now().Add(2*time.Hour)) || tokenEnds.After(grantEnds) {
		t.Fatalf("grant ends %v, token %v; want the grant 2h from now and the token no later", grantEnds, tokenEnds)
	}

	renewed, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, issued.RefreshToken, "")
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	var carried time.Time
	if err := testPool.QueryRow(ctx, `
		SELECT grant_expires_at FROM auth.oidc_refresh_tokens
		WHERE client_id = $1 AND user_id = $2 AND used_at IS NULL`, f.clientID, me).Scan(&carried); err != nil {
		t.Fatalf("read renewed grant: %v", err)
	}
	if !carried.Equal(grantEnds) {
		t.Errorf("renewal moved the grant's end from %v to %v", grantEnds, carried)
	}

	if _, err := testPool.Exec(ctx, `
		UPDATE auth.oidc_refresh_tokens SET grant_expires_at = NOW() - INTERVAL '1 second', expires_at = NOW() - INTERVAL '1 second'
		WHERE client_id = $1 AND user_id = $2`, f.clientID, me); err != nil {
		t.Fatalf("end grant: %v", err)
	}
	if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, renewed.RefreshToken, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenExpired) {
		t.Fatalf("renewal past the grant's end: %v, want expired", err)
	}
}

// TestHostedSignInFollowsTheIdleTimeout: a hosted-login session lasts its
// usual 30 minutes, or the organisation's idle timeout when that is shorter.
func TestHostedSignInFollowsTheIdleTimeout(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newLifetimeFixture(t, ctx)
	me := createUserInTenant(t, ctx, f.tenantID)
	endsIn := func() time.Duration {
		raw, err := f.auth.CreateLoginSession(ctx, me, "198.51.100.7", "browser")
		if err != nil {
			t.Fatal(err)
		}
		var exp time.Time
		if err := testPool.QueryRow(ctx, `SELECT expires_at FROM auth.login_sessions WHERE token_hash = $1`, tokens.HashRefresh(raw)).Scan(&exp); err != nil {
			t.Fatal(err)
		}
		return time.Until(exp).Round(time.Minute)
	}
	if got := endsIn(); got != 30*time.Minute {
		t.Errorf("hosted session lasts %v, want 30m", got)
	}
	f.setPolicy(t, "720h", "15m")
	if got := endsIn(); got != 15*time.Minute {
		t.Errorf("hosted session with a 15m idle timeout lasts %v, want 15m", got)
	}
}
