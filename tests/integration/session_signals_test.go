//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	webhook "github.com/qeetgroup/qeet-id-server/internal/developer/webhooks"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

// Every way a session ends is announced to the organisation's
// session.revoked subscribers, naming the person, the session and why — so an
// application can stop trusting a token before it lapses. Signals are queued in
// the transaction that ends the session; if queueing fails the session still
// ends and the failure is counted.

type signalFixture struct {
	sig      *sessionsignal.Signaller
	wh       *webhook.Service
	auth     *auth.Service
	tenantID uuid.UUID
}

func newSignalFixture(t *testing.T, ctx context.Context) *signalFixture {
	t.Helper()
	f := &signalFixture{wh: webhook.NewService(testPool), tenantID: createTenant(t, ctx, uniqueSlug("signals"))}
	f.wh.SetCipher(testEnvelope(t))
	f.sig = sessionsignal.New(f.wh.EnqueueTx)
	f.auth, _ = newAuth()
	f.auth.SetSessionSignals(f.sig)
	subscribeTo(t, ctx, f.wh, f.tenantID, []string{sessionsignal.EventType})
	clearDeliveriesAfter(t, f.tenantID)
	return f
}

// clearDeliveriesAfter removes the deliveries queued for the organisations'
// subscriptions when the test ends: they point at an address nobody serves, and
// a later test's webhook worker would otherwise spend its time on them.
func clearDeliveriesAfter(t *testing.T, tenantIDs ...uuid.UUID) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(), `
			DELETE FROM tenant.webhook_deliveries WHERE subscription_id IN (
			    SELECT id FROM tenant.webhook_subscriptions WHERE tenant_id = ANY($1))`, tenantIDs); err != nil {
			t.Errorf("clear queued deliveries: %v", err)
		}
	})
}

// openSessions signs a member of the organisation in n times and returns the
// account and the sessions.
func (f *signalFixture) openSessions(t *testing.T, ctx context.Context, userID uuid.UUID, n int) []*auth.TokenPair {
	t.Helper()
	var out []*auth.TokenPair
	for i := 0; i < n; i++ {
		pair, err := f.auth.IssuePair(ctx, userID, f.tenantID, "198.51.100.7", "device", "password")
		if err != nil {
			t.Fatalf("open session: %v", err)
		}
		out = append(out, pair)
	}
	return out
}

// announced is the reason and session of every session.revoked signal queued
// for the organisation about userID.
func (f *signalFixture) announced(t *testing.T, ctx context.Context, tenantID, userID uuid.UUID) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range queuedDeliveries(t, ctx, tenantID, sessionsignal.EventType) {
		if d.Payload["user_id"] != userID.String() {
			continue
		}
		out[d.Payload["session_id"].(string)] = d.Payload["reason"].(string)
	}
	return out
}

func wantAnnounced(t *testing.T, got map[string]string, reason string, sessions []*auth.TokenPair, notFor ...*auth.TokenPair) {
	t.Helper()
	for _, s := range sessions {
		if got[s.SessionID.String()] != reason {
			t.Errorf("session %s announced as %q, want %q (all: %v)", s.SessionID, got[s.SessionID.String()], reason, got)
		}
	}
	for _, s := range notFor {
		if r, ok := got[s.SessionID.String()]; ok {
			t.Errorf("session %s that was kept was announced (%q)", s.SessionID, r)
		}
	}
}

// TestEverySessionEndingIsAnnounced drives each cause through its real entry
// point and checks the signals queued for the organisation's subscribers.
func TestEverySessionEndingIsAnnounced(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignalFixture(t, ctx)
	policy := authpolicy.NewService(testPool)
	users := &user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New(), PasswordPolicy: policy.ValidateForTenant, SignIns: f.auth, Signals: f.sig}

	t.Run("logout", func(t *testing.T) {
		me := createUserInTenant(t, ctx, f.tenantID)
		s := f.openSessions(t, ctx, me, 1)
		if err := f.auth.Logout(ctx, s[0].SessionID, me); err != nil {
			t.Fatalf("logout: %v", err)
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonLogout, s)
	})
	t.Run("refresh token reuse", func(t *testing.T) {
		me := createUserInTenant(t, ctx, f.tenantID)
		s := f.openSessions(t, ctx, me, 1)
		if _, err := f.auth.Refresh(ctx, auth.RefreshInput{RefreshToken: s[0].RefreshToken}); err != nil {
			t.Fatalf("first refresh: %v", err)
		}
		if _, err := f.auth.Refresh(ctx, auth.RefreshInput{RefreshToken: s[0].RefreshToken}); err == nil {
			t.Fatal("reused refresh token accepted")
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonReuseDetected, s)
	})
	t.Run("sign out other sessions", func(t *testing.T) {
		me := createUserInTenant(t, ctx, f.tenantID)
		s := f.openSessions(t, ctx, me, 3)
		if _, err := f.auth.RevokeOtherSessions(ctx, auth.RevokeOtherSessionsInput{UserID: me, CurrentSessionID: s[0].SessionID}); err != nil {
			t.Fatalf("revoke others: %v", err)
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonOtherSessionsRevoked, s[1:], s[0])
	})
	t.Run("sign out everywhere", func(t *testing.T) {
		me := createUserInTenant(t, ctx, f.tenantID)
		s := f.openSessions(t, ctx, me, 2)
		if _, err := f.auth.RevokeAllSessions(ctx, auth.RevokeAllSessionsInput{UserID: me, SessionID: s[0].SessionID}); err != nil {
			t.Fatalf("revoke all: %v", err)
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonAllSessionsRevoked, s)
	})
	t.Run("password change", func(t *testing.T) {
		me, _ := userWithPassword(t, ctx, f.tenantID, pwOriginal)
		s := f.openSessions(t, ctx, me, 3)
		if err := f.auth.ChangePassword(ctx, auth.ChangePasswordInput{UserID: me, KeepSessionID: s[0].SessionID, Current: pwOriginal, Next: "Brand-New-Passphrase-82!"}); err != nil {
			t.Fatalf("change password: %v", err)
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonPasswordChanged, s[1:], s[0])
	})
	t.Run("password reset", func(t *testing.T) {
		me, email := userWithPassword(t, ctx, f.tenantID, pwOriginal)
		s := f.openSessions(t, ctx, me, 2)
		rec := newRecovery(&captureSender{})
		rec.SetSessionSignals(f.sig)
		token, err := rec.StartPasswordReset(ctx, email)
		if err != nil || token == "" {
			t.Fatalf("start reset: %q %v", token, err)
		}
		if err := rec.ConfirmPasswordReset(ctx, token, "Brand-New-Passphrase-82!", recovery.AuditCtx{}); err != nil {
			t.Fatalf("confirm reset: %v", err)
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonPasswordReset, s)
	})
	t.Run("administrator sets the password", func(t *testing.T) {
		actor := createUserInTenant(t, ctx, f.tenantID)
		me, _ := userWithPassword(t, ctx, f.tenantID, pwOriginal)
		s := f.openSessions(t, ctx, me, 2)
		rr := serveJSON(t, adminRouter(users, actor, f.tenantID), http.MethodPost, "/users/"+me.String()+"/password", map[string]any{"password": "Brand-New-Passphrase-82!"})
		if rr.Code >= 300 {
			t.Fatalf("admin set-password = %d %s", rr.Code, rr.Body.String())
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonAdminPasswordSet, s)
	})
	t.Run("administrator force sign-out", func(t *testing.T) {
		actor := createUserInTenant(t, ctx, f.tenantID)
		me := createUserInTenant(t, ctx, f.tenantID)
		s := f.openSessions(t, ctx, me, 2)
		rr := serveJSON(t, adminRouter(users, actor, f.tenantID), http.MethodPost, "/users/"+me.String()+"/sessions/revoke-all", map[string]any{})
		if rr.Code >= 300 {
			t.Fatalf("force sign-out = %d %s", rr.Code, rr.Body.String())
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonAdminRevokedAll, s)
	})
	t.Run("suspension", func(t *testing.T) {
		actor := createUserInTenant(t, ctx, f.tenantID)
		me := createUserInTenant(t, ctx, f.tenantID)
		s := f.openSessions(t, ctx, me, 2)
		rr := serveJSON(t, adminRouter(users, actor, f.tenantID), http.MethodPatch, "/users/"+me.String(), map[string]any{"status": "suspended"})
		if rr.Code >= 300 {
			t.Fatalf("suspend = %d %s", rr.Code, rr.Body.String())
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonSuspended, s)
	})
	t.Run("deprovisioning", func(t *testing.T) {
		me := createUserInTenant(t, ctx, f.tenantID)
		s := f.openSessions(t, ctx, me, 1)
		svc := scim.NewService(testPool, user.NewRepository(testPool))
		svc.SetSessionSignals(f.sig)
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		token, err := svc.Rotate(ctx, tx, f.tenantID)
		if err != nil {
			t.Fatalf("rotate SCIM token: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		r := chi.NewRouter()
		(&scim.Handler{Service: svc}).MountPublic(r)
		req := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+me.String(), strings.NewReader(
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/scim+json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code >= 300 {
			t.Fatalf("SCIM deactivate = %d %s", rr.Code, rr.Body.String())
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonDeprovisioned, s)
	})
	t.Run("erasure", func(t *testing.T) {
		me := createUserInTenant(t, ctx, f.tenantID)
		s := f.openSessions(t, ctx, me, 2)
		g := gdpr.NewService(testPool, time.Hour)
		g.SetSessionSignals(f.sig)
		if err := g.PurgeSelf(ctx, me); err != nil {
			t.Fatalf("erase: %v", err)
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonDeleted, s)
	})
	t.Run("organisation switch", func(t *testing.T) {
		me := createUserInTenant(t, ctx, f.tenantID)
		addTenantMembership(t, ctx, me, f.tenantID)
		other := createTenant(t, ctx, uniqueSlug("signals-other"))
		addTenantMembership(t, ctx, me, other)
		s := f.openSessions(t, ctx, me, 1)
		if _, err := f.auth.SwitchTenant(ctx, auth.SwitchTenantInput{UserID: me, FromSessionID: s[0].SessionID, TenantID: other}); err != nil {
			t.Fatalf("switch: %v", err)
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonTenantSwitch, s)
	})
	t.Run("expiry", func(t *testing.T) {
		me := createUserInTenant(t, ctx, f.tenantID)
		s := f.openSessions(t, ctx, me, 1)
		if _, err := testPool.Exec(ctx, `UPDATE auth.sessions SET created_at = NOW() - INTERVAL '40 days' WHERE id = $1`, s[0].SessionID); err != nil {
			t.Fatalf("age session: %v", err)
		}
		if _, err := testPool.Exec(ctx, `UPDATE auth.refresh_tokens SET expires_at = NOW() - INTERVAL '8 days' WHERE session_id = $1`, s[0].SessionID); err != nil {
			t.Fatalf("age refresh token: %v", err)
		}
		if _, err := auth.PurgeEndedSessions(ctx, testPool, auth.SessionRetention, f.sig); err != nil {
			t.Fatalf("cleanup: %v", err)
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonExpired, s)
	})
}

// TestSessionWithoutAnOrganisationIsAnnouncedToTheUsersOrganisations: a
// session with no organisation is announced to every organisation the user
// belongs to (home and member), with a null tenant_id.
func TestSessionWithoutAnOrganisationIsAnnouncedToTheUsersOrganisations(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignalFixture(t, ctx)
	other := createTenant(t, ctx, uniqueSlug("signals-member"))
	subscribeTo(t, ctx, f.wh, other, []string{sessionsignal.EventType})
	clearDeliveriesAfter(t, other)
	me := createUserInTenant(t, ctx, f.tenantID)
	addTenantMembership(t, ctx, me, other)
	pair, err := f.auth.IssuePair(ctx, me, uuid.Nil, "198.51.100.7", "console", "password")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := f.auth.Logout(ctx, pair.SessionID, me); err != nil {
		t.Fatalf("logout: %v", err)
	}
	for _, tid := range []uuid.UUID{f.tenantID, other} {
		found := false
		for _, d := range queuedDeliveries(t, ctx, tid, sessionsignal.EventType) {
			if d.Payload["session_id"] == pair.SessionID.String() {
				found = true
				if d.Payload["tenant_id"] != nil {
					t.Errorf("tenant_id = %v, want null for a session with no organisation", d.Payload["tenant_id"])
				}
			}
		}
		if !found {
			t.Errorf("organisation %s was not told the session ended", tid)
		}
	}
}

// TestSignalThatCannotBeQueuedLeavesTheRevocationAndIsCounted: when queueing
// the signal fails, the session still ends and the failure is counted.
func TestSignalThatCannotBeQueuedLeavesTheRevocationAndIsCounted(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc, _ := newAuth()
	svc.SetSessionSignals(sessionsignal.New(func(context.Context, pgx.Tx, uuid.UUID, string, any) error {
		return errors.New("queue unavailable")
	}))
	tenantID := createTenant(t, ctx, uniqueSlug("signals-fail"))
	me := createUserInTenant(t, ctx, tenantID)
	pair, err := svc.IssuePair(ctx, me, tenantID, "198.51.100.7", "device", "password")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	before := signalFailures(t, sessionsignal.ReasonLogout)
	if err := svc.Logout(ctx, pair.SessionID, me); err != nil {
		t.Fatalf("logout failed because the signal could not be queued: %v", err)
	}
	if n := liveSessionCount(t, ctx, me); n != 0 {
		t.Fatalf("live sessions = %d, want the session ended", n)
	}
	if after := signalFailures(t, sessionsignal.ReasonLogout); after != before+1 {
		t.Fatalf("failure metric %v → %v, want one more", before, after)
	}
}

// TestEachSignalHasItsOwnEventID: signals carry the person, the session, the
// reason, the time and an event id unique to each signal (a redelivery repeats
// it; a new signal never does).
func TestEachSignalHasItsOwnEventID(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignalFixture(t, ctx)
	me := createUserInTenant(t, ctx, f.tenantID)
	s := f.openSessions(t, ctx, me, 3)
	if _, err := f.auth.RevokeAllSessions(ctx, auth.RevokeAllSessionsInput{UserID: me, SessionID: s[0].SessionID}); err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	seen := map[any]bool{}
	for _, d := range queuedDeliveries(t, ctx, f.tenantID, sessionsignal.EventType) {
		if d.Payload["user_id"] != me.String() {
			continue
		}
		for _, k := range []string{"event_id", "user_id", "session_id", "reason", "revoked_at"} {
			if d.Payload[k] == nil || d.Payload[k] == "" {
				t.Errorf("signal lacks %s: %v", k, d.Payload)
			}
		}
		if seen[d.Payload["event_id"]] {
			t.Errorf("event_id %v repeated across signals", d.Payload["event_id"])
		}
		seen[d.Payload["event_id"]] = true
	}
	if len(seen) != 3 {
		t.Fatalf("signals = %d, want one per ended session (3)", len(seen))
	}
}

// signalFailures reads session_revocation_signal_failures_total{reason}.
func signalFailures(t *testing.T, reason string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "session_revocation_signal_failures_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "reason" && l.GetValue() == reason {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
