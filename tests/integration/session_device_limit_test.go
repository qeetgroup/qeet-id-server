//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const (
	chromeMac   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0 Safari/537.36"
	safariPhone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
)

type listedSession struct {
	ID         string `json:"id"`
	Device     string `json:"device"`
	DeviceKind string `json:"device_kind"`
	Country    string `json:"country"`
	Current    bool   `json:"current"`
	Status     string `json:"status"`
	UserAgent  string `json:"user_agent"`
	LastSeenAt time.Time
}

func listSessions(t *testing.T, f *lifetimeFixture, token string) map[string]listedSession {
	t.Helper()
	rr := f.do(http.MethodGet, "/v1/auth/sessions", token, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list sessions: %d %s", rr.Code, rr.Body.String())
	}
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &page)
	out := map[string]listedSession{}
	for _, raw := range page.Items {
		var s listedSession
		_ = json.Unmarshal(raw, &s)
		var withCountry map[string]any
		_ = json.Unmarshal(raw, &withCountry)
		if _, ok := withCountry["country"]; !ok {
			s.Country = "<absent>"
		}
		out[s.ID] = s
	}
	return out
}

// TestSessionListDescribesEachSession covers: each entry carries a readable
// device description from the server (a neutral one for an unknown user
// agent), keeps the raw user agent, marks exactly the caller's session as
// current, shows the country the session was opened from when the deployment
// supplies one and omits it otherwise; another person's sessions never
// appear; a revoked session shows as revoked on reload.
func TestSessionListDescribesEachSession(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newLifetimeFixture(t, ctx)
	me := createUserInTenant(t, ctx, f.tenantID)
	open := func(ctx context.Context, ua string) *auth.TokenPair {
		pair, err := f.auth.IssuePair(ctx, me, f.tenantID, "198.51.100.7", ua, "password")
		if err != nil {
			t.Fatal(err)
		}
		return pair
	}
	laptop := open(httpx.WithGeoCountry(ctx, "IN"), chromeMac)
	phone := open(ctx, safariPhone)
	script := open(ctx, "curl/8.7.1")
	other := createUserInTenant(t, ctx, f.tenantID)
	if _, err := f.auth.IssuePair(ctx, other, f.tenantID, "198.51.100.8", chromeMac, "password"); err != nil {
		t.Fatal(err)
	}

	got := listSessions(t, f, phone.AccessToken)
	if len(got) != 3 {
		t.Fatalf("listed %d sessions, want my 3", len(got))
	}
	want := map[uuid.UUID]listedSession{
		laptop.SessionID: {Device: "Chrome on macOS", DeviceKind: "desktop", Country: "IN"},
		phone.SessionID:  {Device: "Safari on iPhone", DeviceKind: "mobile", Country: "<absent>", Current: true},
		script.SessionID: {Device: "Unknown device", DeviceKind: "unknown", Country: "<absent>"},
	}
	for id, w := range want {
		g := got[id.String()]
		if g.Device != w.Device || g.DeviceKind != w.DeviceKind || g.Country != w.Country || g.Current != w.Current {
			t.Errorf("session %s listed as %+v, want %+v", id, g, w)
		}
		if g.UserAgent == "" {
			t.Errorf("session %s lost its raw user agent", id)
		}
	}

	if err := f.auth.Logout(ctx, laptop.SessionID, me); err != nil {
		t.Fatal(err)
	}
	if s := listSessions(t, f, phone.AccessToken)[laptop.SessionID.String()]; s.Status != "revoked" {
		t.Errorf("revoked session listed as %q", s.Status)
	}
}

// TestUsingASessionKeepsItActive: a request made with a session's access
// token records its use, so its idle timeout counts from that use and the
// list shows it as recently active.
func TestUsingASessionKeepsItActive(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newLifetimeFixture(t, ctx)
	issuer := f.issuer
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: issuer, SessionUsed: f.auth.SessionUsed}))
		(&auth.Handler{Service: f.auth, Validate: validator.New()}).MountAuthed(r)
	})
	f.router = r
	me := createUserInTenant(t, ctx, f.tenantID)
	pair := f.signIn(t, ctx, me)
	ageSession(t, ctx, pair.SessionID, "last_seen_at = NOW() - INTERVAL '20 minutes'")

	if rr := f.do(http.MethodGet, "/v1/auth/me", pair.AccessToken, nil); rr.Code != http.StatusOK {
		t.Fatalf("use the session: %d %s", rr.Code, rr.Body.String())
	}
	if b := boundsOf(t, ctx, pair.SessionID); time.Since(b.lastSeen) > time.Minute {
		t.Errorf("last use is %v ago after a request, want now", time.Since(b.lastSeen))
	}
}

// setSessionLimit sets the organisation's limit directly.
func setSessionLimit(t *testing.T, ctx context.Context, tenantID uuid.UUID, max int, action string) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.security_policies (tenant_id, max_sessions, session_limit_action) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET max_sessions = EXCLUDED.max_sessions, session_limit_action = EXCLUDED.session_limit_action`,
		tenantID, max, action); err != nil {
		t.Fatalf("set session limit: %v", err)
	}
}

func liveSessionsIn(t *testing.T, ctx context.Context, userID, tenantID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`, userID, tenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSessionLimit covers: under the limit a sign-in opens a session; at the
// limit with eviction the least recently used session ends (its renewal
// refused, recorded and announced) and the sign-in succeeds; with refusal the
// sign-in is refused with a stated reason and recorded; no limit means no
// limit; another organisation's lower limit has no effect; two sign-ins at
// once do not exceed the limit.
func TestSessionLimit(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newLifetimeFixture(t, ctx)

	t.Run("evict the least recently used", func(t *testing.T) {
		setSessionLimit(t, ctx, f.tenantID, 2, "evict_oldest")
		me := createUserInTenant(t, ctx, f.tenantID)
		oldest := f.signIn(t, ctx, me)
		ageSession(t, ctx, oldest.SessionID, "last_seen_at = NOW() - INTERVAL '30 minutes'")
		recent := f.signIn(t, ctx, me)
		third := f.signIn(t, ctx, me)
		if liveSessionsIn(t, ctx, me, f.tenantID) != 2 {
			t.Fatalf("live sessions = %d, want the limit of 2", liveSessionsIn(t, ctx, me, f.tenantID))
		}
		if boundsOf(t, ctx, oldest.SessionID).revoked == false || boundsOf(t, ctx, recent.SessionID).revoked || boundsOf(t, ctx, third.SessionID).revoked {
			t.Error("the wrong session was ended")
		}
		if rr := f.refresh(oldest.RefreshToken); rr.Code != http.StatusUnauthorized {
			t.Errorf("renewing the evicted session: %d %s", rr.Code, rr.Body.String())
		}
		wantAnnounced(t, f.announced(t, ctx, f.tenantID, me), sessionsignal.ReasonSessionLimit, []*auth.TokenPair{oldest}, recent, third)
		var audits int
		_ = testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE action = 'auth.session_evicted' AND resource_id = $1`, oldest.SessionID).Scan(&audits)
		if audits != 1 {
			t.Errorf("eviction audited %d times, want once", audits)
		}
	})

	t.Run("refuse", func(t *testing.T) {
		setSessionLimit(t, ctx, f.tenantID, 2, "refuse")
		me := createUserInTenant(t, ctx, f.tenantID)
		f.signIn(t, ctx, me)
		f.signIn(t, ctx, me)
		if _, err := f.auth.IssuePair(ctx, me, f.tenantID, "198.51.100.7", "device", "password"); !errors.Is(err, errs.ErrAuthSessionLimit) {
			t.Fatalf("sign-in at the limit: %v, want refused", err)
		}
		if liveSessionsIn(t, ctx, me, f.tenantID) != 2 {
			t.Error("a refused sign-in changed the sessions")
		}
		var audits int
		_ = testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE action = 'auth.sign_in_refused_session_limit' AND resource_id = $1`, me).Scan(&audits)
		if audits != 1 {
			t.Errorf("refusal audited %d times, want once", audits)
		}
	})

	t.Run("two sign-ins at once", func(t *testing.T) {
		setSessionLimit(t, ctx, f.tenantID, 2, "refuse")
		me := createUserInTenant(t, ctx, f.tenantID)
		f.signIn(t, ctx, me)
		var wg sync.WaitGroup
		results := make([]error, 2)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, results[i] = f.auth.IssuePair(ctx, me, f.tenantID, "198.51.100.7", "device", "password")
			}(i)
		}
		wg.Wait()
		if n := liveSessionsIn(t, ctx, me, f.tenantID); n != 2 {
			t.Fatalf("two sign-ins at once left %d live sessions (%v), want the limit of 2", n, results)
		}
	})

	t.Run("no limit, and another organisation's limit", func(t *testing.T) {
		other := createTenant(t, ctx, uniqueSlug("strict"))
		setSessionLimit(t, ctx, other, 1, "refuse")
		free := createTenant(t, ctx, uniqueSlug("free"))
		me := createUserInTenant(t, ctx, free)
		for i := 0; i < 5; i++ {
			if _, err := f.auth.IssuePair(ctx, me, free, "198.51.100.7", "device", "password"); err != nil {
				t.Fatalf("sign-in %d with no limit: %v", i+1, err)
			}
		}
	})
}
