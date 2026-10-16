//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// "Sign out all other sessions" is one self-service call. These tests
// drive it through the real handler behind the real bearer-token middleware,
// so the session that is kept is the one named by the caller's access token.

const revokeOthersPath = "/v1/auth/sessions/revoke-others"

type revokeOthersFixture struct {
	svc    *auth.Service
	router http.Handler
}

func newRevokeOthersFixture(t *testing.T) *revokeOthersFixture {
	t.Helper()
	issuer := mustIssuer()
	svc := auth.NewService(testPool, user.NewRepository(testPool), issuer)
	h := &auth.Handler{Service: svc, Validate: validator.New()}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: issuer}))
		h.MountAuthed(r)
	})
	return &revokeOthersFixture{svc: svc, router: r}
}

// newAccount creates a tenant-less user with 1+extra live sessions, each with
// its own access and refresh token. The account is inserted directly (not via
// Signup) so these tests do not depend on how sign-up checks passwords.
func (f *revokeOthersFixture) newAccount(t *testing.T, ctx context.Context, extra int) (uuid.UUID, []*auth.TokenPair) {
	t.Helper()
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES (NULL, $1) RETURNING id
	`, uniqueSlug("revoke-others")+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	var pairs []*auth.TokenPair
	for i := 0; i <= extra; i++ {
		pair, err := f.svc.IssuePair(ctx, userID, uuid.Nil, "198.51.100.7", fmt.Sprintf("device-%d", i), "password")
		if err != nil {
			t.Fatalf("open session %d: %v", i, err)
		}
		pairs = append(pairs, pair)
	}
	return userID, pairs
}

type revokeOthersResponse struct {
	status  int
	revoked *int64
	code    string
}

func (f *revokeOthersFixture) revokeOthers(t *testing.T, accessToken string) revokeOthersResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, revokeOthersPath, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	out := revokeOthersResponse{status: rr.Code}
	var body struct {
		Revoked *int64 `json:"revoked"`
		Error   struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	out.revoked = body.Revoked
	out.code = body.Error.Code
	if out.code == "" && rr.Code >= 400 {
		out.code = strings.TrimSpace(rr.Body.String())
	}
	return out
}

func sessionIsLive(t *testing.T, ctx context.Context, sessionID uuid.UUID) bool {
	t.Helper()
	var live bool
	if err := testPool.QueryRow(ctx, `SELECT revoked_at IS NULL FROM auth.sessions WHERE id = $1`, sessionID).Scan(&live); err != nil {
		t.Fatalf("inspect session %s: %v", sessionID, err)
	}
	return live
}

func liveSessionCount(t *testing.T, ctx context.Context, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL`, userID).Scan(&n); err != nil {
		t.Fatalf("count live sessions: %v", err)
	}
	return n
}

// TestRevokeOtherSessionsEndsEveryOtherSessionAndKeepsCurrent covers: every
// other session ends (including ones far beyond the first page of the session
// list) while the current one continues; the response says how many ended;
// renewal credentials of the ended sessions stop working; another user's
// sessions are untouched; the action is audited.
func TestRevokeOtherSessionsEndsEveryOtherSessionAndKeepsCurrent(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRevokeOthersFixture(t)

	userID, pairs := f.newAccount(t, ctx, 3)
	current := pairs[1]
	// 120 more sessions so the set is well past a 50- or 100-row list page.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.sessions (user_id, created_at, last_seen_at, user_agent)
		SELECT $1, NOW() - (series || ' minutes')::interval, NOW() - (series || ' minutes')::interval, 'old-device'
		FROM generate_series(1, 120) AS series
	`, userID); err != nil {
		t.Fatalf("seed old sessions: %v", err)
	}
	// One session that had already ended must not be counted again.
	if err := f.svc.Logout(ctx, pairs[3].SessionID, userID); err != nil {
		t.Fatalf("pre-end a session: %v", err)
	}
	otherUserID, otherPairs := f.newAccount(t, ctx, 2)

	res := f.revokeOthers(t, current.AccessToken)
	if res.status != http.StatusOK {
		t.Fatalf("revoke others status = %d (%s), want 200", res.status, res.code)
	}
	// device-0 + device-2 + the 120 seeded; device-3 had already ended.
	if res.revoked == nil || *res.revoked != 122 {
		t.Fatalf("revoked = %v, want 122", res.revoked)
	}

	if !sessionIsLive(t, ctx, current.SessionID) {
		t.Fatal("the caller's current session must stay live")
	}
	if got := liveSessionCount(t, ctx, userID); got != 1 {
		t.Fatalf("live sessions after revoke others = %d, want only the current one", got)
	}
	if _, err := f.svc.Refresh(ctx, auth.RefreshInput{RefreshToken: current.RefreshToken}); err != nil {
		t.Fatalf("the current session must still renew: %v", err)
	}
	for _, ended := range []*auth.TokenPair{pairs[0], pairs[2]} {
		if _, err := f.svc.Refresh(ctx, auth.RefreshInput{RefreshToken: ended.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
			t.Fatalf("refresh of ended session %s: err = %v, want session revoked", ended.SessionID, err)
		}
	}

	if got := liveSessionCount(t, ctx, otherUserID); got != len(otherPairs) {
		t.Fatalf("other user's live sessions = %d, want %d untouched", got, len(otherPairs))
	}
	for _, pair := range otherPairs {
		if _, err := f.svc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken}); err != nil {
			t.Fatalf("other user's session %s must still renew: %v", pair.SessionID, err)
		}
	}

	var audits int
	var recorded int64
	if err := testPool.QueryRow(ctx, `
		SELECT count(*), COALESCE(max((metadata->>'revoked_sessions')::bigint), -1)
		FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.other_sessions_revoked'
	`, userID).Scan(&audits, &recorded); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if audits != 1 || recorded != 122 {
		t.Fatalf("audit rows = %d with revoked_sessions = %d, want 1 with 122", audits, recorded)
	}
}

// TestRevokeOtherSessionsWithOnlyTheCurrentSessionChangesNothing: the request
// succeeds, reports zero, and the current session is unaffected — also when
// repeated.
func TestRevokeOtherSessionsWithOnlyTheCurrentSessionChangesNothing(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRevokeOthersFixture(t)
	userID, pairs := f.newAccount(t, ctx, 0)
	current := pairs[0]

	for attempt := 1; attempt <= 2; attempt++ {
		res := f.revokeOthers(t, current.AccessToken)
		if res.status != http.StatusOK {
			t.Fatalf("attempt %d: status = %d (%s), want 200", attempt, res.status, res.code)
		}
		if res.revoked == nil || *res.revoked != 0 {
			t.Fatalf("attempt %d: revoked = %v, want 0", attempt, res.revoked)
		}
	}
	if !sessionIsLive(t, ctx, current.SessionID) || liveSessionCount(t, ctx, userID) != 1 {
		t.Fatal("the only session must stay live")
	}
	if _, err := f.svc.Refresh(ctx, auth.RefreshInput{RefreshToken: current.RefreshToken}); err != nil {
		t.Fatalf("the current session must still renew: %v", err)
	}
}

// TestRevokeOtherSessionsReportsFailureAndEndsNothing: when one session cannot
// be ended the call fails, and no session is left ended — the user is never
// shown success for a partial result.
func TestRevokeOtherSessionsReportsFailureAndEndsNothing(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRevokeOthersFixture(t)
	userID, pairs := f.newAccount(t, ctx, 4)
	current := pairs[0]
	stuck := pairs[3]

	suffix := strings.ReplaceAll(stuck.SessionID.String(), "-", "")
	name := "test_block_session_end_" + suffix
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'forced failure ending one session';
		END $$;
		CREATE TRIGGER %[1]s BEFORE UPDATE ON auth.sessions
		FOR EACH ROW WHEN (OLD.id = '%[2]s'::uuid) EXECUTE FUNCTION %[1]s();
	`, name, stuck.SessionID)); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), fmt.Sprintf("DROP TRIGGER IF EXISTS %[1]s ON auth.sessions; DROP FUNCTION IF EXISTS %[1]s()", name))
	})

	res := f.revokeOthers(t, current.AccessToken)
	if res.status < 500 {
		t.Fatalf("status = %d (%s), want a server error when a session cannot be ended", res.status, res.code)
	}
	if res.revoked != nil {
		t.Fatalf("a failed call must not report a count, got %d", *res.revoked)
	}
	if got := liveSessionCount(t, ctx, userID); got != len(pairs) {
		t.Fatalf("live sessions after a failed call = %d, want all %d (nothing half-done)", got, len(pairs))
	}
	var audits int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.other_sessions_revoked'`, userID).Scan(&audits); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if audits != 0 {
		t.Fatalf("a failed call left %d audit rows", audits)
	}
}

// TestRevokeOtherSessionsRejectsAnAlreadyEndedSession: an access token that is
// still within its lifetime but whose session has ended cannot be used to end
// the user's remaining sessions.
func TestRevokeOtherSessionsRejectsAnAlreadyEndedSession(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRevokeOthersFixture(t)
	userID, pairs := f.newAccount(t, ctx, 2)
	ended := pairs[2]
	if err := f.svc.Logout(ctx, ended.SessionID, userID); err != nil {
		t.Fatalf("end session: %v", err)
	}

	res := f.revokeOthers(t, ended.AccessToken)
	if res.status != http.StatusUnauthorized || res.code != errs.CodeAuthSessionRevoked {
		t.Fatalf("status = %d code = %q, want 401 %s", res.status, res.code, errs.CodeAuthSessionRevoked)
	}
	if got := liveSessionCount(t, ctx, userID); got != 2 {
		t.Fatalf("live sessions = %d, want the 2 untouched", got)
	}
}

// TestRevokeOtherSessionsFromTwoDevicesAtOnceKeepsExactlyOne: two of the
// user's sessions ask at the same moment. The calls run one after the other, so
// exactly one device stays signed in and the other is told its session ended —
// never both signed out, never a server error.
func TestRevokeOtherSessionsFromTwoDevicesAtOnceKeepsExactlyOne(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRevokeOthersFixture(t)

	for round := 0; round < 10; round++ {
		userID, pairs := f.newAccount(t, ctx, 3)
		a, b := pairs[1], pairs[2]

		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]revokeOthersResponse, 2)
		for i, pair := range []*auth.TokenPair{a, b} {
			wg.Add(1)
			go func(i int, token string) {
				defer wg.Done()
				<-start
				results[i] = f.revokeOthers(t, token)
			}(i, pair.AccessToken)
		}
		close(start)
		wg.Wait()

		var winners, losers int
		for i, res := range results {
			switch {
			case res.status == http.StatusOK:
				winners++
				if !sessionIsLive(t, ctx, []*auth.TokenPair{a, b}[i].SessionID) {
					t.Fatalf("round %d: the successful caller's session was ended", round)
				}
			case res.status == http.StatusUnauthorized && res.code == errs.CodeAuthSessionRevoked:
				losers++
			default:
				t.Fatalf("round %d: unexpected response %d (%s)", round, res.status, res.code)
			}
		}
		if winners != 1 || losers != 1 {
			t.Fatalf("round %d: winners = %d losers = %d, want exactly one of each", round, winners, losers)
		}
		if got := liveSessionCount(t, ctx, userID); got != 1 {
			t.Fatalf("round %d: live sessions = %d, want exactly one", round, got)
		}
	}
}

// TestRevokeOtherSessionsIsConsistentWithConcurrentSignIns: sessions are
// created while the action runs. Every session that existed before it ends;
// each one created during it is either fully ended or fully live (its refresh
// token agrees with the session); and the reported count matches exactly the
// sessions that were ended.
func TestRevokeOtherSessionsIsConsistentWithConcurrentSignIns(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newRevokeOthersFixture(t)
	userID, pairs := f.newAccount(t, ctx, 10)
	current := pairs[0]
	before := pairs[1:]

	const creators, perCreator = 4, 10
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created []*auth.TokenPair
		started = make(chan struct{}, creators)
	)
	for c := 0; c < creators; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			for i := 0; i < perCreator; i++ {
				pair, err := f.svc.IssuePair(ctx, userID, uuid.Nil, "203.0.113.5", fmt.Sprintf("concurrent-%d-%d", c, i), "password")
				if err != nil {
					t.Errorf("concurrent sign-in: %v", err)
					return
				}
				mu.Lock()
				created = append(created, pair)
				mu.Unlock()
				if i == 1 {
					started <- struct{}{}
				}
			}
		}(c)
	}
	for c := 0; c < creators; c++ {
		<-started // every creator is mid-flight
	}
	res := f.revokeOthers(t, current.AccessToken)
	wg.Wait()

	if res.status != http.StatusOK || res.revoked == nil {
		t.Fatalf("status = %d (%s), want 200 with a count", res.status, res.code)
	}
	if !sessionIsLive(t, ctx, current.SessionID) {
		t.Fatal("the current session must stay live")
	}
	for _, pair := range before {
		if sessionIsLive(t, ctx, pair.SessionID) {
			t.Fatalf("session %s existed before the action and must have ended", pair.SessionID)
		}
	}
	var ended int64
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NOT NULL`, userID).Scan(&ended); err != nil {
		t.Fatalf("count ended sessions: %v", err)
	}
	if ended != *res.revoked {
		t.Fatalf("reported %d ended sessions, but %d are ended", *res.revoked, ended)
	}
	for _, pair := range created {
		live := sessionIsLive(t, ctx, pair.SessionID)
		_, err := f.svc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken})
		switch {
		case live && err != nil:
			t.Fatalf("session %s is live but its refresh token fails: %v", pair.SessionID, err)
		case !live && !errors.Is(err, errs.ErrAuthSessionRevoked):
			t.Fatalf("session %s ended but its refresh token gave err = %v", pair.SessionID, err)
		}
	}
}
