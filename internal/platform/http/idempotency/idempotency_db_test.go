//go:build integration

package idempotency

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// newStore returns a Store over the test pool with a fresh cipher.
func newStore(t *testing.T) *Store {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(dbtest.Pool(t), cipher)
}

// TestRetriesGetTheFirstAnswer checks that a create sent again with its key
// is answered from the first time without running again, and the ways a key
// is refused.
func TestRetriesGetTheFirstAnswer(t *testing.T) {
	var runs atomic.Int32
	status := http.StatusCreated
	h := newStore(t).Middleware([]string{"POST /v1/things"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := runs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"run":%d}`, n)
	}))
	organization, user := uuid.New(), uuid.New()
	send := func(path, key, body string, as uuid.UUID) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if key != "" {
			r.Header.Set(Header, key)
		}
		r = r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{ActorType: "user", Subject: as.String(), UserID: &as, OrganizationID: &organization}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	first := send("/v1/things", "key-1", `{"name":"a"}`, user)
	again := send("/v1/things", "key-1", `{"name":"a"}`, user)
	if first.Code != http.StatusCreated || again.Code != http.StatusCreated || again.Body.String() != first.Body.String() {
		t.Fatalf("retry answered %d %s, first %d %s", again.Code, again.Body, first.Code, first.Body)
	}
	if again.Header().Get("Idempotent-Replayed") != "true" || again.Header().Get("Content-Type") != "application/json" || runs.Load() != 1 {
		t.Errorf("retry: headers %v, %d runs; want a replay of one run", again.Header(), runs.Load())
	}
	if rec := send("/v1/things", "key-1", `{"name":"b"}`, user); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("same key, another body: %d, want 422", rec.Code)
	}
	if rec := send("/v1/things", "key-1", `{"name":"a"}`, uuid.New()); rec.Code != http.StatusCreated || runs.Load() != 2 {
		t.Errorf("same key from another caller: %d after %d runs, want its own create", rec.Code, runs.Load())
	}
	if rec := send("/v1/things", "bad key", `{}`, user); rec.Code != http.StatusBadRequest {
		t.Errorf("a key with a space: %d, want 400", rec.Code)
	}
	if send("/v1/things", "", `{}`, user); runs.Load() != 3 {
		t.Error("a request without a key did not run")
	}
	if send("/v1/other", "key-1", `{}`, user); runs.Load() != 4 {
		t.Error("an unlisted route with a key did not run")
	}

	status = http.StatusInternalServerError
	send("/v1/things", "key-2", `{}`, user)
	status = http.StatusCreated
	if rec := send("/v1/things", "key-2", `{}`, user); rec.Code != http.StatusCreated || rec.Header().Get("Idempotent-Replayed") != "" {
		t.Errorf("retry after a server error: %d %v, want it to run again", rec.Code, rec.Header())
	}
}

// sender sends POST /v1/things through h as one caller of one organization.
type sender struct {
	h                  http.Handler
	organization, user uuid.UUID
}

func (s sender) send(t *testing.T, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/things", strings.NewReader(body))
	r.Header.Set(Header, key)
	r = r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{ActorType: "user", Subject: s.user.String(), UserID: &s.user, OrganizationID: &s.organization}))
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, r)
	return rec
}

// TestInterruptedRequestIsNotRunAgain: a request that took effect but whose
// instance stopped before storing its answer left its key claimed and
// unanswered, and a retry a minute later took the key over and ran it again,
// doing the action twice. A retry now hears the request is in progress and,
// once the claim is old, that its outcome is unknown; it never runs again.
func TestInterruptedRequestIsNotRunAgain(t *testing.T) {
	var runs atomic.Int32
	h := newStore(t).Middleware([]string{"POST /v1/things"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runs.Add(1) // the action takes effect
		if r.Header.Get("X-Crash") != "" {
			panic(http.ErrAbortHandler) // the instance stops before the answer is stored
		}
		w.WriteHeader(http.StatusCreated)
	}))
	s := sender{h: h, organization: uuid.New(), user: uuid.New()}
	func() {
		defer func() { _ = recover() }()
		r := httptest.NewRequest(http.MethodPost, "/v1/things", strings.NewReader(`{"name":"a"}`))
		r.Header.Set(Header, "key-1")
		r.Header.Set("X-Crash", "1")
		r = r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{ActorType: "user", Subject: s.user.String(), UserID: &s.user, OrganizationID: &s.organization}))
		h.ServeHTTP(httptest.NewRecorder(), r)
	}()

	if rec := s.send(t, "key-1", `{"name":"a"}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "idempotency.in_progress") {
		t.Errorf("retry at once: %d %s, want 409 idempotency.in_progress", rec.Code, rec.Body)
	}
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		UPDATE platform.idempotency_keys SET created_at = NOW() - interval '2 minutes' WHERE scope LIKE $1`, s.organization.String()+"|%"); err != nil {
		t.Fatal(err)
	}
	if rec := s.send(t, "key-1", `{"name":"a"}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "idempotency.outcome_unknown") {
		t.Errorf("retry after the claim aged: %d %s, want 409 idempotency.outcome_unknown", rec.Code, rec.Body)
	}
	if rec := s.send(t, "key-1", `{"name":"b"}`); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("same key, another body: %d, want 422", rec.Code)
	}
	if runs.Load() != 1 {
		t.Fatalf("the interrupted request ran %d times, want once", runs.Load())
	}
	if rec := s.send(t, "key-2", `{"name":"a"}`); rec.Code != http.StatusCreated || runs.Load() != 2 {
		t.Errorf("retry with a new key: %d after %d runs, want it to run", rec.Code, runs.Load())
	}
}

// TestConcurrentRequestsRunOnce sends the same request twice at once: the
// second is refused as in progress and the first runs alone.
func TestConcurrentRequestsRunOnce(t *testing.T) {
	var runs atomic.Int32
	entered, finish := make(chan struct{}), make(chan struct{})
	h := newStore(t).Middleware([]string{"POST /v1/things"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		runs.Add(1)
		close(entered)
		<-finish
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"run":1}`))
	}))
	s := sender{h: h, organization: uuid.New(), user: uuid.New()}
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- s.send(t, "key-1", `{}`) }()
	<-entered
	if rec := s.send(t, "key-1", `{}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "idempotency.in_progress") {
		t.Errorf("overlapping request: %d %s, want 409 idempotency.in_progress", rec.Code, rec.Body)
	}
	close(finish)
	if rec := <-first; rec.Code != http.StatusCreated {
		t.Fatalf("first request: %d", rec.Code)
	}
	if rec := s.send(t, "key-1", `{}`); rec.Header().Get("Idempotent-Replayed") != "true" || rec.Body.String() != `{"run":1}` || runs.Load() != 1 {
		t.Errorf("retry: %d %s after %d runs, want the first answer replayed", rec.Code, rec.Body, runs.Load())
	}
}

// TestOnlyTheClaimingAttemptAnswers checks that an attempt whose claim was
// released, and the key claimed again by another, can neither store its
// answer over the other's claim nor free the key from under it.
func TestOnlyTheClaimingAttemptAnswers(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	s := newStore(t)
	scope := "-|user:" + uuid.NewString()
	first, claimed, err := s.claim(ctx, scope, "k", "h")
	if err != nil || !claimed {
		t.Fatalf("first claim: %v, %v", claimed, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE platform.idempotency_keys SET created_at = NOW() - interval '2 minutes' WHERE scope = $1`, scope); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := s.claim(ctx, scope, "k", "h"); err != nil || claimed {
		t.Fatalf("claim of an old unanswered key: %v, %v; want refused", claimed, err)
	}

	if err := s.release(ctx, scope, "k", first); err != nil {
		t.Fatal(err)
	}
	second, claimed, err := s.claim(ctx, scope, "k", "h")
	if err != nil || !claimed {
		t.Fatalf("claim after the release: %v, %v", claimed, err)
	}
	if stored, err := s.complete(ctx, scope, "k", first, platformScope, http.StatusCreated, "application/json", []byte(`{"from":"first"}`)); err != nil || stored {
		t.Errorf("late answer of the first attempt: stored %v, %v; want refused", stored, err)
	}
	if err := s.release(ctx, scope, "k", first); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.idempotency_keys WHERE scope = $1 AND attempt = $2 AND status IS NULL`, scope, second); n != 1 {
		t.Fatalf("the second attempt's claim: %d rows, want it kept unanswered", n)
	}
	if stored, err := s.complete(ctx, scope, "k", second, platformScope, http.StatusCreated, "application/json", []byte(`{"from":"second"}`)); err != nil || !stored {
		t.Fatalf("the second attempt's answer: stored %v, %v", stored, err)
	}
	var enc, nonce []byte
	if err := pool.QueryRow(ctx, `SELECT body_enc, body_nonce FROM platform.idempotency_keys WHERE scope = $1`, scope).Scan(&enc, &nonce); err != nil {
		t.Fatal(err)
	}
	if body, err := s.cipher.Open(platformScope, purpose, scope+"|k", enc, nonce); err != nil || string(body) != `{"from":"second"}` {
		t.Errorf("stored answer %s, %v; want the second attempt's", body, err)
	}
}
