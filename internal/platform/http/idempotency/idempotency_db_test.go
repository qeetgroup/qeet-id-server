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
	tenant, user := uuid.New(), uuid.New()
	send := func(path, key, body string, as uuid.UUID) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if key != "" {
			r.Header.Set(Header, key)
		}
		r = r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{ActorType: "user", Subject: as.String(), UserID: &as, TenantID: &tenant}))
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

// TestUnansweredKeyIsInProgress checks that a key claimed by a request still
// running is refused as in progress.
func TestUnansweredKeyIsInProgress(t *testing.T) {
	s := newStore(t)
	scope := "-|user:" + uuid.NewString()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `INSERT INTO platform.idempotency_keys (scope, key, request_hash) VALUES ($1, 'k', 'h')`, scope); err != nil {
		t.Fatal(err)
	}
	if claimed, err := s.claim(dbtest.Context(t), scope, "k", "h"); err != nil || claimed {
		t.Errorf("claim of a running key: %v, %v; want refused", claimed, err)
	}
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE platform.idempotency_keys SET created_at = NOW() - interval '2 minutes' WHERE scope = $1`, scope); err != nil {
		t.Fatal(err)
	}
	if claimed, err := s.claim(dbtest.Context(t), scope, "k", "h"); err != nil || !claimed {
		t.Errorf("claim of an abandoned key: %v, %v; want taken over", claimed, err)
	}
}
