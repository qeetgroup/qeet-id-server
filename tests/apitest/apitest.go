//go:build integration

// Package apitest runs the whole API for the tests in tests/: every service wired as the server wires
// it (bootstrap.Services, bootstrap.NewRouter) over the test package's database, and a client whose
// every answer is checked against the API documents in api/openapi. Call dbtest.Main from TestMain.
package apitest

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// userAgent is an ordinary browser's, which every request sends: sign-in scores a request without
// one as a bot.
const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"

// Server is the API under test.
type Server struct {
	t        testing.TB
	handler  http.Handler
	contract *contract
	cfg      *config.Config
}

// Response is one answer, read in full.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Start wires the API as the server does, in development mode, over the test package's database.
func Start(t testing.TB) *Server {
	t.Helper()
	// Errors only: the request log is noise here, and a failure says what it saw.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	cfg := testConfig(t)
	deps, err := bootstrap.Services(dbtest.Context(t), cfg, dbtest.Pool(t))
	if err != nil {
		t.Fatalf("apitest: wire the services: %v", err)
	}
	return &Server{t: t, handler: bootstrap.NewRouter(deps), contract: loadContract(t), cfg: cfg}
}

// testConfig is the development configuration with its defaults, whatever the environment holds:
// make test-db loads .env, so every setting is cleared first and only the database named.
func testConfig(t testing.TB) *config.Config {
	t.Helper()
	fields := reflect.TypeFor[config.Config]()
	for i := range fields.NumField() {
		if key := fields.Field(i).Tag.Get("envconfig"); key != "" {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv("SERVICE_ENV", config.EnvDev)
	t.Setenv("DB_URL", dbtest.DSN(t))
	t.Setenv("SECRETS_KEY", secretsKey())                // one per run: each Start opens what the last one sealed
	t.Setenv("BREACHED_PASSWORD_CHECK", "false")         // no calls out of the test
	t.Setenv("ALLOWED_ORIGINS", "http://localhost:3003") // the hosted login, whose pages send cookies
	t.Setenv("LOGIN_BASE_URL", "http://localhost:3003")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("apitest: load the configuration: %v", err)
	}
	return cfg
}

// secretsKey is a random data key, the same for every Start in this test binary.
var secretsKey = sync.OnceValue(func() string {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(key)
})

// Do sends method path with body (JSON, when not nil) and the bearer token (when not empty), and
// fails the test unless the API documents describe the answer. A 429 is waited out and sent again.
func (s *Server) Do(method, path, token string, body any) *Response {
	s.t.Helper()
	return s.Send(func() *http.Request { return s.request(method, path, token, body) })
}

// Send serves the request build makes, checked as Do checks it. build is called again for the
// check, since serving reads the body.
func (s *Server) Send(build func() *http.Request) *Response {
	s.t.Helper()
	for attempt := 0; ; attempt++ {
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, build())
		if rec.Code == http.StatusTooManyRequests && attempt < 5 {
			wait, _ := strconv.Atoi(rec.Header().Get("Retry-After"))
			time.Sleep(time.Duration(max(wait, 1)) * time.Second)
			continue
		}
		res := &Response{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}
		s.contract.check(s.t, build(), res)
		return res
	}
}

// Form is a form-encoded request to path, for Send.
func (s *Server) Form(method, path string, form url.Values) *http.Request {
	s.t.Helper()
	req := httptest.NewRequestWithContext(dbtest.Context(s.t), method, path, strings.NewReader(form.Encode()))
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func (s *Server) request(method, path, token string, body any) *http.Request {
	s.t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			s.t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequestWithContext(dbtest.Context(s.t), method, path, reader)
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// JSON decodes the body into v, failing the test if it can't.
func (r *Response) JSON(t testing.TB, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		t.Fatalf("apitest: decode %d %s: %v", r.Status, r.Body, err)
	}
}

// Want fails the test unless the answer has status.
func (r *Response) Want(t testing.TB, status int) *Response {
	t.Helper()
	if r.Status != status {
		t.Fatalf("got %d, want %d: %s", r.Status, status, r.Body)
	}
	return r
}
