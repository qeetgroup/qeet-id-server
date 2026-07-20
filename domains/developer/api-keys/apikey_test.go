package apikey

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/platform/api/rest/errs"
	httpx "github.com/qeetgroup/qeet-id-server/platform/api/rest/httpx"
)

// generateRaw, Verify's malformed-key branch, and Middleware's scheme handling
// all run before any DB access, so they are unit-testable with a nil pool. The
// DB-backed paths (Create/List/Revoke and Verify's happy path) are covered by
// the integration suite.

func TestGenerateRaw_Format(t *testing.T) {
	prefix, secret, full, err := generateRaw()
	if err != nil {
		t.Fatalf("generateRaw: %v", err)
	}

	if !strings.HasPrefix(prefix, "qk_") {
		t.Errorf("prefix %q does not start with qk_", prefix)
	}
	if full != prefix+"."+secret {
		t.Errorf("full %q != prefix.secret (%q.%q)", full, prefix, secret)
	}
	if strings.Count(full, ".") != 1 {
		t.Errorf("full %q must contain exactly one '.' separator", full)
	}
	if strings.Contains(secret, ".") {
		t.Errorf("secret %q must not contain '.' (would break SplitN parsing)", secret)
	}

	// Prefix payload is 6 random bytes; secret is 24 — both base64url (raw).
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(prefix, "qk_"))
	if err != nil {
		t.Errorf("prefix payload not valid base64url: %v", err)
	} else if len(payload) != 6 {
		t.Errorf("prefix payload = %d bytes; want 6", len(payload))
	}
	sb, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		t.Errorf("secret not valid base64url: %v", err)
	} else if len(sb) != 24 {
		t.Errorf("secret = %d bytes; want 24", len(sb))
	}
}

func TestGenerateRaw_Unique(t *testing.T) {
	const n = 2000
	seenFull := make(map[string]bool, n)
	seenPrefix := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		prefix, secret, full, err := generateRaw()
		if err != nil {
			t.Fatalf("generateRaw: %v", err)
		}
		if prefix == secret {
			t.Fatal("prefix and secret must differ")
		}
		if seenFull[full] {
			t.Fatalf("duplicate full key generated after %d iterations", i)
		}
		if seenPrefix[prefix] {
			t.Fatalf("duplicate prefix generated after %d iterations", i)
		}
		seenFull[full] = true
		seenPrefix[prefix] = true
	}
}

func TestVerify_MalformedKey(t *testing.T) {
	// nil pool is safe: the malformed-key branch returns before any query.
	s := &Service{pool: nil}

	for _, raw := range []string{"", "no-dot-here", "qk_onlyprefix"} {
		t.Run("raw="+raw, func(t *testing.T) {
			k, err := s.Verify(context.Background(), raw)
			if k != nil {
				t.Errorf("expected nil key for malformed input, got %+v", k)
			}
			e := errs.As(err)
			if e == nil {
				t.Fatalf("expected an *errs.Error, got %T: %v", err, err)
			}
			if e.Status != http.StatusUnauthorized || e.Code != "unauthorized" {
				t.Errorf("got status=%d code=%q; want 401/unauthorized", e.Status, e.Code)
			}
		})
	}
}

func TestMiddleware_PassesThroughWhenNoApiKeyScheme(t *testing.T) {
	s := &Service{pool: nil} // Verify must never be called on these paths

	for name, authHeader := range map[string]string{
		"no header":     "",
		"bearer scheme": "Bearer some-jwt-token",
		"basic scheme":  "Basic dXNlcjpwYXNz",
	} {
		t.Run(name, func(t *testing.T) {
			var nextCalled bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
					t.Errorf("no principal should be attached, got %+v", p)
				}
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if authHeader != "" {
				req.Header.Set("Authorization", authHeader)
			}
			rec := httptest.NewRecorder()

			s.Middleware(next).ServeHTTP(rec, req)

			if !nextCalled {
				t.Error("next handler was not called")
			}
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d; want 200", rec.Code)
			}
		})
	}
}

func TestMiddleware_RejectsMalformedApiKey(t *testing.T) {
	s := &Service{pool: nil} // malformed key is rejected before any DB access

	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "ApiKey malformed-no-dot")
	rec := httptest.NewRecorder()

	s.Middleware(next).ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next handler must NOT be called when the api key is rejected")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", rec.Code)
	}
}
