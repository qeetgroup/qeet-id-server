package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sign, truncate, and deliver carry the security-critical webhook contract
// (HMAC-SHA256 body signature + headers) and need no DB, so they are
// unit-tested here. The DB-backed dispatcher/queue paths live in integration.

func TestSign_MatchesHMACSHA256Hex(t *testing.T) {
	secret := "whsec_abc123"
	body := []byte(`{"event":"user.created","id":"01J"}`)

	// Independently recompute with HMAC-SHA256 → hex. This guards against
	// algorithm drift (sha1/md5) and encoding drift (base64 vs hex).
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	got := sign(secret, body)
	if got != want {
		t.Errorf("sign = %q; want %q", got, want)
	}
	if len(got) != 64 {
		t.Errorf("signature length = %d; want 64 hex chars (sha256)", len(got))
	}
	if got != strings.ToLower(got) {
		t.Errorf("signature %q must be lowercase hex", got)
	}
}

func TestSign_Deterministic(t *testing.T) {
	secret, body := "s", []byte("payload")
	if sign(secret, body) != sign(secret, body) {
		t.Error("sign must be deterministic for the same secret+body")
	}
}

func TestSign_SensitiveToSecretAndBody(t *testing.T) {
	body := []byte(`{"a":1}`)
	if sign("secret-A", body) == sign("secret-B", body) {
		t.Error("different secrets must produce different signatures")
	}
	if sign("secret", []byte(`{"a":1}`)) == sign("secret", []byte(`{"a":2}`)) {
		t.Error("different bodies must produce different signatures")
	}
}

func TestSign_EmptyBody(t *testing.T) {
	// Empty body still yields a valid 64-char HMAC (an empty message is signed).
	if got := sign("secret", []byte{}); len(got) != 64 {
		t.Errorf("empty-body signature length = %d; want 64", len(got))
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"", 5, ""},
		{"abc", 5, "abc"},
		{"abcde", 5, "abcde"},
		{"abcdef", 5, "abcde"},
		{"abcdef", 0, ""},
	}
	for _, c := range cases {
		if got := truncate(c.in, c.max); got != c.want {
			t.Errorf("truncate(%q, %d) = %q; want %q", c.in, c.max, got, c.want)
		}
	}
}

func TestDeliver_SignsBodyAndSetsHeaders(t *testing.T) {
	secret := "whsec_delivery"
	body := []byte(`{"event":"ping","n":42}`)
	eventType := "webhook.test"

	var (
		gotMethod, gotCT, gotEvent, gotSig string
		gotBody                            []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotEvent = r.Header.Get("X-Qeet-Event")
		gotSig = r.Header.Get("X-Qeet-Signature")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := &Service{client: &http.Client{Timeout: 5 * time.Second}}
	status, respBody, err := s.deliver(context.Background(), srv.URL, secret, eventType, body)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d; want 200", status)
	}
	if respBody != "ok" {
		t.Errorf("respBody = %q; want %q", respBody, "ok")
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q; want POST", gotMethod)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q; want application/json", gotCT)
	}
	if gotEvent != eventType {
		t.Errorf("X-Qeet-Event = %q; want %q", gotEvent, eventType)
	}
	if string(gotBody) != string(body) {
		t.Errorf("delivered body = %q; want %q", gotBody, body)
	}
	// The signature header must be sha256= over the EXACT bytes sent.
	wantSig := "sha256=" + sign(secret, body)
	if gotSig != wantSig {
		t.Errorf("X-Qeet-Signature = %q; want %q", gotSig, wantSig)
	}
}

func TestDeliver_Non2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	s := &Service{client: &http.Client{Timeout: 5 * time.Second}}
	status, respBody, err := s.deliver(context.Background(), srv.URL, "secret", "evt", []byte("{}"))
	if err == nil {
		t.Error("expected an error for a non-2xx response")
	}
	if status != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", status)
	}
	if respBody != "boom" {
		t.Errorf("respBody = %q; want %q", respBody, "boom")
	}
}
