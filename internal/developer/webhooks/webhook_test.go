package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// sign, truncate, and deliver carry the security-critical webhook contract
// (HMAC-SHA256 signature over the timestamp and body, and the headers) and
// need no DB, so they are unit-tested here. The DB-backed dispatcher/queue
// paths live in integration.

func TestSign_MatchesHMACSHA256Hex(t *testing.T) {
	secret := "whsec_abc123"
	body := []byte(`{"event":"user.created","id":"01J"}`)

	// Independently recompute with HMAC-SHA256 → hex over "timestamp.body".
	// This guards against algorithm drift (sha1/md5), encoding drift (base64
	// vs hex) and the timestamp falling out of what is signed.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("1700000000." + string(body)))
	want := hex.EncodeToString(mac.Sum(nil))

	got := sign(secret, "1700000000", body)
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
	first := sign(secret, "1", body)
	second := sign(secret, "1", body)
	if first != second {
		t.Error("sign must be deterministic for the same secret+body")
	}
}

func TestSign_SensitiveToSecretTimestampAndBody(t *testing.T) {
	body := []byte(`{"a":1}`)
	if sign("secret-A", "1", body) == sign("secret-B", "1", body) {
		t.Error("different secrets must produce different signatures")
	}
	if sign("secret", "1", body) == sign("secret", "2", body) {
		t.Error("different timestamps must produce different signatures")
	}
	if sign("secret", "1", []byte(`{"a":1}`)) == sign("secret", "1", []byte(`{"a":2}`)) {
		t.Error("different bodies must produce different signatures")
	}
}

func TestSign_EmptyBody(t *testing.T) {
	// Empty body still yields a valid 64-char HMAC (an empty message is signed).
	if got := sign("secret", "1", []byte{}); len(got) != 64 {
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
		gotMethod, gotCT, gotEvent, gotDeliveryID, gotSig, gotTimestamp string
		gotBody                                                         []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotEvent = r.Header.Get("X-Qeet-Event")
		gotDeliveryID = r.Header.Get("X-Qeet-Delivery-ID")
		gotSig = r.Header.Get("X-Qeet-Signature")
		gotTimestamp = r.Header.Get("X-Qeet-Timestamp")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := &Service{client: &http.Client{Timeout: 5 * time.Second}}
	deliveryID := uuid.New()
	status, respBody, err := s.deliver(context.Background(), deliveryID, srv.URL, secret, eventType, body)
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
	if gotDeliveryID != deliveryID.String() {
		t.Errorf("X-Qeet-Delivery-ID = %q; want %q", gotDeliveryID, deliveryID)
	}
	if string(gotBody) != string(body) {
		t.Errorf("delivered body = %q; want %q", gotBody, body)
	}
	// The signature header must be sha256= over the timestamp sent and the
	// EXACT bytes sent, and the timestamp must be the time of sending.
	if sent, err := strconv.ParseInt(gotTimestamp, 10, 64); err != nil || time.Since(time.Unix(sent, 0)).Abs() > time.Minute {
		t.Errorf("X-Qeet-Timestamp = %q; want the Unix time of sending", gotTimestamp)
	}
	wantSig := "sha256=" + sign(secret, gotTimestamp, body)
	if gotSig != wantSig {
		t.Errorf("X-Qeet-Signature = %q; want %q", gotSig, wantSig)
	}
}

// TestRetryable checks that only an answer that may change is retried: no
// answer, a redirect, a 5xx, 408 and 429, never another 4xx.
func TestRetryable(t *testing.T) {
	for status, want := range map[int]bool{
		0: true, 302: true, 500: true, 503: true, 408: true, 429: true,
		400: false, 401: false, 404: false, 410: false, 422: false,
	} {
		if got := retryable(status); got != want {
			t.Errorf("retryable(%d) = %v; want %v", status, got, want)
		}
	}
}

// TestJittered checks that a backoff keeps between half and all of itself.
func TestJittered(t *testing.T) {
	for range 100 {
		if got := jittered(time.Minute); got < 30*time.Second || got > time.Minute {
			t.Fatalf("jittered(1m) = %s; want 30s..1m", got)
		}
	}
}

// TestSubscribableEvents checks that a subscription names at least one event,
// only ones in the catalogue, each once, and never the test event.
func TestSubscribableEvents(t *testing.T) {
	got, err := subscribableEvents([]string{"user.created", "session.revoked", "user.created"})
	if err != nil || !slices.Equal(got, []string{"user.created", "session.revoked"}) {
		t.Errorf("subscribableEvents = %v, %v; want the two events once each", got, err)
	}
	if _, err := subscribableEvents(nil); !errors.Is(err, errs.ErrWebhookEventsRequired) {
		t.Errorf("no events: %v; want %v", err, errs.ErrWebhookEventsRequired)
	}
	for _, name := range []string{"user.exploded", TestEvent, ""} {
		if _, err := subscribableEvents([]string{name}); !errors.Is(err, errs.ErrWebhookEventUnknown) {
			t.Errorf("%q: %v; want %v", name, err, errs.ErrWebhookEventUnknown)
		}
	}
}

func TestDeliver_Non2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	s := &Service{client: &http.Client{Timeout: 5 * time.Second}}
	status, respBody, err := s.deliver(context.Background(), uuid.New(), srv.URL, "secret", "evt", []byte("{}"))
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
