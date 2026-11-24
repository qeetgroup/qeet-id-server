package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/requestsig"
)

// deliver carries the security-critical webhook contract (the
// headers, signed with requestsig over the timestamp and body) and need no
// DB, so they are unit-tested here. The DB-backed dispatcher/queue paths live
// in integration.

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
	status, respBody, err := s.deliver(context.Background(), deliveryID, srv.URL, []string{secret}, eventType, body)
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
	wantSig := "sha256=" + requestsig.Sign(secret, gotTimestamp, body)
	if gotSig != wantSig {
		t.Errorf("X-Qeet-Signature = %q; want %q", gotSig, wantSig)
	}
}

// TestDeliver_SignsWithEachSecret checks that while a rotated-out secret
// overlaps the new one, the signature header holds a value for each, in order.
func TestDeliver_SignsWithEachSecret(t *testing.T) {
	var gotSig, gotTimestamp string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig, gotTimestamp = r.Header.Get("X-Qeet-Signature"), r.Header.Get("X-Qeet-Timestamp")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	body := []byte(`{"id":"1"}`)
	s := &Service{client: &http.Client{Timeout: 5 * time.Second}}
	if _, _, err := s.deliver(context.Background(), uuid.New(), srv.URL, []string{"new", "old"}, "evt", body); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	want := "sha256=" + requestsig.Sign("new", gotTimestamp, body) + ",sha256=" + requestsig.Sign("old", gotTimestamp, body)
	if gotSig != want {
		t.Errorf("X-Qeet-Signature = %q; want %q", gotSig, want)
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

func TestDeliver_Non2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	s := &Service{client: &http.Client{Timeout: 5 * time.Second}}
	status, respBody, err := s.deliver(context.Background(), uuid.New(), srv.URL, []string{"secret"}, "evt", []byte("{}"))
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
