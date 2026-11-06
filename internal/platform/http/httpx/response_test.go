package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestWriteErrorTellsAnOverloadedClientWhenToRetry checks that server.overloaded,
// however deeply wrapped, is answered 503 with a Retry-After of 1 to
// overloadRetryAfter seconds, in the header and in the body's metadata.
func TestWriteErrorTellsAnOverloadedClientWhenToRetry(t *testing.T) {
	for range 20 {
		rec := httptest.NewRecorder()
		WriteError(rec, httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil), fmt.Errorf("sign in: %w", errs.ErrServerOverloaded))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", rec.Code)
		}
		retry, err := strconv.Atoi(rec.Header().Get("Retry-After"))
		if err != nil || retry < 1 || retry > overloadRetryAfter {
			t.Fatalf("Retry-After %q, want 1..%d", rec.Header().Get("Retry-After"), overloadRetryAfter)
		}
		var body struct {
			Error struct {
				Code      string         `json:"code"`
				Retryable bool           `json:"retryable"`
				Metadata  map[string]any `json:"metadata"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Error.Code != errs.CodeServerOverloaded || !body.Error.Retryable || body.Error.Metadata["retry_after"] != float64(retry) {
			t.Fatalf("body %s, want server.overloaded, retryable, retry_after %d", rec.Body, retry)
		}
	}

	rec := httptest.NewRecorder()
	WriteError(rec, httptest.NewRequest(http.MethodGet, "/", nil), errs.ErrNotFound)
	if got := rec.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After %q on a 404, want none", got)
	}
}

// TestWriteErrorAnswersAnAbandonedRequest499: work cancelled because the client
// went away is not a server fault, so it is not a 500; the same cancellation
// while the client is still waiting is.
func TestWriteErrorAnswersAnAbandonedRequest499(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	gone := httptest.NewRequest(http.MethodPost, "/v1/mfa/push/pairing/claim", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	WriteError(rec, gone, fmt.Errorf("claim: %w", context.Canceled))
	if rec.Code != StatusClientClosedRequest {
		t.Errorf("client gone: status %d, want %d", rec.Code, StatusClientClosedRequest)
	}

	waiting := httptest.NewRequest(http.MethodPost, "/v1/mfa/push/pairing/claim", nil)
	rec = httptest.NewRecorder()
	WriteError(rec, waiting, fmt.Errorf("claim: %w", context.Canceled))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("client still waiting: status %d, want 500", rec.Code)
	}
}
