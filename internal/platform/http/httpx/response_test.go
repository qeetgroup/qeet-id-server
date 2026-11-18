package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

func TestDecodeJSONLimitsAndTrailingValues(t *testing.T) {
	type body struct {
		Name string `json:"name"`
	}
	valid := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok"}`))
	var decoded body
	if err := DecodeJSONLimit(valid, &decoded, 64); err != nil || decoded.Name != "ok" {
		t.Fatalf("valid JSON decode = %+v, err %v", decoded, err)
	}

	trailing := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok"} {"name":"second"}`))
	if err := DecodeJSONLimit(trailing, &decoded, 128); !errors.Is(err, errs.ErrBadRequest) {
		t.Fatalf("trailing JSON error = %v, want bad request", err)
	}

	oversized := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"`+strings.Repeat("x", 100)+`"}`))
	if err := DecodeJSONLimit(oversized, &decoded, 32); !errors.Is(err, errs.ErrRequestBodyTooLarge) {
		t.Fatalf("known-length oversized JSON error = %v", err)
	}

	chunked := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"`+strings.Repeat("x", 100)+`"}`))
	chunked.ContentLength = -1
	if err := DecodeJSONLimit(chunked, &decoded, 32); !errors.Is(err, errs.ErrRequestBodyTooLarge) {
		t.Fatalf("chunked oversized JSON error = %v", err)
	}
}

func TestParseFormLimit(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("code="+strings.Repeat("x", 128)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := ParseForm(request, 32); !errors.Is(err, errs.ErrRequestBodyTooLarge) {
		t.Fatalf("oversized form error = %v", err)
	}
}

func TestOversizedBodiesMapTo413(t *testing.T) {
	jsonHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		if err := DecodeJSONLimit(r, &body, 32); err != nil {
			WriteError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	jsonRecorder := httptest.NewRecorder()
	jsonRequest := httptest.NewRequest(http.MethodPost, "/json", strings.NewReader(`{"name":"`+strings.Repeat("x", 100)+`"}`))
	jsonHandler.ServeHTTP(jsonRecorder, jsonRequest)
	if jsonRecorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized JSON status = %d, want 413", jsonRecorder.Code)
	}

	formHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := ParseForm(r, 32); err != nil {
			WriteError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	formRecorder := httptest.NewRecorder()
	formRequest := httptest.NewRequest(http.MethodPost, "/form", strings.NewReader("code="+strings.Repeat("x", 128)))
	formRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formHandler.ServeHTTP(formRecorder, formRequest)
	if formRecorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized form status = %d, want 413", formRecorder.Code)
	}
}
