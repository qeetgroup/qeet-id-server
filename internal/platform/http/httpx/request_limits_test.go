package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

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
