//go:build integration

package dbtest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Principal is a signed-in user acting in tenant.
func Principal(userID, tenant uuid.UUID) *httpx.Principal {
	return &httpx.Principal{UserID: &userID, TenantID: &tenant, ActorType: "user", Subject: userID.String()}
}

// Serve returns a router that runs the routes mount registers as p, behind the
// same tenant-scope guard as the authenticated /v1 routes.
func Serve(p *httpx.Principal, mount func(chi.Router)) http.Handler {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
			})
		})
		r.Use(httpx.EnforceTenantScope)
		mount(r)
	})
	return r
}

// Do sends a request to h, with body (when not nil) encoded as JSON, under the
// per-test deadline of Context.
func Do(t testing.TB, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatalf("dbtest: encode body: %v", err)
		}
	}
	req := httptest.NewRequestWithContext(Context(t), method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Decode decodes rec's JSON body into v.
func Decode(t testing.TB, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("dbtest: decode %d response: %v\nbody: %s", rec.Code, err, rec.Body.String())
	}
}

// IDs returns the "id" of every element of the response's "items" array.
func IDs(t testing.TB, rec *httptest.ResponseRecorder) []uuid.UUID {
	t.Helper()
	var page struct {
		Items []struct {
			ID uuid.UUID `json:"id"`
		} `json:"items"`
	}
	Decode(t, rec, &page)
	ids := make([]uuid.UUID, len(page.Items))
	for i, item := range page.Items {
		ids[i] = item.ID
	}
	return ids
}
