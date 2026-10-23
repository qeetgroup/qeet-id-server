package httpx

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// TestAccessLogNamesThePrincipal checks that the access line carries the
// principal an authentication middleware below it adds to the request.
func TestAccessLogNamesThePrincipal(t *testing.T) {
	var logs bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })

	userID, tenantID := uuid.New(), uuid.New()
	router := chi.NewRouter()
	router.Use(AccessLog)
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &Principal{UserID: &userID, TenantID: &tenantID, ActorType: "user"}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	})
	router.Get("/v1/me", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/me", nil))

	for _, want := range []string{`"user_id":"` + userID.String() + `"`, `"tenant_id":"` + tenantID.String() + `"`, `"actor_type":"user"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("access log lacks %s: %s", want, logs.String())
		}
	}
}

func TestAccessAndErrorLogsRedactAdminPortalToken(t *testing.T) {
	const secret = "portal-capability-token-must-not-leak"
	var logs bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })

	router := chi.NewRouter()
	router.Use(AccessLog)
	router.Get("/v1/admin-portal/{token}/context", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, errors.New("forced failure"))
	})
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/admin-portal/"+secret+"/context", nil))
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("matched-route logs leaked portal token: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `/v1/admin-portal/{token}/context`) {
		t.Fatalf("logs should retain the safe route pattern: %s", logs.String())
	}

	logs.Reset()
	request := httptest.NewRequest(http.MethodGet, "/v1/admin-portal/"+secret+"/context", nil)
	WriteError(httptest.NewRecorder(), request, errors.New("forced unmatched failure"))
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("unmatched-route error log leaked portal token: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "/v1/admin-portal/{redacted}/context") {
		t.Fatalf("unmatched route should redact the capability segment: %s", logs.String())
	}
}
