package scim

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type observerFixture struct {
	tenant    uuid.UUID
	status    int
	resource  string
	operation string
	calls     int
	err       error
}

func (observer *observerFixture) RecordOperation(_ context.Context, tenant uuid.UUID, _ string, operation, resource, _ string, status int, _ time.Time, _ time.Duration) error {
	observer.tenant, observer.status, observer.resource, observer.operation = tenant, status, resource, operation
	observer.calls++
	return observer.err
}

func TestObserverPreservesProtocolResponseWhenTelemetryFails(test *testing.T) {
	observer := &observerFixture{err: errors.New("telemetry unavailable")}
	handler := &Handler{Service: &Service{observer: observer}}
	tenantID := uuid.New()
	request := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{"password":"never-observed"}`))
	request = request.WithContext(context.WithValue(request.Context(), tenantCtxKey, tenantID))
	response := httptest.NewRecorder()
	handler.observeMutations(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/scim+json")
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{"id":"created"}`))
	})).ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Body.String() != `{"id":"created"}` {
		test.Fatal("observer changed the SCIM response")
	}
	if observer.calls != 1 || observer.tenant != tenantID || observer.status != 201 || observer.resource != "user" || observer.operation != "post" {
		test.Fatalf("unexpected observation: %+v", observer)
	}
}

func TestObserverDoesNotRecordReadsOrUnauthenticatedRequests(test *testing.T) {
	for _, authenticated := range []bool{false, true} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			observer := &observerFixture{}
			handler := &Handler{Service: &Service{observer: observer}}
			request := httptest.NewRequest(method, "/scim/v2/Groups", nil)
			if authenticated {
				request = request.WithContext(context.WithValue(request.Context(), tenantCtxKey, uuid.New()))
			}
			handler.observeMutations(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusConflict) })).ServeHTTP(httptest.NewRecorder(), request)
			want := 0
			if authenticated && method == http.MethodPost {
				want = 1
			}
			if observer.calls != want {
				test.Fatalf("authenticated=%v method=%s observed=%d", authenticated, method, observer.calls)
			}
		}
	}
}
