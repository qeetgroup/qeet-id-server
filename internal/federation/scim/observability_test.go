package scim

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type observerFixture struct {
	tenant    uuid.UUID
	status    int
	resource  string
	operation string
	reason    string
	calls     int
	err       error
}

func (observer *observerFixture) RecordSCIMOperation(_ context.Context, op Operation) error {
	observer.tenant, observer.status, observer.resource, observer.operation = op.TenantID, op.Status, op.Resource, op.Operation
	observer.reason = op.Reason
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

// TestObserverKeepsTheSCIMErrorType checks that a change refused with a SCIM
// error type is recorded with it as its reason.
func TestObserverKeepsTheSCIMErrorType(test *testing.T) {
	observer := &observerFixture{}
	handler := &Handler{Service: &Service{observer: observer}}
	request := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", nil)
	request = request.WithContext(context.WithValue(request.Context(), tenantCtxKey, uuid.New()))
	handler.observeMutations(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		writeSCIMTypedErr(response, http.StatusConflict, "uniqueness", "a user with that userName exists")
	})).ServeHTTP(httptest.NewRecorder(), request)
	if observer.status != http.StatusConflict || observer.reason != "scim.uniqueness" {
		test.Fatalf("a refused change recorded as %d %q; want 409 scim.uniqueness", observer.status, observer.reason)
	}
}
