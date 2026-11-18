package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestPathUUID checks that a route parameter holding a UUID is read, and that
// any other value, or none, answers the caller's own error.
func TestPathUUID(t *testing.T) {
	errInvalid := errors.New("invalid id")
	request := func(value string, set bool) *http.Request {
		rc := chi.NewRouteContext()
		if set {
			rc.URLParams.Add("id", value)
		}
		return httptest.NewRequestWithContext(context.WithValue(context.Background(), chi.RouteCtxKey, rc), http.MethodGet, "/", nil)
	}
	id := uuid.New()
	if got, err := PathUUID(request(id.String(), true), "id", errInvalid); err != nil || got != id {
		t.Errorf("a UUID: %s, %v; want %s", got, err, id)
	}
	for _, c := range []struct {
		value string
		set   bool
	}{{"not-a-uuid", true}, {"", true}, {"", false}} {
		if got, err := PathUUID(request(c.value, c.set), "id", errInvalid); !errors.Is(err, errInvalid) || got != uuid.Nil {
			t.Errorf("%q (set %v): %s, %v; want the given error", c.value, c.set, got, err)
		}
	}
}

// TestPathOrganization checks that the {organizationID} path parameter must name the
// caller's own organization.
func TestPathOrganization(t *testing.T) {
	own, other := uuid.New(), uuid.New()
	request := func(param string, organization *uuid.UUID) *http.Request {
		rc := chi.NewRouteContext()
		rc.URLParams.Add("organizationID", param)
		ctx := context.WithValue(context.Background(), chi.RouteCtxKey, rc)
		if organization != nil {
			ctx = WithPrincipal(ctx, &Principal{ActorType: "user", OrganizationID: organization})
		}
		return httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	}

	if got, err := PathOrganization(request(own.String(), &own)); err != nil || got != own {
		t.Errorf("own organization: %s, %v", got, err)
	}
	if _, err := PathOrganization(request(other.String(), &own)); !errors.Is(err, errs.ErrForbidden) {
		t.Errorf("another organization: %v, want forbidden", err)
	}
	if _, err := PathOrganization(request("not-a-uuid", &own)); !errors.Is(err, errs.ErrBadRequest) {
		t.Errorf("malformed organization: %v, want bad_request", err)
	}
	if _, err := PathOrganization(request(own.String(), nil)); err == nil {
		t.Error("a caller with no organization was let through")
	}
}
