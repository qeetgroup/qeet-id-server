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

// TestPathOrganization checks that the {tenantID} path parameter must name the
// caller's own organization, with the domain's errors where it gives them.
func TestPathOrganization(t *testing.T) {
	own, other := uuid.New(), uuid.New()
	request := func(param string, organization *uuid.UUID) *http.Request {
		rc := chi.NewRouteContext()
		rc.URLParams.Add("tenantID", param)
		ctx := context.WithValue(context.Background(), chi.RouteCtxKey, rc)
		if organization != nil {
			ctx = WithPrincipal(ctx, &Principal{ActorType: "user", OrganizationID: organization})
		}
		return httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	}
	invalid, mismatch := errors.New("invalid"), errors.New("mismatch")

	if got, err := PathOrganization(request(own.String(), &own)); err != nil || got != own {
		t.Errorf("own tenant: %s, %v", got, err)
	}
	if _, err := PathOrganization(request(other.String(), &own)); !errors.Is(err, errs.ErrForbidden) {
		t.Errorf("another tenant: %v, want forbidden", err)
	}
	if _, err := PathOrganization(request("not-a-uuid", &own)); !errors.Is(err, errs.ErrBadRequest) {
		t.Errorf("malformed tenant: %v, want bad_request", err)
	}
	if _, err := PathOrganizationOr(request(other.String(), &own), invalid, mismatch); !errors.Is(err, mismatch) {
		t.Errorf("another tenant with domain errors: %v, want %v", err, mismatch)
	}
	if _, err := PathOrganizationOr(request("x", &own), invalid, mismatch); !errors.Is(err, invalid) {
		t.Errorf("malformed tenant with domain errors: %v, want %v", err, invalid)
	}
	if _, err := PathOrganization(request(own.String(), nil)); err == nil {
		t.Error("a caller with no tenant was let through")
	}
}
