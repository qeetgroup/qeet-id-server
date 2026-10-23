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

// TestPathTenant checks that the {tenantID} path parameter must name the
// caller's own tenant, with the domain's errors where it gives them.
func TestPathTenant(t *testing.T) {
	own, other := uuid.New(), uuid.New()
	request := func(param string, tenant *uuid.UUID) *http.Request {
		rc := chi.NewRouteContext()
		rc.URLParams.Add("tenantID", param)
		ctx := context.WithValue(context.Background(), chi.RouteCtxKey, rc)
		if tenant != nil {
			ctx = WithPrincipal(ctx, &Principal{ActorType: "user", TenantID: tenant})
		}
		return httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	}
	invalid, mismatch := errors.New("invalid"), errors.New("mismatch")

	if got, err := PathTenant(request(own.String(), &own)); err != nil || got != own {
		t.Errorf("own tenant: %s, %v", got, err)
	}
	if _, err := PathTenant(request(other.String(), &own)); !errors.Is(err, errs.ErrForbidden) {
		t.Errorf("another tenant: %v, want forbidden", err)
	}
	if _, err := PathTenant(request("not-a-uuid", &own)); !errors.Is(err, errs.ErrBadRequest) {
		t.Errorf("malformed tenant: %v, want bad_request", err)
	}
	if _, err := PathTenantOr(request(other.String(), &own), invalid, mismatch); !errors.Is(err, mismatch) {
		t.Errorf("another tenant with domain errors: %v, want %v", err, mismatch)
	}
	if _, err := PathTenantOr(request("x", &own), invalid, mismatch); !errors.Is(err, invalid) {
		t.Errorf("malformed tenant with domain errors: %v, want %v", err, invalid)
	}
	if _, err := PathTenant(request(own.String(), nil)); err == nil {
		t.Error("a caller with no tenant was let through")
	}
}
