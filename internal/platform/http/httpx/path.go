package httpx

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// PathUUID returns the UUID in r's route parameter name, or invalid (the
// handler's own bad-request error) when the parameter is not one.
func PathUUID(r *http.Request, name string, invalid error) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		return uuid.Nil, invalid
	}
	return id, nil
}

// PathOrganization returns the caller's organization once the {organizationID} path parameter
// names it: bad_request for a malformed parameter, forbidden for another
// organization's. It repeats EnforceOrganizationScope's check inside a handler.
func PathOrganization(r *http.Request) (uuid.UUID, error) {
	pathOrganization, err := PathUUID(r, "organizationID", errs.ErrBadRequest.WithDetail("invalid organizationID"))
	if err != nil {
		return uuid.Nil, err
	}
	scope, err := RequireOrganization(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathOrganization != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("organization mismatch")
	}
	return scope, nil
}
