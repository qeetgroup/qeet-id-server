package ssosync

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the group mappings of the organization's SAML and LDAP
// connections.
type Handler struct {
	Service *Service
	// GrantCheck refuses mapping to a group whose roles carry authority the
	// caller doesn't hold (rbac.Repository.CheckGrantGroup): whoever maps a
	// group hands out what it grants. Without it creating a mapping is refused.
	GrantCheck func(ctx context.Context, caller *httpx.Principal, organizationID, groupID uuid.UUID) error
}

// Mount registers the group-mapping routes of both connection kinds on r.
func (h *Handler) Mount(r chi.Router) {
	for _, kind := range []string{"saml", "ldap"} {
		base := "/organizations/{organizationID}/" + kind + "/{id}/group-mappings"
		r.Get(base, h.list(kind))
		r.Post(base, h.create(kind))
		r.Delete(base+"/{mappingID}", h.del(kind))
	}
}

// scope returns the organization in the path, which must be the caller's, and the
// connection's ID.
func scope(r *http.Request) (uuid.UUID, uuid.UUID, error) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	connectionID, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return organizationID, connectionID, nil
}
