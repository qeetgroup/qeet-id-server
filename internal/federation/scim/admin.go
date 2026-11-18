package scim

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// adminUser is the plain (non-SCIM-envelope) shape the admin console renders.
type adminUser struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName *string   `json:"display_name"`
	Status      string    `json:"status"`
	ExternalID  *string   `json:"external_id"`
	CreatedAt   time.Time `json:"created_at"`
}

// adminPage is a console page of a list: its items, the next page's cursor,
// and how many there are.
type adminPage[T any] struct {
	paging.Result[T]
	Total int `json:"total"`
}

// adminWindow reads a console list's limit (1..maxPageCount, default 50) and
// cursor.
func adminWindow(r *http.Request) (int, paging.Cursor, error) {
	after, err := paging.ParseCursor(r.URL.Query())
	return paging.Limit(r.URL.Query(), 50, maxPageCount), after, err
}

// adminUsers is a page of the organization's provisioned users, newest first,
// limit long, after the cursor.
func (s *Service) adminUsers(ctx context.Context, organizationID uuid.UUID, limit int, after paging.Cursor) (*adminPage[adminUser], error) {
	total, err := s.q.CountProvisionedUsers(ctx, &organizationID)
	if err != nil {
		return nil, err
	}
	params := dbgen.ListProvisionedUsersPageParams{OrganizationID: &organizationID, Lim: int32(limit + 1)} // #nosec G115 -- at most maxPageCount+1
	params.BeforeTs, params.BeforeID = after.Before()
	rows, err := s.q.ListProvisionedUsersPage(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]adminUser, len(rows))
	for i, r := range rows {
		items[i] = adminUser(r)
	}
	return &adminPage[adminUser]{
		Result: paging.Page(paging.Next(items, limit, func(u adminUser) (time.Time, uuid.UUID) { return u.CreatedAt, u.ID })),
		Total:  int(total),
	}, nil
}

// adminGroups is a page of the groups the organization's SCIM made, newest
// first, each with its count of live members, limit long, after the cursor.
func (s *Service) adminGroups(ctx context.Context, organizationID uuid.UUID, limit int, after paging.Cursor) (*adminPage[adminGroup], error) {
	total, err := s.q.CountScimGroups(ctx, dbgen.CountScimGroupsParams{OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	params := dbgen.ListScimGroupsPageParams{OrganizationID: organizationID, Lim: int32(limit + 1)} // #nosec G115 -- at most maxPageCount+1
	params.BeforeTs, params.BeforeID = after.Before()
	rows, err := s.q.ListScimGroupsPage(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]adminGroup, len(rows))
	for i, r := range rows {
		items[i] = adminGroup{ID: r.ID, Name: r.Name, ExternalID: r.ExternalID, Members: int(r.Members), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	}
	return &adminPage[adminGroup]{
		Result: paging.Page(paging.Next(items, limit, func(g adminGroup) (time.Time, uuid.UUID) { return g.CreatedAt, g.ID })),
		Total:  int(total),
	}, nil
}

// adminListUsers returns a page of this organization's SCIM-provisioned users for the
// admin UI, newest first, with how many there are.
func (h *Handler) adminListUsers(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limit, after, err := adminWindow(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	page, err := h.Service.adminUsers(r.Context(), organizationID, limit, after)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// adminGroup is a group SCIM made, as the console lists it.
type adminGroup struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	ExternalID *string   `json:"external_id"`
	Members    int       `json:"members"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// adminListGroups returns a page of the groups this organization's SCIM made, newest
// first, each with its count of live members, and how many there are.
func (h *Handler) adminListGroups(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limit, after, err := adminWindow(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	page, err := h.Service.adminGroups(r.Context(), organizationID, limit, after)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

func (h *Handler) config(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cfg, err := h.Service.Config(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	_, full, err := h.Service.Rotate(ctx, organizationID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cfg, err := h.Service.Config(ctx, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"token": full, "config": cfg})
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Revoke(r.Context(), organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func tokenID(r *http.Request) (uuid.UUID, error) {
	return httpx.PathUUID(r, "id", ErrTokenIDInvalid)
}

func (h *Handler) listTokens(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tokens, err := h.Service.Tokens(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(tokens))
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in TokenInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	t, full, err := h.Service.CreateToken(r.Context(), organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"token": full, "scim_token": t})
}

func (h *Handler) rotateToken(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := tokenID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in RotateInput
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &in); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	fresh, old, full, err := h.Service.RotateToken(r.Context(), organizationID, id, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"token": full, "scim_token": fresh, "replaced": old})
}

func (h *Handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := tokenID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if _, err := h.Service.RevokeToken(r.Context(), organizationID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
