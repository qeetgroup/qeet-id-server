package saml

// Who may sign in to an organization's service provider. One set to assigned
// people only (assignment_required) signs in the people of the organization
// assigned to it, directly or through a group of it they belong to; any other
// service provider signs in every one of them.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// SPAssignments is who is assigned to a service provider: people, and groups
// whose members are.
type SPAssignments struct {
	Users  []SPUserAssignment  `json:"users"`
	Groups []SPGroupAssignment `json:"groups"`
}

// SPUserAssignment is a person assigned to a service provider.
type SPUserAssignment struct {
	UserID      uuid.UUID  `json:"user_id"`
	Email       string     `json:"email"`
	DisplayName *string    `json:"display_name"`
	AssignedAt  time.Time  `json:"assigned_at"`
	AssignedBy  *uuid.UUID `json:"assigned_by"`
}

// SPGroupAssignment is a group whose members are assigned to a service provider.
type SPGroupAssignment struct {
	GroupID    uuid.UUID  `json:"group_id"`
	Name       string     `json:"name"`
	AssignedAt time.Time  `json:"assigned_at"`
	AssignedBy *uuid.UUID `json:"assigned_by"`
}

// assigned reports whether userID is assigned to sp, themselves or through a
// group of sp's organization.
func (i *IdP) assigned(ctx context.Context, sp *ServiceProvider, userID uuid.UUID) (bool, error) {
	return i.q.IsAssignedToSamlSP(ctx, dbgen.IsAssignedToSamlSPParams{OrganizationID: sp.OrganizationID, SpID: sp.ID, UserID: userID})
}

// ListAssignments returns who is assigned to the organization's service provider spID.
func (i *IdP) ListAssignments(ctx context.Context, organizationID, spID uuid.UUID) (*SPAssignments, error) {
	if _, err := i.GetSP(ctx, spID, organizationID); err != nil {
		return nil, err
	}
	users, err := i.q.ListSamlSPUserAssignments(ctx, dbgen.ListSamlSPUserAssignmentsParams{OrganizationID: organizationID, SpID: spID})
	if err != nil {
		return nil, err
	}
	groups, err := i.q.ListSamlSPGroupAssignments(ctx, dbgen.ListSamlSPGroupAssignmentsParams{OrganizationID: organizationID, SpID: spID})
	if err != nil {
		return nil, err
	}
	out := &SPAssignments{Users: make([]SPUserAssignment, len(users)), Groups: make([]SPGroupAssignment, len(groups))}
	for j, u := range users {
		out.Users[j] = SPUserAssignment{UserID: u.UserID, Email: u.Email, DisplayName: u.DisplayName, AssignedAt: u.AssignedAt, AssignedBy: u.AssignedBy}
	}
	for j, g := range groups {
		out.Groups[j] = SPGroupAssignment{GroupID: g.GroupID, Name: g.Name, AssignedAt: g.AssignedAt, AssignedBy: g.AssignedBy}
	}
	return out, nil
}

// requireSP is ErrNotFound unless spID is one of the organization's service
// providers.
func requireSP(ctx context.Context, q *dbgen.Queries, organizationID, spID uuid.UUID) error {
	_, err := q.GetSamlSP(ctx, dbgen.GetSamlSPParams{ID: spID, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	return err
}

// AssignUser assigns the person userID, whose home must be the organization, to its
// service provider spID, recorded as actor's when they weren't already.
func (i *IdP) AssignUser(ctx context.Context, organizationID, spID, userID uuid.UUID, actor audit.Actor) error {
	return i.changeAssignment(ctx, actor, organizationID, spID, "saml.sp_user_assigned", map[string]any{"user_id": userID},
		func(q *dbgen.Queries) (bool, error) {
			return assignUser(ctx, q, organizationID, spID, userID, actor.UserID)
		})
}

// UnassignUser removes the person userID's own assignment to the organization's
// service provider spID, recorded as actor's; one through a group stays.
func (i *IdP) UnassignUser(ctx context.Context, organizationID, spID, userID uuid.UUID, actor audit.Actor) error {
	return i.changeAssignment(ctx, actor, organizationID, spID, "saml.sp_user_unassigned", map[string]any{"user_id": userID},
		func(q *dbgen.Queries) (bool, error) { return true, unassignUser(ctx, q, organizationID, spID, userID) })
}

// AssignGroup assigns the members of the organization's group groupID to its
// service provider spID, recorded as actor's when it wasn't already.
func (i *IdP) AssignGroup(ctx context.Context, organizationID, spID, groupID uuid.UUID, actor audit.Actor) error {
	return i.changeAssignment(ctx, actor, organizationID, spID, "saml.sp_group_assigned", map[string]any{"group_id": groupID},
		func(q *dbgen.Queries) (bool, error) {
			return assignGroup(ctx, q, organizationID, spID, groupID, actor.UserID)
		})
}

// UnassignGroup removes the group groupID's assignment to the organization's
// service provider spID, recorded as actor's.
func (i *IdP) UnassignGroup(ctx context.Context, organizationID, spID, groupID uuid.UUID, actor audit.Actor) error {
	return i.changeAssignment(ctx, actor, organizationID, spID, "saml.sp_group_unassigned", map[string]any{"group_id": groupID},
		func(q *dbgen.Queries) (bool, error) {
			return true, unassignGroup(ctx, q, organizationID, spID, groupID)
		})
}

// changeAssignment makes one assignment change to the organization's service
// provider spID in a transaction, auditing it as actor's action when change
// reports it changed anything.
func (i *IdP) changeAssignment(ctx context.Context, actor audit.Actor, organizationID, spID uuid.UUID, action string, meta map[string]any, change func(*dbgen.Queries) (bool, error)) error {
	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	changed, err := change(i.q.WithTx(tx))
	if err != nil {
		return err
	}
	if changed {
		if err := recordSPChange(ctx, tx, actor, organizationID, spID, action, meta); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// assignUser assigns userID to spID through q, reporting whether they weren't
// already.
func assignUser(ctx context.Context, q *dbgen.Queries, organizationID, spID, userID uuid.UUID, by *uuid.UUID) (bool, error) {
	if err := requireSP(ctx, q, organizationID, spID); err != nil {
		return false, err
	}
	ok, err := q.IsSamlAssignableUser(ctx, dbgen.IsSamlAssignableUserParams{UserID: userID, OrganizationID: &organizationID})
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrAssigneeNotFound
	}
	n, err := q.InsertSamlSPUserAssignment(ctx, dbgen.InsertSamlSPUserAssignmentParams{
		OrganizationID: organizationID, SpID: spID, UserID: userID, AssignedBy: by,
	})
	return n > 0, err
}

// unassignUser removes userID's own assignment to spID through q.
func unassignUser(ctx context.Context, q *dbgen.Queries, organizationID, spID, userID uuid.UUID) error {
	if err := requireSP(ctx, q, organizationID, spID); err != nil {
		return err
	}
	n, err := q.DeleteSamlSPUserAssignment(ctx, dbgen.DeleteSamlSPUserAssignmentParams{OrganizationID: organizationID, SpID: spID, UserID: userID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// assignGroup assigns groupID to spID through q, reporting whether it wasn't
// already.
func assignGroup(ctx context.Context, q *dbgen.Queries, organizationID, spID, groupID uuid.UUID, by *uuid.UUID) (bool, error) {
	if err := requireSP(ctx, q, organizationID, spID); err != nil {
		return false, err
	}
	ok, err := q.IsSamlAssignableGroup(ctx, dbgen.IsSamlAssignableGroupParams{GroupID: groupID, OrganizationID: organizationID})
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrAssigneeNotFound
	}
	n, err := q.InsertSamlSPGroupAssignment(ctx, dbgen.InsertSamlSPGroupAssignmentParams{
		OrganizationID: organizationID, SpID: spID, GroupID: groupID, AssignedBy: by,
	})
	return n > 0, err
}

// unassignGroup removes groupID's assignment to spID through q.
func unassignGroup(ctx context.Context, q *dbgen.Queries, organizationID, spID, groupID uuid.UUID) error {
	if err := requireSP(ctx, q, organizationID, spID); err != nil {
		return err
	}
	n, err := q.DeleteSamlSPGroupAssignment(ctx, dbgen.DeleteSamlSPGroupAssignmentParams{OrganizationID: organizationID, SpID: spID, GroupID: groupID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// =====================================================================
// Assignment admin handlers (user-JWT, organization-scoped)
// =====================================================================

func (h *Handler) listSPAssignments(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	spID, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.IdP.ListAssignments(r.Context(), organizationID, spID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) assignSPUser(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, "userID", h.IdP.AssignUser)
}

func (h *Handler) unassignSPUser(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, "userID", h.IdP.UnassignUser)
}

func (h *Handler) assignSPGroup(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, "groupID", h.IdP.AssignGroup)
}

func (h *Handler) unassignSPGroup(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, "groupID", h.IdP.UnassignGroup)
}

// changeAssignment applies change to the service provider and the person or
// group the path's param names, as the caller, and answers 204.
func (h *Handler) changeAssignment(w http.ResponseWriter, r *http.Request, param string, change func(ctx context.Context, organizationID, spID, id uuid.UUID, actor audit.Actor) error) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	spID, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, param, ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := change(r.Context(), organizationID, spID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
