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

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
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
		out.Users[j] = SPUserAssignment{UserID: u.UserID, Email: u.Email, DisplayName: u.DisplayName, AssignedAt: u.AssignedAt, AssignedBy: optionalUUID(u.AssignedBy)}
	}
	for j, g := range groups {
		out.Groups[j] = SPGroupAssignment{GroupID: g.GroupID, Name: g.Name, AssignedAt: g.AssignedAt, AssignedBy: optionalUUID(g.AssignedBy)}
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
// service provider spID within tx, reporting whether they weren't already.
func (i *IdP) AssignUser(ctx context.Context, tx pgx.Tx, organizationID, spID, userID uuid.UUID, by *uuid.UUID) (bool, error) {
	q := i.q.WithTx(tx)
	if err := requireSP(ctx, q, organizationID, spID); err != nil {
		return false, err
	}
	ok, err := q.IsSamlAssignableUser(ctx, dbgen.IsSamlAssignableUserParams{UserID: userID, OrganizationID: pgtype.UUID{Bytes: organizationID, Valid: true}})
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errs.ErrSAMLAssigneeNotFound
	}
	n, err := q.InsertSamlSPUserAssignment(ctx, dbgen.InsertSamlSPUserAssignmentParams{
		OrganizationID: organizationID, SpID: spID, UserID: userID, AssignedBy: pgUUID(by),
	})
	return n > 0, err
}

// UnassignUser removes the person userID's own assignment to the organization's
// service provider spID within tx; one through a group stays.
func (i *IdP) UnassignUser(ctx context.Context, tx pgx.Tx, organizationID, spID, userID uuid.UUID) error {
	q := i.q.WithTx(tx)
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

// AssignGroup assigns the members of the organization's group groupID to its service
// provider spID within tx, reporting whether it wasn't already.
func (i *IdP) AssignGroup(ctx context.Context, tx pgx.Tx, organizationID, spID, groupID uuid.UUID, by *uuid.UUID) (bool, error) {
	q := i.q.WithTx(tx)
	if err := requireSP(ctx, q, organizationID, spID); err != nil {
		return false, err
	}
	ok, err := q.IsSamlAssignableGroup(ctx, dbgen.IsSamlAssignableGroupParams{GroupID: groupID, OrganizationID: organizationID})
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errs.ErrSAMLAssigneeNotFound
	}
	n, err := q.InsertSamlSPGroupAssignment(ctx, dbgen.InsertSamlSPGroupAssignmentParams{
		OrganizationID: organizationID, SpID: spID, GroupID: groupID, AssignedBy: pgUUID(by),
	})
	return n > 0, err
}

// UnassignGroup removes the group groupID's assignment to the organization's service
// provider spID within tx.
func (i *IdP) UnassignGroup(ctx context.Context, tx pgx.Tx, organizationID, spID, groupID uuid.UUID) error {
	q := i.q.WithTx(tx)
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

func optionalUUID(v pgtype.UUID) *uuid.UUID {
	if !v.Valid {
		return nil
	}
	id := uuid.UUID(v.Bytes)
	return &id
}

func pgUUID(v *uuid.UUID) pgtype.UUID {
	if v == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *v, Valid: true}
}

// =====================================================================
// Assignment admin handlers (user-JWT, organization-scoped)
// =====================================================================

func (h *Handler) listSPAssignments(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	spID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrSAMLIDInvalid)
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
	h.changeAssignment(w, r, "userID", func(ctx context.Context, tx pgx.Tx, organizationID, spID, id uuid.UUID, by *uuid.UUID) (bool, error) {
		return h.IdP.AssignUser(ctx, tx, organizationID, spID, id, by)
	}, "saml.sp_user_assigned", "user_id")
}

func (h *Handler) unassignSPUser(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, "userID", func(ctx context.Context, tx pgx.Tx, organizationID, spID, id uuid.UUID, _ *uuid.UUID) (bool, error) {
		return true, h.IdP.UnassignUser(ctx, tx, organizationID, spID, id)
	}, "saml.sp_user_unassigned", "user_id")
}

func (h *Handler) assignSPGroup(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, "groupID", func(ctx context.Context, tx pgx.Tx, organizationID, spID, id uuid.UUID, by *uuid.UUID) (bool, error) {
		return h.IdP.AssignGroup(ctx, tx, organizationID, spID, id, by)
	}, "saml.sp_group_assigned", "group_id")
}

func (h *Handler) unassignSPGroup(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, "groupID", func(ctx context.Context, tx pgx.Tx, organizationID, spID, id uuid.UUID, _ *uuid.UUID) (bool, error) {
		return true, h.IdP.UnassignGroup(ctx, tx, organizationID, spID, id)
	}, "saml.sp_group_unassigned", "group_id")
}

// assignmentChange makes one assignment change within tx, reporting whether it
// changed anything.
type assignmentChange func(ctx context.Context, tx pgx.Tx, organizationID, spID, id uuid.UUID, by *uuid.UUID) (bool, error)

// changeAssignment applies change to the service provider and the person or
// group the path's param names, auditing it as action when it changed
// anything, and answers 204.
func (h *Handler) changeAssignment(w http.ResponseWriter, r *http.Request, param string, change assignmentChange, action, metaKey string) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	spID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrSAMLIDInvalid)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, param))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrSAMLIDInvalid)
		return
	}
	ctx := r.Context()
	tx, err := h.IdP.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	by, _ := audit.ActorOf(r).Identity()
	changed, err := change(ctx, tx, organizationID, spID, id, by)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if changed {
		if err := h.recordSPAudit(ctx, tx, r, organizationID, spID, action, map[string]any{metaKey: id}); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
