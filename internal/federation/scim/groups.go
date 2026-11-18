package scim

// SCIM 2.0 Groups (RFC 7643 §4.2, RFC 7644), which IdPs use to push groups and
// sync membership. They are the organization's ordinary groups: displayName is the
// name, members[].value are user IDs, and externalId is the IdP's own key.
// SCIM reads and changes only the groups it created, so an IdP can't put
// anyone in a group an administrator gave roles to; every change is audited
// in its transaction.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// scimActor is who a SCIM request acts as, for its audit records: the
// directory, from r's client.
func scimActor(r *http.Request) audit.Actor {
	return audit.Actor{Type: "scim", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
}

// memberSet is groupID's members, read inside the change's transaction.
func memberSet(ctx context.Context, q *dbgen.Queries, organizationID, groupID uuid.UUID) (map[uuid.UUID]bool, error) {
	rows, err := q.ListGroupMembers(ctx, dbgen.ListGroupMembersParams{GroupID: groupID, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]bool, len(rows))
	for _, r := range rows {
		out[r.UserID] = true
	}
	return out, nil
}

// recordGroupChange audits, in tx, a SCIM change to groupID: action on the
// group ("" for none), then a group.member_added or group.member_removed for
// each member it has gained or lost against before, each with its event.
func recordGroupChange(ctx context.Context, tx pgx.Tx, q *dbgen.Queries, actor audit.Actor, organizationID, groupID uuid.UUID, action string, meta map[string]any, before map[uuid.UUID]bool) error {
	if action != "" {
		if err := audit.Record(ctx, tx, actor.Event(organizationID, action, "group", groupID, meta)); err != nil {
			return err
		}
		payload := map[string]any{"group_id": groupID, "organization_id": organizationID, "source": "scim"}
		if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: groupID, Topic: "group.events", EventType: action, Payload: payload}); err != nil {
			return err
		}
	}
	after, err := memberSet(ctx, q, organizationID, groupID)
	if err != nil {
		return err
	}
	change := func(userID uuid.UUID, member string) error {
		if err := audit.Record(ctx, tx, actor.Event(organizationID, member, "group", groupID, map[string]any{"user_id": userID})); err != nil {
			return err
		}
		return outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: groupID, Topic: "group.events", EventType: member,
			Payload: map[string]any{"group_id": groupID, "user_id": userID, "organization_id": organizationID, "source": "scim"}})
	}
	for id := range after {
		if !before[id] {
			if err := change(id, "group.member_added"); err != nil {
				return err
			}
		}
	}
	for id := range before {
		if !after[id] {
			if err := change(id, "group.member_removed"); err != nil {
				return err
			}
		}
	}
	return nil
}

const schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"

// groupRow is the SCIM group read side (mirrors userRow).
type groupRow struct {
	ID         uuid.UUID
	Name       string
	ExternalID *string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// groupMember is a member of a group enriched with the user's email +
// display_name so the SCIM `members[].display` can be populated without a
// per-member follow-up call.
type groupMember struct {
	UserID      uuid.UUID
	Email       string
	DisplayName *string
}

func (s *Service) getGroup(ctx context.Context, organizationID, id uuid.UUID) (*groupRow, error) {
	r, err := s.q.GetScimGroup(ctx, dbgen.GetScimGroupParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &groupRow{
		ID:         r.ID,
		Name:       r.Name,
		ExternalID: r.ExternalID,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}, nil
}

func (s *Service) listGroups(ctx context.Context, organizationID uuid.UUID, nameFilter string, start, count int) ([]groupRow, int, error) {
	total, err := s.q.CountScimGroups(ctx, dbgen.CountScimGroupsParams{OrganizationID: organizationID, Name: nameFilter})
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.q.ListScimGroups(ctx, dbgen.ListScimGroupsParams{
		OrganizationID: organizationID, Name: nameFilter, Lim: int64(count), Off: int64(start - 1), // SCIM startIndex is 1-based
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]groupRow, len(rows))
	for i, r := range rows {
		out[i] = groupRow(r)
	}
	return out, int(total), nil
}

// listMembers returns a group's members (organization-scoped, live users only),
// joined to the user so SCIM can render members[].display.
func (s *Service) listMembers(ctx context.Context, organizationID, groupID uuid.UUID) ([]groupMember, error) {
	rows, err := s.q.ListGroupMembers(ctx, dbgen.ListGroupMembersParams{
		GroupID:        groupID,
		OrganizationID: organizationID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]groupMember, len(rows))
	for i, r := range rows {
		out[i] = groupMember{UserID: r.UserID, Email: r.Email, DisplayName: r.DisplayName}
	}
	return out, nil
}

// createGroup inserts a group + its initial members atomically. Members are
// validated to belong to this organization; unknown/foreign ids are silently
// dropped (SCIM imports must not fail wholesale on a stale member ref).
func (s *Service) createGroup(ctx context.Context, actor audit.Actor, organizationID uuid.UUID, name, externalID string, members []uuid.UUID) (*groupRow, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)

	var ext *string
	if externalID != "" {
		ext = &externalID
	}
	r, err := q.InsertScimGroup(ctx, dbgen.InsertScimGroupParams{
		OrganizationID: organizationID,
		Name:           name,
		ExternalID:     ext,
	})
	if err != nil {
		return nil, err
	}
	g := &groupRow{
		ID:         r.ID,
		Name:       r.Name,
		ExternalID: r.ExternalID,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}
	for _, uid := range members {
		if err := addMemberTx(ctx, q, organizationID, g.ID, uid); err != nil {
			return nil, err
		}
	}
	if err := recordGroupChange(ctx, tx, q, actor, organizationID, g.ID, "group.created", map[string]any{"name": name}, nil); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return g, nil
}

// replaceGroup does a full PUT: it overwrites displayName/externalId and
// replaces the entire member set with the supplied one, all in one tx. A
// member it gives a first role, through the group's, takes a seat, refused
// with errs.ErrPlanLimit beyond the plan's seats.
func (s *Service) replaceGroup(ctx context.Context, actor audit.Actor, organizationID, id uuid.UUID, name string, externalID *string, members []uuid.UUID) (*groupRow, error) {
	limit, err := s.seatLimit(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)

	if err := touchGroupTx(ctx, q, organizationID, id, &name, externalID); err != nil {
		return nil, err
	}
	before, err := memberSet(ctx, q, organizationID, id)
	if err != nil {
		return nil, err
	}
	if err := s.withinSeats(ctx, tx, organizationID, limit, func() error {
		if err := q.DeleteGroupMembers(ctx, dbgen.DeleteGroupMembersParams{GroupID: id, OrganizationID: organizationID}); err != nil {
			return err
		}
		for _, uid := range members {
			if err := addMemberTx(ctx, q, organizationID, id, uid); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if err := recordGroupChange(ctx, tx, q, actor, organizationID, id, "group.updated", map[string]any{"name": name}, before); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.getGroupTx(ctx, organizationID, id)
}

// deleteGroup hard-deletes the group (group_members cascade) for this organization,
// recording it with each member it loses.
func (s *Service) deleteGroup(ctx context.Context, actor audit.Actor, organizationID, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	before, err := memberSet(ctx, q, organizationID, id)
	if err != nil {
		return err
	}
	n, err := q.DeleteScimGroup(ctx, dbgen.DeleteScimGroupParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := recordGroupChange(ctx, tx, q, actor, organizationID, id, "group.deleted", nil, before); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) getGroupTx(ctx context.Context, organizationID, id uuid.UUID) (*groupRow, error) {
	return s.getGroup(ctx, organizationID, id)
}

// addMemberTx links a user to a group, but only if the user belongs to the
// same organization and isn't deleted — this is the membership organization-isolation
// guard. Unknown/foreign users are skipped (no error), matching SCIM import
// tolerance for stale member refs.
func addMemberTx(ctx context.Context, q *dbgen.Queries, organizationID, groupID, userID uuid.UUID) error {
	ok, err := q.CheckUserInOrganization(ctx, dbgen.CheckUserInOrganizationParams{
		ID:             userID,
		OrganizationID: &organizationID,
	})
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return q.AddGroupMember(ctx, dbgen.AddGroupMemberParams{
		GroupID:        groupID,
		UserID:         userID,
		OrganizationID: organizationID,
	})
}

// touchGroupTx updates name/external_id (only the non-nil fields; an empty
// external ID clears it) and bumps updated_at, scoped to the organization.
// Returns ErrNotFound if no row matched.
func touchGroupTx(ctx context.Context, q *dbgen.Queries, organizationID, id uuid.UUID, name, externalID *string) error {
	var ext *string
	if externalID != nil && *externalID != "" {
		ext = externalID
	}
	n, err := q.TouchScimGroup(ctx, dbgen.TouchScimGroupParams{
		ID: id, OrganizationID: organizationID, Name: name, SetExternalID: externalID != nil, ExternalID: ext,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func parseDisplayNameFilter(filter string) (string, error) {
	return parseEqualityFilter(filter, "displayName")
}

// toGroupResource renders a group row + its members as a SCIM core Group.
func (h *Handler) toGroupResource(ctx context.Context, r *http.Request, g *groupRow) (map[string]any, error) {
	tid, _ := organizationFromCtx(ctx)
	members, err := h.Service.listMembers(ctx, tid, g.ID)
	if err != nil {
		return nil, err
	}
	resMembers := make([]map[string]any, 0, len(members))
	for _, m := range members {
		entry := map[string]any{
			"value": m.UserID.String(),
			"$ref":  h.location(r, "/Users/"+m.UserID.String()),
		}
		if m.DisplayName != nil && *m.DisplayName != "" {
			entry["display"] = *m.DisplayName
		} else {
			entry["display"] = m.Email
		}
		resMembers = append(resMembers, entry)
	}
	res := map[string]any{
		"schemas":     []string{schemaGroup},
		"id":          g.ID.String(),
		"displayName": g.Name,
		"members":     resMembers,
		"meta": map[string]any{
			"resourceType": "Group",
			"created":      g.CreatedAt.UTC().Format(time.RFC3339),
			"lastModified": g.UpdatedAt.UTC().Format(time.RFC3339),
			"location":     h.location(r, "/Groups/"+g.ID.String()),
		},
	}
	if g.ExternalID != nil && *g.ExternalID != "" {
		res["externalId"] = *g.ExternalID
	}
	return res, nil
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	tid, ok := organizationFromCtx(r.Context())
	if !ok {
		writeSCIMErr(w, http.StatusUnauthorized, "no organization")
		return
	}
	start, count := listWindow(r)
	name, err := parseDisplayNameFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeSCIMTypedErr(w, http.StatusBadRequest, "invalidFilter", "Only displayName eq \"value\" is supported.")
		return
	}

	rows, total, err := h.Service.listGroups(r.Context(), tid, name, start, count)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	resources := make([]map[string]any, 0, len(rows))
	for i := range rows {
		res, err := h.toGroupResource(r.Context(), r, &rows[i])
		if err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "list failed")
			return
		}
		resources = append(resources, res)
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{schemaListResp},
		"totalResults": total,
		"startIndex":   start,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

type scimGroupMemberRef struct {
	Value string `json:"value"`
}

type scimGroupPayload struct {
	DisplayName string               `json:"displayName"`
	ExternalID  string               `json:"externalId"`
	Members     []scimGroupMemberRef `json:"members"`
}

// memberIDs parses the payload's member refs into user UUIDs, skipping
// malformed values (SCIM imports tolerate junk member refs).
func (p scimGroupPayload) memberIDs() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(p.Members))
	for _, m := range p.Members {
		if id, err := uuid.Parse(strings.TrimSpace(m.Value)); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	tid, ok := organizationFromCtx(r.Context())
	if !ok {
		writeSCIMErr(w, http.StatusUnauthorized, "no organization")
		return
	}
	var p scimGroupPayload
	if !decodeSCIMBody(w, r, &p) {
		return
	}
	name := strings.TrimSpace(p.DisplayName)
	if name == "" {
		writeSCIMErr(w, http.StatusBadRequest, "displayName is required")
		return
	}
	ctx := r.Context()
	g, err := h.Service.createGroup(ctx, scimActor(r), tid, name, p.ExternalID, p.memberIDs())
	if err != nil {
		if !writeGroupConflict(w, err) {
			writeSCIMErr(w, http.StatusBadRequest, "create failed")
		}
		return
	}
	res, err := h.toGroupResource(ctx, r, g)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "reload failed")
		return
	}
	writeSCIM(w, http.StatusCreated, res)
}

// writeGroupConflict answers err with RFC 7644's 409 uniqueness when it is a
// taken name or externalId, and reports whether it did. A name is unique in the
// organization, ignoring case, among groups without an externalId.
func writeGroupConflict(w http.ResponseWriter, err error) bool {
	if !postgres.IsUnique(err) {
		return false
	}
	writeSCIMTypedErr(w, http.StatusConflict, "uniqueness", "a group with this displayName or externalId already exists")
	return true
}

// writeSeatLimit answers, in the SCIM error format, a membership change that
// needs more seats than the organization's plan has, and reports whether err
// was that refusal.
func writeSeatLimit(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, errs.ErrPlanLimit) {
		return false
	}
	writeSCIMErr(w, http.StatusForbidden, "the organization's plan has no seat left for another person holding a role")
	return true
}

func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	g, err := h.Service.getGroup(r.Context(), tid, id)
	if err != nil {
		writeSCIMErr(w, http.StatusNotFound, "group not found")
		return
	}
	res, err := h.toGroupResource(r.Context(), r, g)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "render failed")
		return
	}
	writeSCIM(w, http.StatusOK, res)
}

func (h *Handler) replaceGroup(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	var p scimGroupPayload
	if !decodeSCIMBody(w, r, &p) {
		return
	}
	name := strings.TrimSpace(p.DisplayName)
	if name == "" {
		writeSCIMErr(w, http.StatusBadRequest, "displayName is required")
		return
	}
	ext := &p.ExternalID // PUT is a full replace: externalId is authoritative (empty clears it)
	g, err := h.Service.replaceGroup(r.Context(), scimActor(r), tid, id, name, ext, p.memberIDs())
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			writeSCIMErr(w, http.StatusNotFound, "group not found")
			return
		}
		if !writeSeatLimit(w, err) && !writeGroupConflict(w, err) {
			writeSCIMErr(w, http.StatusBadRequest, "replace failed")
		}
		return
	}
	res, err := h.toGroupResource(r.Context(), r, g)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "render failed")
		return
	}
	writeSCIM(w, http.StatusOK, res)
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	if err := h.Service.deleteGroup(r.Context(), scimActor(r), tid, id); err != nil {
		writeSCIMErr(w, http.StatusNotFound, "group not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
