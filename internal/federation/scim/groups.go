// SCIM 2.0 Groups (RFC 7643 §4.2, RFC 7644): the surface Okta/Entra ID drive to
// push groups and sync membership. Membership sync arrives as PatchOp add/remove
// of `members`, so PATCH support here must be exact. Groups map onto the existing
// tenant.groups / tenant.group_members tables (not a parallel store): SCIM
// displayName is the group's name, members[].value are user ids, and an optional
// externalId lets the IdP reconcile on its own key. Scoped by the bearer token's tenant.
package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

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

const groupRowCols = `id, name, external_id, created_at, updated_at`

func (s *Service) getGroup(ctx context.Context, tenantID, id uuid.UUID) (*groupRow, error) {
	r, err := s.q.GetScimGroup(ctx, dbgen.GetScimGroupParams{ID: id, TenantID: tenantID})
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

func (s *Service) listGroups(ctx context.Context, tenantID uuid.UUID, nameFilter string, start, count int) ([]groupRow, int, error) {
	args := []any{tenantID}
	where := `tenant_id = $1`
	if nameFilter != "" {
		args = append(args, nameFilter)
		where += ` AND LOWER(name) = LOWER($2)`
	}

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM tenant.groups WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, count, start-1) // SCIM startIndex is 1-based
	rows, err := s.pool.Query(ctx, `
		SELECT `+groupRowCols+` FROM tenant.groups WHERE `+where+`
		ORDER BY created_at DESC, id DESC
		LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []groupRow
	for rows.Next() {
		var g groupRow
		if err := rows.Scan(&g.ID, &g.Name, &g.ExternalID, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	return out, total, rows.Err()
}

// listMembers returns a group's members (tenant-scoped, live users only),
// joined to the user so SCIM can render members[].display.
func (s *Service) listMembers(ctx context.Context, tenantID, groupID uuid.UUID) ([]groupMember, error) {
	rows, err := s.q.ListGroupMembers(ctx, dbgen.ListGroupMembersParams{
		GroupID:  groupID,
		TenantID: tenantID,
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
// validated to belong to this tenant; unknown/foreign ids are silently
// dropped (SCIM imports must not fail wholesale on a stale member ref).
func (s *Service) createGroup(ctx context.Context, tenantID uuid.UUID, name, externalID string, members []uuid.UUID) (*groupRow, error) {
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
		TenantID:   tenantID,
		Name:       name,
		ExternalID: ext,
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
		if err := addMemberTx(ctx, q, tenantID, g.ID, uid); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return g, nil
}

// replaceGroup does a full PUT: it overwrites displayName/externalId and
// replaces the entire member set with the supplied one, all in one tx.
func (s *Service) replaceGroup(ctx context.Context, tenantID, id uuid.UUID, name string, externalID *string, members []uuid.UUID) (*groupRow, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)

	if err := touchGroupTx(ctx, tx, tenantID, id, &name, externalID); err != nil {
		return nil, err
	}
	if err := q.DeleteGroupMembers(ctx, dbgen.DeleteGroupMembersParams{GroupID: id, TenantID: tenantID}); err != nil {
		return nil, err
	}
	for _, uid := range members {
		if err := addMemberTx(ctx, q, tenantID, id, uid); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.getGroupTx(ctx, tenantID, id)
}

// patchGroup applies a parsed PatchOp set in one tx: displayName/externalId
// changes plus member add/remove/replace.
func (s *Service) patchGroup(ctx context.Context, tenantID, id uuid.UUID, p *groupPatch) (*groupRow, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)

	// Confirm the group exists for this tenant before mutating membership.
	if _, err := q.GetScimGroup(ctx, dbgen.GetScimGroupParams{ID: id, TenantID: tenantID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}

	if p.setName != nil || p.setExternalID != nil {
		if err := touchGroupTx(ctx, tx, tenantID, id, p.setName, p.setExternalID); err != nil {
			return nil, err
		}
	}
	if p.replaceMembers {
		if err := q.DeleteGroupMembers(ctx, dbgen.DeleteGroupMembersParams{GroupID: id, TenantID: tenantID}); err != nil {
			return nil, err
		}
	}
	for _, uid := range p.addMembers {
		if err := addMemberTx(ctx, q, tenantID, id, uid); err != nil {
			return nil, err
		}
	}
	for _, uid := range p.removeMembers {
		if err := q.RemoveGroupMember(ctx, dbgen.RemoveGroupMemberParams{GroupID: id, UserID: uid, TenantID: tenantID}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.getGroupTx(ctx, tenantID, id)
}

// deleteGroup hard-deletes the group (group_members cascade) for this tenant.
func (s *Service) deleteGroup(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := s.q.DeleteScimGroup(ctx, dbgen.DeleteScimGroupParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (s *Service) getGroupTx(ctx context.Context, tenantID, id uuid.UUID) (*groupRow, error) {
	return s.getGroup(ctx, tenantID, id)
}

// addMemberTx links a user to a group, but only if the user belongs to the
// same tenant and isn't deleted — this is the membership tenant-isolation
// guard. Unknown/foreign users are skipped (no error), matching SCIM import
// tolerance for stale member refs.
func addMemberTx(ctx context.Context, q *dbgen.Queries, tenantID, groupID, userID uuid.UUID) error {
	ok, err := q.CheckUserInTenant(ctx, dbgen.CheckUserInTenantParams{
		ID:       userID,
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
	})
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return q.AddGroupMember(ctx, dbgen.AddGroupMemberParams{
		GroupID:  groupID,
		UserID:   userID,
		TenantID: tenantID,
	})
}

// touchGroupTx updates name/external_id (only the non-nil fields) and bumps
// updated_at, scoped to the tenant. Returns ErrNotFound if no row matched.
func touchGroupTx(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID, name, externalID *string) error {
	var ext any
	if externalID != nil {
		if *externalID != "" {
			ext = *externalID
		}
	}
	ct, err := tx.Exec(ctx, `
		UPDATE tenant.groups SET
			name        = COALESCE($3, name),
			external_id = CASE WHEN $4::bool THEN $5 ELSE external_id END,
			updated_at  = NOW()
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID, name, externalID != nil, ext)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// parseDisplayNameFilter extracts the value from a `displayName eq "x"`
// filter. Anything else is treated as "no filter" (returns all groups),
// mirroring parseUserNameFilter.
func parseDisplayNameFilter(filter string) string {
	f := strings.TrimSpace(filter)
	if f == "" {
		return ""
	}
	lower := strings.ToLower(f)
	if !strings.HasPrefix(lower, "displayname eq") {
		return ""
	}
	rest := strings.TrimSpace(f[len("displayName eq"):])
	rest = strings.Trim(rest, " ")
	rest = strings.Trim(rest, `"`)
	return rest
}

// toGroupResource renders a group row + its members as a SCIM core Group.
func (s *Service) toGroupResource(ctx context.Context, r *http.Request, g *groupRow) (map[string]any, error) {
	tid, _ := tenantFromCtx(ctx)
	members, err := s.listMembers(ctx, tid, g.ID)
	if err != nil {
		return nil, err
	}
	resMembers := make([]map[string]any, 0, len(members))
	for _, m := range members {
		entry := map[string]any{
			"value": m.UserID.String(),
			"$ref":  scimLocation(r, "/Users/"+m.UserID.String()),
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
			"location":     scimLocation(r, "/Groups/"+g.ID.String()),
		},
	}
	if g.ExternalID != nil && *g.ExternalID != "" {
		res["externalId"] = *g.ExternalID
	}
	return res, nil
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	tid, ok := tenantFromCtx(r.Context())
	if !ok {
		writeSCIMErr(w, http.StatusUnauthorized, "no tenant")
		return
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if start < 1 {
		start = 1
	}
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil || count <= 0 {
		count = defaultPageCount
	}
	if count > maxPageCount {
		count = maxPageCount
	}
	name := parseDisplayNameFilter(r.URL.Query().Get("filter"))

	rows, total, err := h.Service.listGroups(r.Context(), tid, name, start, count)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	resources := make([]map[string]any, 0, len(rows))
	for i := range rows {
		res, err := h.Service.toGroupResource(r.Context(), r, &rows[i])
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
	tid, ok := tenantFromCtx(r.Context())
	if !ok {
		writeSCIMErr(w, http.StatusUnauthorized, "no tenant")
		return
	}
	var p scimGroupPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeSCIMErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(p.DisplayName)
	if name == "" {
		writeSCIMErr(w, http.StatusBadRequest, "displayName is required")
		return
	}
	ctx := r.Context()
	g, err := h.Service.createGroup(ctx, tid, name, p.ExternalID, p.memberIDs())
	if err != nil {
		writeSCIMErr(w, http.StatusBadRequest, "create failed")
		return
	}
	res, err := h.Service.toGroupResource(ctx, r, g)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "reload failed")
		return
	}
	writeSCIM(w, http.StatusCreated, res)
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
	res, err := h.Service.toGroupResource(r.Context(), r, g)
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
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeSCIMErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(p.DisplayName)
	if name == "" {
		writeSCIMErr(w, http.StatusBadRequest, "displayName is required")
		return
	}
	var ext *string
	ext = &p.ExternalID // PUT is a full replace: externalId is authoritative (empty clears it)
	g, err := h.Service.replaceGroup(r.Context(), tid, id, name, ext, p.memberIDs())
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			writeSCIMErr(w, http.StatusNotFound, "group not found")
			return
		}
		writeSCIMErr(w, http.StatusBadRequest, "replace failed")
		return
	}
	res, err := h.Service.toGroupResource(r.Context(), r, g)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "render failed")
		return
	}
	writeSCIM(w, http.StatusOK, res)
}

// groupPatch is the resolved effect of a PatchOp request on a group.
type groupPatch struct {
	setName        *string
	setExternalID  *string
	addMembers     []uuid.UUID
	removeMembers  []uuid.UUID
	replaceMembers bool // replace the whole member set with addMembers
}

// patchGroup supports the membership-sync flow Okta/Entra drive: op
// add/remove/replace targeting `members` (whole-set replace or individual
// add/remove) and replace of `displayName`/`externalId`.
func (h *Handler) patchGroup(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	var body patchBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeSCIMErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	p, err := parseGroupPatch(body)
	if err != nil {
		writeSCIMErr(w, http.StatusBadRequest, err.Error())
		return
	}
	g, err := h.Service.patchGroup(r.Context(), tid, id, p)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			writeSCIMErr(w, http.StatusNotFound, "group not found")
			return
		}
		writeSCIMErr(w, http.StatusBadRequest, "patch failed")
		return
	}
	res, err := h.Service.toGroupResource(r.Context(), r, g)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "render failed")
		return
	}
	writeSCIM(w, http.StatusOK, res)
}

// parseGroupPatch resolves a SCIM PatchOp body into a groupPatch. It handles
// the two shapes IdPs send for membership:
//   - path-scoped:  {"op":"add","path":"members","value":[{"value":"<id>"}]}
//   - path-scoped remove of one member via a value filter is normalized by
//     Okta to path `members[value eq "<id>"]` (op remove, no value); we parse
//     the id out of the path.
//   - path-less replace: {"op":"replace","value":{"displayName":"x","members":[...]}}
func parseGroupPatch(body patchBody) (*groupPatch, error) {
	p := &groupPatch{}
	for _, op := range body.Operations {
		action := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.TrimSpace(strings.Trim(op.Path, `"`))
		lowerPath := strings.ToLower(path)

		switch {
		case lowerPath == "displayname":
			if action == "add" || action == "replace" {
				var dn string
				if json.Unmarshal(op.Value, &dn) == nil {
					p.setName = &dn
				}
			}
		case lowerPath == "externalid":
			if action == "add" || action == "replace" {
				var ext string
				if json.Unmarshal(op.Value, &ext) == nil {
					p.setExternalID = &ext
				}
			}
		case lowerPath == "members":
			switch action {
			case "replace":
				// Replace the entire membership with the supplied set.
				p.replaceMembers = true
				p.addMembers = append(p.addMembers, decodeMemberRefs(op.Value)...)
			case "add":
				p.addMembers = append(p.addMembers, decodeMemberRefs(op.Value)...)
			case "remove":
				// remove with path "members" and a value list of refs, OR a
				// bare remove of all members (no value).
				if len(op.Value) == 0 || string(op.Value) == "null" {
					p.replaceMembers = true // clear all, add none
				} else {
					p.removeMembers = append(p.removeMembers, decodeMemberRefs(op.Value)...)
				}
			}
		case strings.HasPrefix(lowerPath, "members["):
			// Okta-style targeted member remove/add: members[value eq "<uuid>"].
			if id, ok := memberIDFromFilterPath(path); ok {
				switch action {
				case "remove":
					p.removeMembers = append(p.removeMembers, id)
				case "add":
					p.addMembers = append(p.addMembers, id)
				}
			}
		case path == "":
			// Path-less op: value is an object of attributes.
			var obj struct {
				DisplayName *string              `json:"displayName"`
				ExternalID  *string              `json:"externalId"`
				Members     []scimGroupMemberRef `json:"members"`
			}
			if json.Unmarshal(op.Value, &obj) != nil {
				continue
			}
			if obj.DisplayName != nil {
				p.setName = obj.DisplayName
			}
			if obj.ExternalID != nil {
				p.setExternalID = obj.ExternalID
			}
			if obj.Members != nil {
				// A path-less replace of members replaces the whole set; for
				// add it augments. Default SCIM op is replace.
				if action == "add" {
					for _, m := range obj.Members {
						if mid, err := uuid.Parse(strings.TrimSpace(m.Value)); err == nil {
							p.addMembers = append(p.addMembers, mid)
						}
					}
				} else {
					p.replaceMembers = true
					for _, m := range obj.Members {
						if mid, err := uuid.Parse(strings.TrimSpace(m.Value)); err == nil {
							p.addMembers = append(p.addMembers, mid)
						}
					}
				}
			}
		}
	}
	return p, nil
}

// decodeMemberRefs parses a PatchOp `value` that is an array of member refs
// ([{"value":"<id>"}]) into user UUIDs, skipping malformed entries. Some IdPs
// also send a single object instead of an array; handle both.
func decodeMemberRefs(raw json.RawMessage) []uuid.UUID {
	if len(raw) == 0 {
		return nil
	}
	var refs []scimGroupMemberRef
	if json.Unmarshal(raw, &refs) != nil {
		var one scimGroupMemberRef
		if json.Unmarshal(raw, &one) != nil {
			return nil
		}
		refs = []scimGroupMemberRef{one}
	}
	out := make([]uuid.UUID, 0, len(refs))
	for _, ref := range refs {
		if id, err := uuid.Parse(strings.TrimSpace(ref.Value)); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// memberIDFromFilterPath extracts the uuid from an Okta-style targeted path
// like `members[value eq "5d4..."]`.
func memberIDFromFilterPath(path string) (uuid.UUID, bool) {
	open := strings.Index(path, "[")
	close := strings.LastIndex(path, "]")
	if open < 0 || close <= open {
		return uuid.Nil, false
	}
	expr := path[open+1 : close]
	lower := strings.ToLower(expr)
	idx := strings.Index(lower, "eq")
	if idx < 0 {
		return uuid.Nil, false
	}
	val := strings.TrimSpace(expr[idx+2:])
	val = strings.Trim(val, ` "`)
	id, err := uuid.Parse(val)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	if err := h.Service.deleteGroup(r.Context(), tid, id); err != nil {
		writeSCIMErr(w, http.StatusNotFound, "group not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
