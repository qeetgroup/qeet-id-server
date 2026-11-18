package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// patchGroup applies a parsed PatchOp set in one tx: displayName/externalId
// changes plus member add/remove/replace. A member it gives a first role takes
// a seat, as replaceGroup does.
func (s *Service) patchGroup(ctx context.Context, actor audit.Actor, organizationID, id uuid.UUID, p *groupPatch) (*groupRow, error) {
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

	// Confirm the group exists for this organization before mutating membership.
	if _, err := q.GetScimGroup(ctx, dbgen.GetScimGroupParams{ID: id, OrganizationID: organizationID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	before, err := memberSet(ctx, q, organizationID, id)
	if err != nil {
		return nil, err
	}

	action := ""
	if p.setName != nil || p.setExternalID != nil {
		if err := touchGroupTx(ctx, q, organizationID, id, p.setName, p.setExternalID); err != nil {
			return nil, err
		}
		action = "group.updated"
	}
	if err := s.withinSeats(ctx, tx, organizationID, limit, func() error {
		if p.replaceMembers {
			if err := q.DeleteGroupMembers(ctx, dbgen.DeleteGroupMembersParams{GroupID: id, OrganizationID: organizationID}); err != nil {
				return err
			}
		}
		for _, uid := range p.addMembers {
			if err := addMemberTx(ctx, q, organizationID, id, uid); err != nil {
				return err
			}
		}
		for _, uid := range p.removeMembers {
			if err := q.RemoveGroupMember(ctx, dbgen.RemoveGroupMemberParams{GroupID: id, UserID: uid, OrganizationID: organizationID}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if err := recordGroupChange(ctx, tx, q, actor, organizationID, id, action, nil, before); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.getGroupTx(ctx, organizationID, id)
}

// groupPatch is the resolved effect of a PatchOp request on a group.
type groupPatch struct {
	setName        *string     // new display name; nil keeps it
	setExternalID  *string     // new external ID; nil keeps it
	addMembers     []uuid.UUID // members to add, or the whole set when replaceMembers
	removeMembers  []uuid.UUID // members to remove
	replaceMembers bool        // replace the member set with addMembers
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
	if !decodeSCIMBody(w, r, &body) {
		return
	}
	p, err := parseGroupPatch(body)
	if err != nil {
		writeSCIMErr(w, http.StatusBadRequest, err.Error())
		return
	}
	g, err := h.Service.patchGroup(r.Context(), scimActor(r), tid, id, p)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			writeSCIMErr(w, http.StatusNotFound, "group not found")
			return
		}
		if !writeSeatLimit(w, err) && !writeGroupConflict(w, err) {
			writeSCIMErr(w, http.StatusBadRequest, "patch failed")
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

// parseGroupPatch resolves a SCIM PatchOp body into a groupPatch. It accepts
// ops on "displayName", "externalId" and "members" (a value-less remove clears
// externalId and members, and is refused for the required displayName), Okta's
// `members[value eq "<id>"]` path, and path-less ops whose value holds those
// attributes. Anything else is ignored.
func parseGroupPatch(body patchBody) (*groupPatch, error) {
	p := &groupPatch{}
	for _, op := range body.Operations {
		action := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.TrimSpace(strings.Trim(op.Path, `"`))
		lowerPath := strings.ToLower(path)

		switch {
		case lowerPath == "displayname":
			var dn string
			switch action {
			case "remove":
				p.setName = &dn // blank, which the update refuses
			case "add", "replace":
				if json.Unmarshal(op.Value, &dn) == nil {
					p.setName = &dn
				}
			}
		case lowerPath == "externalid":
			var ext string
			switch action {
			case "remove":
				p.setExternalID = &ext // blank clears it
			case "add", "replace":
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
	// The name is stored trimmed, as on create, and can't be emptied.
	if p.setName != nil {
		name := strings.TrimSpace(*p.setName)
		if name == "" {
			return nil, errors.New("displayName is required")
		}
		p.setName = &name
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
	idx := indexEqFold(expr)
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

// indexEqFold returns the byte index in s of the first "eq" in any letter case,
// or -1. SCIM operators are case-insensitive (RFC 7644 §3.4.2.2).
func indexEqFold(s string) int {
	for i := 0; i+1 < len(s); i++ {
		if s[i]|0x20 == 'e' && s[i+1]|0x20 == 'q' {
			return i
		}
	}
	return -1
}
