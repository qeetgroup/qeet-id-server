package rebac

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// ObjectType is a type of object the organization's tuples name, with how many
// objects of it they name and how many tuples.
type ObjectType struct {
	Type    string `json:"type"`
	Objects int    `json:"objects"`
	Tuples  int    `json:"tuples"`
}

// ObjectTypes returns the types of object the organization's tuples name.
func (s *Service) ObjectTypes(ctx context.Context, organizationID uuid.UUID) ([]ObjectType, error) {
	rows, err := s.q.ListRelationObjectTypes(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]ObjectType, 0, len(rows))
	for _, r := range rows {
		out = append(out, ObjectType{Type: r.ObjectType, Objects: int(r.Objects), Tuples: int(r.Tuples)})
	}
	return out, nil
}

// Object is an object the organization's tuples name, with how many.
type Object struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Tuples int    `json:"tuples"`
}

// ObjectPage is a page of objects, by id, with how many there are. Its cursor
// is the last object's id.
type ObjectPage struct {
	paging.Result[Object]
	Total int `json:"total"`
}

// Objects returns a page of up to limit (100 when unset, at most 500) of the
// objects of objType the organization's tuples name, by id, after cursor.
func (s *Service) Objects(ctx context.Context, organizationID uuid.UUID, objType string, limit int, cursor string) (*ObjectPage, error) {
	if strings.TrimSpace(objType) == "" {
		return nil, errs.ErrBadRequest.WithMessage("Name the type of object to list.")
	}
	limit = paging.Clamp(limit, 100, 500)
	after := ""
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return nil, errs.ErrBadRequest.WithDetail("invalid cursor")
		}
		after = string(raw)
	}
	total, err := s.q.CountRelationObjects(ctx, dbgen.CountRelationObjectsParams{OrganizationID: organizationID, ObjectType: objType})
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListRelationObjects(ctx, dbgen.ListRelationObjectsParams{
		OrganizationID: organizationID, ObjectType: objType, After: after, RowLimit: int32(limit + 1), // #nosec G115 -- limit is at most 500
	})
	if err != nil {
		return nil, err
	}
	items := make([]Object, len(rows))
	for i, r := range rows {
		items[i] = Object{Object: graphNodeID(objType, r.ObjectID), ID: r.ObjectID, Tuples: int(r.Tuples)}
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = base64.RawURLEncoding.EncodeToString([]byte(items[limit-1].ID))
	}
	return &ObjectPage{Result: paging.Page(items, next), Total: int(total)}, nil
}
