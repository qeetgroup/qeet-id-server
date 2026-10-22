package group

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// maxImportRows bounds one import request. Large directories should page rather
// than send a single unbounded body.
const maxImportRows = 500

// ImportRow is one group in an import payload. Parent is matched by NAME, not
// id, because the caller is importing from somewhere else (a CSV export, an
// IdP) where our ids don't exist yet.
type ImportRow struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Parent      string `json:"parent"`
}

// ImportResult reports per-row outcomes. Rows are attempted independently so one
// bad row doesn't discard an otherwise good import — the operator gets a list of
// exactly what failed and why, and can re-submit just those.
type ImportResult struct {
	Created int               `json:"created"`
	Skipped int               `json:"skipped"`
	Failed  int               `json:"failed"`
	Rows    []ImportRowResult `json:"rows"`
}

// ImportRowResult is the outcome of one imported row. Status is created, skipped
// or failed.
type ImportRowResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// ImportGroups creates groups from a flat list, resolving each parent by name
// among existing groups and rows created earlier in the call. It makes repeated
// passes, since a child may come before its parent; rows whose parent never
// appears (or that form a cycle) are reported as failed.
func (s *Service) ImportGroups(
	ctx context.Context, tenantID uuid.UUID, rows []ImportRow, actor audit.Actor,
) (*ImportResult, error) {
	if len(rows) == 0 {
		return nil, errs.ErrGroupImportEmpty
	}
	if len(rows) > maxImportRows {
		return nil, errs.ErrGroupImportTooLarge
	}

	existing, err := s.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	// Lowercased name -> id, for parent lookups and clash checks: names match
	// case-insensitively.
	byName := make(map[string]uuid.UUID, len(existing)+len(rows))
	for _, g := range existing {
		byName[strings.ToLower(g.Name)] = g.ID
	}

	res := &ImportResult{Rows: make([]ImportRowResult, 0, len(rows))}
	pending := make([]ImportRow, 0, len(rows))
	for _, r := range rows {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			res.Failed++
			res.Rows = append(res.Rows, ImportRowResult{
				Name: r.Name, Status: "failed", Reason: "name is required",
			})
			continue
		}
		if _, clash := byName[strings.ToLower(name)]; clash {
			res.Skipped++
			res.Rows = append(res.Rows, ImportRowResult{
				Name: name, Status: "skipped", Reason: "a group with this name already exists",
			})
			continue
		}
		r.Name = name
		pending = append(pending, r)
	}

	for len(pending) > 0 {
		progressed := false
		next := make([]ImportRow, 0, len(pending))

		for _, r := range pending {
			var parentID *uuid.UUID
			if p := strings.TrimSpace(r.Parent); p != "" {
				id, ok := byName[strings.ToLower(p)]
				if !ok {
					// Parent may still be created by a later pass.
					next = append(next, r)
					continue
				}
				parentID = &id
			}

			g, err := s.Create(ctx, CreateInput{
				TenantID:    tenantID,
				ParentID:    parentID,
				Name:        r.Name,
				Description: r.Description,
			}, actor)
			if err != nil {
				reason := "could not be created"
				if pgxerr.IsUnique(err) {
					reason = "a group with this name already exists"
				}
				res.Failed++
				res.Rows = append(res.Rows, ImportRowResult{
					Name: r.Name, Status: "failed", Reason: reason,
				})
				progressed = true
				continue
			}
			byName[strings.ToLower(g.Name)] = g.ID
			res.Created++
			res.Rows = append(res.Rows, ImportRowResult{Name: g.Name, Status: "created"})
			progressed = true
		}

		if !progressed {
			// Nothing resolvable is left: the rest name a parent that doesn't
			// exist, or reference each other in a cycle.
			for _, r := range next {
				res.Failed++
				res.Rows = append(res.Rows, ImportRowResult{
					Name:   r.Name,
					Status: "failed",
					Reason: "parent group \"" + r.Parent + "\" was not found",
				})
			}
			break
		}
		pending = next
	}

	return res, nil
}
