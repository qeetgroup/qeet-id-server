package group

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/groups/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// maxTemplateDepth bounds how deep a template tree may nest, since applying a
// template writes every node.
const maxTemplateDepth = 6

// maxTemplateNodes bounds the total groups one apply can create.
const maxTemplateNodes = 200

// TemplateNode is one group in a template tree.
type TemplateNode struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Children    []TemplateNode `json:"children,omitempty"`
}

type GroupTemplate struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Nodes       []TemplateNode `json:"nodes"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	// GroupCount is how many groups applying this template would create.
	GroupCount int `json:"group_count"`
}

type TemplateInput struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Nodes       []TemplateNode `json:"nodes"`
}

// countNodes walks a template tree, validating shape as it goes. It returns the
// total number of groups the tree would create.
func countNodes(nodes []TemplateNode, depth int) (int, error) {
	if depth > maxTemplateDepth {
		return 0, errs.ErrGroupTemplateTooDeep
	}
	total := 0
	for _, n := range nodes {
		if strings.TrimSpace(n.Name) == "" {
			return 0, errs.ErrGroupTemplateNodeUnnamed
		}
		child, err := countNodes(n.Children, depth+1)
		if err != nil {
			return 0, err
		}
		total += 1 + child
	}
	return total, nil
}

// duplicateNodeName returns a name that more than one node of the tree uses,
// ignoring case and surrounding space, or "" if there is none. seen holds the
// names met so far.
func duplicateNodeName(nodes []TemplateNode, seen map[string]bool) string {
	for _, n := range nodes {
		name := strings.TrimSpace(n.Name)
		if seen[strings.ToLower(name)] {
			return name
		}
		seen[strings.ToLower(name)] = true
		if dup := duplicateNodeName(n.Children, seen); dup != "" {
			return dup
		}
	}
	return ""
}

// validateTemplate checks a template's name and tree and returns how many
// groups applying it creates. Group names are unique in an organization, so a
// tree that uses one twice could never be applied.
func validateTemplate(in TemplateInput) (int, error) {
	if strings.TrimSpace(in.Name) == "" {
		return 0, errs.ErrGroupTemplateUnnamed
	}
	count, err := countNodes(in.Nodes, 1)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, errs.ErrGroupTemplateEmpty
	}
	if count > maxTemplateNodes {
		return 0, errs.ErrGroupTemplateTooLarge
	}
	if dup := duplicateNodeName(in.Nodes, map[string]bool{}); dup != "" {
		return 0, errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "nodes", Code: "duplicate_name",
			Message: fmt.Sprintf("%q is used more than once; each group in a template needs its own name.", dup),
		}})
	}
	return count, nil
}

// The template queries below are hand-written SQL, not sqlc.

func (s *Service) ListTemplates(ctx context.Context, tenantID uuid.UUID) ([]GroupTemplate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, description, nodes, created_at, updated_at
		FROM tenant.group_templates
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]GroupTemplate, 0)
	for rows.Next() {
		var t GroupTemplate
		var raw []byte
		if err := rows.Scan(&t.ID, &t.TenantID, &t.Name, &t.Description, &raw,
			&t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &t.Nodes); err != nil {
			return nil, err
		}
		t.GroupCount, _ = countNodes(t.Nodes, 1)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Service) CreateTemplate(
	ctx context.Context, tenantID uuid.UUID, in TemplateInput, actor audit.Actor,
) (*GroupTemplate, error) {
	count, err := validateTemplate(in)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(in.Nodes)
	if err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var t GroupTemplate
	err = tx.QueryRow(ctx, `
		INSERT INTO tenant.group_templates (tenant_id, name, description, nodes)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, name, description, created_at, updated_at
	`, tenantID, strings.TrimSpace(in.Name), in.Description, raw).
		Scan(&t.ID, &t.TenantID, &t.Name, &t.Description, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrGroupTemplateNameExists
		}
		return nil, err
	}
	t.Nodes, t.GroupCount = in.Nodes, count

	if err := audit.Record(ctx, tx, actor.Event(tenantID, "group_template.created",
		"group_template", t.ID, map[string]any{"name": t.Name, "groups": count})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Service) DeleteTemplate(
	ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var name string
	err = tx.QueryRow(ctx,
		`DELETE FROM tenant.group_templates WHERE id = $1 AND tenant_id = $2 RETURNING name`,
		id, tenantID).Scan(&name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrNotFound
		}
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "group_template.deleted",
		"group_template", id, map[string]any{"name": name})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ApplyTemplate creates a template's tree as groups under an optional parent, in
// one transaction: a half-applied tree is worse than none.
func (s *Service) ApplyTemplate(
	ctx context.Context, id, tenantID uuid.UUID, parentID *uuid.UUID, actor audit.Actor,
) ([]Group, error) {
	var raw []byte
	var tmplName string
	err := s.pool.QueryRow(ctx,
		`SELECT name, nodes FROM tenant.group_templates WHERE id = $1 AND tenant_id = $2`,
		id, tenantID).Scan(&tmplName, &raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	var nodes []TemplateNode
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return nil, err
	}

	// The parent is caller-supplied and must be one of this tenant's groups;
	// checking first gives ErrGroupNotFound rather than a foreign-key error.
	if parentID != nil {
		ok, err := s.q.GroupExists(ctx, dbgen.GroupExistsParams{ID: *parentID, TenantID: tenantID})
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errs.ErrGroupNotFound
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	created, err := insertTree(ctx, tx, tenantID, parentID, nodes)
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "group_template.applied",
		"group_template", id,
		map[string]any{"name": tmplName, "groups_created": len(created)})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: id, Topic: "group.events", EventType: "group_template.applied",
		Payload: map[string]any{"template_id": id, "groups": created},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return created, nil
}

func insertTree(
	ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, parentID *uuid.UUID, nodes []TemplateNode,
) ([]Group, error) {
	out := make([]Group, 0, len(nodes))
	for _, n := range nodes {
		var g Group
		var parent any
		if parentID != nil {
			parent = *parentID
		}
		err := tx.QueryRow(ctx, `
			INSERT INTO tenant.groups (tenant_id, parent_id, name, description)
			VALUES ($1, $2, $3, $4)
			RETURNING id, tenant_id, name, description, created_at
		`, tenantID, parent, strings.TrimSpace(n.Name), n.Description).
			Scan(&g.ID, &g.TenantID, &g.Name, &g.Description, &g.CreatedAt)
		if err != nil {
			if pgxerr.IsUnique(err) {
				return nil, errs.ErrGroupNameExists.WithDetail(
					fmt.Sprintf("group %q already exists in this organization", strings.TrimSpace(n.Name)))
			}
			return nil, err
		}
		g.ParentID = parentID
		out = append(out, g)

		if len(n.Children) > 0 {
			kids, err := insertTree(ctx, tx, tenantID, &g.ID, n.Children)
			if err != nil {
				return nil, err
			}
			out = append(out, kids...)
		}
	}
	return out, nil
}
