package group

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/group/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
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

// GroupTemplate is a stored tree of groups the organization can apply.
type GroupTemplate struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID uuid.UUID      `json:"organization_id"`
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	Nodes          []TemplateNode `json:"nodes"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	// GroupCount is how many groups applying this template would create.
	GroupCount int `json:"group_count"`
}

// TemplateInput is what CreateTemplate takes.
type TemplateInput struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Nodes       []TemplateNode `json:"nodes"`
}

// countNodes walks a template tree, validating shape as it goes. It returns the
// total number of groups the tree would create.
func countNodes(nodes []TemplateNode, depth int) (int, error) {
	if depth > maxTemplateDepth {
		return 0, ErrTemplateTooDeep
	}
	total := 0
	for _, n := range nodes {
		if strings.TrimSpace(n.Name) == "" {
			return 0, ErrTemplateNodeUnnamed
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
		return 0, ErrTemplateUnnamed
	}
	count, err := countNodes(in.Nodes, 1)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, ErrTemplateEmpty
	}
	if count > maxTemplateNodes {
		return 0, ErrTemplateTooLarge
	}
	if dup := duplicateNodeName(in.Nodes, map[string]bool{}); dup != "" {
		return 0, errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "nodes", Code: "duplicate_name",
			Message: fmt.Sprintf("%q is used more than once; each group in a template needs its own name.", dup),
		}})
	}
	return count, nil
}

// ListTemplates returns the organization's group templates: at most
// paging.MaxListItems+1, as the handler truncates the rest.
func (s *Service) ListTemplates(ctx context.Context, organizationID uuid.UUID) ([]GroupTemplate, error) {
	rows, err := s.q.ListGroupTemplates(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]GroupTemplate, 0, len(rows))
	for _, row := range rows {
		t := GroupTemplate{ID: row.ID, OrganizationID: row.OrganizationID, Name: row.Name,
			Description: row.Description, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
		if err := json.Unmarshal(row.Nodes, &t.Nodes); err != nil {
			return nil, err
		}
		t.GroupCount, _ = countNodes(t.Nodes, 1)
		out = append(out, t)
	}
	return out, nil
}

// CreateTemplate stores a group template for the organization.
func (s *Service) CreateTemplate(
	ctx context.Context, organizationID uuid.UUID, in TemplateInput, actor audit.Actor,
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

	row, err := s.q.WithTx(tx).InsertGroupTemplate(ctx, dbgen.InsertGroupTemplateParams{
		OrganizationID: organizationID, Name: strings.TrimSpace(in.Name), Description: in.Description, Nodes: raw,
	})
	if err != nil {
		if postgres.IsUnique(err) {
			return nil, ErrTemplateNameExists
		}
		return nil, err
	}
	t := GroupTemplate{ID: row.ID, OrganizationID: row.OrganizationID, Name: row.Name, Description: row.Description,
		Nodes: in.Nodes, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, GroupCount: count}

	if err := audit.Record(ctx, tx, actor.Event(organizationID, "group_template.created",
		"group_template", t.ID, map[string]any{"name": t.Name, "groups": count})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteTemplate removes one of the organization's group templates.
func (s *Service) DeleteTemplate(
	ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	name, err := s.q.WithTx(tx).DeleteGroupTemplate(ctx, dbgen.DeleteGroupTemplateParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrNotFound
		}
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "group_template.deleted",
		"group_template", id, map[string]any{"name": name})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ApplyTemplate creates a template's tree as groups under an optional parent, in
// one transaction: a half-applied tree is worse than none.
// ApplyOptions are where a template's groups go and what they're called:
// under ParentID (nil: at the root), each named Prefix + its template name, and
// the template's one top group named RootName instead, when given.
type ApplyOptions struct {
	ParentID *uuid.UUID
	Prefix   string
	RootName string
}

// maxGroupNameRunes bounds a group name a template produces.
const maxGroupNameRunes = 200

// named returns nodes with the names applying them under o gives, refusing a
// root name for a template without exactly one top group and any name left
// empty or longer than maxGroupNameRunes.
func (o ApplyOptions) named(nodes []TemplateNode) ([]TemplateNode, error) {
	if strings.TrimSpace(o.RootName) != "" && len(nodes) != 1 {
		return nil, errs.ErrValidationFailed.WithFields([]errs.FieldError{{Field: "root_name", Code: "invalid",
			Message: "This template has more than one top group, so there is none to rename."}})
	}
	var rename func(nodes []TemplateNode, top bool) ([]TemplateNode, error)
	rename = func(nodes []TemplateNode, top bool) ([]TemplateNode, error) {
		out := make([]TemplateNode, len(nodes))
		for i, n := range nodes {
			name := n.Name
			if top && strings.TrimSpace(o.RootName) != "" {
				name = o.RootName
			}
			n.Name = strings.TrimSpace(o.Prefix + strings.TrimSpace(name))
			if n.Name == "" || utf8.RuneCountInString(n.Name) > maxGroupNameRunes {
				return nil, errs.ErrValidationFailed.WithFields([]errs.FieldError{{Field: "prefix", Code: "too_long",
					Message: fmt.Sprintf("Group names can be at most %d characters; %q would be longer.", maxGroupNameRunes, n.Name)}})
			}
			kids, err := rename(n.Children, false)
			if err != nil {
				return nil, err
			}
			n.Children = kids
			out[i] = n
		}
		return out, nil
	}
	return rename(nodes, true)
}

// ApplyTemplate makes the template's groups in one transaction, named as opts
// says; a name already taken makes none.
func (s *Service) ApplyTemplate(
	ctx context.Context, id, organizationID uuid.UUID, opts ApplyOptions, actor audit.Actor,
) ([]Group, error) {
	parentID := opts.ParentID
	tmpl, err := s.q.GetGroupTemplate(ctx, dbgen.GetGroupTemplateParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	var nodes []TemplateNode
	if err := json.Unmarshal(tmpl.Nodes, &nodes); err != nil {
		return nil, err
	}
	if nodes, err = opts.named(nodes); err != nil {
		return nil, err
	}

	// The parent is caller-supplied and must be one of this organization's groups;
	// checking first gives ErrGroupNotFound rather than a foreign-key error.
	if parentID != nil {
		ok, err := s.q.GroupExists(ctx, dbgen.GroupExistsParams{ID: *parentID, OrganizationID: organizationID})
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

	created, err := insertTree(ctx, s.q.WithTx(tx), organizationID, parentID, nodes)
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "group_template.applied",
		"group_template", id,
		map[string]any{"name": tmpl.Name, "groups_created": len(created), "prefix": opts.Prefix, "root_name": opts.RootName})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: id, Topic: "group.events", EventType: "group_template.applied",
		Payload: map[string]any{"template_id": id, "organization_id": organizationID, "groups": created},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return created, nil
}

// insertTree creates nodes, and below each its children, under parentID (nil:
// at the root) with q, a transaction's queries.
func insertTree(
	ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID, parentID *uuid.UUID, nodes []TemplateNode,
) ([]Group, error) {
	out := make([]Group, 0, len(nodes))
	for _, n := range nodes {
		row, err := q.InsertGroup(ctx, dbgen.InsertGroupParams{
			OrganizationID: organizationID, ParentID: parentID, Name: strings.TrimSpace(n.Name), Description: n.Description,
		})
		if err != nil {
			if postgres.IsUnique(err) {
				return nil, ErrNameExists.WithDetail(
					fmt.Sprintf("group %q already exists in this organization", strings.TrimSpace(n.Name)))
			}
			return nil, err
		}
		g := groupFromInsertRow(row)
		out = append(out, g)

		if len(n.Children) > 0 {
			kids, err := insertTree(ctx, q, organizationID, &g.ID, n.Children)
			if err != nil {
				return nil, err
			}
			out = append(out, kids...)
		}
	}
	return out, nil
}
