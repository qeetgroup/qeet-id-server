// Package search is the admin console's search across users, organizations,
// groups, roles, OIDC clients and audit events. It runs a read-only ILIKE query
// per type, scores and merges the rows in Go, and returns a cursor-paginated
// page, scoped to one tenant and to the types the user may read.
package search

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/search/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// permissionChecker reports whether a user holds a permission in a tenant.
// *rbac.Repository satisfies it.
type permissionChecker interface {
	Check(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (bool, error)
}

// Resource types a Result can have.
const (
	TypeUser         = "user"
	TypeOrganization = "organization"
	TypeGroup        = "group"
	TypeRole         = "role"
	TypeOIDCClient   = "oidc_client"
	TypeAuditEvent   = "audit_event"
)

// supportedTypes lists the searchable resource types in query order; results
// are sorted by score afterwards.
var supportedTypes = []string{
	TypeUser,
	TypeOrganization,
	TypeGroup,
	TypeRole,
	TypeOIDCClient,
	TypeAuditEvent,
}

// typePermission maps each resource type to the permission a user needs to see
// it in results.
var typePermission = map[string]string{
	TypeUser:         "user.read",
	TypeOrganization: "tenant.read",
	TypeGroup:        "group.read",
	TypeRole:         "role.read",
	TypeOIDCClient:   "connection.read",
	TypeAuditEvent:   "audit.read",
}

// perTypeLimit is the most rows fetched per resource type per request, so one
// search holds at most 300 rows in memory.
const perTypeLimit = 50

// Result is one item in a search response.
type Result struct {
	Type      string         `json:"type"`
	ID        uuid.UUID      `json:"id"`
	Title     string         `json:"title"`
	Subtitle  string         `json:"subtitle"`
	URL       string         `json:"url"`
	Status    string         `json:"status"`
	UpdatedAt time.Time      `json:"updated_at"`
	Score     float64        `json:"score"`
	Metadata  map[string]any `json:"metadata"`
}

// Service runs the per-type queries and merges their results.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	rbac permissionChecker
}

// NewService returns a Service that checks per-type permissions with checker.
func NewService(pool *pgxpool.Pool, checker permissionChecker) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), rbac: checker}
}

// Search returns up to limit results in tenantID (20 if limit is not in 1..50),
// best score first, and the next page's cursor, or "" on the last page. types
// narrows the search and unknown types are ignored. With a non-nil userID, types
// the user may not read are skipped; a nil userID skips the checks.
func (s *Service) Search(
	ctx context.Context,
	tenantID uuid.UUID,
	userID *uuid.UUID,
	q string,
	types []string,
	cursor string,
	limit int,
) ([]Result, string, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	// pattern is passed as a bind variable, never concatenated into SQL.
	pattern := "%" + q + "%"

	// Honour the caller's type filter, dropping unknown types.
	candidates := supportedTypes
	if len(types) > 0 {
		candidates = make([]string, 0, len(types))
		for _, t := range types {
			if _, ok := typePermission[t]; ok {
				candidates = append(candidates, t)
			}
		}
	}

	// Skip types the user may not read. A checker error fails the request rather
	// than return an over-broad result.
	var all []Result
	for _, t := range candidates {
		if userID != nil {
			ok, err := s.rbac.Check(ctx, *userID, tenantID, typePermission[t])
			if err != nil {
				return nil, "", err
			}
			if !ok {
				continue
			}
		}
		rows, err := s.fetchType(ctx, tenantID, pattern, q, t)
		if err != nil {
			return nil, "", err
		}
		all = append(all, rows...)
	}

	// Sort: score DESC, then ID ASC for a stable tiebreaker.
	sort.Slice(all, func(i, j int) bool {
		if all[i].Score != all[j].Score {
			return all[i].Score > all[j].Score
		}
		return bytes.Compare(all[i].ID[:], all[j].ID[:]) < 0
	})

	// The cursor holds the (score, id) of the previous page's last item; the next
	// page starts after it.
	if cursor != "" {
		curScore, curID, err := decodeCursor(cursor)
		if err != nil {
			return nil, "", err
		}
		newStart := len(all) // default: past end (empty next page)
		for i, r := range all {
			if r.ID == curID {
				// Cursor item found — the next page begins at i+1.
				newStart = i + 1
				break
			}
			// The cursor item is gone (deleted since); start at the first item that
			// sorts after its position.
			if r.Score < curScore || (r.Score == curScore && bytes.Compare(r.ID[:], curID[:]) > 0) {
				newStart = i
				break
			}
		}
		all = all[newStart:]
	}

	// Emit next-page cursor when more results remain.
	var nextCursor string
	if len(all) > limit {
		last := all[limit-1]
		nextCursor = encodeCursor(last.Score, last.ID)
		all = all[:limit]
	}

	// Always return a non-nil slice so the JSON encoder emits [] not null.
	if all == nil {
		all = []Result{}
	}
	return all, nextCursor, nil
}

// --- per-type fetch helpers ---

func (s *Service) fetchType(ctx context.Context, tenantID uuid.UUID, pattern, rawQ, t string) ([]Result, error) {
	switch t {
	case TypeUser:
		return s.fetchUsers(ctx, tenantID, pattern, rawQ)
	case TypeOrganization:
		return s.fetchOrganization(ctx, tenantID, pattern, rawQ)
	case TypeGroup:
		return s.fetchGroups(ctx, tenantID, pattern, rawQ)
	case TypeRole:
		return s.fetchRoles(ctx, tenantID, pattern, rawQ)
	case TypeOIDCClient:
		return s.fetchOIDCClients(ctx, tenantID, pattern, rawQ)
	case TypeAuditEvent:
		return s.fetchAuditEvents(ctx, tenantID, pattern, rawQ)
	}
	return nil, nil
}

func (s *Service) fetchUsers(ctx context.Context, tenantID uuid.UUID, pattern, rawQ string) ([]Result, error) {
	rows, err := s.q.SearchUsers(ctx, dbgen.SearchUsersParams{
		TenantID: tenantID,
		Q:        pattern,
		RowLimit: perTypeLimit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(rows))
	for _, r := range rows {
		name := r.Email
		if r.DisplayName != nil && *r.DisplayName != "" {
			name = *r.DisplayName
		}
		sc := maxScore(scoreText(r.Email, rawQ), scoreText(name, rawQ))
		out = append(out, Result{
			Type:      TypeUser,
			ID:        r.ID,
			Title:     name,
			Subtitle:  r.Email,
			URL:       "/users/" + r.ID.String(),
			Status:    r.Status,
			UpdatedAt: r.UpdatedAt,
			Score:     sc,
			Metadata:  map[string]any{"display_name": name},
		})
	}
	return out, nil
}

func (s *Service) fetchOrganization(ctx context.Context, tenantID uuid.UUID, pattern, rawQ string) ([]Result, error) {
	rows, err := s.q.SearchOrganization(ctx, dbgen.SearchOrganizationParams{
		TenantID: tenantID,
		Q:        pattern,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(rows))
	for _, r := range rows {
		sc := maxScore(scoreText(r.Name, rawQ), scoreText(r.Slug, rawQ))
		out = append(out, Result{
			Type:      TypeOrganization,
			ID:        r.ID,
			Title:     r.Name,
			Subtitle:  r.Slug,
			URL:       "/organizations/" + r.ID.String(),
			Status:    r.Status,
			UpdatedAt: r.UpdatedAt,
			Score:     sc,
			Metadata:  map[string]any{"slug": r.Slug},
		})
	}
	return out, nil
}

func (s *Service) fetchGroups(ctx context.Context, tenantID uuid.UUID, pattern, rawQ string) ([]Result, error) {
	rows, err := s.q.SearchGroups(ctx, dbgen.SearchGroupsParams{
		TenantID: tenantID,
		Q:        pattern,
		RowLimit: perTypeLimit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(rows))
	for _, r := range rows {
		out = append(out, Result{
			Type:      TypeGroup,
			ID:        r.ID,
			Title:     r.Name,
			Subtitle:  r.Description,
			URL:       "/groups/" + r.ID.String(),
			Status:    "active",
			UpdatedAt: r.CreatedAt,
			Score:     scoreText(r.Name, rawQ),
			Metadata:  map[string]any{"description": r.Description},
		})
	}
	return out, nil
}

func (s *Service) fetchRoles(ctx context.Context, tenantID uuid.UUID, pattern, rawQ string) ([]Result, error) {
	rows, err := s.q.SearchRoles(ctx, dbgen.SearchRolesParams{
		TenantID: tenantID,
		Q:        pattern,
		RowLimit: perTypeLimit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(rows))
	for _, r := range rows {
		out = append(out, Result{
			Type:      TypeRole,
			ID:        r.ID,
			Title:     r.Name,
			Subtitle:  r.Description,
			URL:       "/roles/" + r.ID.String(),
			Status:    "active",
			UpdatedAt: r.CreatedAt,
			Score:     scoreText(r.Name, rawQ),
			Metadata:  map[string]any{"is_system": r.IsSystem},
		})
	}
	return out, nil
}

func (s *Service) fetchOIDCClients(ctx context.Context, tenantID uuid.UUID, pattern, rawQ string) ([]Result, error) {
	rows, err := s.q.SearchOIDCClients(ctx, dbgen.SearchOIDCClientsParams{
		TenantID: tenantID,
		Q:        pattern,
		RowLimit: perTypeLimit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(rows))
	for _, r := range rows {
		sc := maxScore(scoreText(r.Name, rawQ), scoreText(r.ClientID, rawQ))
		out = append(out, Result{
			Type:      TypeOIDCClient,
			ID:        r.ID,
			Title:     r.Name,
			Subtitle:  r.ClientID,
			URL:       "/oidc/clients/" + r.ID.String(),
			Status:    "active",
			UpdatedAt: r.CreatedAt,
			Score:     sc,
			Metadata:  map[string]any{"client_id": r.ClientID, "type": r.ClientType},
		})
	}
	return out, nil
}

func (s *Service) fetchAuditEvents(ctx context.Context, tenantID uuid.UUID, pattern, rawQ string) ([]Result, error) {
	rows, err := s.q.SearchAuditEvents(ctx, dbgen.SearchAuditEventsParams{
		// audit.events.tenant_id is NULL for platform rows; search always passes a
		// tenant.
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Q:        pattern,
		RowLimit: perTypeLimit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(rows))
	for _, r := range rows {
		sc := maxScore(scoreText(r.Action, rawQ), scoreText(r.ResourceType, rawQ))
		var resourceID string
		if r.ResourceID.Valid {
			resourceID = uuid.UUID(r.ResourceID.Bytes).String()
		}
		out = append(out, Result{
			Type:      TypeAuditEvent,
			ID:        r.ID,
			Title:     r.Action,
			Subtitle:  r.ResourceType,
			URL:       "/audit#" + r.ID.String(),
			Status:    "recorded",
			UpdatedAt: r.CreatedAt,
			Score:     sc,
			Metadata:  map[string]any{"resource_type": r.ResourceType, "resource_id": resourceID},
		})
	}
	return out, nil
}

// --- scoring helpers ---

// scoreText scores field against the query, ignoring case: 1.0 for an exact
// match, 0.75 for a prefix match, otherwise 0.5 (the ILIKE matched a
// substring).
func scoreText(field, q string) float64 {
	f := strings.ToLower(strings.TrimSpace(field))
	ql := strings.ToLower(strings.TrimSpace(q))
	if f == "" || ql == "" {
		return 0.5
	}
	switch {
	case f == ql:
		return 1.0
	case strings.HasPrefix(f, ql):
		return 0.75
	default:
		return 0.5
	}
}

func maxScore(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// --- cursor helpers ---

// encodeCursor packs (score, id) into an opaque base64url token. The score is
// stored as its IEEE 754 bits, so it round-trips exactly.
func encodeCursor(score float64, id uuid.UUID) string {
	bits := math.Float64bits(score)
	raw := fmt.Sprintf("%016x|%s", bits, id.String())
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor is the inverse of encodeCursor. It returns errs.ErrBadRequest
// for malformed input.
func decodeCursor(cursor string) (float64, uuid.UUID, error) {
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	parts := strings.SplitN(string(b), "|", 2)
	if len(parts) != 2 {
		return 0, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	var bits uint64
	if _, err := fmt.Sscanf(parts[0], "%016x", &bits); err != nil {
		return 0, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return 0, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	return math.Float64frombits(bits), id, nil
}
