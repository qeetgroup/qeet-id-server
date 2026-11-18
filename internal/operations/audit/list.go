package audit

import (
	"context"
	"encoding/json"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Reader reads an organization's audit log.
type Reader struct {
	pool *pgxpool.Pool
}

// NewReader returns a Reader over pool.
func NewReader(pool *pgxpool.Pool) *Reader {
	return &Reader{pool: pool}
}

// Row is one audit event as List returns it.
type Row struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID *uuid.UUID     `json:"organization_id"`
	ActorUserID    *uuid.UUID     `json:"actor_user_id"`
	ActorType      string         `json:"actor_type"`
	Action         string         `json:"action"`
	ResourceType   string         `json:"resource_type"`
	ResourceID     *uuid.UUID     `json:"resource_id"`
	IP             *string        `json:"ip"`
	UserAgent      *string        `json:"user_agent"`
	RequestID      *string        `json:"request_id"`
	CreatedAt      time.Time      `json:"created_at"`
	Metadata       map[string]any `json:"metadata"`
}

// ListFilter narrows List's results; zero-value fields do not filter, and set
// ones combine. Actions and ResourceTypes match any of theirs. Search finds
// words of the action, resource, user agent, address and metadata, as
// prefixes ("quoted phrases", -exclusions and OR as websearch_to_tsquery
// reads them), or the actor's name or email.
type ListFilter struct {
	Actions       []string
	ResourceTypes []string
	ResourceID    *uuid.UUID
	ActorUserID   uuid.UUID
	IP            *netip.Addr
	From, To      *time.Time
	Search        string
}

// MaxCounted is how far List's total counts; past it the total says it is
// capped, as a count of a long history would read all of it.
const MaxCounted = 10000

// where is filter's conditions beyond the organization's own rows ($1), with their
// arguments, the organization's first.
func (filter ListFilter) where(organizationID uuid.UUID) (string, []any) {
	q := `TRUE`
	args := []any{organizationID}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if len(filter.Actions) > 0 {
		q += ` AND action = ANY(` + arg(filter.Actions) + `)`
	}
	if len(filter.ResourceTypes) > 0 {
		q += ` AND resource_type = ANY(` + arg(filter.ResourceTypes) + `)`
	}
	if filter.ResourceID != nil {
		q += ` AND resource_id = ` + arg(*filter.ResourceID)
	}
	if filter.ActorUserID != uuid.Nil {
		q += ` AND actor_user_id = ` + arg(filter.ActorUserID)
	}
	if filter.IP != nil {
		q += ` AND ip = ` + arg(filter.IP.String()) + `::inet`
	}
	if filter.From != nil {
		q += ` AND created_at >= ` + arg(*filter.From)
	}
	if filter.To != nil {
		q += ` AND created_at <= ` + arg(*filter.To)
	}
	if filter.Search != "" {
		search, like := arg(filter.Search), arg(postgres.EscapeLike(filter.Search))
		q += ` AND (search_vector @@ audit.search_query(` + search + `) OR actor_user_id IN (
			SELECT su.id FROM account.users su
			WHERE (su.email ILIKE ` + like + ` || '%' OR su.display_name ILIKE '%' || ` + like + ` || '%')
			  AND (su.organization_id = $1 OR su.id IN (SELECT sr.user_id FROM rbac.user_roles sr WHERE sr.organization_id = $1))))`
	}
	return q, args
}

// List returns up to limit of the organization's audit rows (50 when limit is
// unset, at most 200), newest first, a cursor for the next page, or "" on the
// last page, and how many rows match, up to MaxCounted.
func (rd *Reader) List(ctx context.Context, organizationID uuid.UUID, limit int, cursor string, filter ListFilter) ([]Row, string, int, error) {
	limit = paging.Clamp(limit, 50, 200)
	where, args := filter.where(organizationID)
	var total int
	if err := rd.pool.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM audit.events WHERE organization_id = $1 AND `+where+
		` LIMIT `+strconv.Itoa(MaxCounted+1)+`) matched`, args...).Scan(&total); err != nil {
		return nil, "", 0, err
	}
	q := `
		SELECT id, organization_id, actor_user_id, actor_type, action, resource_type, resource_id,
		       host(ip), user_agent, request_id, created_at, metadata
		FROM audit.events
		WHERE organization_id = $1 AND ` + where
	if cursor != "" {
		cid, err := uuid.Parse(cursor)
		if err != nil {
			return nil, "", 0, ErrCursorInvalid
		}
		args = append(args, cid)
		q += ` AND (created_at, id) < (SELECT created_at, id FROM audit.events WHERE id = $` + strconv.Itoa(len(args)) + ` AND organization_id = $1)`
	}
	args = append(args, limit+1)
	q += ` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(len(args))

	resRows, err := rd.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, "", 0, err
	}
	defer resRows.Close()
	// Empty, not nil, so an empty page encodes as [] rather than null.
	out := []Row{}
	for resRows.Next() {
		var r Row
		var meta []byte
		if err := resRows.Scan(&r.ID, &r.OrganizationID, &r.ActorUserID, &r.ActorType, &r.Action,
			&r.ResourceType, &r.ResourceID, &r.IP, &r.UserAgent, &r.RequestID, &r.CreatedAt, &meta); err != nil {
			return nil, "", 0, err
		}
		r.Metadata = map[string]any{}
		if len(meta) > 0 {
			if err := json.Unmarshal(meta, &r.Metadata); err != nil {
				return nil, "", 0, err
			}
		}
		out = append(out, r)
	}
	// Without this, a truncated read would return a short page that looks
	// complete.
	if err := resRows.Err(); err != nil {
		return nil, "", 0, err
	}
	// The cursor is the last row returned; the next page starts after it.
	var next string
	if len(out) > limit {
		out = out[:limit]
		next = out[limit-1].ID.String()
	}
	return out, next, total, nil
}
