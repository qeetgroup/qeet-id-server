package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// RoleRef is one of a person's roles in an organisation.
type RoleRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// ListFilter narrows and orders an organisation's members. Each set field
// narrows, and they combine. Sort is "created" (the default), "name" or
// "last_seen"; Desc orders newest, or Z, first.
type ListFilter struct {
	Query         string // display name, email or phone, case-insensitive
	Role          string // a role name in the organisation
	Department    string // metadata.department
	MFA           *bool  // a confirmed second factor
	EmailVerified *bool
	Status        string // active, invited or suspended
	LastSeen      string // today, week, month, older or never
	Sort          string
	Desc          bool

	id *uuid.UUID // one member, for a single read
}

// Last-seen buckets, by how long ago the person last used the organisation.
var lastSeenBuckets = map[string]string{
	"today": `m.last_seen_at >= NOW() - INTERVAL '1 day'`,
	"week":  `m.last_seen_at < NOW() - INTERVAL '1 day' AND m.last_seen_at >= NOW() - INTERVAL '7 days'`,
	"month": `m.last_seen_at < NOW() - INTERVAL '7 days' AND m.last_seen_at >= NOW() - INTERVAL '30 days'`,
	"older": `m.last_seen_at < NOW() - INTERVAL '30 days'`,
	"never": `m.last_seen_at IS NULL`,
}

// Orders of the members list; each ends on id so pages are stable.
var listSorts = map[string]string{
	"created":   `m.created_at %[1]s, m.id %[1]s`,
	"name":      `lower(COALESCE(NULLIF(m.display_name, ''), m.email)) %[1]s, m.id %[1]s`,
	"last_seen": `m.last_seen_at %[1]s NULLS LAST, m.id %[1]s`,
}

// ParseListFilter reads the members list's query parameters: q, role,
// department, mfa (on or off), email_verified, status, last_seen, sort and
// order (asc or desc). A malformed one is refused with ErrBadRequest.
func ParseListFilter(v url.Values) (ListFilter, error) {
	f := ListFilter{
		Query:      strings.TrimSpace(v.Get("q")),
		Role:       strings.TrimSpace(v.Get("role")),
		Department: strings.TrimSpace(v.Get("department")),
		Status:     v.Get("status"),
		LastSeen:   v.Get("last_seen"),
		Sort:       v.Get("sort"),
	}
	bad := func(name string) (ListFilter, error) {
		return ListFilter{}, errs.ErrBadRequest.WithDetail("invalid " + name)
	}
	switch v.Get("mfa") {
	case "":
	case "on", "off":
		on := v.Get("mfa") == "on"
		f.MFA = &on
	default:
		return bad("mfa")
	}
	if raw := v.Get("email_verified"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return bad("email_verified")
		}
		f.EmailVerified = &b
	}
	switch f.Status {
	case "", "active", "invited", "suspended":
	default:
		return bad("status")
	}
	if _, ok := lastSeenBuckets[f.LastSeen]; f.LastSeen != "" && !ok {
		return bad("last_seen")
	}
	if f.Sort == "" {
		f.Sort = "created"
	}
	if _, ok := listSorts[f.Sort]; !ok {
		return bad("sort")
	}
	switch v.Get("order") {
	case "":
		f.Desc = f.Sort != "name"
	case "desc":
		f.Desc = true
	case "asc":
	default:
		return bad("order")
	}
	if len(f.Query) > 200 || len(f.Role) > 200 || len(f.Department) > 200 {
		return bad("filter")
	}
	return f, nil
}

// keyset reports whether f orders the list newest first by creation, the
// one order a cursor pages.
func (f ListFilter) keyset() bool { return f.Sort == "created" && f.Desc }

// membersCTE is an organisation's members ($1): its home people and those
// holding one of its roles, with their roles there, whether they have a second
// factor, how many of its groups they're in, when they were last seen there,
// and their home organisation's name.
const membersCTE = `WITH m AS (
	SELECT ` + userCols + `,
	  COALESCE((
		SELECT array_agg(r.name ORDER BY r.name)
		FROM rbac.user_roles ur2 JOIN rbac.roles r ON r.id = ur2.role_id
		WHERE ur2.user_id = "user".users.id AND ur2.tenant_id = $1
	  ), '{}') AS roles,
	  COALESCE((
		SELECT jsonb_agg(jsonb_build_object('id', r.id, 'name', r.name) ORDER BY r.name)
		FROM rbac.user_roles ur2 JOIN rbac.roles r ON r.id = ur2.role_id
		WHERE ur2.user_id = "user".users.id AND ur2.tenant_id = $1
	  ), '[]') AS role_refs,
	  (EXISTS(SELECT 1 FROM auth.mfa_totp t WHERE t.user_id = "user".users.id AND t.confirmed_at IS NOT NULL)
	   OR EXISTS(SELECT 1 FROM auth.mfa_otp_factors o WHERE o.user_id = "user".users.id AND o.verified_at IS NOT NULL)
	   OR EXISTS(SELECT 1 FROM auth.mfa_push_devices d WHERE d.user_id = "user".users.id))::boolean AS mfa_enabled,
	  (SELECT count(*) FROM tenant.group_members gm
	   WHERE gm.user_id = "user".users.id AND gm.tenant_id = $1)::int AS groups_count,
	  ` + lastSeenCols + `,
	  (SELECT ht.name FROM tenant.tenants ht WHERE ht.id = "user".users.tenant_id) AS home_tenant_name
	FROM "user".users
	WHERE deleted_at IS NULL
	  AND id IN (
		SELECT u.id FROM "user".users u WHERE u.tenant_id = $1 AND u.deleted_at IS NULL
		UNION
		SELECT ur.user_id FROM rbac.user_roles ur WHERE ur.tenant_id = $1
	  )
)
`

// where is f's conditions on the members m, with their arguments after the
// args already taken.
func (f ListFilter) where(args []any) (string, []any) {
	conds := []string{"TRUE"}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if f.id != nil {
		conds = append(conds, "m.id = "+arg(*f.id))
	}
	if f.Query != "" {
		p := arg("%" + postgres.EscapeLike(f.Query) + "%")
		conds = append(conds, "(m.display_name ILIKE "+p+" OR m.email ILIKE "+p+" OR m.phone ILIKE "+p+")")
	}
	if f.Role != "" {
		conds = append(conds, "EXISTS (SELECT 1 FROM unnest(m.roles) rn WHERE lower(rn) = lower("+arg(f.Role)+"))")
	}
	if f.Department != "" {
		conds = append(conds, "lower(m.metadata->>'department') = lower("+arg(f.Department)+")")
	}
	if f.MFA != nil {
		conds = append(conds, "m.mfa_enabled = "+arg(*f.MFA))
	}
	if f.EmailVerified != nil {
		conds = append(conds, "(m.email_verified_at IS NOT NULL) = "+arg(*f.EmailVerified))
	}
	if f.Status != "" {
		conds = append(conds, "m.status = "+arg(f.Status))
	}
	if f.LastSeen != "" {
		conds = append(conds, "("+lastSeenBuckets[f.LastSeen]+")")
	}
	return strings.Join(conds, " AND "), args
}

// List returns a page of the tenant's members that f matches, the next
// cursor, and how many match in all. offset > 0 pages by offset; otherwise a
// cursor pages, in the default order only.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID, f ListFilter, limit int, cursor string, offset int) ([]User, string, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if f.Sort == "" {
		f.Sort, f.Desc = "created", true
	}
	where, args := f.where([]any{tenantID})
	// Counted apart from the page: the count reads only the columns the filters
	// name, and the page works out the rest for its own rows alone.
	var total int
	if f.id == nil {
		if err := r.pool.QueryRow(ctx, membersCTE+`SELECT count(*) FROM m WHERE `+where, args...).Scan(&total); err != nil {
			return nil, "", 0, err
		}
	}
	if cursor != "" {
		if !f.keyset() || offset > 0 {
			return nil, "", 0, errs.ErrBadRequest.WithDetail("a cursor pages only the default order, without an offset")
		}
		curT, curID, err := paging.DecodeTimeUUID(cursor)
		if err != nil {
			return nil, "", 0, errs.ErrBadRequest.WithDetail("invalid cursor")
		}
		args = append(append([]any{}, args...), curT, curID)
		where += fmt.Sprintf(" AND (m.created_at, m.id) < ($%d, $%d)", len(args)-1, len(args))
	}
	dir := "ASC"
	if f.Desc {
		dir = "DESC"
	}
	args = append(args, limit+1, offset)
	rows, err := r.pool.Query(ctx, membersCTE+`SELECT `+userCols+`, roles, role_refs, mfa_enabled, groups_count,
		last_seen_at, last_seen_ip, home_tenant_name
		FROM m WHERE `+where+` ORDER BY `+fmt.Sprintf(listSorts[f.Sort], dir)+
		fmt.Sprintf(` LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, "", 0, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		var meta, refs []byte
		var tid *uuid.UUID
		var mfaEnabled bool
		var groupsCount int
		if err := rows.Scan(&u.ID, &tid, &u.Email, &u.EmailVerifiedAt,
			&u.Phone, &u.PhoneVerifiedAt, &u.DisplayName, &u.Status, &meta,
			&u.CreatedAt, &u.UpdatedAt, &u.Roles, &refs,
			&mfaEnabled, &groupsCount, &u.LastSeenAt, &u.LastSeenIP, &u.HomeTenantName); err != nil {
			return nil, "", 0, err
		}
		if tid != nil {
			u.TenantID = *tid
		}
		if err := json.Unmarshal(refs, &u.AssignedRoles); err != nil {
			return nil, "", 0, err
		}
		u.MfaEnabled, u.GroupsCount = &mfaEnabled, &groupsCount
		u.Metadata = parseUserMetadata(meta, u.ID)
		out = append(out, *u.SeenBy(tenantID))
	}
	// A mid-stream failure stops the loop without an error from Scan; unchecked,
	// it returns a short page and a cursor that skips people.
	if err := rows.Err(); err != nil {
		return nil, "", 0, err
	}
	var next string
	if len(out) > limit {
		out = out[:limit]
		if f.keyset() && offset == 0 {
			last := out[limit-1]
			next = paging.EncodeTimeUUID(last.CreatedAt, last.ID)
		}
	}
	return out, next, total, nil
}

// Member is user id as a member of tenantID sees them: their roles there,
// second factor, groups, when they were last seen there and their home
// organisation's name. ErrNotFound if they aren't a member.
func (r *Repository) Member(ctx context.Context, tenantID, id uuid.UUID) (*User, error) {
	out, _, _, err := r.List(ctx, tenantID, ListFilter{id: &id}, 1, "", 0)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errs.ErrNotFound
	}
	return &out[0], nil
}

// Suspension is why and when a person was suspended, and by whom, as their
// home organisation recorded it.
type Suspension struct {
	Reason           string     `json:"reason"`
	Source           string     `json:"source"`
	SuspendedAt      *time.Time `json:"suspended_at"`
	SuspendedBy      *uuid.UUID `json:"suspended_by"`
	SuspendedByEmail *string    `json:"suspended_by_email"`
}

// SuspensionOf returns user id's suspension in tenantID, their home: the
// recorded reason and source, and who last suspended them by hand. nil when
// they aren't suspended, or tenantID isn't their home.
func (r *Repository) SuspensionOf(ctx context.Context, tenantID, id uuid.UUID) (*Suspension, error) {
	var s Suspension
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(u.suspension_reason, 'unspecified'), COALESCE(u.suspension_source, 'unknown'), u.suspended_at,
		       e.actor_user_id, a.email
		FROM "user".users u
		LEFT JOIN LATERAL (
			SELECT ev.actor_user_id FROM audit.events ev
			WHERE ev.tenant_id = $1 AND ev.resource_id = u.id AND ev.action = 'user.suspended'
			ORDER BY ev.created_at DESC LIMIT 1
		) e ON TRUE
		LEFT JOIN "user".users a ON a.id = e.actor_user_id
		WHERE u.id = $2 AND u.tenant_id = $1 AND u.status = 'suspended' AND u.deleted_at IS NULL`,
		tenantID, id).Scan(&s.Reason, &s.Source, &s.SuspendedAt, &s.SuspendedBy, &s.SuspendedByEmail)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// MemberCounts is the rest of the Users summary: members by when they were
// last seen, the owners and admins without a second factor, the members
// whose email isn't verified, and members by role and by department.
type MemberCounts struct {
	LastSeen         map[string]int `json:"last_seen"`
	AdminsWithoutMFA int            `json:"admins_without_mfa"`
	EmailUnverified  int            `json:"email_unverified"`
	ByRole           []RoleCount    `json:"by_role"`
	ByDepartment     []DeptCount    `json:"by_department"`
}

// RoleCount is how many members hold a role.
type RoleCount struct {
	Role  string `json:"role"`
	Count int    `json:"count"`
}

// DeptCount is how many members are in a department.
type DeptCount struct {
	Department string `json:"department"`
	Count      int    `json:"count"`
}

// Counts returns the tenant's MemberCounts, each with the same edges as the
// list's filters, so a count equals the list's total for that filter.
func (r *Repository) Counts(ctx context.Context, tenantID uuid.UUID) (*MemberCounts, error) {
	c := MemberCounts{LastSeen: map[string]int{}}
	var today, week, month, older, never int
	if err := r.pool.QueryRow(ctx, membersCTE+`SELECT
		count(*) FILTER (WHERE `+lastSeenBuckets["today"]+`),
		count(*) FILTER (WHERE `+lastSeenBuckets["week"]+`),
		count(*) FILTER (WHERE `+lastSeenBuckets["month"]+`),
		count(*) FILTER (WHERE `+lastSeenBuckets["older"]+`),
		count(*) FILTER (WHERE `+lastSeenBuckets["never"]+`),
		count(*) FILTER (WHERE NOT m.mfa_enabled AND EXISTS (
			SELECT 1 FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
			WHERE ur.user_id = m.id AND ur.tenant_id = $1 AND r.is_system AND r.name IN ('owner', 'admin'))),
		count(*) FILTER (WHERE m.email_verified_at IS NULL)
		FROM m`, tenantID).Scan(&today, &week, &month, &older, &never, &c.AdminsWithoutMFA, &c.EmailUnverified); err != nil {
		return nil, err
	}
	c.LastSeen = map[string]int{"today": today, "week": week, "month": month, "older": older, "never": never}

	rows, err := r.pool.Query(ctx, membersCTE+`SELECT rn, count(*)::int FROM m, unnest(m.roles) rn
		GROUP BY rn ORDER BY 2 DESC, 1`, tenantID)
	if err != nil {
		return nil, err
	}
	c.ByRole, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (RoleCount, error) {
		var rc RoleCount
		return rc, row.Scan(&rc.Role, &rc.Count)
	})
	if err != nil {
		return nil, err
	}
	rows, err = r.pool.Query(ctx, membersCTE+`SELECT m.metadata->>'department', count(*)::int FROM m
		WHERE COALESCE(m.metadata->>'department', '') <> ''
		GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 200`, tenantID)
	if err != nil {
		return nil, err
	}
	c.ByDepartment, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (DeptCount, error) {
		var dc DeptCount
		return dc, row.Scan(&dc.Department, &dc.Count)
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}
