package user

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/user/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// RoleRef is one of a person's roles in an organization.
type RoleRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// ListFilter narrows and orders an organization's members. Each set field
// narrows, and they combine. Sort is "created" (the default), "name" or
// "last_seen"; Desc orders newest, or Z, first.
type ListFilter struct {
	Query         string // display name, email or phone, case-insensitive
	Role          string // a role name in the organization
	Department    string // metadata.department, of the organization's own people
	MFA           *bool  // a confirmed second factor
	EmailVerified *bool
	Status        string // active, invited or suspended
	LastSeen      string // today, week, month, older or never
	// AdminsWithoutMFA is an owner or admin with no second factor, as the
	// summary counts them; InGroup is in one of the organization's groups.
	AdminsWithoutMFA *bool
	InGroup          *bool
	// IDs and Emails name the members wanted (an email exactly, in any case),
	// and IncludeDeleted lets the list name someone since deleted, as history
	// still names them.
	IDs            []uuid.UUID
	Emails         []string
	IncludeDeleted bool
	Sort           string
	Desc           bool

	id *uuid.UUID // one member, for a single read
}

// Last-seen buckets, by how long ago the person last used the organization.
var lastSeenBuckets = map[string]string{
	"today": `m.last_seen_at >= NOW() - INTERVAL '1 day'`,
	"week":  `m.last_seen_at < NOW() - INTERVAL '1 day' AND m.last_seen_at >= NOW() - INTERVAL '7 days'`,
	"month": `m.last_seen_at < NOW() - INTERVAL '7 days' AND m.last_seen_at >= NOW() - INTERVAL '30 days'`,
	"older": `m.last_seen_at < NOW() - INTERVAL '30 days'`,
	"never": `m.last_seen_at IS NULL`,
}

// sortName is the key the name order sorts by: the display name, or the
// email without one, lower-cased.
const sortName = `lower(COALESCE(NULLIF(m.display_name, ''), m.email))`

// Orders of the members list; each ends on id so pages are stable, and a
// member never seen comes last in either direction.
var listSorts = map[string]string{
	"created":   `m.created_at %[1]s, m.id %[1]s`,
	"name":      sortName + ` %[1]s, m.id %[1]s`,
	"last_seen": `m.last_seen_at %[1]s NULLS LAST, m.id %[1]s`,
}

// adminWithoutMFA is a member m holding the organization's ($1) built-in
// owner or admin role with no second factor: the summary's
// admins_without_mfa and the list's filter of the same name.
const adminWithoutMFA = `NOT m.mfa_enabled AND EXISTS (
	SELECT 1 FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
	WHERE ur.user_id = m.id AND ur.organization_id = $1 AND r.is_system AND r.name IN ('owner', 'admin'))`

// maxNamed is how many members one list may name by id, and by email.
const maxNamed = 200

// ParseListFilter reads the members list's query parameters: q, role,
// department, mfa (on or off), email_verified, status, last_seen,
// admins_without_mfa, in_group, id and email (each repeatable, up to
// maxNamed), include_deleted, sort and order (asc or desc). A malformed one
// is refused with ErrBadRequest.
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
	if len(v["id"]) > maxNamed || len(v["email"]) > maxNamed {
		return bad("id or email: at most " + strconv.Itoa(maxNamed))
	}
	for _, raw := range v["id"] {
		id, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			return bad("id")
		}
		f.IDs = append(f.IDs, id)
	}
	for _, raw := range v["email"] {
		email := strings.ToLower(strings.TrimSpace(raw))
		if email == "" || len(email) > 320 {
			return bad("email")
		}
		f.Emails = append(f.Emails, email)
	}
	if raw := v.Get("include_deleted"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return bad("include_deleted")
		}
		f.IncludeDeleted = b
	}
	for name, into := range map[string]**bool{
		"email_verified": &f.EmailVerified, "admins_without_mfa": &f.AdminsWithoutMFA, "in_group": &f.InGroup,
	} {
		if raw := v.Get(name); raw != "" {
			b, err := strconv.ParseBool(raw)
			if err != nil {
				return bad(name)
			}
			*into = &b
		}
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

// membersCTE is an organization's live members ($1): its home people and
// those holding one of its roles, with their roles there, whether they have a
// second factor, how many of its groups they're in, when they were last seen
// there, and their home organization's name.
var membersCTE = membersOf(false)

// membersOf is membersCTE, with the members since deleted too when
// includeDeleted: its people deleted from their home here, and those still
// holding one of its roles.
func membersOf(includeDeleted bool) string {
	live, liveHome := "deleted_at IS NULL\n\t  AND ", " AND u.deleted_at IS NULL"
	if includeDeleted {
		live, liveHome = "", ""
	}
	return `WITH m AS (
	SELECT ` + userCols + `, account.users.deleted_at,
	  COALESCE((
		SELECT array_agg(r.name ORDER BY r.name)
		FROM rbac.user_roles ur2 JOIN rbac.roles r ON r.id = ur2.role_id
		WHERE ur2.user_id = account.users.id AND ur2.organization_id = $1
	  ), '{}') AS roles,
	  COALESCE((
		SELECT jsonb_agg(jsonb_build_object('id', r.id, 'name', r.name) ORDER BY r.name)
		FROM rbac.user_roles ur2 JOIN rbac.roles r ON r.id = ur2.role_id
		WHERE ur2.user_id = account.users.id AND ur2.organization_id = $1
	  ), '[]') AS role_refs,
	  (EXISTS(SELECT 1 FROM auth.mfa_totp t WHERE t.user_id = account.users.id AND t.confirmed_at IS NOT NULL)
	   OR EXISTS(SELECT 1 FROM auth.mfa_otp_factors o WHERE o.user_id = account.users.id AND o.verified_at IS NOT NULL)
	   OR EXISTS(SELECT 1 FROM auth.mfa_push_devices d WHERE d.user_id = account.users.id))::boolean AS mfa_enabled,
	  (SELECT count(*) FROM organization.group_members gm
	   WHERE gm.user_id = account.users.id AND gm.organization_id = $1)::int AS groups_count,
	  ` + lastSeenCols + `,
	  (SELECT ht.name FROM organization.organizations ht WHERE ht.id = account.users.organization_id) AS home_organization_name
	FROM account.users
	WHERE ` + live + `id IN (
		SELECT u.id FROM account.users u WHERE u.organization_id = $1` + liveHome + `
		UNION
		SELECT ur.user_id FROM rbac.user_roles ur WHERE ur.organization_id = $1
	  )
)
`
}

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
	if len(f.IDs) > 0 {
		conds = append(conds, "m.id = ANY("+arg(f.IDs)+"::uuid[])")
	}
	if len(f.Emails) > 0 {
		conds = append(conds, "lower(m.email) = ANY("+arg(f.Emails)+"::text[])")
	}
	if f.Query != "" {
		p := arg("%" + postgres.EscapeLike(f.Query) + "%")
		conds = append(conds, "(m.display_name ILIKE "+p+" OR m.email ILIKE "+p+" OR m.phone ILIKE "+p+")")
	}
	if f.Role != "" {
		conds = append(conds, "EXISTS (SELECT 1 FROM unnest(m.roles) rn WHERE lower(rn) = lower("+arg(f.Role)+"))")
	}
	if f.Department != "" {
		// Another organization's people show it no metadata (SeenBy).
		conds = append(conds, "m.organization_id = $1 AND lower(m.metadata->>'department') = lower("+arg(f.Department)+")")
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
	if f.AdminsWithoutMFA != nil {
		conds = append(conds, "("+adminWithoutMFA+") = "+arg(*f.AdminsWithoutMFA))
	}
	if f.InGroup != nil {
		conds = append(conds, "(m.groups_count > 0) = "+arg(*f.InGroup))
	}
	return strings.Join(conds, " AND "), args
}

// The members list's page sizes: by default, and at most.
const (
	listLimit    = 50
	listMaxLimit = 200
)

// List returns a page of the organization's members that f matches, after
// cursor (one a page in f's order gave) when it is set, the next page's
// cursor, and how many match in all. Every order pages.
func (r *Repository) List(ctx context.Context, organizationID uuid.UUID, f ListFilter, limit int, cursor string) ([]User, string, int, error) {
	limit = paging.Clamp(limit, listLimit, listMaxLimit)
	if f.Sort == "" {
		f.Sort, f.Desc = "created", true
	}
	after, err := f.parseCursor(cursor)
	if err != nil {
		return nil, "", 0, err
	}
	members := membersOf(f.IncludeDeleted)
	where, args := f.where([]any{organizationID})
	// Counted apart from the page: the count reads only the columns the filters
	// name, and the page works out the rest for its own rows alone.
	var total int
	if f.id == nil {
		if err := r.pool.QueryRow(ctx, members+`SELECT count(*) FROM m WHERE `+where, args...).Scan(&total); err != nil {
			return nil, "", 0, err
		}
	}
	if after != nil {
		var cond string
		cond, args = f.after(after, append([]any{}, args...))
		where += " AND " + cond
	}
	dir := "ASC"
	if f.Desc {
		dir = "DESC"
	}
	args = append(args, limit+1)
	rows, err := r.pool.Query(ctx, members+`SELECT `+userCols+`, roles, role_refs, mfa_enabled, groups_count,
		last_seen_at, last_seen_ip, home_organization_name, `+sortName+`, deleted_at
		FROM m WHERE `+where+` ORDER BY `+fmt.Sprintf(listSorts[f.Sort], dir)+
		fmt.Sprintf(` LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, "", 0, err
	}
	defer rows.Close()

	var out []User
	var names []string
	for rows.Next() {
		var u User
		var meta, refs []byte
		var tid *uuid.UUID
		var mfaEnabled bool
		var groupsCount int
		var name string
		if err := rows.Scan(&u.ID, &tid, &u.Email, &u.EmailVerifiedAt,
			&u.Phone, &u.PhoneVerifiedAt, &u.DisplayName, &u.Status, &meta,
			&u.CreatedAt, &u.UpdatedAt, &u.Roles, &refs,
			&mfaEnabled, &groupsCount, &u.LastSeenAt, &u.LastSeenIP, &u.HomeOrganizationName, &name, &u.DeletedAt); err != nil {
			return nil, "", 0, err
		}
		if tid != nil {
			u.OrganizationID = *tid
		}
		if err := json.Unmarshal(refs, &u.AssignedRoles); err != nil {
			return nil, "", 0, err
		}
		u.MfaEnabled, u.GroupsCount = &mfaEnabled, &groupsCount
		u.Metadata = parseUserMetadata(meta, u.ID)
		out = append(out, *u.SeenBy(organizationID))
		names = append(names, name)
	}
	// A mid-stream failure stops the loop without an error from Scan; unchecked,
	// it returns a short page and a cursor that skips people.
	if err := rows.Err(); err != nil {
		return nil, "", 0, err
	}
	if len(out) <= limit {
		return out, "", total, nil
	}
	out = out[:limit]
	next, err := f.cursorAfter(out[limit-1], names[limit-1])
	return out, next, total, err
}

// listCursor is where a page of the members list in a non-default order
// starts: after the member with ID and this sort key, At (when created, or
// last seen, nil for never) or Name (the name order's key). It names the
// order it came from, which it pages alone.
type listCursor struct {
	Sort string     `json:"sort"`
	Desc bool       `json:"desc"`
	At   *time.Time `json:"at,omitempty"`
	Name string     `json:"name,omitempty"`
	ID   uuid.UUID  `json:"id"`
}

// errCursorOrder refuses a cursor a page in another order gave.
var errCursorOrder = errs.ErrBadRequest.WithDetail("invalid cursor, or one from a page in another order")

// cursorAfter is the cursor of the page after u, in f's order; name is u's
// sort name. The default order's is paging's (created_at, id) cursor.
func (f ListFilter) cursorAfter(u User, name string) (string, error) {
	if f.defaultOrder() {
		return paging.EncodeTimeUUID(u.CreatedAt, u.ID), nil
	}
	c := listCursor{Sort: f.Sort, Desc: f.Desc, ID: u.ID}
	switch f.Sort {
	case "name":
		c.Name = name
	case "last_seen":
		c.At = u.LastSeenAt
	default:
		c.At = &u.CreatedAt
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// parseCursor reads cursor, which must be one a page in f's order gave; ""
// is the first page (nil).
func (f ListFilter) parseCursor(cursor string) (*listCursor, error) {
	if cursor == "" {
		return nil, nil
	}
	if f.defaultOrder() {
		at, id, err := paging.DecodeTimeUUID(cursor)
		if err != nil {
			return nil, errCursorOrder
		}
		return &listCursor{Sort: f.Sort, Desc: f.Desc, At: &at, ID: id}, nil
	}
	var c listCursor
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Sort != f.Sort || c.Desc != f.Desc || c.ID == uuid.Nil ||
		(c.Sort == "created" && c.At == nil) {
		return nil, errCursorOrder
	}
	return &c, nil
}

// defaultOrder reports whether f orders the list newest first by creation.
func (f ListFilter) defaultOrder() bool { return f.Sort == "created" && f.Desc }

// after is the condition keeping the members that come after c in f's order,
// with its arguments after args. A member never seen comes last either way.
func (f ListFilter) after(c *listCursor, args []any) (string, []any) {
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	cmp := ">"
	if f.Desc {
		cmp = "<"
	}
	switch f.Sort {
	case "name":
		return fmt.Sprintf("(%s, m.id) %s (%s, %s)", sortName, cmp, arg(c.Name), arg(c.ID)), args
	case "last_seen":
		if c.At == nil {
			return fmt.Sprintf("(m.last_seen_at IS NULL AND m.id %s %s)", cmp, arg(c.ID)), args
		}
		at, id := arg(*c.At), arg(c.ID)
		return fmt.Sprintf("(m.last_seen_at %[1]s %[2]s OR (m.last_seen_at = %[2]s AND m.id %[1]s %[3]s) OR m.last_seen_at IS NULL)",
			cmp, at, id), args
	default:
		return fmt.Sprintf("(m.created_at, m.id) %s (%s, %s)", cmp, arg(*c.At), arg(c.ID)), args
	}
}

// Member is user id as a member of organizationID sees them: their roles there,
// second factor, groups, when they were last seen there and their home
// organization's name. ErrNotFound if they aren't a member.
func (r *Repository) Member(ctx context.Context, organizationID, id uuid.UUID) (*User, error) {
	out, _, _, err := r.List(ctx, organizationID, ListFilter{id: &id}, 1, "")
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errs.ErrNotFound
	}
	return &out[0], nil
}

// Suspension is why and when a person was suspended, and by whom, as their
// home organization recorded it.
type Suspension struct {
	Reason           string     `json:"reason"`
	Source           string     `json:"source"`
	SuspendedAt      *time.Time `json:"suspended_at"`
	SuspendedBy      *uuid.UUID `json:"suspended_by"`
	SuspendedByEmail *string    `json:"suspended_by_email"`
}

// SuspensionOf returns user id's suspension in organizationID, their home: the
// recorded reason and source, and who last suspended them by hand. nil when
// they aren't suspended, or organizationID isn't their home.
func (r *Repository) SuspensionOf(ctx context.Context, organizationID, id uuid.UUID) (*Suspension, error) {
	row, err := r.q.GetSuspension(ctx, dbgen.GetSuspensionParams{OrganizationID: organizationID, ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Suspension{Reason: row.Reason, Source: row.Source, SuspendedAt: row.SuspendedAt,
		SuspendedBy: row.ActorUserID, SuspendedByEmail: row.ActorEmail}, nil
}

// MemberCounts is the rest of the Users summary: members by when they were
// last seen, the owners and admins without a second factor, the members
// whose email isn't verified, members by role, and the organization's own
// people by department, by team and by location.
type MemberCounts struct {
	LastSeen         map[string]int  `json:"last_seen"`
	AdminsWithoutMFA int             `json:"admins_without_mfa"`
	EmailUnverified  int             `json:"email_unverified"`
	ByRole           []RoleCount     `json:"by_role"`
	ByDepartment     []DeptCount     `json:"by_department"`
	ByTeam           []TeamCount     `json:"by_team"`
	ByLocation       []LocationCount `json:"by_location"`
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

// TeamCount is how many members are in a team, within its department ("" when
// they name none).
type TeamCount struct {
	Department string `json:"department"`
	Team       string `json:"team"`
	Count      int    `json:"count"`
}

// LocationCount is how many members work in a location.
type LocationCount struct {
	Location string `json:"location"`
	Count    int    `json:"count"`
}

// maxBreakdown is how many departments, teams or locations the summary lists.
const maxBreakdown = 200

// Counts returns the organization's MemberCounts, each with the same edges as the
// list's filters, so a count equals the list's total for that filter. The
// departments, teams and locations come from the metadata of the people whose
// home is the organization: another organization's people show it none, as
// SeenBy does.
func (r *Repository) Counts(ctx context.Context, organizationID uuid.UUID) (*MemberCounts, error) {
	c := MemberCounts{LastSeen: map[string]int{}}
	var today, week, month, older, never int
	if err := r.pool.QueryRow(ctx, membersCTE+`SELECT
		count(*) FILTER (WHERE `+lastSeenBuckets["today"]+`),
		count(*) FILTER (WHERE `+lastSeenBuckets["week"]+`),
		count(*) FILTER (WHERE `+lastSeenBuckets["month"]+`),
		count(*) FILTER (WHERE `+lastSeenBuckets["older"]+`),
		count(*) FILTER (WHERE `+lastSeenBuckets["never"]+`),
		count(*) FILTER (WHERE `+adminWithoutMFA+`),
		count(*) FILTER (WHERE m.email_verified_at IS NULL)
		FROM m`, organizationID).Scan(&today, &week, &month, &older, &never, &c.AdminsWithoutMFA, &c.EmailUnverified); err != nil {
		return nil, err
	}
	c.LastSeen = map[string]int{"today": today, "week": week, "month": month, "older": older, "never": never}

	var err error
	if c.ByRole, err = collect(ctx, r, membersCTE+`SELECT rn, count(*)::int FROM m, unnest(m.roles) rn
		GROUP BY rn ORDER BY 2 DESC, 1`, func(row pgx.CollectableRow) (RoleCount, error) {
		var rc RoleCount
		return rc, row.Scan(&rc.Role, &rc.Count)
	}, organizationID); err != nil {
		return nil, err
	}
	if c.ByDepartment, err = collect(ctx, r, membersCTE+`SELECT m.metadata->>'department', count(*)::int FROM m
		WHERE m.organization_id = $1 AND COALESCE(m.metadata->>'department', '') <> ''
		GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $2`, func(row pgx.CollectableRow) (DeptCount, error) {
		var dc DeptCount
		return dc, row.Scan(&dc.Department, &dc.Count)
	}, organizationID, maxBreakdown); err != nil {
		return nil, err
	}
	if c.ByTeam, err = collect(ctx, r, membersCTE+`SELECT COALESCE(m.metadata->>'department', ''), m.metadata->>'team', count(*)::int FROM m
		WHERE m.organization_id = $1 AND COALESCE(m.metadata->>'team', '') <> ''
		GROUP BY 1, 2 ORDER BY 3 DESC, 1, 2 LIMIT $2`, func(row pgx.CollectableRow) (TeamCount, error) {
		var tc TeamCount
		return tc, row.Scan(&tc.Department, &tc.Team, &tc.Count)
	}, organizationID, maxBreakdown); err != nil {
		return nil, err
	}
	if c.ByLocation, err = collect(ctx, r, membersCTE+`SELECT m.metadata->>'location', count(*)::int FROM m
		WHERE m.organization_id = $1 AND COALESCE(m.metadata->>'location', '') <> ''
		GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $2`, func(row pgx.CollectableRow) (LocationCount, error) {
		var lc LocationCount
		return lc, row.Scan(&lc.Location, &lc.Count)
	}, organizationID, maxBreakdown); err != nil {
		return nil, err
	}
	return &c, nil
}

// collect runs query with args and returns each row as scan reads it, an
// empty list (never nil) for none.
func collect[T any](ctx context.Context, r *Repository, query string, scan pgx.RowToFunc[T], args ...any) ([]T, error) {
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, scan)
	if out == nil && err == nil {
		out = []T{}
	}
	return out, err
}
