package user

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// SuspendedUser is a suspended account, as listed for review.
type SuspendedUser struct {
	ID          uuid.UUID  `json:"id"`
	Email       string     `json:"email"`
	DisplayName *string    `json:"display_name"`
	AvatarURL   *string    `json:"avatar_url"`
	Team        string     `json:"team"`
	Reason      string     `json:"reason"`
	Source      string     `json:"source"`
	Risk        string     `json:"risk"`
	Review      string     `json:"review"`
	SuspendedAt *time.Time `json:"suspended_at"`
	LastSignIn  *time.Time `json:"last_sign_in"`
	CanManage   bool       `json:"can_manage"`
}

// SuspensionFilters narrow the suspended-accounts list.
type SuspensionFilters struct {
	Search string
	Reason string
	Source string
	Team   string
	Risk   string
	Review string
	Limit  int
	After  paging.Cursor
}

// SuspensionSummary counts the suspended accounts on the filter.
type SuspensionSummary struct {
	Total    int `json:"total"`
	HighRisk int `json:"high_risk"`
	Policy   int `json:"policy"`
	Manual   int `json:"manual"`
	Pending  int `json:"pending"`
}

// SuspensionBreakdown is how many suspensions share a key, such as a reason.
type SuspensionBreakdown struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// SuspendedPage is one page of suspended accounts with their summary.
type SuspendedPage struct {
	paging.Result[SuspendedUser]
	Total   int                   `json:"total"`
	Limit   int                   `json:"limit"`
	Summary SuspensionSummary     `json:"summary"`
	Reasons []SuspensionBreakdown `json:"reasons"`
	Risks   []SuspensionBreakdown `json:"risks"`
	Queue   []SuspendedUser       `json:"queue"`
	Teams   []string              `json:"teams"`
}

func validSuspensionValue(value string, values ...string) bool {
	for _, allowed := range values {
		if value == allowed {
			return true
		}
	}
	return false
}

func parseSuspensionFilters(request *http.Request) (SuspensionFilters, error) {
	query := request.URL.Query()
	filter := SuspensionFilters{Search: strings.TrimSpace(query.Get("q")), Reason: query.Get("reason"), Source: query.Get("source"), Team: query.Get("team"), Risk: query.Get("risk"), Review: query.Get("review"), Limit: 25}
	if len(filter.Search) > 200 || len(filter.Team) > 200 {
		return filter, errs.ErrBadRequest
	}
	if !validSuspensionValue(filter.Reason, "", "unspecified", "provider", "suspicious_activity", "policy_violation", "account_compromise", "offboarding", "inactive", "other", "managed_elsewhere") {
		return filter, errs.ErrBadRequest
	}
	if !validSuspensionValue(filter.Source, "", "unknown", "manual", "scim", "ldap", "policy", "external") {
		return filter, errs.ErrBadRequest
	}
	if !validSuspensionValue(filter.Risk, "", "unknown", "low", "medium", "high") {
		return filter, errs.ErrBadRequest
	}
	if !validSuspensionValue(filter.Review, "", "pending", "reviewed", "external") {
		return filter, errs.ErrBadRequest
	}
	filter.Limit = paging.Limit(query, filter.Limit, 100)
	after, err := paging.ParseCursor(query)
	if err != nil {
		return filter, err
	}
	filter.After = after
	return filter, nil
}

const suspendedDataset = `WITH suspended AS (
 SELECT u.id,u.email,u.display_name,u.avatar_url,
 COALESCE((SELECT p.profile->>'department' FROM organization.directory_profiles p WHERE p.organization_id=$1 AND p.user_id=u.id AND p.profile->>'department' IS NOT NULL ORDER BY p.updated_at DESC LIMIT 1),'') AS team,
 CASE WHEN u.organization_id=$1 THEN COALESCE(u.suspension_reason,'unspecified') ELSE 'managed_elsewhere' END AS reason,
 CASE WHEN u.organization_id=$1 THEN COALESCE(u.suspension_source,'unknown') ELSE 'external' END AS source,
 CASE WHEN u.organization_id=$1 THEN COALESCE(u.suspension_risk,'unknown') ELSE 'unknown' END AS risk,
 CASE WHEN u.organization_id=$1 THEN COALESCE(u.suspension_review,'pending') ELSE 'external' END AS review,
 CASE WHEN u.organization_id=$1 THEN u.suspended_at ELSE NULL END AS suspended_at,
 GREATEST((SELECT max(s.created_at) FROM auth.sessions s WHERE s.organization_id=$1 AND s.user_id=u.id),
  (SELECT max(e.created_at) FROM audit.events e WHERE e.organization_id=$1 AND e.actor_user_id=u.id AND e.action='auth.login_succeeded')) AS last_sign_in,
 COALESCE(u.organization_id=$1,false) AS can_manage
 FROM account.users u WHERE u.status='suspended' AND u.deleted_at IS NULL
 AND (u.organization_id=$1 OR EXISTS(SELECT 1 FROM rbac.user_roles roles WHERE roles.organization_id=$1 AND roles.user_id=u.id))
) `
const suspendedWhere = `($2='' OR email ILIKE '%'||$2||'%' OR display_name ILIKE '%'||$2||'%' OR id::text ILIKE '%'||$2||'%') AND ($3='' OR reason=$3) AND ($4='' OR source=$4) AND ($5='' OR team=$5) AND ($6='' OR risk=$6) AND ($7='' OR review=$7)`
const suspendedColumns = `id,email,display_name,avatar_url,team,reason,source,risk,review,suspended_at,last_sign_in,can_manage`

func scanSuspended(row pgx.Row) (SuspendedUser, error) {
	var user SuspendedUser
	err := row.Scan(&user.ID, &user.Email, &user.DisplayName, &user.AvatarURL, &user.Team, &user.Reason, &user.Source, &user.Risk, &user.Review, &user.SuspendedAt, &user.LastSignIn, &user.CanManage)
	return user, err
}

// ListSuspended returns one page of the organization's suspended accounts.
func (repository *Repository) ListSuspended(ctx context.Context, organizationID uuid.UUID, filter SuspensionFilters) (SuspendedPage, error) {
	page := SuspendedPage{Result: paging.Page([]SuspendedUser{}, ""), Reasons: []SuspensionBreakdown{}, Risks: []SuspensionBreakdown{}, Queue: []SuspendedUser{}, Teams: []string{}, Limit: filter.Limit}
	if organizationID == uuid.Nil {
		return page, errs.ErrUnauthorized
	}
	args := []any{organizationID, postgres.EscapeLike(filter.Search), filter.Reason, filter.Source, filter.Team, filter.Risk, filter.Review}
	err := repository.pool.QueryRow(ctx, suspendedDataset+`SELECT count(*),count(*) FILTER(WHERE risk='high'),count(*) FILTER(WHERE source='policy'),count(*) FILTER(WHERE source='manual'),count(*) FILTER(WHERE review='pending') FROM suspended WHERE `+suspendedWhere, args...).Scan(&page.Summary.Total, &page.Summary.HighRisk, &page.Summary.Policy, &page.Summary.Manual, &page.Summary.Pending)
	if err != nil {
		return page, err
	}
	page.Total = page.Summary.Total
	if err := repository.suspendedItems(ctx, args, filter, &page); err != nil {
		return page, err
	}
	if err := repository.suspendedBreakdowns(ctx, args, &page); err != nil {
		return page, err
	}
	if err := repository.suspendedQueue(ctx, organizationID, &page); err != nil {
		return page, err
	}
	return page, repository.suspendedTeams(ctx, organizationID, &page)
}

// suspendedItems reads into page the page of suspended accounts filter asks
// for, args selecting them. The order is suspended_at newest first, then the
// never-dated (people another organization manages) last, then id; a cursor's
// zero time stands for a NULL suspended_at.
func (repository *Repository) suspendedItems(ctx context.Context, args []any, filter SuspensionFilters, page *SuspendedPage) error {
	var afterTime *time.Time
	if filter.After.Set && !filter.After.Time.IsZero() {
		afterTime = &filter.After.Time
	}
	rows, err := repository.pool.Query(ctx, suspendedDataset+`SELECT `+suspendedColumns+` FROM suspended WHERE `+suspendedWhere+`
 AND (NOT $9::boolean
  OR ($10::timestamptz IS NOT NULL AND (suspended_at < $10 OR (suspended_at = $10 AND id > $11) OR suspended_at IS NULL))
  OR ($10::timestamptz IS NULL AND suspended_at IS NULL AND id > $11))
 ORDER BY suspended_at DESC NULLS LAST,id LIMIT $8`, append(args, filter.Limit+1, filter.After.Set, afterTime, filter.After.ID)...)
	if err != nil {
		return err
	}
	for rows.Next() {
		user, err := scanSuspended(rows)
		if err != nil {
			rows.Close()
			return err
		}
		page.Items = append(page.Items, user)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	page.Items, page.NextCursor = paging.Next(page.Items, filter.Limit, func(user SuspendedUser) (time.Time, uuid.UUID) {
		if user.SuspendedAt == nil {
			return time.Time{}, user.ID
		}
		return *user.SuspendedAt, user.ID
	})
	return nil
}

// suspendedBreakdowns counts into page the suspended accounts args select by
// reason and by risk.
func (repository *Repository) suspendedBreakdowns(ctx context.Context, args []any, page *SuspendedPage) error {
	for _, group := range []struct {
		column      string
		destination *[]SuspensionBreakdown
	}{{"reason", &page.Reasons}, {"risk", &page.Risks}} {
		rows, err := repository.pool.Query(ctx, suspendedDataset+`SELECT `+group.column+`,count(*) FROM suspended WHERE `+suspendedWhere+` GROUP BY 1 ORDER BY 2 DESC,1`, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var value SuspensionBreakdown
			if err := rows.Scan(&value.Key, &value.Count); err != nil {
				rows.Close()
				return err
			}
			*group.destination = append(*group.destination, value)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// suspendedQueue reads into page the organization's suspensions waiting longest
// for review.
func (repository *Repository) suspendedQueue(ctx context.Context, organizationID uuid.UUID, page *SuspendedPage) error {
	queue, err := repository.pool.Query(ctx, suspendedDataset+`SELECT `+suspendedColumns+` FROM suspended WHERE review='pending' ORDER BY suspended_at ASC NULLS FIRST,id LIMIT 5`, organizationID)
	if err != nil {
		return err
	}
	for queue.Next() {
		user, err := scanSuspended(queue)
		if err != nil {
			queue.Close()
			return err
		}
		page.Queue = append(page.Queue, user)
	}
	err = queue.Err()
	queue.Close()
	return err
}

// suspendedTeams reads into page the teams of the organization's suspended
// accounts, for the team filter.
func (repository *Repository) suspendedTeams(ctx context.Context, organizationID uuid.UUID, page *SuspendedPage) error {
	teams, err := repository.pool.Query(ctx, suspendedDataset+`SELECT DISTINCT team FROM suspended WHERE team<>'' ORDER BY team LIMIT 100`, organizationID)
	if err != nil {
		return err
	}
	defer teams.Close()
	for teams.Next() {
		var team string
		if err := teams.Scan(&team); err != nil {
			return err
		}
		page.Teams = append(page.Teams, team)
	}
	return teams.Err()
}

func (handler *Handler) listSuspended(response http.ResponseWriter, request *http.Request) {
	organizationID, err := httpx.RequireOrganization(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	filter, err := parseSuspensionFilters(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	page, err := handler.Repo.ListSuspended(request.Context(), organizationID, filter)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, page)
}

// profileChanges names the profile fields input changes on before, the
// account as it was: names only, as a phone number or metadata may be
// personal. A field set to what it holds is not a change.
func profileChanges(before *User, input UpdateInput) []string {
	value := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	var changed []string
	if input.DisplayName != nil && *input.DisplayName != value(before.DisplayName) {
		changed = append(changed, "display_name")
	}
	if input.AvatarURL != nil && *input.AvatarURL != value(before.AvatarURL) {
		changed = append(changed, "avatar_url")
	}
	if input.Phone != nil && *input.Phone != value(before.Phone) {
		changed = append(changed, "phone")
	}
	if input.Metadata != nil && (len(input.Metadata) > 0 || len(before.Metadata) > 0) && !reflect.DeepEqual(input.Metadata, before.Metadata) {
		changed = append(changed, "metadata")
	}
	return changed
}

func (handler *Handler) reactivateUser(response http.ResponseWriter, request *http.Request) {
	userID, organizationID, err := handler.actOnID(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	user, err := handler.accounts().reactivate(request.Context(), organizationID, userID, audit.ActorOf(request))
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, user)
}

func (handler *Handler) reviewSuspension(response http.ResponseWriter, request *http.Request) {
	userID, organizationID, err := handler.scopedID(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	var input suspensionReview
	if err := httpx.DecodeJSON(request, &input); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if !validSuspensionValue(input.Reason, "unspecified", "provider", "suspicious_activity", "policy_violation", "account_compromise", "offboarding", "inactive", "other") || !validSuspensionValue(input.Risk, "unknown", "low", "medium", "high") || !validSuspensionValue(input.Review, "pending", "reviewed") {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	if err := handler.accounts().reviewSuspension(request.Context(), organizationID, userID, input, audit.ActorOf(request)); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
