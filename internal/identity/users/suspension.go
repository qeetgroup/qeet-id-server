package user

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	Offset int
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
	Items   []SuspendedUser       `json:"items"`
	Total   int                   `json:"total"`
	Limit   int                   `json:"limit"`
	Offset  int                   `json:"offset"`
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
	for key, destination := range map[string]*int{"limit": &filter.Limit, "offset": &filter.Offset} {
		if raw := query.Get(key); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 0 || value > 100000 || (key == "limit" && (value < 1 || value > 100)) {
				return filter, errs.ErrBadRequest
			}
			*destination = value
		}
	}
	return filter, nil
}

const suspendedDataset = `WITH suspended AS (
 SELECT u.id,u.email,u.display_name,u.avatar_url,
 COALESCE((SELECT p.profile->>'department' FROM tenant.directory_profiles p WHERE p.tenant_id=$1 AND p.user_id=u.id AND p.profile->>'department' IS NOT NULL ORDER BY p.updated_at DESC LIMIT 1),'') AS team,
 CASE WHEN u.tenant_id=$1 THEN COALESCE(u.suspension_reason,'unspecified') ELSE 'managed_elsewhere' END AS reason,
 CASE WHEN u.tenant_id=$1 THEN COALESCE(u.suspension_source,'unknown') ELSE 'external' END AS source,
 CASE WHEN u.tenant_id=$1 THEN COALESCE(u.suspension_risk,'unknown') ELSE 'unknown' END AS risk,
 CASE WHEN u.tenant_id=$1 THEN COALESCE(u.suspension_review,'pending') ELSE 'external' END AS review,
 CASE WHEN u.tenant_id=$1 THEN u.suspended_at ELSE NULL END AS suspended_at,
 (SELECT max(s.created_at) FROM auth.sessions s WHERE s.tenant_id=$1 AND s.user_id=u.id) AS last_sign_in,
 COALESCE(u.tenant_id=$1,false) AS can_manage
 FROM "user".users u WHERE u.status='suspended' AND u.deleted_at IS NULL
 AND (u.tenant_id=$1 OR EXISTS(SELECT 1 FROM rbac.user_roles roles WHERE roles.tenant_id=$1 AND roles.user_id=u.id))
) `
const suspendedWhere = `($2='' OR email ILIKE '%'||$2||'%' OR display_name ILIKE '%'||$2||'%' OR id::text ILIKE '%'||$2||'%') AND ($3='' OR reason=$3) AND ($4='' OR source=$4) AND ($5='' OR team=$5) AND ($6='' OR risk=$6) AND ($7='' OR review=$7)`
const suspendedColumns = `id,email,display_name,avatar_url,team,reason,source,risk,review,suspended_at,last_sign_in,can_manage`

func scanSuspended(row pgx.Row) (SuspendedUser, error) {
	var user SuspendedUser
	err := row.Scan(&user.ID, &user.Email, &user.DisplayName, &user.AvatarURL, &user.Team, &user.Reason, &user.Source, &user.Risk, &user.Review, &user.SuspendedAt, &user.LastSignIn, &user.CanManage)
	return user, err
}

// ListSuspended returns one page of the tenant's suspended accounts.
func (repository *Repository) ListSuspended(ctx context.Context, tenantID uuid.UUID, filter SuspensionFilters) (SuspendedPage, error) {
	page := SuspendedPage{Items: []SuspendedUser{}, Reasons: []SuspensionBreakdown{}, Risks: []SuspensionBreakdown{}, Queue: []SuspendedUser{}, Teams: []string{}, Limit: filter.Limit, Offset: filter.Offset}
	if tenantID == uuid.Nil {
		return page, errs.ErrUnauthorized
	}
	args := []any{tenantID, filter.Search, filter.Reason, filter.Source, filter.Team, filter.Risk, filter.Review}
	err := repository.pool.QueryRow(ctx, suspendedDataset+`SELECT count(*),count(*) FILTER(WHERE risk='high'),count(*) FILTER(WHERE source='policy'),count(*) FILTER(WHERE source='manual'),count(*) FILTER(WHERE review='pending') FROM suspended WHERE `+suspendedWhere, args...).Scan(&page.Summary.Total, &page.Summary.HighRisk, &page.Summary.Policy, &page.Summary.Manual, &page.Summary.Pending)
	if err != nil {
		return page, err
	}
	page.Total = page.Summary.Total
	rows, err := repository.pool.Query(ctx, suspendedDataset+`SELECT `+suspendedColumns+` FROM suspended WHERE `+suspendedWhere+` ORDER BY suspended_at DESC NULLS LAST,id LIMIT $8 OFFSET $9`, append(args, filter.Limit, filter.Offset)...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		user, err := scanSuspended(rows)
		if err != nil {
			rows.Close()
			return page, err
		}
		page.Items = append(page.Items, user)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	for _, group := range []struct {
		column      string
		destination *[]SuspensionBreakdown
	}{{"reason", &page.Reasons}, {"risk", &page.Risks}} {
		rows, err := repository.pool.Query(ctx, suspendedDataset+`SELECT `+group.column+`,count(*) FROM suspended WHERE `+suspendedWhere+` GROUP BY 1 ORDER BY 2 DESC,1`, args...)
		if err != nil {
			return page, err
		}
		for rows.Next() {
			var value SuspensionBreakdown
			if err := rows.Scan(&value.Key, &value.Count); err != nil {
				rows.Close()
				return page, err
			}
			*group.destination = append(*group.destination, value)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return page, err
		}
	}
	queue, err := repository.pool.Query(ctx, suspendedDataset+`SELECT `+suspendedColumns+` FROM suspended WHERE review='pending' ORDER BY suspended_at ASC NULLS FIRST,id LIMIT 5`, tenantID)
	if err != nil {
		return page, err
	}
	for queue.Next() {
		user, err := scanSuspended(queue)
		if err != nil {
			queue.Close()
			return page, err
		}
		page.Queue = append(page.Queue, user)
	}
	err = queue.Err()
	queue.Close()
	if err != nil {
		return page, err
	}
	teams, err := repository.pool.Query(ctx, suspendedDataset+`SELECT DISTINCT team FROM suspended WHERE team<>'' ORDER BY team LIMIT 100`, tenantID)
	if err != nil {
		return page, err
	}
	defer teams.Close()
	for teams.Next() {
		var team string
		if err := teams.Scan(&team); err != nil {
			return page, err
		}
		page.Teams = append(page.Teams, team)
	}
	return page, teams.Err()
}

func (handler *Handler) listSuspended(response http.ResponseWriter, request *http.Request) {
	tenantID, err := httpx.RequireTenant(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	filter, err := parseSuspensionFilters(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	page, err := handler.Repo.ListSuspended(request.Context(), tenantID, filter)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, page)
}

func (handler *Handler) updateStatusWithEvidence(request *http.Request, tenantID, userID uuid.UUID, input UpdateInput) (*User, error) {
	ctx := request.Context()
	tx, err := handler.Repo.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var previous string
	if err := tx.QueryRow(ctx, `SELECT status FROM "user".users WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, tenantID, userID).Scan(&previous); err != nil {
		return nil, errs.ErrNotFound
	}
	if input.Status != nil && *input.Status == "active" && previous == "suspended" {
		if principal := httpx.PrincipalFromCtx(ctx); principal != nil && principal.UserID != nil && *principal.UserID == userID {
			return nil, errs.ErrForbidden
		}
	}
	user, err := handler.Repo.UpdateTx(ctx, tx, userID, input)
	if err != nil {
		return nil, err
	}
	if input.Status != nil && previous != *input.Status {
		action := "user.reactivated"
		if *input.Status == "suspended" {
			action = "user.suspended"
			if _, err := tx.Exec(ctx, `UPDATE "user".users SET suspension_source='manual' WHERE tenant_id=$1 AND id=$2`, tenantID, userID); err != nil {
				return nil, err
			}
		}
		reason := sessionsignal.ReasonReactivated
		if *input.Status == "suspended" {
			reason = sessionsignal.ReasonSuspended
		}
		if err := handler.endEverySignIn(ctx, tx, userID, reason); err != nil {
			return nil, err
		}
		if err := recordSuspensionEvidence(ctx, tx, request, tenantID, userID, action); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return user, nil
}

func recordSuspensionEvidence(ctx context.Context, tx pgx.Tx, request *http.Request, tenantID, userID uuid.UUID, action string) error {
	principal := httpx.PrincipalFromCtx(ctx)
	var actor *uuid.UUID
	actorType := "system"
	if principal != nil {
		actor = principal.UserID
		actorType = principal.ActorType
	}
	if err := audit.Record(ctx, tx, audit.Event{TenantID: &tenantID, ActorUserID: actor, ActorType: actorType, Action: action, ResourceType: "user", ResourceID: &userID, IP: httpx.ClientIP(request), RequestID: httpx.RequestID(request)}); err != nil {
		return err
	}
	return outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: userID, Topic: "user.events", EventType: action, Payload: map[string]any{"tenant_id": tenantID, "user_id": userID}})
}

func (handler *Handler) reactivateUser(response http.ResponseWriter, request *http.Request) {
	userID, tenantID, err := handler.scopedID(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if principal := httpx.PrincipalFromCtx(request.Context()); principal != nil && principal.UserID != nil && *principal.UserID == userID {
		httpx.WriteError(response, request, errs.ErrForbidden)
		return
	}
	ctx := request.Context()
	tx, err := handler.Repo.pool.Begin(ctx)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	defer tx.Rollback(ctx)
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM "user".users WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, tenantID, userID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteError(response, request, errs.ErrNotFound)
		return
	}
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if status != "suspended" {
		httpx.WriteError(response, request, errs.ErrConflict)
		return
	}
	active := "active"
	user, err := handler.Repo.UpdateTx(ctx, tx, userID, UpdateInput{Status: &active})
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := handler.endEverySignIn(ctx, tx, userID, sessionsignal.ReasonReactivated); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := recordSuspensionEvidence(ctx, tx, request, tenantID, userID, "user.reactivated"); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, user)
}

func (handler *Handler) reviewSuspension(response http.ResponseWriter, request *http.Request) {
	userID, tenantID, err := handler.scopedID(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	var input struct {
		Reason string `json:"reason"`
		Risk   string `json:"risk"`
		Review string `json:"review"`
	}
	if err := httpx.DecodeJSON(request, &input); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if !validSuspensionValue(input.Reason, "unspecified", "provider", "suspicious_activity", "policy_violation", "account_compromise", "offboarding", "inactive", "other") || !validSuspensionValue(input.Risk, "unknown", "low", "medium", "high") || !validSuspensionValue(input.Review, "pending", "reviewed") {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	ctx := request.Context()
	tx, err := handler.Repo.pool.Begin(ctx)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `UPDATE "user".users SET suspension_reason=$3,suspension_risk=$4,suspension_review=$5,updated_at=NOW() WHERE tenant_id=$1 AND id=$2 AND status='suspended' AND deleted_at IS NULL`, tenantID, userID, input.Reason, input.Risk, input.Review)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if result.RowsAffected() == 0 {
		httpx.WriteError(response, request, errs.ErrConflict)
		return
	}
	if err := recordSuspensionEvidence(ctx, tx, request, tenantID, userID, "user.suspension_reviewed"); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
