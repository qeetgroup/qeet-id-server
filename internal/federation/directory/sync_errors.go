package directory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/directory/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// ErrorSummary counts the directory errors on a page's filter.
type ErrorSummary struct {
	Open          int  `json:"open"`
	Critical      int  `json:"critical"`
	Warning       int  `json:"warning"`
	Retried       int  `json:"retried"`
	ImpactedUsers *int `json:"impacted_users"`
}

// Breakdown is how many errors share a key, such as a category.
type Breakdown struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// ErrorPage is one page of directory errors with their summary.
type ErrorPage struct {
	paging.Result[Event]
	Total        int          `json:"total"`
	Summary      ErrorSummary `json:"summary"`
	Categories   []Breakdown  `json:"categories"`
	Connections  []Breakdown  `json:"connections"`
	Remediations []Event      `json:"remediations"`
	Limit        int          `json:"limit"`
}

type errorFilter struct {
	eventFilter
	Severity   string
	Resolution string
}

const errorWhere = `organization_id=$1 AND started_at >= $2 AND ($3='' OR connection_id=$3) AND ($4='' OR severity=$4) AND ($5='' OR resolution=$5) AND ($6='' OR message ILIKE '%'||$6||'%' OR error_code ILIKE '%'||$6||'%' OR reason ILIKE '%'||$6||'%' OR subject ILIKE '%'||$6||'%' OR resource_id ILIKE '%'||$6||'%') AND status <> 'success' AND status <> 'warning'`

// Errors returns one page of the organization's directory errors.
func (service *Service) Errors(ctx context.Context, organizationID uuid.UUID, filter errorFilter) (ErrorPage, error) {
	page := ErrorPage{Result: paging.Page([]Event{}, ""), Categories: []Breakdown{}, Connections: []Breakdown{}, Remediations: []Event{}, Limit: filter.Limit}
	if organizationID == uuid.Nil || service.pool == nil {
		return page, errs.ErrUnauthorized
	}
	args := []any{organizationID, filter.Since, filter.ConnectionID, filter.Severity, filter.Resolution, postgres.EscapeLike(filter.Search)}
	var impacted, unknown int
	err := service.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE resolution='open'),count(*) FILTER(WHERE resolution='open' AND severity='critical'),count(*) FILTER(WHERE resolution='open' AND severity='warning'),count(*) FILTER(WHERE resolution='retried'),count(DISTINCT NULLIF(resource_id,'')) FILTER(WHERE resource_type='user'),count(*) FILTER(WHERE resource_type='user' AND resource_id='') FROM organization.directory_events WHERE `+errorWhere, args...).Scan(&page.Total, &page.Summary.Open, &page.Summary.Critical, &page.Summary.Warning, &page.Summary.Retried, &impacted, &unknown)
	if err != nil {
		return page, err
	}
	if unknown == 0 {
		page.Summary.ImpactedUsers = &impacted
	}
	rows, err := service.pool.Query(ctx, `SELECT `+eventColumns+` FROM organization.directory_events WHERE `+errorWhere+` AND (NOT $8::boolean OR (started_at,id) < ($9::timestamptz,$10::uuid)) ORDER BY started_at DESC,id DESC LIMIT $7`, append(args, filter.Limit+1, filter.After.Set, filter.After.Time, filter.After.ID)...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		event, scanErr := scanEvent(rows)
		if scanErr != nil {
			rows.Close()
			return page, scanErr
		}
		page.Items = append(page.Items, event)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	page.Items, page.NextCursor = paging.Next(page.Items, filter.Limit, eventKey)
	for _, group := range []struct {
		column      string
		destination *[]Breakdown
	}{{"category", &page.Categories}, {"connection_id", &page.Connections}} {
		rows, err := service.pool.Query(ctx, `SELECT `+group.column+`,count(*) FROM organization.directory_events WHERE `+errorWhere+` GROUP BY 1 ORDER BY 2 DESC,1 LIMIT 20`, args...)
		if err != nil {
			return page, err
		}
		for rows.Next() {
			var item Breakdown
			if err := rows.Scan(&item.Key, &item.Count); err != nil {
				rows.Close()
				return page, err
			}
			*group.destination = append(*group.destination, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return page, err
		}
	}
	remediations, err := service.q.RecentRemediations(ctx, dbgen.RecentRemediationsParams{OrganizationID: organizationID, ConnectionID: filter.ConnectionID})
	if err != nil {
		return page, err
	}
	for _, r := range remediations {
		event, err := toEvent(dbgen.GetOpenDirectoryErrorRow(r))
		if err != nil {
			return page, err
		}
		page.Remediations = append(page.Remediations, event)
	}
	return page, nil
}

// toEvent is an event as its queries return it.
func toEvent(r dbgen.GetOpenDirectoryErrorRow) (Event, error) {
	event := Event{
		ID: r.ID, ConnectionID: r.ConnectionID, Operation: r.Operation, Trigger: r.TriggerType,
		ResourceType: r.ResourceType, ResourceID: r.ResourceID, StartedAt: r.StartedAt, DurationMS: r.DurationMs,
		HTTPStatus: int(r.HttpStatus), Status: r.Status, UsersSynced: int(r.UsersSynced), GroupsSynced: int(r.GroupsSynced),
		ErrorCode: r.ErrorCode, Message: r.Message, Category: r.Category, Severity: r.Severity,
		Resolution: r.Resolution, ResolvedAt: r.ResolvedAt, RetryOf: r.RetryOf,
		Reason: r.Reason, Subject: r.Subject, UserID: r.UserID,
	}
	if err := json.Unmarshal(r.Params, &event.Params); err != nil {
		return event, err
	}
	if len(event.Params) == 0 {
		event.Params = nil
	}
	event.Retryable = canRetry(event)
	return event, nil
}

func (handler *Handler) errors(response http.ResponseWriter, request *http.Request) {
	organizationID, err := requireOrganization(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	base, err := parseEventFilter(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	filter := errorFilter{eventFilter: base, Severity: request.URL.Query().Get("severity"), Resolution: request.URL.Query().Get("resolution")}
	if filter.Severity != "" && filter.Severity != "warning" && filter.Severity != "critical" {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	if filter.Resolution != "" && filter.Resolution != "open" && filter.Resolution != "resolved" && filter.Resolution != "retried" {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	page, err := handler.Service.Errors(request.Context(), organizationID, filter)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, page)
}

type retryContextKey struct{}

// LDAPTester tests an LDAP connection.
type LDAPTester interface {
	TestConnection(context.Context, uuid.UUID, uuid.UUID) error
}

func canRetry(event Event) bool {
	return event.Status != "success" && event.Resolution == "open" && event.Operation == "test" && !strings.HasPrefix(event.ConnectionID, "scim:")
}

func (handler *Handler) resolveError(response http.ResponseWriter, request *http.Request) {
	handler.changeError(response, request, false)
}

func (handler *Handler) retryError(response http.ResponseWriter, request *http.Request) {
	handler.changeError(response, request, true)
}

func (handler *Handler) changeError(response http.ResponseWriter, request *http.Request, retry bool) {
	organizationID, err := requireOrganization(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	eventID, err := httpx.PathUUID(request, "eventID", errs.ErrBadRequest)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	success, err := handler.Service.SettleError(request.Context(), organizationID, eventID, retry, audit.ActorOf(request))
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, map[string]any{"succeeded": success})
}

// SettleError resolves the organization's open error eventID or, with retry,
// runs its connection test again and settles it as retried when that passes,
// recorded as actor's either way. It reports whether the error was settled.
func (service *Service) SettleError(ctx context.Context, organizationID, eventID uuid.UUID, retry bool, actor audit.Actor) (bool, error) {
	key := dbgen.GetOpenDirectoryErrorParams{OrganizationID: organizationID, ID: eventID}
	resolution, action, success := "resolved", "directory.error_resolved", true
	if retry {
		// The check runs before the error's row is locked: it records its own
		// event, pointing back at this error, which a held lock would block.
		row, err := service.q.GetOpenDirectoryError(ctx, key)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, errs.ErrNotFound
		}
		if err != nil {
			return false, err
		}
		event, err := toEvent(row)
		if err != nil {
			return false, err
		}
		tester, ok := service.ldap.(LDAPTester)
		connectionID, parseErr := uuid.Parse(event.ConnectionID)
		if !ok || parseErr != nil || !canRetry(event) {
			return false, errs.ErrConflict
		}
		err = tester.TestConnection(context.WithValue(ctx, retryContextKey{}, eventID), organizationID, connectionID)
		success = err == nil
		resolution, action = "retried", "directory.error_retried"
	}
	tx, err := service.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	q := service.q.WithTx(tx)
	locked, err := q.LockOpenDirectoryError(ctx, dbgen.LockOpenDirectoryErrorParams(key))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, errs.ErrNotFound
	}
	if err != nil {
		return false, err
	}
	if locked.Resolution != "open" {
		return false, errs.ErrConflict
	}
	if success {
		if err := q.SettleDirectoryError(ctx, dbgen.SettleDirectoryErrorParams{
			OrganizationID: organizationID, ID: eventID, Resolution: resolution, ResolvedBy: actor.UserID,
		}); err != nil {
			return false, err
		}
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, action, "directory_error", eventID, map[string]any{"success": success})); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return success, nil
}
